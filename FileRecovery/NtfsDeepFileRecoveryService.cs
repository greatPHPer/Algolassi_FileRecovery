using System.Runtime.InteropServices;
using System.Buffers.Binary;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class NtfsDeepFileRecoveryService
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    private const int IoBufferSize = 4 * 1024 * 1024;
    private const long DefaultMaxBytesToScan = 4L * 1024L * 1024L * 1024L;
    private const long MaxCarvedFileBytes = 64L * 1024L * 1024L;

    public RecoveryResult Recover(
        RecoveryCandidate candidate,
        string destinationDirectory,
        CancellationToken cancellationToken = default,
        long maxBytesToScan = DefaultMaxBytesToScan)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        if (candidate.DataStreamFound)
        {
            throw new InvalidOperationException(
                "Deep NTFS carving is only required for candidates without retained NTFS $DATA evidence.");
        }

        if (maxBytesToScan <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytesToScan));
        }

        RecoveryDestinationPolicy.Validate(candidate.FullPath, destinationDirectory);

        var extension = Path.GetExtension(candidate.Name);
        if (!SupportsExtension(extension))
        {
            throw new InvalidOperationException(
                $"Deep file carving does not have a safe structural carver for '{extension}'. " +
                "This recovery path requires a file type with a recognizable, self-delimiting format.");
        }

        WindowsPrivilege.EnableSeBackupPrivilege();

        var sourceRoot = Path.GetPathRoot(candidate.FullPath);
        if (string.IsNullOrWhiteSpace(sourceRoot))
        {
            throw new InvalidOperationException(
                "The deleted file's source volume could not be determined.");
        }

        if (!string.Equals(
                new DriveInfo(sourceRoot).DriveFormat,
                "NTFS",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Deep file carving currently supports NTFS volumes only.");
        }

        var volumeInfo = new NtfsVolumeInspector().Inspect(sourceRoot);
        using var volumeHandle = CreateVolumeHandle(sourceRoot);
        var bitmapReader = new NtfsVolumeBitmapReader();

        long scannedBytes = 0;

        foreach (var freeExtent in bitmapReader.EnumerateFreeExtents(
                     volumeHandle,
                     volumeInfo,
                     cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var extentBytes = checked(
                freeExtent.ClusterCount * (long)volumeInfo.BytesPerCluster);

            if (extentBytes <= 0)
            {
                continue;
            }

            var extentOffset = checked(
                freeExtent.LogicalClusterNumber * (long)volumeInfo.BytesPerCluster);
            var extentBytesScanned = 0L;

            // A single free extent can be much larger than the 64 MB carve buffer.
            // Walk the entire extent in bounded chunks instead of scanning only its
            // first chunk and then skipping the remainder.
            while (extentBytesScanned < extentBytes &&
                   scannedBytes < maxBytesToScan)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var bytesRemainingInExtent = extentBytes - extentBytesScanned;
                var bytesRemainingOverall = maxBytesToScan - scannedBytes;
                var bytesToRead = Math.Min(
                    bytesRemainingInExtent,
                    Math.Min(bytesRemainingOverall, MaxCarvedFileBytes));

                bytesToRead -= bytesToRead % volumeInfo.BytesPerCluster;

                if (bytesToRead < volumeInfo.BytesPerCluster)
                {
                    break;
                }

                var buffer = new byte[checked((int)bytesToRead)];
                var physicalOffset = checked(extentOffset + extentBytesScanned);

                ReadAt(
                    volumeHandle,
                    physicalOffset,
                    buffer,
                    cancellationToken);

                scannedBytes = checked(scannedBytes + bytesToRead);
                extentBytesScanned = checked(extentBytesScanned + bytesToRead);

                if (!TryCarve(
                        extension,
                        buffer,
                        out var startOffset,
                        out var carvedLength,
                        out var format))
                {
                    continue;
                }

                if (carvedLength <= 0 ||
                    carvedLength > MaxCarvedFileBytes ||
                    startOffset < 0 ||
                    startOffset > buffer.Length ||
                    carvedLength > buffer.Length - startOffset)
                {
                    continue;
                }

                var absoluteByteOffset = checked(physicalOffset + startOffset);
                var firstCluster = absoluteByteOffset / volumeInfo.BytesPerCluster;
                var lastByteExclusive = checked(
                    absoluteByteOffset + carvedLength);
                var lastClusterExclusive = checked(
                    (lastByteExclusive + volumeInfo.BytesPerCluster - 1) /
                    volumeInfo.BytesPerCluster);
                var clusterCount = checked(lastClusterExclusive - firstCluster);

                if (clusterCount <= 0)
                {
                    continue;
                }

                var allocation = bitmapReader.CheckExtents(
                    volumeHandle,
                    [
                        new NtfsDataExtent
                        {
                            VirtualClusterNumber = 0,
                            LogicalClusterNumber = firstCluster,
                            ClusterCount = clusterCount
                        }
                    ],
                    cancellationToken);

                if (allocation.Count != 1 ||
                    allocation[0].AllocatedClusterCount != 0 ||
                    allocation[0].FreeClusterCount != clusterCount)
                {
                    // The source changed while scanning. Do not trust or write this hit.
                    continue;
                }

                var destinationPath = RecoveryDestinationPolicy.CreateSafeFilePath(
                    destinationDirectory,
                    candidate.Name);

                try
                {
                    using var output = new FileStream(
                        destinationPath,
                        FileMode.CreateNew,
                        FileAccess.Write,
                        FileShare.None,
                        IoBufferSize,
                        FileOptions.SequentialScan);

                    output.Write(
                        buffer,
                        startOffset,
                        carvedLength);
                }
                catch
                {
                    TryDelete(destinationPath);
                    throw;
                }

                return new RecoveryResult
                {
                    Success = true,
                    SourcePath = candidate.FullPath,
                    DestinationPath = destinationPath,
                    BytesRecovered = carvedLength,
                    Evidence =
                        $"Deep NTFS file carving recovered {carvedLength:N0} byte(s) as a structurally valid {format} file from currently free clusters."
                };
            }
        }

        throw new InvalidOperationException(
            $"No structurally valid {extension} file was found in the first " +
            $"{scannedBytes:N0} free-space byte(s) scanned.");
    }

    private static bool SupportsExtension(string extension) =>
        extension.Equals(".jpg", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".jpeg", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".png", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".gif", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".bmp", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".wav", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".webp", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".zip", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".docx", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".xlsx", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".pptx", StringComparison.OrdinalIgnoreCase);

    private static bool TryCarve(
        string extension,
        byte[] buffer,
        out int startOffset,
        out int length,
        out string format)
    {
        startOffset = 0;
        length = 0;
        format = string.Empty;

        if (extension.Equals(".jpg", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".jpeg", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindJpeg(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "JPEG";
            return true;
        }

        if (extension.Equals(".png", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindPng(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "PNG";
            return true;
        }

        if (extension.Equals(".gif", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindGif(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "GIF";
            return true;
        }

        if (extension.Equals(".bmp", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindBmp(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "BMP";
            return true;
        }

        if (extension.Equals(".wav", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindWav(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "WAV";
            return true;
        }

        if (extension.Equals(".webp", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindWebp(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "WebP";
            return true;
        }

        if (extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindPdf(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "PDF";
            return true;
        }

        if (extension.Equals(".zip", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".docx", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".xlsx", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".pptx", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindZip(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "ZIP";
            return true;
        }

        return false;
    }

    private static bool TryFindJpeg(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        for (var i = 0; i + 2 < buffer.Length; i++)
        {
            if (buffer[i] != 0xFF ||
                buffer[i + 1] != 0xD8 ||
                buffer[i + 2] != 0xFF)
            {
                continue;
            }

            for (var j = i + 3; j + 1 < buffer.Length; j++)
            {
                if (buffer[j] == 0xFF && buffer[j + 1] == 0xD9)
                {
                    start = i;
                    length = checked(j + 2 - i);
                    return length <= MaxCarvedFileBytes;
                }
            }
        }

        return false;
    }

    private static bool TryFindPng(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        ReadOnlySpan<byte> signature =
        [
            0x89, 0x50, 0x4E, 0x47,
            0x0D, 0x0A, 0x1A, 0x0A
        ];

        for (var candidate = buffer.AsSpan().IndexOf(signature);
             candidate >= 0;)
        {
            var absolute = candidate;
            var position = absolute + signature.Length;

            while (position + 12 <= buffer.Length)
            {
                var chunkLength =
                    BinaryPrimitives.ReadUInt32BigEndian(
                        buffer.AsSpan(position, 4));

                var next = checked((long)position + 12 + chunkLength);
                if (next > buffer.Length || next - absolute > MaxCarvedFileBytes)
                {
                    break;
                }

                var type = buffer.AsSpan(position + 4, 4);
                position = checked((int)next);

                if (type.SequenceEqual("IEND"u8))
                {
                    start = absolute;
                    length = position - absolute;
                    return true;
                }
            }

            var nextSearch = absolute + 1;
            if (nextSearch >= buffer.Length - signature.Length + 1)
            {
                break;
            }

            var found = buffer.AsSpan(nextSearch).IndexOf(signature);
            candidate = found < 0 ? -1 : nextSearch + found;
        }

        return false;
    }

    private static bool TryFindGif(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        for (var i = 0; i + 13 <= buffer.Length; i++)
        {
            if (!(
                buffer.AsSpan(i, 6).SequenceEqual("GIF87a"u8) ||
                buffer.AsSpan(i, 6).SequenceEqual("GIF89a"u8)))
            {
                continue;
            }

            for (var j = i + 13; j < buffer.Length; j++)
            {
                if (buffer[j] == 0x3B)
                {
                    start = i;
                    length = j + 1 - i;
                    return length <= MaxCarvedFileBytes;
                }
            }
        }

        return false;
    }

    private static bool TryFindBmp(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        for (var i = 0; i + 6 <= buffer.Length; i++)
        {
            if (buffer[i] != 0x42 || buffer[i + 1] != 0x4D)
            {
                continue;
            }

            var fileSize = BinaryPrimitives.ReadUInt32LittleEndian(
                buffer.AsSpan(i + 2, 4));

            if (fileSize < 14 ||
                fileSize > MaxCarvedFileBytes ||
                i + fileSize > buffer.Length)
            {
                continue;
            }

            start = i;
            length = checked((int)fileSize);
            return true;
        }

        return false;
    }

    private static bool TryFindWav(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        for (var i = 0; i + 12 <= buffer.Length; i++)
        {
            if (!buffer.AsSpan(i, 4).SequenceEqual("RIFF"u8) ||
                !buffer.AsSpan(i + 8, 4).SequenceEqual("WAVE"u8))
            {
                continue;
            }

            var riffSize = BinaryPrimitives.ReadUInt32LittleEndian(
                buffer.AsSpan(i + 4, 4));

            var totalSize = checked((long)riffSize + 8);
            if (totalSize < 12 ||
                totalSize > MaxCarvedFileBytes ||
                i + totalSize > buffer.Length)
            {
                continue;
            }

            start = i;
            length = checked((int)totalSize);
            return true;
        }

        return false;
    }

    private static bool TryFindWebp(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        for (var i = 0; i + 12 <= buffer.Length; i++)
        {
            if (!buffer.AsSpan(i, 4).SequenceEqual("RIFF"u8) ||
                !buffer.AsSpan(i + 8, 4).SequenceEqual("WEBP"u8))
            {
                continue;
            }

            var riffSize = BinaryPrimitives.ReadUInt32LittleEndian(
                buffer.AsSpan(i + 4, 4));
            var totalSize = checked((long)riffSize + 8);

            if (totalSize < 12 ||
                totalSize > MaxCarvedFileBytes ||
                i + totalSize > buffer.Length)
            {
                continue;
            }

            start = i;
            length = checked((int)totalSize);
            return true;
        }

        return false;
    }

    private static bool TryFindPdf(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        var signature = "%PDF-"u8;
        var eof = "%%EOF"u8;

        var searchFrom = 0;
        while (searchFrom < buffer.Length)
        {
            var relativeStart = buffer.AsSpan(searchFrom).IndexOf(signature);
            if (relativeStart < 0)
            {
                return false;
            }

            start = searchFrom + relativeStart;
            if (start >= buffer.Length)
            {
                return false;
            }

            var eofRelative = buffer.AsSpan(start + signature.Length).IndexOf(eof);
            if (eofRelative < 0)
            {
                searchFrom = start + 1;
                continue;
            }

            var eofStart = start + signature.Length + eofRelative;
            length = eofStart + eof.Length - start;
            if (length <= MaxCarvedFileBytes)
            {
                return true;
            }

            searchFrom = start + 1;
        }

        return false;
    }

    private static bool TryFindZip(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        var localHeader = new byte[] { 0x50, 0x4B, 0x03, 0x04 };
        var emptyHeader = new byte[] { 0x50, 0x4B, 0x05, 0x06 };

        var searchFrom = 0;
        while (searchFrom < buffer.Length)
        {
            var relativeStart = buffer.AsSpan(searchFrom).IndexOf(localHeader);
            if (relativeStart < 0)
            {
                return false;
            }

            start = searchFrom + relativeStart;
            for (var i = buffer.Length - 22; i >= start; i--)
            {
                if (!buffer.AsSpan(i, 4).SequenceEqual(emptyHeader))
                {
                    continue;
                }

                var commentLength = BinaryPrimitives.ReadUInt16LittleEndian(
                    buffer.AsSpan(i + 20, 2));
                var end = checked((long)i + 22 + commentLength);

                if (end <= buffer.Length &&
                    end - start <= MaxCarvedFileBytes)
                {
                    length = checked((int)(end - start));
                    return true;
                }
            }

            searchFrom = start + 1;
        }

        return false;
    }

    private static void ReadAt(
        SafeFileHandle volumeHandle,
        long offset,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        var remaining = buffer.Length;
        var currentOffset = offset;
        var bufferOffset = 0;

        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var chunk = Math.Min(IoBufferSize, remaining);
            if (!SetFilePointerEx(
                    volumeHandle,
                    currentOffset,
                    out _,
                    0))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not seek to free cluster offset {currentOffset:N0}.");
            }

            var chunkBuffer = bufferOffset == 0 && chunk == buffer.Length
                ? buffer
                : new byte[chunk];

            if (!ReadFile(
                    volumeHandle,
                    chunkBuffer,
                    (uint)chunk,
                    out var bytesRead,
                    IntPtr.Zero) ||
                bytesRead != (uint)chunk)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not read free cluster data at byte offset {currentOffset:N0}.");
            }

            if (!ReferenceEquals(chunkBuffer, buffer))
            {
                Buffer.BlockCopy(
                    chunkBuffer,
                    0,
                    buffer,
                    bufferOffset,
                    chunk);
            }

            currentOffset = checked(currentOffset + chunk);
            bufferOffset += chunk;
            remaining -= chunk;
        }
    }

    private static SafeFileHandle CreateVolumeHandle(string root)
    {
        var volumeName = root.TrimEnd(Path.DirectorySeparatorChar);

        var handle = CreateFile(
            $@"\\.\{volumeName[..2]}",
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Could not open NTFS source volume {root} for deep file carving.");
        }

        return handle;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }

    [System.Runtime.InteropServices.DllImport(
        "kernel32.dll",
        CharSet = System.Runtime.InteropServices.CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [System.Runtime.InteropServices.DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [System.Runtime.InteropServices.DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);
}
