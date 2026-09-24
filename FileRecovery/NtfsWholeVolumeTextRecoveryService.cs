using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class NtfsWholeVolumeTextRecoveryService
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    private const int IoBufferSize = 8 * 1024 * 1024;
    private const int ProgressIntervalBytes = 128 * 1024 * 1024;
    private const int MaxMarkerBytes = 4096;
    private const int MaxRecoveredTextBytes = 64 * 1024 * 1024;

    public RecoveryResult Recover(
        RecoveryCandidate candidate,
        string destinationDirectory,
        string marker,
        CancellationToken cancellationToken = default,
        IProgress<long>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        if (string.IsNullOrWhiteSpace(marker))
        {
            throw new ArgumentException(
                "A known text marker is required for the whole-volume forensic scan.",
                nameof(marker));
        }

        var markerBytes = System.Text.Encoding.UTF8.GetBytes(marker);
        if (markerBytes.Length < 4)
        {
            throw new ArgumentException(
                "The text marker must contain at least 4 UTF-8 bytes.",
                nameof(marker));
        }

        if (markerBytes.Length > MaxMarkerBytes)
        {
            throw new ArgumentException(
                $"The text marker cannot exceed {MaxMarkerBytes:N0} UTF-8 bytes.",
                nameof(marker));
        }

        if (candidate.DataStreamFound)
        {
            throw new InvalidOperationException(
                "Whole-volume forensic text scanning is only required for candidates without retained NTFS $DATA evidence.");
        }

        if (!Path.GetExtension(candidate.Name).Equals(
                ".txt",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The whole-volume target-content scan currently supports deleted .txt files only.");
        }

        RecoveryDestinationPolicy.Validate(candidate.FullPath, destinationDirectory);
        WindowsPrivilege.EnableSeBackupPrivilege();

        var sourceRoot = GetNtfsVolumeRoot(candidate.FullPath);
        if (string.IsNullOrWhiteSpace(sourceRoot))
        {
            throw new InvalidOperationException(
                "The deleted file's source volume could not be determined.");
        }

        var volumeInfo = new NtfsVolumeInspector().Inspect(sourceRoot);
        var totalVolumeBytes = checked(
            volumeInfo.TotalClusters * (long)volumeInfo.BytesPerCluster);

        if (totalVolumeBytes <= 0)
        {
            throw new InvalidOperationException(
                "The NTFS volume reported an invalid total byte length.");
        }

        using var volumeHandle = CreateVolumeHandle(sourceRoot);

        var overlapLength = markerBytes.Length - 1;
        var previousTail = Array.Empty<byte>();
        long scannedBytes = 0;
        long lastReportedBytes = 0;

        progress?.Report(0);

        System.Diagnostics.Debug.WriteLine(
            $"NTFS whole-volume target scan started: candidate={candidate.FullPath}, " +
            $"markerBytes={markerBytes.Length:N0}, volumeBytes={totalVolumeBytes:N0}.");

        while (scannedBytes < totalVolumeBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var remaining = totalVolumeBytes - scannedBytes;
            var bytesToRead = (int)Math.Min(IoBufferSize, remaining);
            bytesToRead -= bytesToRead % checked((int)volumeInfo.BytesPerCluster);

            if (bytesToRead < volumeInfo.BytesPerCluster)
            {
                break;
            }

            var physicalOffset = scannedBytes;
            byte[]? buffer = null;
            var attemptedBytes = bytesToRead;

            // Raw volume reads can occasionally fail on a small protected or
            // otherwise unreadable region near filesystem metadata. Do not abort
            // a forensic scan of the entire volume because one large read failed.
            // Reduce the request geometrically until the problematic range can be
            // isolated to a single cluster.
            while (attemptedBytes >= volumeInfo.BytesPerCluster)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    buffer = new byte[attemptedBytes];
                    ReadAt(
                        volumeHandle,
                        physicalOffset,
                        buffer,
                        cancellationToken);
                    break;
                }
                catch (Win32Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS whole-volume target scan read retry: " +
                        $"offset={physicalOffset:N0}, requested={attemptedBytes:N0}, " +
                        $"error={ex.NativeErrorCode}, message={ex.Message}.");

                    attemptedBytes /= 2;
                    attemptedBytes -=
                        attemptedBytes % checked((int)volumeInfo.BytesPerCluster);
                }
            }

            if (buffer is null)
            {
                var skippedBytes = Math.Min(
                    checked((long)volumeInfo.BytesPerCluster),
                    remaining);

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS whole-volume target scan skipped unreadable cluster: " +
                    $"offset={physicalOffset:N0}, bytes={skippedBytes:N0}.");

                scannedBytes = checked(scannedBytes + skippedBytes);
                previousTail = [];

                if (scannedBytes - lastReportedBytes >= ProgressIntervalBytes ||
                    scannedBytes == totalVolumeBytes)
                {
                    lastReportedBytes = scannedBytes;
                    progress?.Report(scannedBytes);
                }

                continue;
            }

            var bytesRead = buffer.Length;
            var window = new byte[checked(previousTail.Length + bytesRead)];

            if (previousTail.Length > 0)
            {
                Buffer.BlockCopy(
                    previousTail,
                    0,
                    window,
                    0,
                    previousTail.Length);
            }

            Buffer.BlockCopy(
                buffer,
                0,
                window,
                previousTail.Length,
                bytesRead);

            var markerOffsetInWindow = window.AsSpan().IndexOf(markerBytes);
            scannedBytes = checked(scannedBytes + bytesRead);

            if (scannedBytes - lastReportedBytes >= ProgressIntervalBytes ||
                scannedBytes == totalVolumeBytes)
            {
                lastReportedBytes = scannedBytes;
                progress?.Report(scannedBytes);
            }

            if (markerOffsetInWindow >= 0)
            {
                var absoluteMarkerOffset = checked(
                    physicalOffset -
                    previousTail.Length +
                    markerOffsetInWindow);

                var recovery = RecoverTextRegionAroundMarker(
                    candidate,
                    destinationDirectory,
                    sourceRoot,
                    volumeInfo,
                    volumeHandle,
                    markerBytes,
                    absoluteMarkerOffset,
                    totalVolumeBytes,
                    cancellationToken);

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS whole-volume target scan hit: " +
                    $"candidate={candidate.FullPath}, " +
                    $"markerOffset={absoluteMarkerOffset:N0}, " +
                    $"scanned={scannedBytes:N0}.");

                return recovery;
            }

            previousTail = buffer.Length <= overlapLength
                ? buffer
                : buffer.AsSpan(buffer.Length - overlapLength).ToArray();
        }

        progress?.Report(scannedBytes);

        System.Diagnostics.Debug.WriteLine(
            $"NTFS whole-volume target scan complete: " +
            $"candidate={candidate.FullPath}, scanned={scannedBytes:N0}, " +
            $"volumeBytes={totalVolumeBytes:N0}, markerFound=false.");

        throw new InvalidOperationException(
            $"The supplied text marker was not found in the first " +
            $"{scannedBytes:N0} byte(s) of the NTFS volume.");
    }

    private static RecoveryResult RecoverTextRegionAroundMarker(
        RecoveryCandidate candidate,
        string destinationDirectory,
        string sourceRoot,
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        byte[] markerBytes,
        long markerOffset,
        long totalVolumeBytes,
        CancellationToken cancellationToken)
    {
        var contextBytesBefore = Math.Min(
            markerOffset,
            MaxRecoveredTextBytes / 2L);
        var contextStart = checked(markerOffset - contextBytesBefore);
        var contextLength = checked(
            (int)Math.Min(
                MaxRecoveredTextBytes,
                totalVolumeBytes - contextStart));

        var context = new byte[contextLength];
        ReadAt(
            volumeHandle,
            contextStart,
            context,
            cancellationToken);

        var markerIndex = checked((int)(markerOffset - contextStart));
        var markerEnd = checked(markerIndex + markerBytes.Length);

        if (markerIndex < 0 ||
            markerEnd > context.Length ||
            !context.AsSpan(markerIndex, markerBytes.Length)
                .SequenceEqual(markerBytes))
        {
            throw new InvalidOperationException(
                "The NTFS volume changed before the matched text marker could be re-read.");
        }

        var start = markerIndex;
        while (start > 0 && IsPlainTextByte(context[start - 1]))
        {
            start--;
        }

        var end = markerEnd;
        while (end < context.Length && IsPlainTextByte(context[end]))
        {
            end++;
        }

        var recoveredLength = end - start;
        if (recoveredLength < markerBytes.Length)
        {
            start = markerIndex;
            end = markerEnd;
            recoveredLength = markerBytes.Length;
        }

        if (recoveredLength > MaxRecoveredTextBytes)
        {
            throw new InvalidOperationException(
                $"The text region containing the marker exceeds the {MaxRecoveredTextBytes:N0}-byte forensic recovery limit.");
        }

        var absoluteStart = checked(contextStart + start);
        var absoluteEnd = checked(contextStart + end);

        var firstCluster = absoluteStart / volumeInfo.BytesPerCluster;
        var lastClusterExclusive = checked(
            (absoluteEnd + volumeInfo.BytesPerCluster - 1) /
            volumeInfo.BytesPerCluster);
        var clusterCount = checked(lastClusterExclusive - firstCluster);

        if (clusterCount <= 0)
        {
            throw new InvalidOperationException(
                "The matched text marker did not map to a valid NTFS cluster range.");
        }

        var allocation = new NtfsVolumeBitmapReader().CheckExtents(
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

        if (allocation.Count != 1)
        {
            throw new InvalidOperationException(
                "The matched NTFS text region could not be classified by the volume bitmap.");
        }

        var allocatedClusters = allocation[0].AllocatedClusterCount;
        var freeClusters = allocation[0].FreeClusterCount;

        var data = context.AsSpan(start, recoveredLength).ToArray();
        var destinationPath = RecoveryDestinationPolicy.CreateSafeFilePath(
            destinationDirectory,
            candidate.Name);

        try
        {
            File.WriteAllBytes(destinationPath, data);
        }
        catch
        {
            TryDelete(destinationPath);
            throw;
        }

        var allocationDescription =
            allocatedClusters > 0 && freeClusters > 0
                ? $"The recovered text spans both allocated and free clusters ({allocatedClusters:N0} allocated, {freeClusters:N0} free)."
                : allocatedClusters > 0
                    ? $"The matched text currently resides in allocated NTFS clusters ({allocatedClusters:N0} cluster(s)). It may be retained inside another live file and is therefore marker-confirmed but not historical file-identity proof."
                    : $"The matched text currently resides in free NTFS clusters ({freeClusters:N0} cluster(s)).";

        return new RecoveryResult
        {
            Success = true,
            SourcePath = candidate.FullPath,
            DestinationPath = destinationPath,
            BytesRecovered = data.Length,
            Evidence =
                $"Whole-volume forensic text scan found the supplied marker at byte " +
                $"{markerOffset:N0} and recovered {data.Length:N0} contiguous text byte(s). " +
                allocationDescription
        };
    }

    private static bool IsPlainTextByte(byte value) =>
        value is 0x09 or 0x0A or 0x0D ||
        value is >= 0x20 and <= 0x7E;

    private static string? GetNtfsVolumeRoot(string path)
    {
        var normalized = path.Trim();

        while (normalized.StartsWith(@"\\?\", StringComparison.Ordinal) ||
               normalized.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }

        return Path.GetPathRoot(normalized);
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
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();

            throw new Win32Exception(
                error,
                $"Could not open NTFS source volume {root} for whole-volume forensic scanning.");
        }

        return handle;
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
                    $"Could not seek to NTFS volume byte offset {currentOffset:N0}.");
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
                    $"Could not read NTFS volume data at byte offset {currentOffset:N0}.");
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

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);
}
