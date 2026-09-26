using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

/// <summary>
/// Conservative forensic helper for extracting a historical file size from the
/// NTFS $LogFile transaction journal.
///
/// NTFS metadata files such as $LogFile can be hidden/protected from ordinary
/// Win32 path access. Instead of opening E:\$LogFile directly, this service reads
/// MFT metadata record 2 ($LogFile) to obtain its $DATA runlist and then reads the
/// mapped clusters through the raw volume handle.
///
/// $LogFile is a finite circular journal, so absence of a match is normal.
/// </summary>
public sealed class NtfsLogFileHistoricalSizeService
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const int ErrorIoPending = 997;

    private const int BufferSize = 1024 * 1024;
    private const uint NtfsFileNameAttributeType = 0x30;
    private const int ParentReferenceOffset = 0;
    private const int AllocatedSizeOffset = 40;
    private const int RealSizeOffset = 48;
    private const int NameLengthOffset = 64;
    private const int NameNamespaceOffset = 65;
    private const int NameOffset = 66;

    // NTFS reserves the first MFT records for well-known metadata files.
    // Record 2 is $LogFile.
    private const ulong LogFileMftSegment = 2;

    public bool TryRecoverFileSize(
        string rootPath,
        string expectedFileName,
        ulong expectedParentFileReferenceNumber,
        long maximumValidFileSize,
        out long fileSizeBytes,
        out string evidence)
    {
        fileSizeBytes = 0;
        evidence = string.Empty;

        if (string.IsNullOrWhiteSpace(rootPath) ||
            string.IsNullOrWhiteSpace(expectedFileName) ||
            expectedParentFileReferenceNumber == 0 ||
            maximumValidFileSize <= 0)
        {
            return false;
        }

        var normalizedRoot = GetNtfsVolumeRoot(rootPath);
        if (string.IsNullOrWhiteSpace(normalizedRoot))
        {
            evidence = "The source path is not on a valid NTFS volume.";
            return false;
        }

        try
        {
            WindowsPrivilege.EnableSeBackupPrivilege();

            var volumeInfo = new NtfsVolumeInspector().Inspect(normalizedRoot);
            using var metadataVolumeHandle = CreateVolumeHandle(
                normalizedRoot,
                overlapped: false);

            using var rawVolumeHandle = CreateVolumeHandle(
                normalizedRoot,
                overlapped: true);

            var dataReader = new NtfsMftDataReader();

            var logStream = dataReader.ReadMetadataFileDataStream(
                volumeInfo,
                metadataVolumeHandle,
                LogFileMftSegment);

            if (!logStream.Found ||
                logStream.IsResident ||
                logStream.Extents.Count == 0 ||
                logStream.FileSizeBytes <= 0)
            {
                evidence =
                    $"NTFS metadata MFT record {LogFileMftSegment} did not expose a usable " +
                    $"nonresident $LogFile $DATA stream. " +
                    $"Found={logStream.Found}, resident={logStream.IsResident}, " +
                    $"fileSize={logStream.FileSizeBytes:N0}, extents={logStream.Extents.Count:N0}. " +
                    logStream.Evidence;
                return false;
            }

            var expectedNameBytes = System.Text.Encoding.Unicode.GetBytes(expectedFileName);
            if (expectedNameBytes.Length == 0)
            {
                evidence = "The deleted filename could not be encoded as UTF-16.";
                return false;
            }

            var overlapLength = Math.Max(
                expectedNameBytes.Length + NameOffset + 16,
                512);

            long scannedBytes = 0;
            var previousTail = Array.Empty<byte>();
            long bestSize = 0;
            long matchCount = 0;
            var expectedVcn = 0L;

            System.Diagnostics.Debug.WriteLine(
                $"NTFS $LogFile raw extent scan started: " +
                $"logicalSize={logStream.FileSizeBytes:N0}, " +
                $"extents={logStream.Extents.Count:N0}, " +
                $"target={expectedFileName}.");

            foreach (var extent in logStream.Extents.OrderBy(
                         x => x.VirtualClusterNumber))
            {
                if (extent.VirtualClusterNumber != expectedVcn)
                {
                    evidence =
                        $"The retained $LogFile $DATA mapping contains a VCN gap at " +
                        $"{expectedVcn:N0}; safe historical-size scanning was stopped.";
                    return false;
                }

                var extentBytes = checked(
                    extent.ClusterCount * (long)volumeInfo.BytesPerCluster);

                if (extentBytes <= 0)
                {
                    expectedVcn = checked(
                        expectedVcn + extent.ClusterCount);
                    continue;
                }

                if (extent.IsSparse)
                {
                    // A sparse region has no physical bytes to search. It also cannot
                    // safely bridge a UTF-16 filename match across the logical hole.
                    previousTail = Array.Empty<byte>();
                    scannedBytes = checked(scannedBytes + extentBytes);
                    expectedVcn = checked(
                        expectedVcn + extent.ClusterCount);
                    continue;
                }

                var physicalExtentOffset = checked(
                    extent.LogicalClusterNumber *
                    (long)volumeInfo.BytesPerCluster);

                var extentBytesScanned = 0L;

                while (extentBytesScanned < extentBytes)
                {
                    var bytesToRead = (int)Math.Min(
                        BufferSize,
                        extentBytes - extentBytesScanned);

                    var physicalOffset = checked(
                        physicalExtentOffset + extentBytesScanned);

                    var logicalOffset = checked(
                        extent.VirtualClusterNumber *
                        (long)volumeInfo.BytesPerCluster +
                        extentBytesScanned);

                    var buffer = new byte[bytesToRead];

                    ReadRawExact(
                        rawVolumeHandle,
                        physicalOffset,
                        buffer);

                    var window = new byte[checked(
                        previousTail.Length + buffer.Length)];

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
                        buffer.Length);

                    var windowLogicalOffset = checked(
                        logicalOffset - previousTail.Length);

                    for (var searchOffset = 0;
                         searchOffset + expectedNameBytes.Length <= window.Length;
                         searchOffset++)
                    {
                        if (!window.AsSpan(
                                searchOffset,
                                expectedNameBytes.Length)
                            .SequenceEqual(expectedNameBytes))
                        {
                            continue;
                        }

                        var valueOffset = searchOffset - NameOffset;
                        if (valueOffset < 0)
                        {
                            continue;
                        }

                        var candidateSize = TryReadFileNameValue(
                            window,
                            valueOffset,
                            expectedFileName,
                            expectedParentFileReferenceNumber,
                            maximumValidFileSize);

                        if (candidateSize <= 0)
                        {
                            continue;
                        }

                        matchCount++;
                        if (candidateSize > bestSize)
                        {
                            bestSize = candidateSize;
                        }

                        System.Diagnostics.Debug.WriteLine(
                            $"NTFS $LogFile historical $FILE_NAME match: " +
                            $"name={expectedFileName}, size={candidateSize:N0}, " +
                            $"logicalOffset={windowLogicalOffset + searchOffset:N0}.");
                    }

                    extentBytesScanned = checked(
                        extentBytesScanned + buffer.Length);

                    scannedBytes = checked(
                        scannedBytes + buffer.Length);

                    previousTail = buffer.Length <= overlapLength
                        ? buffer
                        : buffer.AsSpan(
                            buffer.Length - overlapLength,
                            overlapLength)
                          .ToArray();
                }

                expectedVcn = checked(
                    expectedVcn + extent.ClusterCount);
            }

            if (bestSize <= 0)
            {
                evidence =
                    $"$LogFile was read successfully through MFT record {LogFileMftSegment} " +
                    $"and {logStream.Extents.Count:N0} physical extent(s), " +
                    $"but no structurally valid $FILE_NAME size matching " +
                    $"'{expectedFileName}' and parent reference {expectedParentFileReferenceNumber} " +
                    $"was found after scanning {scannedBytes:N0} bytes of the " +
                    $"{logStream.FileSizeBytes:N0}-byte log stream. " +
                    $"$LogFile evidence: {logStream.Evidence}";
                return false;
            }

            fileSizeBytes = bestSize;
            evidence =
                $"Recovered historical file size {bestSize:N0} bytes from the retained NTFS " +
                $"$LogFile data stream through MFT record {LogFileMftSegment}. " +
                $"Matched {matchCount:N0} structurally valid $FILE_NAME occurrence(s) " +
                $"while scanning {scannedBytes:N0} bytes.";

            return true;
        }
        catch (Exception ex)
        {
            evidence =
                $"NTFS $LogFile historical-size inspection failed: " +
                $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private static long TryReadFileNameValue(
        byte[] buffer,
        int valueOffset,
        string expectedFileName,
        ulong expectedParentFileReferenceNumber,
        long maximumValidFileSize)
    {
        if (valueOffset < 0 ||
            valueOffset + NameOffset > buffer.Length)
        {
            return 0;
        }

        var storedNameLength = buffer[valueOffset + NameLengthOffset];
        var nameNamespace = buffer[valueOffset + NameNamespaceOffset];

        if (storedNameLength == 0 ||
            nameNamespace > 3 ||
            storedNameLength != expectedFileName.Length)
        {
            return 0;
        }

        var nameByteLength = checked(storedNameLength * 2);
        if (NameOffset + nameByteLength > buffer.Length - valueOffset)
        {
            return 0;
        }

        var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(
            buffer.AsSpan(
                valueOffset + ParentReferenceOffset,
                sizeof(ulong)));

        if (parentReference != expectedParentFileReferenceNumber)
        {
            return 0;
        }

        var storedName = System.Text.Encoding.Unicode.GetString(
            buffer,
            valueOffset + NameOffset,
            nameByteLength);

        if (!string.Equals(
                storedName,
                expectedFileName,
                StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        var allocatedSize = BinaryPrimitives.ReadInt64LittleEndian(
            buffer.AsSpan(
                valueOffset + AllocatedSizeOffset,
                sizeof(long)));

        var realSize = BinaryPrimitives.ReadInt64LittleEndian(
            buffer.AsSpan(
                valueOffset + RealSizeOffset,
                sizeof(long)));

        if (realSize < 0 ||
            allocatedSize < 0 ||
            realSize > allocatedSize ||
            realSize > maximumValidFileSize)
        {
            return 0;
        }

        return realSize;
    }

    private static void ReadRawExact(
        SafeFileHandle volumeHandle,
        long fileOffset,
        byte[] buffer)
    {
        using var completionEvent = new ManualResetEvent(initialState: false);

        var overlapped = new NativeOverlapped
        {
            OffsetLow = unchecked((int)(fileOffset & 0xFFFFFFFF)),
            OffsetHigh = unchecked((int)(fileOffset >> 32)),
            HEvent = completionEvent.SafeWaitHandle.DangerousGetHandle()
        };

        var overlappedPtr = Marshal.AllocHGlobal(
            Marshal.SizeOf<NativeOverlapped>());

        try
        {
            Marshal.StructureToPtr(
                overlapped,
                overlappedPtr,
                fDeleteOld: false);

            var bufferHandle = GCHandle.Alloc(
                buffer,
                GCHandleType.Pinned);

            try
            {
                var started = ReadFile(
                    volumeHandle,
                    bufferHandle.AddrOfPinnedObject(),
                    checked((uint)buffer.Length),
                    IntPtr.Zero,
                    overlappedPtr);

                if (!started)
                {
                    var error = Marshal.GetLastWin32Error();

                    if (error != ErrorIoPending)
                    {
                        throw new Win32Exception(
                            error,
                            $"Could not read NTFS $LogFile data at physical byte offset {fileOffset:N0}.");
                    }
                }

                completionEvent.WaitOne();

                if (!GetOverlappedResult(
                        volumeHandle,
                        overlappedPtr,
                        out var bytesRead,
                        bWait: false))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        $"Could not complete NTFS $LogFile data read at physical byte offset {fileOffset:N0}.");
                }

                if (bytesRead != (uint)buffer.Length)
                {
                    throw new EndOfStreamException(
                        $"NTFS $LogFile data read returned {bytesRead:N0} byte(s) instead of {buffer.Length:N0}.");
                }
            }
            finally
            {
                bufferHandle.Free();
            }
        }
        finally
        {
            Marshal.FreeHGlobal(overlappedPtr);
        }
    }

    private static SafeFileHandle CreateVolumeHandle(
        string root,
        bool overlapped)
    {
        var normalizedRoot = GetNtfsVolumeRoot(root)
            ?? throw new ArgumentException(
                "A valid NTFS volume root is required.",
                nameof(root));

        var volumeName = normalizedRoot.TrimEnd(Path.DirectorySeparatorChar);
        var flags = FileFlagBackupSemantics |
                    (overlapped ? FileFlagOverlapped : 0);

        var handle = CreateFile(
            $@"\\.\{volumeName[..2]}",
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();

            throw new Win32Exception(
                error,
                $"Could not open NTFS source volume {normalizedRoot} for $LogFile forensic reading.");
        }

        return handle;
    }

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

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOverlapped
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public int OffsetLow;
        public int OffsetHigh;
        public IntPtr HEvent;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetOverlappedResult(
        SafeFileHandle hFile,
        IntPtr lpOverlapped,
        out uint lpNumberOfBytesTransferred,
        [MarshalAs(UnmanagedType.Bool)] bool bWait);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        IntPtr lpBuffer,
        uint nNumberOfBytesToRead,
        IntPtr lpNumberOfBytesRead,
        IntPtr lpOverlapped);
}
