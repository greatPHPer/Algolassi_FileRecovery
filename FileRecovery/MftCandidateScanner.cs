using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class MftCandidateScanner
{
    private const uint FsctlEnumUsnData = 0x000900B3;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    private const uint UsnReasonFileDelete = 0x00000200;
    private const uint FileAttributeDirectory = 0x00000010;
    private const int UsnRecordV2MinimumLength = 60;

    public IReadOnlyList<RecoveryCandidate> Scan(
        string rootPath,
        CancellationToken cancellationToken = default)
    {
        WindowsPrivilege.EnableSeBackupPrivilege();
        return ScanInternal(
            rootPath,
            targetPaths: null,
            cancellationToken: cancellationToken,
            maxPages: int.MaxValue);
    }

    public IReadOnlyList<RecoveryCandidate> ScanForPaths(
        string rootPath,
        IReadOnlyCollection<string> targetPaths,
        CancellationToken cancellationToken = default,
        int maxPages = 128)
    {
        ArgumentNullException.ThrowIfNull(targetPaths);

        WindowsPrivilege.EnableSeBackupPrivilege();

        if (maxPages <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxPages));
        }

        var normalizedTargets = targetPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(NormalizePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return ScanInternal(rootPath, normalizedTargets, cancellationToken, maxPages);
    }

    public IReadOnlyList<RecoveryCandidate> ScanRawMftForPaths(
        string rootPath,
        IReadOnlyCollection<string> targetPaths,
        CancellationToken cancellationToken = default,
        long maxBytesToScan = 512L * 1024L * 1024L)
    {
        ArgumentNullException.ThrowIfNull(targetPaths);

        WindowsPrivilege.EnableSeBackupPrivilege();

        if (maxBytesToScan <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytesToScan));
        }

        var normalizedTargets = targetPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(NormalizePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (normalizedTargets.Count == 0)
        {
            return [];
        }

        var root = Path.GetPathRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException("A valid Windows volume path is required.", nameof(rootPath));
        }

        if (!string.Equals(
                new DriveInfo(root).DriveFormat,
                "NTFS",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Permanent deleted-file scanning currently supports NTFS volumes only.");
        }

        var fullRoot = Path.GetFullPath(root);
        var volumeInfo = new NtfsVolumeInspector().Inspect(fullRoot);
        using var volumeHandle = CreateVolumeHandle(fullRoot);
        using var mftHandle = NtfsMftDataReader.OpenMftHandle(fullRoot);
        var dataReader = new NtfsMftDataReader();
        var bitmapReader = new NtfsVolumeBitmapReader();

        var targetNames = normalizedTargets
            .Select(Path.GetFileName)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var results = new List<RecoveryCandidate>();
        var seenReferences = new HashSet<ulong>();
        var recordSize = checked((int)volumeInfo.BytesPerFileRecordSegment);

        if (recordSize <= 0 ||
            volumeInfo.MftValidDataLength <= 0)
        {
            return [];
        }

        var bytesToScan = Math.Min(
            volumeInfo.MftValidDataLength,
            maxBytesToScan);

        var bufferSize = 4 * 1024 * 1024;
        bufferSize -= bufferSize % recordSize;
        bufferSize = Math.Max(recordSize, bufferSize);

        var buffer = new byte[bufferSize];
        long scanned = 0;

        while (scanned < bytesToScan &&
               !cancellationToken.IsCancellationRequested)
        {
            var remaining = bytesToScan - scanned;
            var requestBytes = (int)Math.Min(buffer.Length, remaining);
            requestBytes -= requestBytes % recordSize;

            if (requestBytes < recordSize)
            {
                break;
            }

            if (!ReadFile(
                    mftHandle,
                    buffer,
                    (uint)requestBytes,
                    out var bytesRead,
                    IntPtr.Zero))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not read the NTFS MFT while scanning {fullRoot}.");
            }

            if (bytesRead == 0)
            {
                break;
            }

            var usableBytes = (int)bytesRead - ((int)bytesRead % recordSize);
            for (var offset = 0; offset < usableBytes; offset += recordSize)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var record = new byte[recordSize];
                Buffer.BlockCopy(buffer, offset, record, 0, recordSize);

                if (!TryParseDeletedFileNameEntries(
                        record,
                        volumeInfo.BytesPerSector,
                        (ulong)((scanned + offset) / recordSize),
                        out var fileReferenceNumber,
                        out var fileEntries))
                {
                    continue;
                }

                foreach (var entry in fileEntries)
                {
                    if (!targetNames.Contains(entry.Name))
                    {
                        continue;
                    }

                    var directoryPath = NtfsParentPathResolver.Resolve(
                        volumeHandle,
                        entry.ParentFileReferenceNumber);

                    var matchingTarget = normalizedTargets.FirstOrDefault(target =>
                    {
                        var targetName = Path.GetFileName(target);
                        if (!string.Equals(
                                targetName,
                                entry.Name,
                                StringComparison.OrdinalIgnoreCase))
                        {
                            return false;
                        }

                        if (string.IsNullOrWhiteSpace(directoryPath))
                        {
                            return normalizedTargets.Count(target2 =>
                                string.Equals(
                                    Path.GetFileName(target2),
                                    entry.Name,
                                    StringComparison.OrdinalIgnoreCase)) == 1;
                        }

                        return string.Equals(
                            NormalizePath(Path.Combine(directoryPath, entry.Name)),
                            target,
                            StringComparison.OrdinalIgnoreCase);
                    });

                    if (string.IsNullOrWhiteSpace(matchingTarget) ||
                        !seenReferences.Add(fileReferenceNumber))
                    {
                        continue;
                    }

                    var historicalDirectory = Path.GetDirectoryName(matchingTarget);
                    directoryPath = string.IsNullOrWhiteSpace(directoryPath)
                        ? historicalDirectory ?? string.Empty
                        : directoryPath;

                    var data = dataReader.ReadDefaultDataStream(
                        volumeInfo,
                        mftHandle,
                        volumeHandle,
                        fileReferenceNumber);

                    IReadOnlyList<NtfsExtentAllocation> allocations = [];
                    var allocationEvidence = string.Empty;

                    if (data.Found && !data.IsResident && data.Extents.Count > 0)
                    {
                        try
                        {
                            allocations = bitmapReader.CheckExtents(
                                volumeHandle,
                                data.Extents,
                                cancellationToken);

                            allocationEvidence = BuildAllocationEvidence(allocations);
                        }
                        catch (Exception ex)
                        {
                            allocationEvidence =
                                $"Cluster allocation could not be verified: {ex.Message}";
                        }
                    }

                    results.Add(BuildCandidate(
                        fileReferenceNumber,
                        entry.ParentFileReferenceNumber,
                        entry.Name,
                        directoryPath,
                        entry.TimestampUtc,
                        data,
                        allocations,
                        allocationEvidence));

                    if (results.Count >= normalizedTargets.Count)
                    {
                        return results;
                    }
                }
            }

            scanned += usableBytes;

            if (bytesRead < (uint)requestBytes)
            {
                break;
            }
        }

        return results;
    }

    public IReadOnlyList<RecoveryCandidate> ScanForFileReferences(
        string rootPath,
        IReadOnlyCollection<(string FullPath, ulong FileReferenceNumber, ulong ParentFileReferenceNumber, DateTime DeletedAtUtc)> targets,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targets);

        WindowsPrivilege.EnableSeBackupPrivilege();

        var normalizedTargets = targets
            .Where(target =>
                !string.IsNullOrWhiteSpace(target.FullPath) &&
                target.FileReferenceNumber != 0 &&
                target.ParentFileReferenceNumber != 0)
            .Select(target => (
                FullPath: NormalizePath(target.FullPath),
                target.FileReferenceNumber,
                target.ParentFileReferenceNumber,
                target.DeletedAtUtc))
            .ToList();

        if (normalizedTargets.Count == 0)
        {
            return [];
        }

        var root = Path.GetPathRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException("A valid Windows volume path is required.", nameof(rootPath));
        }

        if (!string.Equals(new DriveInfo(root).DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Permanent deleted-file scanning currently supports NTFS volumes only.");
        }

        var fullRoot = Path.GetFullPath(root);
        var volumeInfo = new NtfsVolumeInspector().Inspect(fullRoot);
        using var volumeHandle = CreateVolumeHandle(fullRoot);
        using var mftHandle = NtfsMftDataReader.OpenMftHandle(fullRoot);
        var dataReader = new NtfsMftDataReader();
        var bitmapReader = new NtfsVolumeBitmapReader();
        var results = new List<RecoveryCandidate>();

        foreach (var target in normalizedTargets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var directoryPath = NtfsParentPathResolver.Resolve(
                volumeHandle,
                target.ParentFileReferenceNumber) ?? string.Empty;

            var name = Path.GetFileName(target.FullPath);
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            // The NTFS file reference is authoritative. Parent-path reconstruction
            // can fail for a deleted file even when its MFT record is still intact.
            // Do not discard the candidate merely because the reconstructed path
            // differs from the historical path.
            if (string.IsNullOrWhiteSpace(directoryPath) ||
                directoryPath.StartsWith("(Parent directory unavailable)", StringComparison.OrdinalIgnoreCase))
            {
                var historicalDirectory = Path.GetDirectoryName(target.FullPath);
                directoryPath = string.IsNullOrWhiteSpace(historicalDirectory)
                    ? string.Empty
                    : historicalDirectory;
            }

            var data = dataReader.ReadDefaultDataStream(
                volumeInfo,
                mftHandle,
                volumeHandle,
                target.FileReferenceNumber);

            IReadOnlyList<NtfsExtentAllocation> allocations = [];
            string allocationEvidence = string.Empty;

            if (data.Found && !data.IsResident && data.Extents.Count > 0)
            {
                try
                {
                    allocations = bitmapReader.CheckExtents(
                        volumeHandle,
                        data.Extents,
                        cancellationToken);

                    allocationEvidence = BuildAllocationEvidence(allocations);
                }
                catch (Exception ex)
                {
                    allocationEvidence = $"Cluster allocation could not be verified: {ex.Message}";
                }
            }

            results.Add(BuildCandidate(
                target.FileReferenceNumber,
                target.ParentFileReferenceNumber,
                name,
                directoryPath,
                target.DeletedAtUtc,
                data,
                allocations,
                allocationEvidence));
        }

        return results;
    }

    private IReadOnlyList<RecoveryCandidate> ScanInternal(
        string rootPath,
        IReadOnlySet<string>? targetPaths,
        CancellationToken cancellationToken,
        int maxPages)
    {
        var root = Path.GetPathRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException("A valid Windows volume path is required.", nameof(rootPath));
        }

        if (!string.Equals(new DriveInfo(root).DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Permanent deleted-file scanning currently supports NTFS volumes only.");
        }

        var fullRoot = Path.GetFullPath(root);
        var volumeInfo = new NtfsVolumeInspector().Inspect(fullRoot);
        using var volumeHandle = CreateVolumeHandle(fullRoot);
        using var mftHandle = NtfsMftDataReader.OpenMftHandle(fullRoot);
        var dataReader = new NtfsMftDataReader();
        var bitmapReader = new NtfsVolumeBitmapReader();

        var results = new List<RecoveryCandidate>();
        var targetFileNames = targetPaths is null
            ? null
            : targetPaths
                .Select(Path.GetFileName)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

        ulong startFileReferenceNumber = 0;
        var pagesRead = 0;

        while (!cancellationToken.IsCancellationRequested &&
               pagesRead < maxPages)
        {
            pagesRead++;

            var request = new MftEnumDataV0
            {
                StartFileReferenceNumber = startFileReferenceNumber,
                LowUsn = 0,
                HighUsn = long.MaxValue
            };

            var input = StructureToBytes(request);
            var output = new byte[1024 * 1024];

            if (!DeviceIoControl(
                    volumeHandle,
                    FsctlEnumUsnData,
                    input,
                    (uint)input.Length,
                    output,
                    (uint)output.Length,
                    out var bytesReturned,
                    IntPtr.Zero))
            {
                var error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error,
                    $"NTFS MFT enumeration failed for {fullRoot}.");
            }

            if (bytesReturned < sizeof(ulong))
            {
                break;
            }

            var nextStart = BinaryPrimitives.ReadUInt64LittleEndian(output.AsSpan(0, 8));
            var offset = 8;
            var foundRecords = 0;

            while (offset + 4 <= bytesReturned)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var recordLength = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(offset, 4));
                if (recordLength < UsnRecordV2MinimumLength ||
                    recordLength > bytesReturned - offset)
                {
                    break;
                }

                var recordSpan = output.AsSpan(offset, checked((int)recordLength));
                var majorVersion = BinaryPrimitives.ReadUInt16LittleEndian(recordSpan.Slice(4, 2));
                if (majorVersion == 2)
                {
                    var fileReference = BinaryPrimitives.ReadUInt64LittleEndian(recordSpan.Slice(8, 8));
                    var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(recordSpan.Slice(16, 8));
                    var timestampFileTime = BinaryPrimitives.ReadInt64LittleEndian(recordSpan.Slice(32, 8));
                    var reason = BinaryPrimitives.ReadUInt32LittleEndian(recordSpan.Slice(40, 4));
                    var attributes = BinaryPrimitives.ReadUInt32LittleEndian(recordSpan.Slice(52, 4));
                    var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(recordSpan.Slice(56, 2));
                    var nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(recordSpan.Slice(58, 2));

                    if ((reason & UsnReasonFileDelete) != 0 &&
                        (attributes & FileAttributeDirectory) == 0 &&
                        nameOffset + nameLength <= recordSpan.Length)
                    {
                        var name = System.Text.Encoding.Unicode.GetString(
                            recordSpan.Slice(nameOffset, nameLength));

                        if (targetFileNames is not null &&
                            !targetFileNames.Contains(name))
                        {
                            offset += checked((int)recordLength);
                            continue;
                        }

                        var timestampUtc = DateTime.UtcNow;
                        try
                        {
                            timestampUtc = DateTime.FromFileTimeUtc(timestampFileTime);
                        }
                        catch
                        {
                        }

                        var directoryPath = NtfsParentPathResolver.Resolve(
                            volumeHandle,
                            parentReference) ?? string.Empty;

                        var fullPath = string.IsNullOrWhiteSpace(directoryPath)
                            ? name
                            : Path.Combine(directoryPath, name);

                        if (targetPaths is not null &&
                            !targetPaths.Contains(NormalizePath(fullPath)))
                        {
                            offset += checked((int)recordLength);
                            continue;
                        }

                        var data = dataReader.ReadDefaultDataStream(
                            volumeInfo,
                            mftHandle,
                            volumeHandle,
                            fileReference);

                        IReadOnlyList<NtfsExtentAllocation> allocations = [];
                        string allocationEvidence = string.Empty;

                        if (data.Found && !data.IsResident && data.Extents.Count > 0)
                        {
                            try
                            {
                                allocations = bitmapReader.CheckExtents(
                                    volumeHandle,
                                    data.Extents,
                                    cancellationToken);

                                allocationEvidence = BuildAllocationEvidence(allocations);
                            }
                            catch (Exception ex)
                            {
                                allocationEvidence = $"Cluster allocation could not be verified: {ex.Message}";
                            }
                        }

                        results.Add(BuildCandidate(
                            fileReference,
                            parentReference,
                            name,
                            directoryPath,
                            timestampUtc,
                            data,
                            allocations,
                            allocationEvidence));

                        foundRecords++;

                        if (targetPaths is not null &&
                            results.Count >= targetPaths.Count)
                        {
                            return results;
                        }
                    }
                }

                offset += checked((int)recordLength);
            }

            if (nextStart <= startFileReferenceNumber || foundRecords == 0 && bytesReturned <= sizeof(ulong))
            {
                break;
            }

            startFileReferenceNumber = nextStart;
        }

        return results;
    }

    private static bool TryParseDeletedFileNameEntries(
        byte[] record,
        uint bytesPerSector,
        ulong segmentNumber,
        out ulong fileReferenceNumber,
        out IReadOnlyList<DeletedFileNameEntry> entries)
    {
        fileReferenceNumber = 0;
        entries = [];

        if (record.Length < 48 ||
            record[0] != (byte)'F' ||
            record[1] != (byte)'I' ||
            record[2] != (byte)'L' ||
            record[3] != (byte)'E')
        {
            return false;
        }

        try
        {
            NtfsMftDataReader.ApplyUpdateSequenceFixups(
                record,
                checked((int)bytesPerSector));
        }
        catch
        {
            return false;
        }

        var flags = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(22, 2));

        // Only deleted file records: bit 0 (IN_USE) is clear and bit 1
        // (DIRECTORY) is clear.
        if ((flags & 0x0001) != 0 || (flags & 0x0002) != 0)
        {
            return false;
        }

        var sequenceNumber = BinaryPrimitives.ReadUInt16LittleEndian(
            record.AsSpan(16, 2));

        fileReferenceNumber =
            (segmentNumber & 0x0000FFFFFFFFFFFFUL) |
            ((ulong)sequenceNumber << 48);

        var firstAttributeOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            record.AsSpan(20, 2));

        if (firstAttributeOffset < 24 ||
            firstAttributeOffset >= record.Length)
        {
            return false;
        }

        var found = new List<DeletedFileNameEntry>();
        var offset = (int)firstAttributeOffset;

        while (offset + 16 <= record.Length)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(
                record.AsSpan(offset, 4));

            if (type == 0xFFFFFFFF)
            {
                break;
            }

            var attributeLength = BinaryPrimitives.ReadUInt32LittleEndian(
                record.AsSpan(offset + 4, 4));

            if (attributeLength < 24 ||
                offset + attributeLength > record.Length)
            {
                break;
            }

            var nonResident = record[offset + 8];
            var attributeNameLength = record[offset + 9];

            if (type == 0x30 && nonResident == 0 && attributeNameLength == 0)
            {
                var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(offset + 16, 4));
                var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                    record.AsSpan(offset + 20, 2));

                if (valueOffset + valueLength <= attributeLength &&
                    valueLength >= 66)
                {
                    var valueStart = offset + valueOffset;
                    var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(
                        record.AsSpan(valueStart, 8));

                    var timestampFileTime = BinaryPrimitives.ReadInt64LittleEndian(
                        record.AsSpan(valueStart + 16, 8));

                    var nameLength = record[valueStart + 64];
                    var nameByteLength = checked(nameLength * 2);

                    if (valueStart + 66 + nameByteLength <= record.Length &&
                        nameLength > 0)
                    {
                        var name = System.Text.Encoding.Unicode.GetString(
                            record,
                            valueStart + 66,
                            nameByteLength);

                        DateTime timestampUtc;
                        try
                        {
                            timestampUtc = DateTime.FromFileTimeUtc(timestampFileTime);
                        }
                        catch
                        {
                            timestampUtc = DateTime.UtcNow;
                        }

                        found.Add(new DeletedFileNameEntry(
                            parentReference,
                            name,
                            timestampUtc));
                    }
                }
            }

            offset += checked((int)attributeLength);
        }

        entries = found;
        return found.Count > 0;
    }

    private readonly record struct DeletedFileNameEntry(
        ulong ParentFileReferenceNumber,
        string Name,
        DateTime TimestampUtc);

    private static string NormalizePath(string path) =>
        path.Trim().Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

    private static RecoveryCandidate BuildCandidate(
        ulong fileReferenceNumber,
        ulong parentFileReferenceNumber,
        string name,
        string directoryPath,
        DateTime timestampUtc,
        NtfsDataStreamInfo data,
        IReadOnlyList<NtfsExtentAllocation> allocations,
        string allocationEvidence)
    {
        var freeClusters = allocations.Sum(x => x.FreeClusterCount);
        var allocatedClusters = allocations.Sum(x => x.AllocatedClusterCount);

        var strength =
            data.Found && data.IsResident ? RecoveryStrength.Medium :
            data.Found && allocations.Count > 0 && allocatedClusters == 0
                ? RecoveryStrength.Medium :
            data.Found && allocatedClusters > 0
                ? RecoveryStrength.Weak :
            string.IsNullOrWhiteSpace(directoryPath)
                ? RecoveryStrength.Weak
                : RecoveryStrength.Medium;

        return new RecoveryCandidate
        {
            FileReferenceNumber = fileReferenceNumber,
            ParentFileReferenceNumber = parentFileReferenceNumber,
            Name = name,
            DirectoryPath = directoryPath,
            LastUsnTimestampUtc = timestampUtc,
            Strength = strength,
            Evidence = string.IsNullOrWhiteSpace(directoryPath)
                ? "NTFS metadata shows a file-delete record, but the parent directory could not be resolved."
                : "NTFS metadata shows a file-delete record and the parent directory was resolved.",
            DataStreamFound = data.Found,
            DataStreamResident = data.IsResident,
            ResidentData = data.ResidentData,
            FileSizeBytes = data.FileSizeBytes,
            ValidDataLengthBytes = data.ValidDataLengthBytes,
            DataExtents = data.Extents,
            ExtentAllocations = allocations,
            FreeDataClusterCount = freeClusters,
            AllocatedDataClusterCount = allocatedClusters,
            DataEvidence = string.Join(
                " ",
                new[] { data.Evidence, allocationEvidence }
                    .Where(x => !string.IsNullOrWhiteSpace(x)))
        };
    }

    private static string BuildAllocationEvidence(IReadOnlyList<NtfsExtentAllocation> allocations)
    {
        var free = allocations.Sum(x => x.FreeClusterCount);
        var allocated = allocations.Sum(x => x.AllocatedClusterCount);

        if (allocated == 0 && free > 0)
        {
            return $"Current NTFS bitmap: {free:N0} data cluster(s) are free.";
        }

        if (allocated > 0 && free > 0)
        {
            return $"Current NTFS bitmap: {free:N0} data cluster(s) are free and {allocated:N0} are allocated.";
        }

        if (allocated > 0)
        {
            return $"Current NTFS bitmap: {allocated:N0} data cluster(s) are currently allocated.";
        }

        return "Current NTFS bitmap did not return usable allocation evidence.";
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
                $"Could not open NTFS volume {root}.");
        }

        return handle;
    }

    private static byte[] StructureToBytes<T>(T value) where T : struct
    {
        var size = Marshal.SizeOf<T>();
        var bytes = new byte[size];
        var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);

        try
        {
            Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), fDeleteOld: false);
            return bytes;
        }
        finally
        {
            handle.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MftEnumDataV0
    {
        public ulong StartFileReferenceNumber;
        public long LowUsn;
        public long HighUsn;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);

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
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        byte[]? lpInBuffer,
        uint nInBufferSize,
        byte[]? lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);
}
