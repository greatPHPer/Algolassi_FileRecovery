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
        var dataReader = new NtfsMftDataReader();
        var bitmapReader = new NtfsVolumeBitmapReader();

        var results = new List<RecoveryCandidate>();
        ulong startFileReferenceNumber = 0;

        while (!cancellationToken.IsCancellationRequested)
        {
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

                        var data = dataReader.ReadDefaultDataStream(
                            volumeInfo,
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

                        results.Add(new RecoveryCandidate
                        {
                            FileReferenceNumber = fileReference,
                            ParentFileReferenceNumber = parentReference,
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
                        });

                        foundRecords++;
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
