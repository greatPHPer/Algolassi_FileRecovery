using System.Buffers.Binary;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class NtfsVolumeInspector
{
    private const uint FsctlGetNtfsVolumeData = 0x00090064;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    public NtfsVolumeInfo Inspect(string rootPath)
    {
        var root = Path.GetPathRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException("A valid Windows volume path is required.", nameof(rootPath));
        }

        var drive = new DriveInfo(root);
        if (!drive.IsReady)
        {
            throw new IOException($"The volume {root} is not ready.");
        }

        if (!string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"The volume {root} is not NTFS.");
        }

        using var handle = CreateVolumeHandle(root);

        var output = new byte[96];
        if (!DeviceIoControl(
                handle,
                FsctlGetNtfsVolumeData,
                null,
                0,
                output,
                (uint)output.Length,
                out var bytesReturned,
                IntPtr.Zero))
        {
            throw new Win32Exception(
                System.Runtime.InteropServices.Marshal.GetLastWin32Error(),
                $"Could not query NTFS volume data for {root}.");
        }

        if (bytesReturned < 96)
        {
            throw new IOException("Windows returned an incomplete NTFS volume data structure.");
        }

        return new NtfsVolumeInfo
        {
            RootPath = root,
            VolumeSerialNumber = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(0, 8)),
            NumberSectors = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(8, 8)),
            TotalClusters = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(16, 8)),
            FreeClusters = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(24, 8)),
            TotalReservedClusters = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(32, 8)),
            BytesPerSector = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(40, 4)),
            BytesPerCluster = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(44, 4)),
            BytesPerFileRecordSegment = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(48, 4)),
            ClustersPerFileRecordSegment = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(52, 4)),
            MftValidDataLength = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(56, 8)),
            MftStartLcn = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(64, 8)),
            Mft2StartLcn = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(72, 8)),
            MftZoneStart = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(80, 8)),
            MftZoneEnd = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(88, 8))
        };
    }

    private static SafeFileHandle CreateVolumeHandle(string root)
    {
        var volumeName = root.TrimEnd(Path.DirectorySeparatorChar);
        var handle = CreateFile(
            $@"\.{volumeName[..2]}",
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            var error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            handle.Dispose();

            throw new Win32Exception(
                error,
                $"Could not open NTFS volume {root}. Device={volumeName}.");
        }

        return handle;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
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
