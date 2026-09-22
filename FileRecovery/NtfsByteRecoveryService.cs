using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class NtfsByteRecoveryService
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    private const int IoBufferSize = 1024 * 1024;

    public RecoveryResult Recover(
        RecoveryCandidate candidate,
        string destinationDirectory,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        if (!candidate.DataStreamFound)
        {
            throw new InvalidOperationException(
                "This candidate does not have retained NTFS $DATA evidence.");
        }

        var sourcePath = candidate.FullPath;
        RecoveryDestinationPolicy.Validate(sourcePath, destinationDirectory);

        var destinationPath = RecoveryDestinationPolicy.CreateSafeFilePath(
            destinationDirectory,
            candidate.Name);

        if (candidate.DataStreamResident)
        {
            return RecoverResident(candidate, destinationPath);
        }

        return RecoverNonResident(candidate, sourcePath, destinationPath, cancellationToken);
    }

    private static RecoveryResult RecoverResident(
        RecoveryCandidate candidate,
        string destinationPath)
    {
        // NtfsMftDataReader supplies the resident bytes through the candidate.
        if (candidate.ResidentData is null)
        {
            throw new InvalidOperationException(
                "Resident NTFS data was identified but the resident bytes were not retained.");
        }

        File.WriteAllBytes(destinationPath, candidate.ResidentData);

        return new RecoveryResult
        {
            Success = true,
            SourcePath = candidate.FullPath,
            DestinationPath = destinationPath,
            BytesRecovered = candidate.ResidentData.LongLength,
            Evidence = "Recovered from resident bytes retained in the NTFS MFT record."
        };
    }

    private RecoveryResult RecoverNonResident(
        RecoveryCandidate candidate,
        string sourcePath,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        if (candidate.FileSizeBytes < 0 ||
            candidate.FileSizeBytes > int.MaxValue * 1024L)
        {
            throw new InvalidOperationException("The candidate file size is outside the supported recovery range.");
        }

        if (candidate.DataExtents.Count == 0)
        {
            throw new InvalidOperationException(
                "No nonresident NTFS data extents are available for this candidate.");
        }

        ValidateExtents(candidate);

        var sourceRoot = Path.GetPathRoot(sourcePath);
        if (string.IsNullOrWhiteSpace(sourceRoot))
        {
            throw new InvalidOperationException("The deleted file's source volume could not be determined.");
        }

        var volumeInfo = new NtfsVolumeInspector().Inspect(sourceRoot);
        using var volumeHandle = CreateVolumeHandle(sourceRoot);

        var currentAllocations = new NtfsVolumeBitmapReader().CheckExtents(
            volumeHandle,
            candidate.DataExtents,
            cancellationToken);

        if (currentAllocations.Count != candidate.DataExtents.Count(x => !x.IsSparse))
        {
            throw new InvalidOperationException(
                "Current NTFS cluster allocation could not be verified for every non-sparse data extent. Recovery is blocked for safety.");
        }

        var currentlyAllocated = currentAllocations.Sum(x => x.AllocatedClusterCount);
        if (currentlyAllocated != 0)
        {
            throw new InvalidOperationException(
                $"Recovery is blocked because {currentlyAllocated:N0} former data cluster(s) are currently allocated.");
        }

        long recovered = 0;

        try
        {
            using var output = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                IoBufferSize,
                FileOptions.SequentialScan);

            var remainingBytes = candidate.FileSizeBytes;
            var expectedVcn = 0L;

            foreach (var extent in candidate.DataExtents)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (extent.VirtualClusterNumber != expectedVcn)
                {
                    throw new InvalidOperationException(
                        "The retained NTFS mapping does not form a complete data stream from VCN 0.");
                }

                var extentBytes = checked(extent.ClusterCount * volumeInfo.BytesPerCluster);
                var bytesToWrite = Math.Min(extentBytes, remainingBytes);

                if (bytesToWrite <= 0)
                {
                    break;
                }

                if (extent.IsSparse)
                {
                    WriteZeros(output, bytesToWrite, cancellationToken);
                }
                else
                {
                    ReadClusters(
                        volumeHandle,
                        output,
                        extent.LogicalClusterNumber,
                        bytesToWrite,
                        volumeInfo.BytesPerCluster,
                        cancellationToken);
                }

                recovered += bytesToWrite;
                remainingBytes -= bytesToWrite;
                expectedVcn = checked(expectedVcn + extent.ClusterCount);

                if (remainingBytes == 0)
                {
                    break;
                }
            }

            if (remainingBytes != 0)
            {
                throw new InvalidOperationException(
                    "The retained NTFS data runs do not cover the entire logical file size.");
            }
        }
        catch
        {
            TryDelete(destinationPath);
            throw;
        }

        return new RecoveryResult
        {
            Success = true,
            SourcePath = sourcePath,
            DestinationPath = destinationPath,
            BytesRecovered = recovered,
            Evidence = "Recovered from retained NTFS nonresident $DATA extents whose current cluster bitmap state was verified before copying."
        };
    }

    private static void ValidateExtents(RecoveryCandidate candidate)
    {
        if (candidate.ExtentAllocations.Count == 0)
        {
            throw new InvalidOperationException(
                "Current NTFS cluster allocation could not be verified. Recovery is blocked for safety.");
        }

        if (candidate.AllocatedDataClusterCount != 0)
        {
            throw new InvalidOperationException(
                "Recovery is blocked because one or more former data clusters are currently allocated.");
        }

        var expectedVcn = 0L;
        foreach (var extent in candidate.DataExtents)
        {
            if (extent.ClusterCount <= 0 ||
                extent.VirtualClusterNumber != expectedVcn)
            {
                throw new InvalidOperationException(
                    "The retained NTFS data runs are incomplete or non-contiguous.");
            }

            expectedVcn = checked(expectedVcn + extent.ClusterCount);
        }
    }

    private static void ReadClusters(
        SafeFileHandle volumeHandle,
        FileStream output,
        long logicalClusterNumber,
        long byteCount,
        uint bytesPerCluster,
        CancellationToken cancellationToken)
    {
        var offset = checked(logicalClusterNumber * (long)bytesPerCluster);
        var buffer = new byte[Math.Min(IoBufferSize, checked((int)bytesPerCluster * 128))];
        buffer = buffer.Length == 0 ? new byte[Math.Min(IoBufferSize, 64 * 1024)] : buffer;

        var remaining = byteCount;
        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var chunk = (int)Math.Min(buffer.Length, remaining);
            if (!ReadAt(volumeHandle, offset, buffer, chunk))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not read deleted-file data at byte offset {offset:N0}.");
            }

            output.Write(buffer, 0, chunk);
            offset = checked(offset + chunk);
            remaining -= chunk;
        }
    }

    private static bool ReadAt(
        SafeFileHandle handle,
        long offset,
        byte[] buffer,
        int count)
    {
        if (!SetFilePointerEx(handle, offset, out _, 0))
        {
            return false;
        }

        return ReadFile(
            handle,
            buffer,
            (uint)count,
            out var bytesRead,
            IntPtr.Zero)
            && bytesRead == (uint)count;
    }

    private static void WriteZeros(
        FileStream output,
        long byteCount,
        CancellationToken cancellationToken)
    {
        var zeros = new byte[Math.Min(IoBufferSize, 1024 * 1024)];
        var remaining = byteCount;

        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var chunk = (int)Math.Min(zeros.Length, remaining);
            output.Write(zeros, 0, chunk);
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
                $"Could not open NTFS source volume {root} for read-only recovery.");
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
            // Best-effort cleanup after a failed recovery.
        }
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
    private static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);
}
