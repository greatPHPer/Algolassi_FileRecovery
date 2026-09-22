using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class NtfsVolumeBitmapReader
{
    private const uint FsctlGetVolumeBitmap = 0x0009006F;
    private const uint ErrorMoreData = 234;

    public IReadOnlyList<NtfsExtentAllocation> CheckExtents(
        SafeFileHandle volumeHandle,
        IReadOnlyList<NtfsDataExtent> extents,
        CancellationToken cancellationToken = default)
    {
        var results = new List<NtfsExtentAllocation>();

        foreach (var extent in extents)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (extent.IsSparse || extent.ClusterCount <= 0)
            {
                continue;
            }

            results.Add(CheckExtent(
                volumeHandle,
                extent.LogicalClusterNumber,
                extent.ClusterCount,
                cancellationToken));
        }

        return results;
    }

    private static NtfsExtentAllocation CheckExtent(
        SafeFileHandle volumeHandle,
        long startingLcn,
        long clusterCount,
        CancellationToken cancellationToken)
    {
        if (startingLcn < 0)
        {
            return new NtfsExtentAllocation
            {
                LogicalClusterNumber = startingLcn,
                ClusterCount = clusterCount,
                Allocation = NtfsClusterAllocation.Unknown
            };
        }

        var remaining = clusterCount;
        var currentLcn = startingLcn;
        long free = 0;
        long allocated = 0;

        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var request = new byte[sizeof(long)];
            BinaryPrimitives.WriteInt64LittleEndian(request, currentLcn);

            var output = new byte[1024 * 1024];
            if (!DeviceIoControl(
                    volumeHandle,
                    FsctlGetVolumeBitmap,
                    request,
                    (uint)request.Length,
                    output,
                    (uint)output.Length,
                    out var bytesReturned,
                    IntPtr.Zero))
            {
                var error = Marshal.GetLastWin32Error();

                if (error != ErrorMoreData)
                {
                    throw new Win32Exception(
                        error,
                        $"Could not query the NTFS volume bitmap at LCN {currentLcn:N0}.");
                }
            }

            if (bytesReturned < 16)
            {
                throw new IOException("Windows returned an incomplete volume bitmap.");
            }

            var returnedStart = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(0, 8));
            var bitmapSize = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(8, 8));

            if (returnedStart < 0 || bitmapSize <= 0)
            {
                throw new IOException("Windows returned an invalid NTFS volume bitmap range.");
            }

            var bitmapBytes = checked((int)Math.Min(
                bytesReturned - 16,
                (bitmapSize + 7) / 8));

            if (bitmapBytes <= 0)
            {
                throw new IOException("Windows returned an empty NTFS volume bitmap.");
            }

            var firstCluster = Math.Max(currentLcn, returnedStart);
            var lastClusterExclusive = Math.Min(
                checked(currentLcn + remaining),
                checked(returnedStart + bitmapSize));

            if (firstCluster >= lastClusterExclusive)
            {
                throw new IOException("The NTFS volume bitmap did not cover the requested cluster range.");
            }

            for (var cluster = firstCluster; cluster < lastClusterExclusive; cluster++)
            {
                var bit = checked(cluster - returnedStart);
                var byteIndex = checked((int)(bit / 8));
                var bitIndex = (int)(bit % 8);

                if (byteIndex >= bitmapBytes)
                {
                    break;
                }

                var isAllocated = (output[16 + byteIndex] & (1 << bitIndex)) != 0;
                if (isAllocated)
                {
                    allocated++;
                }
                else
                {
                    free++;
                }
            }

            var covered = lastClusterExclusive - firstCluster;
            if (covered <= 0)
            {
                throw new IOException("The NTFS volume bitmap returned no progress.");
            }

            currentLcn = lastClusterExclusive;
            remaining -= covered;

            if (remaining > 0 && currentLcn <= returnedStart)
            {
                throw new IOException("The NTFS volume bitmap did not advance.");
            }
        }

        var allocation =
            allocated == 0 && free > 0 ? NtfsClusterAllocation.Free :
            free == 0 && allocated > 0 ? NtfsClusterAllocation.Allocated :
            allocated > 0 && free > 0 ? NtfsClusterAllocation.Mixed :
            NtfsClusterAllocation.Unknown;

        return new NtfsExtentAllocation
        {
            LogicalClusterNumber = startingLcn,
            ClusterCount = clusterCount,
            FreeClusterCount = free,
            AllocatedClusterCount = allocated,
            Allocation = allocation
        };
    }

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
