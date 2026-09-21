using System.Buffers.Binary;

namespace FileRecovery;

internal static class NtfsMappingPairsParser
{
    public static IReadOnlyList<NtfsDataExtent> Parse(
        ReadOnlySpan<byte> mappingPairs,
        long startingVcn)
    {
        var extents = new List<NtfsDataExtent>();
        long currentVcn = startingVcn;
        long currentLcn = 0;
        var offset = 0;

        while (offset < mappingPairs.Length)
        {
            var header = mappingPairs[offset++];
            if (header == 0)
            {
                break;
            }

            var lengthBytes = header & 0x0F;
            var offsetBytes = (header >> 4) & 0x0F;

            if (lengthBytes == 0 ||
                offset + lengthBytes + offsetBytes > mappingPairs.Length)
            {
                throw new InvalidDataException("Invalid NTFS mapping-pairs header.");
            }

            ulong clusterCount = 0;
            for (var i = 0; i < lengthBytes; i++)
            {
                clusterCount |= (ulong)mappingPairs[offset++] << (8 * i);
            }

            if (clusterCount == 0 || clusterCount > long.MaxValue)
            {
                throw new InvalidDataException("Invalid NTFS data-run length.");
            }

            if (offsetBytes == 0)
            {
                extents.Add(new NtfsDataExtent
                {
                    VirtualClusterNumber = currentVcn,
                    ClusterCount = (long)clusterCount,
                    LogicalClusterNumber = -1
                });
            }
            else
            {
                if (offsetBytes > sizeof(long))
                {
                    throw new InvalidDataException("Invalid NTFS data-run LCN width.");
                }

                long delta = ReadSignedLittleEndian(mappingPairs.Slice(offset, offsetBytes));
                offset += offsetBytes;

                currentLcn = checked(currentLcn + delta);

                extents.Add(new NtfsDataExtent
                {
                    VirtualClusterNumber = currentVcn,
                    ClusterCount = (long)clusterCount,
                    LogicalClusterNumber = currentLcn
                });
            }

            currentVcn = checked(currentVcn + (long)clusterCount);
        }

        return extents;
    }

    private static long ReadSignedLittleEndian(ReadOnlySpan<byte> value)
    {
        long result;

        if (value.Length == 8)
        {
            result = BinaryPrimitives.ReadInt64LittleEndian(value);
            return result;
        }

        ulong unsigned = 0;
        for (var i = 0; i < value.Length; i++)
        {
            unsigned |= (ulong)value[i] << (8 * i);
        }

        var bitCount = value.Length * 8;
        if ((unsigned & (1UL << (bitCount - 1))) != 0)
        {
            unsigned |= ulong.MaxValue << bitCount;
        }

        return unchecked((long)unsigned);
    }
}
