namespace FileRecovery;

internal sealed class NtfsAttributeListEntry
{
    public uint AttributeType { get; init; }
    public long LowestVcn { get; init; }
    public ulong SegmentReference { get; init; }
    public bool IsUnnamed { get; init; }
}

internal static class NtfsAttributeListParser
{
    private const uint AttributeEnd = 0xFFFFFFFF;

    public static IReadOnlyList<NtfsAttributeListEntry> Parse(ReadOnlySpan<byte> data)
    {
        var result = new List<NtfsAttributeListEntry>();
        var offset = 0;

        while (offset + 26 <= data.Length)
        {
            var type = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(
                data.Slice(offset, 4));

            if (type == AttributeEnd)
            {
                break;
            }

            var recordLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(
                data.Slice(offset + 4, 2));
            var nameLength = data[offset + 6];
            var nameOffset = data[offset + 7];

            if (recordLength < 26 ||
                offset + recordLength > data.Length)
            {
                throw new InvalidDataException(
                    "An NTFS $ATTRIBUTE_LIST entry has an invalid record length.");
            }

            var lowestVcn = System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(
                data.Slice(offset + 8, 8));
            var segmentReference = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(
                data.Slice(offset + 16, 8));

            if (nameLength != 0 &&
                (nameOffset == 0 ||
                 nameOffset + nameLength * 2 > recordLength))
            {
                throw new InvalidDataException(
                    "An NTFS $ATTRIBUTE_LIST entry has an invalid attribute name.");
            }

            result.Add(new NtfsAttributeListEntry
            {
                AttributeType = type,
                LowestVcn = lowestVcn,
                SegmentReference = segmentReference,
                IsUnnamed = nameLength == 0
            });

            offset += recordLength;
        }

        return result;
    }
}
