using System.Buffers.Binary;
using Xunit;

namespace FileRecovery.Tests;

public sealed class NtfsAttributeListParserTests
{
    [Fact]
    public void Parse_ReturnsUnnamedAndNamedEntries()
    {
        var data = new byte[64];

        WriteEntry(data, 0, 0x80, 0, 42, 0x000200000000002AUL);
        WriteEntry(data, 32, 0x80, 1, 7, 0x0003000000000040UL);

        var entries = NtfsAttributeListParser.Parse(data);

        Assert.Equal(2, entries.Count);

        Assert.Equal((uint)0x80, entries[0].AttributeType);
        Assert.Equal(0, entries[0].LowestVcn);
        Assert.Equal(0x000200000000002AUL, entries[0].SegmentReference);
        Assert.True(entries[0].IsUnnamed);

        Assert.Equal(7, entries[1].LowestVcn);
        Assert.Equal(0x0003000000000040UL, entries[1].SegmentReference);
        Assert.False(entries[1].IsUnnamed);
    }

    [Fact]
    public void Parse_InvalidEntryLength_Throws()
    {
        var data = new byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0, 4), 0x80);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4, 2), 25);

        Assert.Throws<InvalidDataException>(
            () => NtfsAttributeListParser.Parse(data));
    }

    private static void WriteEntry(
        byte[] data,
        int offset,
        uint type,
        byte nameLength,
        long lowestVcn,
        ulong segmentReference)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset, 4), type);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(offset + 4, 2), 32);
        data[offset + 6] = nameLength;
        data[offset + 7] = nameLength == 0 ? (byte)0 : (byte)26;
        BinaryPrimitives.WriteInt64LittleEndian(
            data.AsSpan(offset + 8, 8),
            lowestVcn);
        BinaryPrimitives.WriteUInt64LittleEndian(
            data.AsSpan(offset + 16, 8),
            segmentReference);
    }
}
