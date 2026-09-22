using Xunit;

namespace FileRecovery.Tests;

public sealed class NtfsMappingPairsParserTests
{
    [Fact]
    public void Parse_ContiguousRuns_TracksVcnAndRelativeLcn()
    {
        var mappingPairs = new byte[]
        {
            0x21, 0x03, 0x64, 0x00,
            0x11, 0x02, 0x05,
            0x00
        };

        var extents = NtfsMappingPairsParser.Parse(mappingPairs, startingVcn: 0);

        Assert.Equal(2, extents.Count);
        Assert.Equal(0, extents[0].VirtualClusterNumber);
        Assert.Equal(3, extents[0].ClusterCount);
        Assert.Equal(100, extents[0].LogicalClusterNumber);
        Assert.Equal(3, extents[1].VirtualClusterNumber);
        Assert.Equal(2, extents[1].ClusterCount);
        Assert.Equal(105, extents[1].LogicalClusterNumber);
    }

    [Fact]
    public void Parse_SparseRun_UsesNegativeLogicalClusterNumber()
    {
        var mappingPairs = new byte[]
        {
            0x01, 0x04,
            0x00
        };

        var extents = NtfsMappingPairsParser.Parse(mappingPairs, startingVcn: 5);

        Assert.Single(extents);
        Assert.Equal(5, extents[0].VirtualClusterNumber);
        Assert.Equal(4, extents[0].ClusterCount);
        Assert.True(extents[0].IsSparse);
        Assert.Equal(-1, extents[0].LogicalClusterNumber);
    }

    [Fact]
    public void Parse_NegativeLcnDelta_IsSignExtended()
    {
        var mappingPairs = new byte[]
        {
            0x11, 0x01, 0xFF,
            0x00
        };

        var extents = NtfsMappingPairsParser.Parse(mappingPairs, startingVcn: 0);

        Assert.Single(extents);
        Assert.Equal(-1, extents[0].LogicalClusterNumber);
    }

    [Fact]
    public void Parse_InvalidHeader_Throws()
    {
        var mappingPairs = new byte[] { 0x10 };

        Assert.Throws<InvalidDataException>(
            () => NtfsMappingPairsParser.Parse(mappingPairs, startingVcn: 0));
    }
}
