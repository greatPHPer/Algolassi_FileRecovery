namespace FileRecovery;

public sealed class NtfsVolumeInfo
{
    public string RootPath { get; init; } = string.Empty;
    public long VolumeSerialNumber { get; init; }
    public long NumberSectors { get; init; }
    public long TotalClusters { get; init; }
    public long FreeClusters { get; init; }
    public long TotalReservedClusters { get; init; }
    public uint BytesPerSector { get; init; }
    public uint BytesPerCluster { get; init; }
    public uint BytesPerFileRecordSegment { get; init; }
    public uint ClustersPerFileRecordSegment { get; init; }
    public long MftValidDataLength { get; init; }
    public long MftStartLcn { get; init; }
    public long Mft2StartLcn { get; init; }
    public long MftZoneStart { get; init; }
    public long MftZoneEnd { get; init; }

    public long TotalBytes =>
        checked(TotalClusters * (long)BytesPerCluster);

    public long FreeBytes =>
        checked(FreeClusters * (long)BytesPerCluster);
}
