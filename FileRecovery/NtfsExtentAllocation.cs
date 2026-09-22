namespace FileRecovery;

public sealed class NtfsExtentAllocation
{
    public long LogicalClusterNumber { get; init; }
    public long ClusterCount { get; init; }
    public long FreeClusterCount { get; init; }
    public long AllocatedClusterCount { get; init; }
    public NtfsClusterAllocation Allocation { get; init; } = NtfsClusterAllocation.Unknown;

    public double FreeRatio =>
        ClusterCount <= 0 ? 0 : (double)FreeClusterCount / ClusterCount;
}
