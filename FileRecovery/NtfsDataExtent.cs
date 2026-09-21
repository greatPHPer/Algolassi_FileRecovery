namespace FileRecovery;

public sealed class NtfsDataExtent
{
    public long VirtualClusterNumber { get; init; }
    public long ClusterCount { get; init; }
    public long LogicalClusterNumber { get; init; }
    public bool IsSparse => LogicalClusterNumber < 0;
}
