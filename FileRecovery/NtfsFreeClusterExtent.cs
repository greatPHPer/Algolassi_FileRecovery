namespace FileRecovery;

public sealed record NtfsFreeClusterExtent(
    long LogicalClusterNumber,
    long ClusterCount);
