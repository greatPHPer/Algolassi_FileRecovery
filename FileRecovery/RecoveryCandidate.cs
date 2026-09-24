namespace FileRecovery;

public sealed class RecoveryCandidate
{
    public ulong FileReferenceNumber { get; init; }
    public ulong ParentFileReferenceNumber { get; init; }
    public string Name { get; init; } = string.Empty;
    public string DirectoryPath { get; init; } = string.Empty;
    public DateTime LastUsnTimestampUtc { get; init; }
    public RecoveryStrength Strength { get; init; } = RecoveryStrength.Weak;
    public string Evidence { get; init; } = string.Empty;

    public bool DataStreamFound { get; init; }
    public bool DataStreamResident { get; init; }
    public long FileSizeBytes { get; set; }
    public long ValidDataLengthBytes { get; init; }
    public byte[]? ResidentData { get; init; }
    public IReadOnlyList<NtfsDataExtent> DataExtents { get; init; } = [];
    public IReadOnlyList<NtfsExtentAllocation> ExtentAllocations { get; init; } = [];
    public long FreeDataClusterCount { get; init; }
    public long AllocatedDataClusterCount { get; init; }
    public string DataEvidence { get; init; } = string.Empty;

    public string FullPath =>
        string.IsNullOrWhiteSpace(DirectoryPath)
            ? Name
            : Path.Combine(DirectoryPath, Name);
}
