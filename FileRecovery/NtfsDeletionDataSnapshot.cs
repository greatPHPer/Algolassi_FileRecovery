namespace FileRecovery;

public sealed class NtfsDeletionDataSnapshot
{
    public bool DataCaptured { get; set; }
    public bool IsResident { get; init; }
    public long FileSizeBytes { get; init; }
    public long ValidDataLengthBytes { get; init; }
    public long CapturedByteCount { get; init; }
    public string? DataFileName { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public List<NtfsDataExtent> DataExtents { get; init; } = [];
    public DateTime CapturedAtUtc { get; init; }
    public string Evidence { get; init; } = string.Empty;

    public bool IsComplete =>
        DataCaptured &&
        FileSizeBytes >= 0 &&
        CapturedByteCount == FileSizeBytes;

    public NtfsDeletionDataSnapshot Clone() => new()
    {
        DataCaptured = DataCaptured,
        IsResident = IsResident,
        FileSizeBytes = FileSizeBytes,
        ValidDataLengthBytes = ValidDataLengthBytes,
        CapturedByteCount = CapturedByteCount,
        DataFileName = DataFileName,
        Sha256 = Sha256,
        DataExtents = DataExtents
            .Select(extent => new NtfsDataExtent
            {
                VirtualClusterNumber = extent.VirtualClusterNumber,
                ClusterCount = extent.ClusterCount,
                LogicalClusterNumber = extent.LogicalClusterNumber
            })
            .ToList(),
        CapturedAtUtc = CapturedAtUtc,
        Evidence = Evidence
    };
}
