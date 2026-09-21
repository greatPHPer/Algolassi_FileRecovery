namespace FileRecovery;

public sealed class NtfsDataStreamInfo
{
    public bool Found { get; init; }
    public bool IsResident { get; init; }
    public long FileSizeBytes { get; init; }
    public long ValidDataLengthBytes { get; init; }
    public byte[]? ResidentData { get; init; }
    public IReadOnlyList<NtfsDataExtent> Extents { get; init; } = [];
    public string Evidence { get; init; } = string.Empty;
}
