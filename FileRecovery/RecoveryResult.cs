namespace FileRecovery;

public sealed class RecoveryResult
{
    public bool Success { get; init; }
    public string SourcePath { get; init; } = string.Empty;
    public string DestinationPath { get; init; } = string.Empty;
    public long BytesRecovered { get; init; }
    public string Evidence { get; init; } = string.Empty;
}
