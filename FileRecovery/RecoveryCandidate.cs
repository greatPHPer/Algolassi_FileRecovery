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

    public string FullPath =>
        string.IsNullOrWhiteSpace(DirectoryPath)
            ? Name
            : Path.Combine(DirectoryPath, Name);
}
