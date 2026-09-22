namespace FileRecovery;

public sealed class RecoveryDisplayRow
{
    public Guid? HistoryId { get; init; }
    public string Name { get; init; } = string.Empty;
    public string DeletedOn { get; init; } = string.Empty;
    public string FileSize { get; init; } = string.Empty;
    public string RecoveryStrength { get; init; } = "Unknown";
    public string Evidence { get; init; } = string.Empty;

    internal RecoveryItem? RecoverableItem { get; init; }
    internal RecoveryCandidate? RecoveryCandidate { get; init; }
}
