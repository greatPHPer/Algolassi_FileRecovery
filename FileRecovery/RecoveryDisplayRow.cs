namespace FileRecovery;

public sealed class RecoveryDisplayRow
{
    public string Name { get; init; } = string.Empty;
    public string DeletedOn { get; init; } = string.Empty;
    public string FileSize { get; init; } = string.Empty;
    public string RecoveryStrength { get; init; } = "Unknown";

    internal RecoveryItem? RecoverableItem { get; init; }
}
