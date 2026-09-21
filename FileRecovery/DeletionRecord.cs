namespace FileRecovery;

public sealed class DeletionRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string FullPath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string DirectoryPath { get; set; } = string.Empty;
    public DateTime DeletedAtUtc { get; set; }
    public long? FileSizeBytes { get; set; }
    public string RecoveryStrength { get; set; } = "Unknown";
}
