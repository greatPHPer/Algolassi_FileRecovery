namespace FileRecovery;

public sealed class DeletionDetectedEventArgs(DeletionRecord record, bool historical = false) : EventArgs
{
    public DeletionRecord Record { get; } = record;
    public bool Historical { get; } = historical;
}
