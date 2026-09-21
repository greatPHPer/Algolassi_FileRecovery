namespace FileRecovery;

public sealed class DeletionDetectedEventArgs(DeletionRecord record) : EventArgs
{
    public DeletionRecord Record { get; } = record;
}
