namespace FileRecovery;

public sealed class RecoveryItem
{
    internal RecoveryItem(object shellItem, string name, string originalLocation, string deletedDate, string size)
    {
        ShellItem = shellItem;
        Name = name;
        OriginalLocation = originalLocation;
        DeletedDate = deletedDate;
        Size = size;
    }

    internal object ShellItem { get; }

    public string Name { get; }
    public string OriginalLocation { get; }
    public string DeletedDate { get; }
    public string Size { get; }
}