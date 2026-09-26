namespace FileRecovery;

public sealed class RecycleBinService
{
    private const int RecycleBinShellFolder = 10;

    public IReadOnlyList<RecoveryItem> Scan()
    {
        var shellType = Type.GetTypeFromProgID("Shell.Application", throwOnError: false);
        if (shellType is null)
        {
            throw new InvalidOperationException("Windows Shell automation is not available on this system.");
        }

        dynamic shell = Activator.CreateInstance(shellType)
            ?? throw new InvalidOperationException("Could not create the Windows Shell object.");

        dynamic folder = shell.NameSpace(RecycleBinShellFolder);
        if (folder is null)
        {
            throw new InvalidOperationException("The Windows Recycle Bin could not be opened.");
        }

        // Keep the tuple statically typed. Passing the dynamic folder directly would
        // make this method call dynamic and turn the ValueTuple result into dynamic,
        // causing columns.OriginalLocation to fail at runtime.
        var columns = ReadColumnIndexes((object)folder);
        var results = new List<RecoveryItem>();
        dynamic items = folder.Items();

        for (int i = 0; i < items.Count; i++)
        {
            dynamic item = items.Item(i);
            if (item is null)
            {
                continue;
            }

            string name = SafeString(() => item.Name, "Unknown item");

            // Prefer the normal Details-view value first. Shell ExtendedProperty
            // access can be substantially slower when many Recycle Bin entries
            // exist, and the Details-view column already provides the original
            // location on supported Windows configurations.
            string originalLocation = SafeDetails(
                folder,
                item,
                columns.OriginalLocation);

            if (string.IsNullOrWhiteSpace(originalLocation))
            {
                originalLocation = SafeString(
                    () => item.ExtendedProperty("{9B174B33-40FF-11D2-A27E-00C04FC30871} 2"),
                    string.Empty);
            }

            string deletedDate = SafeDetails(folder, item, columns.DeletedDate);
            string size = SafeDetails(folder, item, columns.Size);

            results.Add(new RecoveryItem(
                item,
                name,
                string.IsNullOrWhiteSpace(originalLocation) ? "(Unavailable)" : originalLocation,
                string.IsNullOrWhiteSpace(deletedDate) ? "(Unavailable)" : deletedDate,
                string.IsNullOrWhiteSpace(size) ? "(Unavailable)" : size));
        }

        return results;
    }

    public void Restore(RecoveryItem item)
    {
        ArgumentNullException.ThrowIfNull(item);
        dynamic shellItem = item.ShellItem;

        try
        {
            shellItem.InvokeVerb("undelete");
            return;
        }
        catch
        {
            // Fall back to the localized verb exposed by the current Shell.
        }

        dynamic verbs = shellItem.Verbs();
        for (int i = 0; i < verbs.Count; i++)
        {
            dynamic verb = verbs.Item(i);
            if (verb is null)
            {
                continue;
            }

            string verbName = SafeString(() => verb.Name, string.Empty)
                .Replace("&", string.Empty, StringComparison.Ordinal)
                .Trim();

            if (verbName.Contains("restore", StringComparison.OrdinalIgnoreCase)
                || verbName.Equals("undelete", StringComparison.OrdinalIgnoreCase))
            {
                verb.DoIt();
                return;
            }
        }

        throw new InvalidOperationException("Windows did not expose a Restore command for this Recycle Bin item.");
    }

    private static (int OriginalLocation, int DeletedDate, int Size) ReadColumnIndexes(object folderObject)
    {
        dynamic folder = folderObject;
        int originalLocation = -1;
        int deletedDate = -1;
        int size = -1;

        for (int column = 0; column < 32; column++)
        {
            string title = SafeString(() => folder.GetDetailsOf(null, column), string.Empty);
            if (string.IsNullOrWhiteSpace(title))
            {
                continue;
            }

            string normalized = title.Replace("&", string.Empty, StringComparison.Ordinal).Trim();

            if (normalized.Contains("original", StringComparison.OrdinalIgnoreCase)
                && normalized.Contains("location", StringComparison.OrdinalIgnoreCase))
            {
                originalLocation = column;
            }
            else if (normalized.Contains("deleted", StringComparison.OrdinalIgnoreCase))
            {
                deletedDate = column;
            }
            else if (normalized.Equals("size", StringComparison.OrdinalIgnoreCase))
            {
                size = column;
            }
        }

        return (originalLocation, deletedDate, size);
    }

    private static string SafeDetails(dynamic folder, dynamic item, int column)
    {
        if (column < 0)
        {
            return string.Empty;
        }

        return SafeString(() => folder.GetDetailsOf(item, column), string.Empty);
    }

    private static string SafeString(Func<object?> getter, string fallback)
    {
        try
        {
            object? value = getter();
            return Convert.ToString(value) ?? fallback;
        }
        catch
        {
            return fallback;
        }
    }
}