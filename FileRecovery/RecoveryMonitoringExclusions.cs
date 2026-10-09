namespace FileRecovery;

internal static class RecoveryMonitoringExclusions
{
    private static readonly object Gate = new();
    private static readonly string InternalStorageDirectory =
        NormalizeDirectory(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AlgoLassi",
                "FileRecovery"));

    private static RecoverySettings? _settings;
    private static HashSet<string> _ignoredDirectories =
        new(StringComparer.OrdinalIgnoreCase);

    public static event EventHandler? Changed;

    public static void Configure(RecoverySettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        lock (Gate)
        {
            _settings = settings;
            settings.IgnoredDirectories ??= [];

            _ignoredDirectories = settings.IgnoredDirectories
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Select(NormalizeDirectory)
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Where(path => !IsSameOrDescendant(path, InternalStorageDirectory))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            settings.IgnoredDirectories = _ignoredDirectories
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    public static IReadOnlyList<string> GetIgnoredDirectories()
    {
        lock (Gate)
        {
            return _ignoredDirectories
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    public static bool AddIgnoredDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        string normalized;
        try
        {
            normalized = NormalizeDirectory(path);
        }
        catch
        {
            return false;
        }

        if (!Path.IsPathFullyQualified(normalized) ||
            IsSameOrDescendant(normalized, InternalStorageDirectory))
        {
            return false;
        }

        lock (Gate)
        {
            if (!_ignoredDirectories.Add(normalized))
            {
                return false;
            }

            SaveIgnoredDirectoriesLocked();
        }

        Changed?.Invoke(null, EventArgs.Empty);
        return true;
    }

    public static bool RemoveIgnoredDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        string normalized;
        try
        {
            normalized = NormalizeDirectory(path);
        }
        catch
        {
            return false;
        }

        lock (Gate)
        {
            if (!_ignoredDirectories.Remove(normalized))
            {
                return false;
            }

            SaveIgnoredDirectoriesLocked();
        }

        Changed?.Invoke(null, EventArgs.Empty);
        return true;
    }

    public static bool IsExcludedPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        string normalized;
        try
        {
            normalized = NormalizeDirectory(path);
        }
        catch
        {
            return false;
        }

        lock (Gate)
        {
            return IsSameOrDescendant(normalized, InternalStorageDirectory) ||
                   _ignoredDirectories.Any(directory =>
                       IsSameOrDescendant(normalized, directory));
        }
    }

    private static void SaveIgnoredDirectoriesLocked()
    {
        if (_settings is null)
        {
            return;
        }

        _settings.IgnoredDirectories = _ignoredDirectories
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();
        _settings.Save();
    }

    private static bool IsSameOrDescendant(string path, string directory)
    {
        if (string.Equals(path, directory, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var prefix = directory.EndsWith(Path.DirectorySeparatorChar)
            ? directory
            : directory + Path.DirectorySeparatorChar;

        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeDirectory(string path)
    {
        var normalized = path
            .Trim()
            .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

        try
        {
            normalized = Path.GetFullPath(normalized);
        }
        catch
        {
            // Keep normalized text if Windows cannot resolve the path.
        }

        var root = Path.GetPathRoot(normalized);
        if (!string.IsNullOrEmpty(root) &&
            string.Equals(normalized, root, StringComparison.OrdinalIgnoreCase))
        {
            return root;
        }

        return normalized.TrimEnd(Path.DirectorySeparatorChar);
    }
}
