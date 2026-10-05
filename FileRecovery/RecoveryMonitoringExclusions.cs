namespace FileRecovery;

internal static class RecoveryMonitoringExclusions
{
    private static readonly string InternalStorageDirectory =
        NormalizeDirectory(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AlgoLassi",
                "FileRecovery"));

    public static bool IsExcludedPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = NormalizeDirectory(path);

        return string.Equals(
                   normalized,
                   InternalStorageDirectory,
                   StringComparison.OrdinalIgnoreCase)
               || normalized.StartsWith(
                   InternalStorageDirectory + Path.DirectorySeparatorChar,
                   StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeDirectory(string path)
    {
        var normalized = path
            .Trim()
            .Replace(
                Path.AltDirectorySeparatorChar,
                Path.DirectorySeparatorChar);

        try
        {
            normalized = Path.GetFullPath(normalized);
        }
        catch
        {
            // Keep the normalized text when Windows cannot resolve the path.
        }

        return normalized.TrimEnd(Path.DirectorySeparatorChar);
    }
}
