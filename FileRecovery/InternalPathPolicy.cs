namespace FileRecovery;

internal static class InternalPathPolicy
{
    private static readonly string InternalRoot = NormalizeRoot(
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AlgoLassi",
            "FileRecovery"));

    public static bool IsIgnoredPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        try
        {
            var normalized = Path.GetFullPath(path)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

            return normalized.Equals(InternalRoot, StringComparison.OrdinalIgnoreCase)
                || normalized.StartsWith(
                    InternalRoot + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string NormalizeRoot(string path) =>
        Path.GetFullPath(path)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
}
