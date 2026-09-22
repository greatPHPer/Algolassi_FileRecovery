namespace FileRecovery;

public static class RecoveryDestinationPolicy
{
    public static void Validate(string sourcePath, string destinationDirectory)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            throw new ArgumentException("A source path is required.", nameof(sourcePath));
        }

        if (string.IsNullOrWhiteSpace(destinationDirectory))
        {
            throw new ArgumentException("A recovery destination is required.", nameof(destinationDirectory));
        }

        var sourceRoot = Path.GetPathRoot(sourcePath);
        var destinationRoot = Path.GetPathRoot(destinationDirectory);

        if (string.IsNullOrWhiteSpace(sourceRoot) ||
            string.IsNullOrWhiteSpace(destinationRoot))
        {
            throw new InvalidOperationException("The source and destination must use normal Windows filesystem paths.");
        }

        if (string.Equals(sourceRoot, destinationRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "For safety, recover deleted data to a different drive or volume from the source.");
        }

        Directory.CreateDirectory(destinationDirectory);
    }

    private static bool PathExists(string path) =>
        File.Exists(path) || Directory.Exists(path);

    public static string CreateSafeFilePath(
        string destinationDirectory,
        string originalFileName)
    {
        Directory.CreateDirectory(destinationDirectory);

        var fileName = Path.GetFileName(originalFileName);
        if (string.IsNullOrWhiteSpace(fileName))
        {
            fileName = "recovered-file";
        }

        var candidate = Path.Combine(destinationDirectory, fileName);
        if (!PathExists(candidate))
        {
            return candidate;
        }

        var stem = Path.GetFileNameWithoutExtension(fileName);
        var extension = Path.GetExtension(fileName);

        for (var i = 1; i < int.MaxValue; i++)
        {
            candidate = Path.Combine(destinationDirectory, $"{stem} ({i}){extension}");
            if (!PathExists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException("Could not create a unique recovery destination path.");
    }
}
