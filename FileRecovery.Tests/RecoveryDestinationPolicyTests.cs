using Xunit;

namespace FileRecovery.Tests;

public sealed class RecoveryDestinationPolicyTests
{
    [Fact]
    public void CreateSafeFilePath_WhenFileAlreadyExists_CreatesUniquePath()
    {
        var directory = CreateTempDirectory();

        try
        {
            var existing = Path.Combine(directory, "report.txt");
            File.WriteAllText(existing, "existing");

            var result = RecoveryDestinationPolicy.CreateSafeFilePath(directory, "report.txt");

            Assert.Equal(Path.Combine(directory, "report (1).txt"), result);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void CreateSafeFilePath_WhenDirectoryAlreadyExists_CreatesUniquePath()
    {
        var directory = CreateTempDirectory();

        try
        {
            Directory.CreateDirectory(Path.Combine(directory, "report.txt"));

            var result = RecoveryDestinationPolicy.CreateSafeFilePath(directory, "report.txt");

            Assert.Equal(Path.Combine(directory, "report (1).txt"), result);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void CreateSafeFilePath_WhenFirstTwoPathsAreOccupied_SkipsBoth()
    {
        var directory = CreateTempDirectory();

        try
        {
            File.WriteAllText(Path.Combine(directory, "report.txt"), "existing");
            Directory.CreateDirectory(Path.Combine(directory, "report (1).txt"));

            var result = RecoveryDestinationPolicy.CreateSafeFilePath(directory, "report.txt");

            Assert.Equal(Path.Combine(directory, "report (2).txt"), result);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string CreateTempDirectory()
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            "AlgoLassi.FileRecovery.Tests",
            Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);
        return directory;
    }
}
