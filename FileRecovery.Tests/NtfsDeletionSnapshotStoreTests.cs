using System.Security.Cryptography;
using Xunit;

namespace FileRecovery.Tests;

public sealed class NtfsDeletionSnapshotStoreTests
{
    [Fact]
    public void TryPromoteFile_AndCopyVerifiedToFile_StreamMultiChunkContent()
    {
        var root = CreateTempDirectory();

        try
        {
            var cacheDirectory = Path.Combine(root, "PreDeleteCache");
            Directory.CreateDirectory(cacheDirectory);

            var source = Path.Combine(cacheDirectory, "large-test-cache.bin");
            const long sourceLength = 5L * 1024L * 1024L + 777L;
            var sourceHash = WriteDeterministicFileAndHash(source, sourceLength);

            var store = new NtfsDeletionSnapshotStore(root);
            var promoted = store.TryPromoteFile(
                Guid.NewGuid(),
                source,
                sourceLength,
                sourceHash,
                out var dataFileName,
                out var dataFilePath);

            Assert.True(promoted);
            Assert.False(File.Exists(source));
            Assert.True(File.Exists(dataFilePath));
            Assert.EndsWith(".bin", dataFileName, StringComparison.Ordinal);
            Assert.Equal(sourceLength, new FileInfo(dataFilePath).Length);

            var destination = Path.Combine(root, "restored", "large-test-restored.bin");
            var restored = store.TryCopyVerifiedToFile(
                dataFileName,
                dataFilePath,
                destination,
                sourceLength,
                sourceLength,
                sourceHash);

            Assert.True(restored);
            Assert.Equal(sourceLength, new FileInfo(destination).Length);
            Assert.Equal(sourceHash, ComputeFileHash(destination));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void TrySaveStreaming_DoesNotOverwriteAnExistingSnapshotForTheSameRecord()
    {
        var root = CreateTempDirectory();

        try
        {
            var store = new NtfsDeletionSnapshotStore(root);
            var recordId = Guid.NewGuid();
            var original = System.Text.Encoding.UTF8.GetBytes("original snapshot bytes");
            var replacement = System.Text.Encoding.UTF8.GetBytes("different later capture");

            var firstSaved = store.TrySaveStreaming(
                recordId,
                original.Length,
                (output, hash) =>
                {
                    output.Write(original, 0, original.Length);
                    hash.AppendData(original);
                },
                out var firstFileName,
                out var firstHash);

            Assert.True(firstSaved);
            Assert.NotEmpty(firstFileName);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(original)), firstHash);

            var secondSaved = store.TrySaveStreaming(
                recordId,
                replacement.Length,
                (output, hash) =>
                {
                    output.Write(replacement, 0, replacement.Length);
                    hash.AppendData(replacement);
                },
                out var secondFileName,
                out var secondHash);

            Assert.False(secondSaved);
            Assert.Empty(secondFileName);
            Assert.Empty(secondHash);

            var existingPath = Path.Combine(root, "NtfsSnapshots", firstFileName);
            Assert.Equal(original, File.ReadAllBytes(existingPath));
            Assert.Equal(firstHash, ComputeFileHash(existingPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void TryCopyVerifiedToFile_WhenHashDoesNotMatch_DoesNotPublishDestination()
    {
        var root = CreateTempDirectory();

        try
        {
            var store = new NtfsDeletionSnapshotStore(root);
            var snapshotDirectory = Path.Combine(root, "NtfsSnapshots");
            Directory.CreateDirectory(snapshotDirectory);

            var snapshotPath = Path.Combine(snapshotDirectory, "known-snapshot.bin");
            var sourceHash = WriteDeterministicFileAndHash(snapshotPath, 2L * 1024L * 1024L + 17L);

            var destination = Path.Combine(root, "restored", "bad-copy.bin");
            var wrongHash = new string('0', 64);

            var restored = store.TryCopyVerifiedToFile(
                "known-snapshot.bin",
                null,
                destination,
                new FileInfo(snapshotPath).Length,
                new FileInfo(snapshotPath).Length,
                wrongHash);

            Assert.False(restored);
            Assert.False(File.Exists(destination));
            Assert.Equal(sourceHash, ComputeFileHash(snapshotPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string WriteDeterministicFileAndHash(string path, long length)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            1024 * 1024,
            FileOptions.SequentialScan);

        var buffer = new byte[1024 * 1024];
        long written = 0;
        var sequence = 0;

        while (written < length)
        {
            var count = (int)Math.Min(buffer.Length, length - written);
            for (var index = 0; index < count; index++)
            {
                buffer[index] = (byte)((index + sequence) % 251);
            }

            stream.Write(buffer, 0, count);
            hash.AppendData(buffer, 0, count);
            written += count;
            sequence++;
        }

        stream.Flush(flushToDisk: true);
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static string ComputeFileHash(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 1024,
            FileOptions.SequentialScan);

        return Convert.ToHexString(SHA256.HashData(stream));
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