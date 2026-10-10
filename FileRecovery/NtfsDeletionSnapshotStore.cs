using System.Security.Cryptography;

namespace FileRecovery;

public sealed class NtfsDeletionSnapshotStore
{
    private const int CopyBufferSize = 1024 * 1024;
    private readonly string _folder;

    public NtfsDeletionSnapshotStore(string? storageRoot = null)
    {
        _folder = string.IsNullOrWhiteSpace(storageRoot)
            ? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "AlgoLassi",
                "FileRecovery",
                "NtfsSnapshots")
            : Path.Combine(Path.GetFullPath(storageRoot.Trim()), "NtfsSnapshots");

        Directory.CreateDirectory(_folder);
    }

    public bool TrySave(
        Guid recordId,
        ReadOnlySpan<byte> data,
        out string dataFileName,
        out string sha256)
    {
        dataFileName = string.Empty;
        sha256 = string.Empty;

        var fileName = $"{recordId:N}.bin";
        var destination = Path.Combine(_folder, fileName);
        var temporary = Path.Combine(
            _folder,
            $".{fileName}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");

        try
        {
            sha256 = Convert.ToHexString(SHA256.HashData(data));

            using (var output = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       CopyBufferSize,
                       FileOptions.SequentialScan))
            {
                output.Write(data);
                output.Flush(flushToDisk: true);
            }

            File.Move(temporary, destination, overwrite: true);
            dataFileName = fileName;
            return true;
        }
        catch
        {
            TryDelete(temporary);
            dataFileName = string.Empty;
            sha256 = string.Empty;
            return false;
        }
    }


    /// <summary>
    /// Saves a snapshot via a bounded-memory writer. The temporary file is
    /// promoted only after the exact expected byte count and SHA-256 are known.
    /// </summary>
    public bool TrySaveStreaming(
        Guid recordId,
        long expectedLength,
        Action<Stream, IncrementalHash> writeContent,
        out string dataFileName,
        out string sha256)
    {
        dataFileName = string.Empty;
        sha256 = string.Empty;
        if (expectedLength < 0 || writeContent is null)
        {
            return false;
        }

        var volumeRoot = Path.GetPathRoot(_folder);
        if (string.IsNullOrWhiteSpace(volumeRoot))
        {
            return false;
        }

        try
        {
            var drive = new DriveInfo(volumeRoot);
            const long safetyReserveBytes = 64L * 1024 * 1024;
            var requiredBytes = checked(expectedLength + safetyReserveBytes);
            if (drive.AvailableFreeSpace < requiredBytes)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS snapshot streaming skipped: insufficient free space; " +
                    $"requiredAtLeast={requiredBytes:N0}, available={drive.AvailableFreeSpace:N0}, " +
                    $"folder={_folder}.");
                return false;
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS snapshot streaming could not validate destination free space: {ex.Message}");
            return false;
        }

        var fileName = $"{recordId:N}.bin";
        var destination = Path.Combine(_folder, fileName);
        if (File.Exists(destination))
        {
            // A published snapshot is immutable forensic evidence. Do not stream a
            // second candidate over it just because another notification/retry uses
            // the same record ID. This also avoids spending another file-sized I/O
            // pass when a duplicate caller arrives after the first save completed.
            System.Diagnostics.Debug.WriteLine(
                $"NTFS snapshot streaming refused to overwrite an existing snapshot: " +
                $"recordId={recordId:N}, destination={destination}.");
            return false;
        }

        var temporary = Path.Combine(
            _folder,
            $".{fileName}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");

        try
        {
            byte[] hashBytes;
            using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            using (var output = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       CopyBufferSize,
                       FileOptions.SequentialScan))
            {
                writeContent(output, hash);
                if (output.Length != expectedLength)
                {
                    throw new InvalidDataException(
                        $"Streamed snapshot length mismatch: expected={expectedLength:N0}, " +
                        $"actual={output.Length:N0}.");
                }

                output.Flush(flushToDisk: true);
                hashBytes = hash.GetHashAndReset();
            }

            sha256 = Convert.ToHexString(hashBytes);
            // The early existence check avoids unnecessary duplicate captures; the
            // non-overwriting move closes the race when two callers start together.
            File.Move(temporary, destination, overwrite: false);
            dataFileName = fileName;
            return true;
        }
        catch (Exception ex)
        {
            TryDelete(temporary);
            dataFileName = string.Empty;
            sha256 = string.Empty;
            System.Diagnostics.Debug.WriteLine(
                $"NTFS snapshot streaming save failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Promotes a verified cache file to the durable snapshot folder without loading
    /// its contents into memory. Cache and snapshot folders should share a storage root,
    /// allowing a same-volume rename instead of a second multi-gigabyte copy.
    /// </summary>
    public bool TryPromoteFile(
        Guid recordId,
        string sourcePath,
        long expectedLength,
        string expectedSha256,
        out string dataFileName,
        out string dataFilePath)
    {
        dataFileName = string.Empty;
        dataFilePath = string.Empty;

        if (string.IsNullOrWhiteSpace(sourcePath) ||
            expectedLength < 0 ||
            string.IsNullOrWhiteSpace(expectedSha256))
        {
            return false;
        }

        var fileName = $"{recordId:N}.bin";
        var destination = Path.Combine(_folder, fileName);

        try
        {
            var sourceInfo = new FileInfo(sourcePath);
            if (!sourceInfo.Exists || sourceInfo.Length != expectedLength)
            {
                return false;
            }

            // The cache SHA-256 was computed during its streamed capture. Avoid
            // reading a multi-gigabyte file a second time merely to promote it.
            // The recovery writer verifies the persisted bytes and SHA-256 before
            // reporting a successful restore.
            File.Move(sourcePath, destination, overwrite: false);

            var destinationInfo = new FileInfo(destination);
            if (!destinationInfo.Exists || destinationInfo.Length != expectedLength)
            {
                // Best effort: return the file to the cache if the promoted file
                // unexpectedly differs in length.
                try
                {
                    if (File.Exists(destination) && !File.Exists(sourcePath))
                    {
                        File.Move(destination, sourcePath, overwrite: false);
                    }
                }
                catch
                {
                    // Preserve failure status; the caller leaves the snapshot unclaimed.
                }

                return false;
            }

            dataFileName = fileName;
            dataFilePath = destination;
            return true;
        }
        catch (IOException)
        {
            // Cross-volume/move restrictions are uncommon because the cache and
            // snapshot folders share a root. A streamed, hash-checked copy is the
            // safe fallback if an atomic move cannot be used.
            return TryPromoteByStreamingCopy(
                recordId,
                sourcePath,
                expectedLength,
                expectedSha256,
                out dataFileName,
                out dataFilePath);
        }
        catch
        {
            return false;
        }
    }

    private bool TryPromoteByStreamingCopy(
        Guid recordId,
        string sourcePath,
        long expectedLength,
        string expectedSha256,
        out string dataFileName,
        out string dataFilePath)
    {
        dataFileName = string.Empty;
        dataFilePath = string.Empty;

        var fileName = $"{recordId:N}.bin";
        var destination = Path.Combine(_folder, fileName);
        var temporary = Path.Combine(
            _folder,
            $".{fileName}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");

        try
        {
            long copied = 0;
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using (var input = new FileStream(
                       sourcePath,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.Read,
                       CopyBufferSize,
                       FileOptions.SequentialScan))
            using (var output = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       CopyBufferSize,
                       FileOptions.SequentialScan))
            {
                var buffer = new byte[CopyBufferSize];
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, read);
                    hash.AppendData(buffer, 0, read);
                    copied = checked(copied + read);
                }

                output.Flush(flushToDisk: true);
            }

            var actualHash = Convert.ToHexString(hash.GetHashAndReset());
            if (copied != expectedLength ||
                !string.Equals(actualHash, expectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                TryDelete(temporary);
                return false;
            }

            File.Move(temporary, destination, overwrite: false);
            TryDelete(sourcePath);

            dataFileName = fileName;
            dataFilePath = destination;
            return true;
        }
        catch
        {
            TryDelete(temporary);
            return false;
        }
    }

    /// <summary>
    /// Copies a snapshot to the recovery destination using a fixed-size buffer and
    /// verifies byte count and SHA-256 before publishing the destination file.
    /// This works for files larger than Int32.MaxValue without allocating their size.
    /// </summary>
    public bool TryCopyVerifiedToFile(
        string? dataFileName,
        string? dataFilePath,
        string destinationPath,
        long expectedLength,
        long expectedCapturedByteCount,
        string? expectedSha256)
    {
        if (string.IsNullOrWhiteSpace(destinationPath) ||
            expectedLength < 0 ||
            expectedCapturedByteCount != expectedLength)
        {
            return false;
        }

        string sourcePath;
        if (!string.IsNullOrWhiteSpace(dataFilePath) &&
            Path.IsPathFullyQualified(dataFilePath))
        {
            sourcePath = dataFilePath;
        }
        else if (!string.IsNullOrWhiteSpace(dataFileName) &&
                 string.Equals(
                     Path.GetFileName(dataFileName),
                     dataFileName,
                     StringComparison.Ordinal))
        {
            sourcePath = Path.Combine(_folder, dataFileName);
        }
        else
        {
            return false;
        }

        if (!File.Exists(sourcePath))
        {
            return false;
        }

        var destinationDirectory = Path.GetDirectoryName(destinationPath);
        if (string.IsNullOrWhiteSpace(destinationDirectory))
        {
            return false;
        }

        Directory.CreateDirectory(destinationDirectory);
        var temporary = destinationPath +
                        $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";

        try
        {
            long copied = 0;
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using (var input = new FileStream(
                       sourcePath,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.Read,
                       CopyBufferSize,
                       FileOptions.SequentialScan))
            {
                if (input.Length != expectedLength)
                {
                    return false;
                }

                using var output = new FileStream(
                    temporary,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    CopyBufferSize,
                    FileOptions.SequentialScan);

                var buffer = new byte[CopyBufferSize];
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, read);
                    hash.AppendData(buffer, 0, read);
                    copied = checked(copied + read);
                }

                output.Flush(flushToDisk: true);
            }

            var actualHash = Convert.ToHexString(hash.GetHashAndReset());
            if (copied != expectedLength ||
                (!string.IsNullOrWhiteSpace(expectedSha256) &&
                 !string.Equals(actualHash, expectedSha256, StringComparison.OrdinalIgnoreCase)))
            {
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS snapshot streaming restore rejected: path={sourcePath}, " +
                    $"expectedBytes={expectedLength:N0}, actualBytes={copied:N0}, " +
                    $"expectedSha256={expectedSha256 ?? "(none)"}, actualSha256={actualHash}.");
                TryDelete(temporary);
                return false;
            }

            File.Move(temporary, destinationPath, overwrite: true);
            return true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS snapshot streaming restore failed: source={sourcePath}, " +
                $"destination={destinationPath}, error={ex.GetType().Name}: {ex.Message}");
            TryDelete(temporary);
            return false;
        }
    }

    public bool TryLoad(string? dataFileName, out byte[] data)
    {
        data = [];

        if (string.IsNullOrWhiteSpace(dataFileName) ||
            !string.Equals(
                Path.GetFileName(dataFileName),
                dataFileName,
                StringComparison.Ordinal))
        {
            return false;
        }

        var path = Path.Combine(_folder, dataFileName);

        try
        {
            if (!File.Exists(path))
            {
                return false;
            }

            data = File.ReadAllBytes(path);
            return true;
        }
        catch
        {
            data = [];
            return false;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best-effort cleanup.
        }
    }
}