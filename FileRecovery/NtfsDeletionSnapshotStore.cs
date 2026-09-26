using System.Security.Cryptography;

namespace FileRecovery;

public sealed class NtfsDeletionSnapshotStore
{
    private readonly string _folder;

    public NtfsDeletionSnapshotStore()
    {
        _folder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AlgoLassi",
            "FileRecovery",
            "NtfsSnapshots");

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
            sha256 = Convert.ToHexString(
                SHA256.HashData(data));

            File.WriteAllBytes(temporary, data.ToArray());
            File.Move(temporary, destination, overwrite: true);

            dataFileName = fileName;
            return true;
        }
        catch
        {
            try
            {
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }
            catch
            {
                // Best-effort cleanup.
            }

            dataFileName = string.Empty;
            sha256 = string.Empty;
            return false;
        }
    }

    public bool TryLoad(
        string? dataFileName,
        out byte[] data)
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
}
