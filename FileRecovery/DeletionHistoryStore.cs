using System.Text.Json;

namespace FileRecovery;

public sealed class DeletionHistoryStore
{
    private const int MaxRecords = 500;
    private readonly object _gate = new();
    private readonly object _saveGate = new();
    private readonly string _path;
    private List<DeletionRecord> _records;

    public event EventHandler? Changed;

    public DeletionHistoryStore()
    {
        var folder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AlgoLassi",
            "FileRecovery");

        Directory.CreateDirectory(folder);
        _path = Path.Combine(folder, "deletions.json");
        _records = Load();
    }

    public IReadOnlyList<DeletionRecord> GetRecent(int count = 500)
    {
        lock (_gate)
        {
            return _records
                .OrderByDescending(x => x.DeletedAtUtc)
                .Take(Math.Clamp(count, 1, MaxRecords))
                .Select(Clone)
                .ToList();
        }
    }

    public IReadOnlyList<string> GetRecentDirectories(int count = 20)
    {
        lock (_gate)
        {
            return _records
                .OrderByDescending(x => x.DeletedAtUtc)
                .Select(x => x.DirectoryPath)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(Math.Clamp(count, 1, 50))
                .ToList();
        }
    }

    public bool Upsert(DeletionRecord record)
    {
        bool existed;

        // Serialize persistence operations without holding _gate during disk I/O.
        lock (_saveGate)
        {
            List<DeletionRecord> snapshot;

            lock (_gate)
            {
                var index = _records.FindIndex(x =>
                    x.Id == record.Id ||
                    (string.Equals(x.FullPath, record.FullPath, StringComparison.OrdinalIgnoreCase) &&
                     Math.Abs((x.DeletedAtUtc - record.DeletedAtUtc).TotalSeconds) <= 5));

                existed = index >= 0;

                if (existed)
                {
                    _records[index] = record;
                }
                else
                {
                    _records.Add(record);
                }

                _records = _records
                    .OrderByDescending(x => x.DeletedAtUtc)
                    .Take(MaxRecords)
                    .ToList();

                snapshot = _records
                    .Select(Clone)
                    .ToList();
            }

            Save(snapshot);
        }

        Changed?.Invoke(this, EventArgs.Empty);
        return existed;
    }

    public void Clear()
    {
        // Serialize persistence operations without holding _gate during disk I/O.
        lock (_saveGate)
        {
            List<DeletionRecord> snapshot;

            lock (_gate)
            {
                _records.Clear();
                snapshot = [];
            }

            Save(snapshot);
        }

        Changed?.Invoke(this, EventArgs.Empty);
    }

    private List<DeletionRecord> Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return [];
            }

            var json = File.ReadAllText(_path);
            return JsonSerializer.Deserialize<List<DeletionRecord>>(json) ?? [];
        }
        catch
        {
            return [];
        }
    }

    private void Save(IReadOnlyList<DeletionRecord> snapshot)
    {
        var directory = Path.GetDirectoryName(_path)!;
        Directory.CreateDirectory(directory);

        if (Directory.Exists(_path))
        {
            throw new InvalidOperationException(
                $"The deletion history path is a directory instead of a file: {_path}");
        }

        var temp = Path.Combine(
            directory,
            $".{Path.GetFileName(_path)}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");

        try
        {
            var json = JsonSerializer.Serialize(
                snapshot,
                new JsonSerializerOptions { WriteIndented = true });

            File.WriteAllText(temp, json);

            if (File.Exists(_path))
            {
                var attributes = File.GetAttributes(_path);
                if ((attributes & FileAttributes.ReadOnly) != 0)
                {
                    File.SetAttributes(_path, attributes & ~FileAttributes.ReadOnly);
                }
            }

            const int maxAttempts = 3;
            for (var attempt = 1; attempt <= maxAttempts; attempt++)
            {
                try
                {
                    File.Move(temp, _path, overwrite: true);
                    return;
                }
                catch (UnauthorizedAccessException) when (attempt < maxAttempts)
                {
                    Thread.Sleep(100);
                }
                catch (IOException) when (attempt < maxAttempts)
                {
                    Thread.Sleep(100);
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Deletion history is non-critical. Keep the monitor alive if Windows
            // temporarily blocks replacement of the local history file.
        }
        catch (IOException)
        {
            // Deletion history is non-critical. Keep the monitor alive if the
            // history file is temporarily unavailable or locked.
        }
        finally
        {
            try
            {
                if (File.Exists(temp))
                {
                    File.Delete(temp);
                }
            }
            catch
            {
                // Best-effort cleanup only.
            }
        }
    }

    private static DeletionRecord Clone(DeletionRecord item) => new()
    {
        Id = item.Id,
        FullPath = item.FullPath,
        FileName = item.FileName,
        DirectoryPath = item.DirectoryPath,
        DeletedAtUtc = item.DeletedAtUtc,
        FileSizeBytes = item.FileSizeBytes,
        RecoveryStrength = item.RecoveryStrength
    };
}
