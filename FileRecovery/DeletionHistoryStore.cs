using System.Text.Json;

namespace FileRecovery;

public sealed class DeletionHistoryStore
{
    private const int MaxRecords = 500;
    private readonly object _gate = new();
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

    public void Add(DeletionRecord record)
    {
        lock (_gate)
        {
            _records.Add(record);
            _records = _records
                .OrderByDescending(x => x.DeletedAtUtc)
                .Take(MaxRecords)
                .ToList();
            Save();
        }

        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Clear()
    {
        lock (_gate)
        {
            _records.Clear();
            Save();
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

    private void Save()
    {
        var temp = _path + ".tmp";
        var json = JsonSerializer.Serialize(_records, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(temp, json);
        File.Move(temp, _path, overwrite: true);
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
