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
        _records = Load()
            .Where(record => !RecoveryMonitoringExclusions.IsExcludedPath(record.FullPath))
            .ToList();
    }

    public IReadOnlyList<DeletionRecord> GetRecent(int count = 500)
    {
        lock (_gate)
        {
            var limit = Math.Clamp(count, 1, MaxRecords);

            // Complete NTFS deletion snapshots are authoritative forensic evidence.
            // Always surface them even when they are older than the ordinary history
            // window, otherwise the recovery UI cannot discover the snapshot that was
            // intentionally preserved by Upsert().
            var snapshotRecords = _records
                .Where(x => x.NtfsDataSnapshot?.IsComplete == true)
                .OrderByDescending(x => x.DeletedAtUtc)
                .ToList();

            var ordinaryRecords = _records
                .Where(x => x.NtfsDataSnapshot?.IsComplete != true)
                .OrderByDescending(x => x.DeletedAtUtc)
                .Take(limit)
                .ToList();

            return snapshotRecords
                .Concat(ordinaryRecords)
                .OrderByDescending(x => x.DeletedAtUtc)
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
        if (RecoveryMonitoringExclusions.IsExcludedPath(record.FullPath))
        {
            return false;
        }

        bool existed;

        // Serialize persistence operations without holding _gate during disk I/O.
        lock (_saveGate)
        {
            List<DeletionRecord> snapshot;

            lock (_gate)
            {
                // Once a USN file reference is known, it is the strongest
                // identity available for this deletion. Prefer it over the transient
                // Guid assigned independently by FileSystemWatcher/USN event sources.
                // This collapses the duplicate-row race between the two monitors.
                var index = -1;

                if (record.FileReferenceNumber.HasValue)
                {
                    index = _records.FindIndex(x =>
                        x.FileReferenceNumber.HasValue &&
                        x.FileReferenceNumber.Value == record.FileReferenceNumber.Value);
                }

                if (index < 0)
                {
                    index = _records.FindIndex(x => x.Id == record.Id);
                }

                // FileSystemWatcher and USN can report the same deletion at slightly
                // different times. A watcher row may have no NTFS reference while the
                // authoritative USN row already has one. When the path and timestamps
                // identify the same live deletion, upgrade that watcher row instead of
                // creating a second history entry.
                if (index < 0)
                {
                    index = _records.FindIndex(x =>
                        string.Equals(
                            x.FullPath,
                            record.FullPath,
                            StringComparison.OrdinalIgnoreCase) &&
                        Math.Abs(
                            (x.DeletedAtUtc - record.DeletedAtUtc).TotalSeconds) <= 10 &&
                        (!x.FileReferenceNumber.HasValue ||
                         !record.FileReferenceNumber.HasValue ||
                         x.FileReferenceNumber.Value == record.FileReferenceNumber.Value));
                }

                existed = index >= 0;

                if (existed)
                {
                    var existing = _records[index];

                    // FileSystemWatcher/Recycle Bin updates may arrive after the
                    // USN record and omit NTFS identifiers. Never erase identifiers
                    // that are already known for the same deletion.
                    if (!record.FileReferenceNumber.HasValue &&
                        existing.FileReferenceNumber.HasValue)
                    {
                        record.FileReferenceNumber = existing.FileReferenceNumber;
                    }

                    if (!record.ParentFileReferenceNumber.HasValue &&
                        existing.ParentFileReferenceNumber.HasValue)
                    {
                        record.ParentFileReferenceNumber = existing.ParentFileReferenceNumber;
                    }

                    if (!record.FileSizeBytes.HasValue &&
                        existing.FileSizeBytes.HasValue)
                    {
                        record.FileSizeBytes = existing.FileSizeBytes;
                    }

                    // A complete delete-time snapshot is immutable forensic
                    // evidence. Do not replace an already-complete snapshot merely
                    // because a later monitor retry/reused-MFT read produced another
                    // byte stream for the same file reference.
                    if (existing.NtfsDataSnapshot?.IsComplete == true)
                    {
                        record.NtfsDataSnapshot = existing.NtfsDataSnapshot.Clone();
                        record.FileSizeBytes = existing.FileSizeBytes;
                        record.RecoveryStrength = existing.RecoveryStrength;
                    }
                    else if (record.NtfsDataSnapshot is null &&
                             existing.NtfsDataSnapshot is not null)
                    {
                        record.NtfsDataSnapshot = existing.NtfsDataSnapshot.Clone();
                    }

                    _records[index] = record;
                }
                else
                {
                    _records.Add(record);
                }

                // Keep ordinary deletion history bounded, but never evict a complete
                // deletion-time NTFS snapshot just because a burst of unrelated
                // filesystem events pushed the record beyond MaxRecords. The snapshot
                // is immutable forensic evidence and may be the only authoritative
                // copy of the deleted file data after the MFT entry is reused.
                var snapshotRecords = _records
                    .Where(x => x.NtfsDataSnapshot?.IsComplete == true)
                    .OrderByDescending(x => x.DeletedAtUtc)
                    .ToList();

                var ordinaryRecords = _records
                    .Where(x => x.NtfsDataSnapshot?.IsComplete != true)
                    .OrderByDescending(x => x.DeletedAtUtc)
                    .Take(MaxRecords)
                    .ToList();

                _records = snapshotRecords
                    .Concat(ordinaryRecords)
                    .OrderByDescending(x => x.DeletedAtUtc)
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
        FileReferenceNumber = item.FileReferenceNumber,
        ParentFileReferenceNumber = item.ParentFileReferenceNumber,
        FullPath = item.FullPath,
        FileName = item.FileName,
        DirectoryPath = item.DirectoryPath,
        DeletedAtUtc = item.DeletedAtUtc,
        FileSizeBytes = item.FileSizeBytes,
        RecoveryStrength = item.RecoveryStrength,
        NtfsDataSnapshot = item.NtfsDataSnapshot?.Clone()
    };
}