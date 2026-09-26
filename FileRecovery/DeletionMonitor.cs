using System.Collections.Concurrent;

namespace FileRecovery;

public sealed class DeletionMonitor : IDisposable
{
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentDictionary<string, long> _knownSizes =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly RecycleBinService _recycleBinService = new();
    private readonly object _gate = new();
    private bool _started;

    public event EventHandler<DeletionDetectedEventArgs>? DeletionDetected;
    public event EventHandler<string>? StatusChanged;

    public void Start()
    {
        lock (_gate)
        {
            if (_started)
            {
                return;
            }

            _started = true;
        }

        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (!drive.IsReady || drive.DriveType != DriveType.Fixed)
                {
                    continue;
                }

                if (!string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var watcher = new FileSystemWatcher(drive.RootDirectory.FullName)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024,
                    Filter = "*"
                };

                watcher.Created += OnCreated;
                watcher.Changed += OnChanged;
                watcher.Renamed += OnRenamed;
                watcher.Deleted += OnDeleted;
                watcher.Error += OnWatcherError;
                watcher.EnableRaisingEvents = true;

                _watchers.Add(watcher);
                StatusChanged?.Invoke(this, $"Monitoring {drive.RootDirectory.FullName}");
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"Could not monitor {drive.RootDirectory.FullName}: {ex.Message}");
            }
        }

        if (_watchers.Count == 0)
        {
            StatusChanged?.Invoke(this, "No ready NTFS volumes are currently being monitored.");
        }
    }

    public void Stop()
    {
        lock (_gate)
        {
            if (!_started)
            {
                return;
            }

            _started = false;
        }

        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Created -= OnCreated;
                watcher.Changed -= OnChanged;
                watcher.Renamed -= OnRenamed;
                watcher.Deleted -= OnDeleted;
                watcher.Error -= OnWatcherError;
                watcher.Dispose();
            }
            catch
            {
                // Best effort cleanup.
            }
        }

        _watchers.Clear();
        _knownSizes.Clear();
    }

    private void OnCreated(object sender, FileSystemEventArgs e) => RememberSize(e.FullPath);
    private void OnChanged(object sender, FileSystemEventArgs e) => RememberSize(e.FullPath);

    private void OnRenamed(object sender, RenamedEventArgs e)
    {
        long? originalSize = null;

        if (!string.IsNullOrWhiteSpace(e.OldFullPath) &&
            _knownSizes.TryRemove(e.OldFullPath, out var cachedSize))
        {
            originalSize = cachedSize;
        }

        var oldPath = NormalizePath(e.OldFullPath);
        var newPath = NormalizePath(e.FullPath);

        // A normal Delete performed through Windows Explorer commonly moves the
        // file into the volume's Recycle Bin rather than generating a direct
        // FileSystemWatcher Deleted event for the original path. Treat that
        // old->Recycle.Bin rename as a live deletion observation so the USN
        // snapshot path can capture the file before its metadata/data become
        // harder to recover.
        if (IsRecycleBinPath(newPath) &&
            !IsRecycleBinPath(oldPath))
        {
            var directory = Path.GetDirectoryName(oldPath) ?? string.Empty;
            var fileName = Path.GetFileName(oldPath);

            if (!string.IsNullOrWhiteSpace(fileName))
            {
                var record = new DeletionRecord
                {
                    FullPath = oldPath,
                    FileName = fileName,
                    DirectoryPath = directory,
                    DeletedAtUtc = DateTime.UtcNow,
                    FileSizeBytes = originalSize,
                    RecoveryStrength = "Strong"
                };

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS immediate Recycle Bin rename detected: " +
                    $"oldPath={oldPath}, newPath={newPath}, size={originalSize?.ToString() ?? "(unknown)"}.");

                DeletionDetected?.Invoke(
                    this,
                    new DeletionDetectedEventArgs(record));

                _ = Task.Run(() => UpdateRecoveryStrength(record));
            }
        }

        RememberSize(e.FullPath);
    }

    private static bool IsRecycleBinPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = NormalizePath(path);
        var root = Path.GetPathRoot(normalized);

        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        var recycleRoot = Path.Combine(
            root.TrimEnd(Path.DirectorySeparatorChar),
            "$Recycle.Bin");

        return normalized.Equals(
                   recycleRoot,
                   StringComparison.OrdinalIgnoreCase)
            || normalized.StartsWith(
                   recycleRoot + Path.DirectorySeparatorChar,
                   StringComparison.OrdinalIgnoreCase);
    }

    private void OnDeleted(object sender, FileSystemEventArgs e)
    {
        long? size = _knownSizes.TryRemove(e.FullPath, out var cachedSize)
            ? cachedSize
            : null;

        var fullPath = NormalizePath(e.FullPath);
        var directory = Path.GetDirectoryName(fullPath) ?? string.Empty;
        var fileName = Path.GetFileName(fullPath);

        if (string.IsNullOrWhiteSpace(fileName))
        {
            return;
        }

        var record = new DeletionRecord
        {
            FullPath = fullPath,
            FileName = fileName,
            DirectoryPath = directory,
            DeletedAtUtc = DateTime.UtcNow,
            FileSizeBytes = size,
            RecoveryStrength = "Weak"
        };

        DeletionDetected?.Invoke(this, new DeletionDetectedEventArgs(record));

        _ = Task.Run(() => UpdateRecoveryStrength(record));
    }

    private void UpdateRecoveryStrength(DeletionRecord record)
    {
        try
        {
            var items = _recycleBinService.Scan();
            var match = items.FirstOrDefault(item =>
                string.Equals(item.Name, record.FileName, StringComparison.OrdinalIgnoreCase)
                && PathMatches(item.OriginalLocation, record.DirectoryPath));

            if (match is not null)
            {
                record.RecoveryStrength = "Strong";
                if (!record.FileSizeBytes.HasValue &&
                    TryParseSize(match.Size, out var sizeBytes))
                {
                    record.FileSizeBytes = sizeBytes;
                }
            }

            DeletionDetected?.Invoke(this, new DeletionDetectedEventArgs(record));
        }
        catch
        {
            // Recycle Bin lookup is only an enhancement to the live deletion event.
        }
    }

    private static bool PathMatches(string originalLocation, string directoryPath)
    {
        var normalizedOriginal = NormalizePath(originalLocation).TrimEnd(Path.DirectorySeparatorChar);
        var normalizedDirectory = NormalizePath(directoryPath).TrimEnd(Path.DirectorySeparatorChar);

        return string.Equals(normalizedOriginal, normalizedDirectory, StringComparison.OrdinalIgnoreCase)
            || normalizedOriginal.StartsWith(
                normalizedDirectory + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryParseSize(string value, out long size)
    {
        size = 0;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var cleaned = new string(value.Where(c => char.IsDigit(c) || c == '.').ToArray());
        if (!double.TryParse(cleaned, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var number))
        {
            return false;
        }

        var multiplier = value.Contains("GB", StringComparison.OrdinalIgnoreCase) ? 1024L * 1024L * 1024L
            : value.Contains("MB", StringComparison.OrdinalIgnoreCase) ? 1024L * 1024L
            : value.Contains("KB", StringComparison.OrdinalIgnoreCase) ? 1024L
            : 1L;

        size = checked((long)(number * multiplier));
        return true;
    }

    private void RememberSize(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return;
            }

            var info = new FileInfo(path);
            _knownSizes[path] = info.Length;
        }
        catch
        {
            // Files can disappear/change between the event and the metadata read.
        }
    }

    private static string NormalizePath(string path) =>
        path.Trim().Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

    private void OnWatcherError(object sender, ErrorEventArgs e) =>
        StatusChanged?.Invoke(this, $"File monitoring warning: {e.GetException().Message}");

    public void Dispose() => Stop();
}
