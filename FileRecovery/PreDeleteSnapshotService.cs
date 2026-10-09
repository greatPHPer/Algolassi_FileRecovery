using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FileRecovery;

/// <summary>
/// Keeps a bounded, rolling copy of eligible files in user-selected directories.
/// These copies are made while files still exist, rather than relying solely on
/// post-deletion NTFS reads. Protection is opt-in and never scans an entire volume
/// unless a user explicitly selects a directory (volume roots are disallowed).
/// </summary>
public sealed class PreDeleteSnapshotService : IDisposable
{
    private const long MinimumFileBytes = 1L * 1024L * 1024L;
    private const long MaximumAllowedFileBytes = 1024L * 1024L * 1024L * 1024L;
    private const long MinimumCacheBytes = 1L * 1024L * 1024L;
    private const long MaximumAllowedCacheBytes = 4096L * 1024L * 1024L * 1024L;
    private const int CopyBufferSize = 1024 * 1024;
    private const int MaximumCacheEntries = 3000;
    private const int MaximumInitialScanFiles = 20000;
    private const int MaximumInitialSnapshots = 2000;
    private static readonly TimeSpan SnapshotDebounce = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan CacheRetention = TimeSpan.FromDays(7);

    private readonly RecoverySettings _settings;
    private string _storageRoot;
    private string _cacheDirectory;
    private string _indexPath;
    private bool _storageAvailable;

    private long MaximumFileBytes =>
        Math.Clamp(_settings.PreDeleteMaxFileSizeBytes, MinimumFileBytes, MaximumAllowedFileBytes);

    private long MaximumCacheBytes =>
        Math.Clamp(_settings.PreDeleteCacheLimitBytes, MinimumCacheBytes, MaximumAllowedCacheBytes);
    private readonly object _gate = new();
    private readonly SemaphoreSlim _captureSlots = new(2, 2);
    private readonly Dictionary<string, PreDeleteSnapshotCacheEntry> _entries =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ObservedFileVersion> _observedVersions =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, CancellationTokenSource> _pending =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = [];

    private string[] _protectedDirectories = [];
    private CancellationTokenSource _configurationCancellation = new();
    private bool _started;
    private bool _disposed;

    public event EventHandler<string>? StatusChanged;

    public PreDeleteSnapshotService(RecoverySettings settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _storageRoot = _settings.EffectivePreDeleteStorageDirectory;
        _cacheDirectory = Path.Combine(_storageRoot, "PreDeleteCache");
        _indexPath = Path.Combine(_cacheDirectory, "index.json");

        try
        {
            Directory.CreateDirectory(_cacheDirectory);
            _storageAvailable = true;
            LoadIndex();
        }
        catch (Exception ex)
        {
            _storageAvailable = false;
            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete storage unavailable at {_storageRoot}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    public void Start()
    {
        string[] roots;

        lock (_gate)
        {
            if (_disposed || _started)
            {
                return;
            }

            _started = true;
            roots = _settings.ProtectedDirectories?.ToArray() ?? [];
        }

        ApplyProtectedDirectories(roots, persist: false);
    }

    public void SetConfiguration(
        IEnumerable<string> directories,
        string storageDirectory,
        long maximumFileBytes,
        long cacheLimitBytes)
    {
        ArgumentNullException.ThrowIfNull(directories);

        var normalized = NormalizeProtectedDirectories(directories);
        var normalizedStorage = Path.GetFullPath(storageDirectory.Trim());
        var clampedMaxFileBytes = Math.Clamp(
            maximumFileBytes,
            MinimumFileBytes,
            MaximumAllowedFileBytes);
        var clampedCacheLimitBytes = Math.Clamp(
            cacheLimitBytes,
            MinimumCacheBytes,
            MaximumAllowedCacheBytes);

        Directory.CreateDirectory(normalizedStorage);
        var probe = Path.Combine(
            normalizedStorage,
            $".algolassi-write-test-{Environment.ProcessId}-{Guid.NewGuid():N}.tmp");
        using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose))
        {
        }

        _settings.ProtectedDirectories = normalized.ToList();
        _settings.PreDeleteStorageDirectory = normalizedStorage;
        _settings.PreDeleteMaxFileSizeBytes = clampedMaxFileBytes;
        _settings.PreDeleteCacheLimitBytes = clampedCacheLimitBytes;
        _settings.Save();

        var storageChanged = !string.Equals(
            normalizedStorage,
            _storageRoot,
            StringComparison.OrdinalIgnoreCase);

        if (storageChanged)
        {
            // The durable snapshots have their own absolute DataFilePath and remain
            // recoverable after a storage-location change. Old rolling-cache files
            // are disposable; clean only entries this service previously recorded.
            lock (_gate)
            {
                foreach (var entry in _entries.Values.ToList())
                {
                    TryDeleteFile(Path.Combine(_cacheDirectory, entry.CacheFileName));
                }

                TryDeleteFile(_indexPath);
                _entries.Clear();
                _observedVersions.Clear();
                _storageRoot = normalizedStorage;
                _cacheDirectory = Path.Combine(_storageRoot, "PreDeleteCache");
                _indexPath = Path.Combine(_cacheDirectory, "index.json");
            }

            try
            {
                Directory.CreateDirectory(_cacheDirectory);
                _storageAvailable = true;
                LoadIndex();
            }
            catch (Exception ex)
            {
                _storageAvailable = false;
                System.Diagnostics.Trace.WriteLine(
                    $"Pre-delete storage switch failed at {_storageRoot}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        ApplyProtectedDirectories(normalized, persist: false);
    }

    public bool TryAttachSnapshot(DeletionRecord deletion)
    {
        ArgumentNullException.ThrowIfNull(deletion);

        if (deletion.NtfsDataSnapshot?.IsComplete == true ||
            string.IsNullOrWhiteSpace(deletion.FullPath) ||
            deletion.DeletedAtUtc == default ||
            RecoveryMonitoringExclusions.IsExcludedPath(deletion.FullPath))
        {
            return false;
        }

        string path;
        try
        {
            path = NormalizeFilePath(deletion.FullPath);
        }
        catch
        {
            return false;
        }

        PreDeleteSnapshotCacheEntry entry;
        ObservedFileVersion observed;
        string cacheDirectory;
        string storageRoot;

        lock (_gate)
        {
            if (_disposed ||
                !_storageAvailable ||
                !IsProtectedPathLocked(path) ||
                !_entries.TryGetValue(path, out var cached) ||
                !_observedVersions.TryGetValue(path, out observed))
            {
                return false;
            }

            entry = cached.Clone();
            cacheDirectory = _cacheDirectory;
            storageRoot = _storageRoot;
        }

        if (entry.Length <= 0 ||
            entry.Length > MaximumFileBytes ||
            entry.Length > MaximumCacheBytes ||
            observed.Length != entry.Length ||
            observed.LastWriteTimeUtcTicks != entry.LastWriteTimeUtcTicks ||
            (deletion.FileSizeBytes.HasValue &&
             deletion.FileSizeBytes.Value > 0 &&
             deletion.FileSizeBytes.Value != entry.Length))
        {
            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete snapshot not used: cached version does not match last observed file " +
                $"path={path}, cachedBytes={entry.Length:N0}, observedBytes={observed.Length:N0}, " +
                $"deletionBytes={deletion.FileSizeBytes?.ToString("N0") ?? "(unknown)"}.");
            return false;
        }

        var age = DateTime.UtcNow - entry.CapturedAtUtc;
        if (age < TimeSpan.Zero ||
            age > CacheRetention ||
            entry.CapturedAtUtc > deletion.DeletedAtUtc)
        {
            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete snapshot not used: timestamp guard failed for path={path}, " +
                $"capturedAt={entry.CapturedAtUtc:O}, deletedAt={deletion.DeletedAtUtc:O}.");
            return false;
        }

        var cachePath = Path.Combine(cacheDirectory, entry.CacheFileName);
        var cacheInfo = new FileInfo(cachePath);
        if (!cacheInfo.Exists ||
            cacheInfo.Length != entry.Length ||
            string.IsNullOrWhiteSpace(entry.Sha256))
        {
            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete snapshot not used: cache file is missing or has the wrong size/hash metadata for path={path}.");
            return false;
        }

        // Promotion is a same-storage-root move rather than a second in-memory or
        // on-disk copy. The recovery stage validates SHA-256 while streaming the
        // promoted file to the user's destination.
        var store = new NtfsDeletionSnapshotStore(storageRoot);
        if (!store.TryPromoteFile(
                deletion.Id,
                cachePath,
                entry.Length,
                entry.Sha256,
                out var snapshotFileName,
                out var snapshotFilePath))
        {
            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete snapshot not used: could not promote cache file for path={path}.");
            return false;
        }

        deletion.FileSizeBytes = entry.Length;
        deletion.RecoveryStrength = "Strong";
        deletion.NtfsDataSnapshot = new NtfsDeletionDataSnapshot
        {
            DataCaptured = true,
            IsResident = false,
            FileSizeBytes = entry.Length,
            ValidDataLengthBytes = entry.Length,
            CapturedByteCount = entry.Length,
            DataFileName = snapshotFileName,
            DataFilePath = snapshotFilePath,
            Sha256 = entry.Sha256,
            CapturedAtUtc = entry.CapturedAtUtc,
            Evidence =
                "A rolling pre-delete snapshot was streamed from a user-protected directory " +
                "and retained for recovery. Its SHA-256 is checked again during restore."
        };

        lock (_gate)
        {
            if (_entries.TryGetValue(path, out var current) &&
                string.Equals(current.CacheFileName, entry.CacheFileName, StringComparison.OrdinalIgnoreCase))
            {
                // The cache file has been moved into the durable snapshot store.
                _entries.Remove(path);
                SaveIndexLocked();
            }
        }

        System.Diagnostics.Trace.WriteLine(
            $"Pre-delete snapshot promoted to recovery history: path={path}, " +
            $"size={entry.Length:N0}, capturedAt={entry.CapturedAtUtc:O}, " +
            $"sha256={entry.Sha256}, dataFile={snapshotFilePath}.");

        return true;
    }

    private void ApplyProtectedDirectories(IEnumerable<string> directories, bool persist)
    {
        var roots = NormalizeProtectedDirectories(directories);
        List<FileSystemWatcher> oldWatchers;
        CancellationTokenSource oldCancellation;

        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            oldWatchers = _watchers.ToList();
            _watchers.Clear();

            oldCancellation = _configurationCancellation;
            oldCancellation.Cancel();
            _configurationCancellation = new CancellationTokenSource();

            foreach (var pending in _pending.Values)
            {
                pending.Cancel();
            }

            _pending.Clear();
            _observedVersions.Clear();
            _protectedDirectories = roots;

            var entriesToRemove = _entries
                .Where(pair => !IsProtectedPathLocked(pair.Key))
                .Select(pair => pair.Key)
                .ToList();

            foreach (var path in entriesToRemove)
            {
                RemoveEntryLocked(path);
            }

            PruneLocked(DateTime.UtcNow);
            SaveIndexLocked();
        }

        oldCancellation.Dispose();
        DisposeWatchers(oldWatchers);

        if (persist)
        {
            _settings.ProtectedDirectories = roots.ToList();
            _settings.Save();
        }

        if (roots.Length == 0)
        {
            StatusChanged?.Invoke(this, "Pre-delete protection is off; no protected directories are configured.");
            System.Diagnostics.Trace.WriteLine(
                "Pre-delete protection inactive: no protected directories are configured.");
            return;
        }

        foreach (var root in roots)
        {
            try
            {
                var watcher = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName |
                                   NotifyFilters.DirectoryName |
                                   NotifyFilters.Size |
                                   NotifyFilters.LastWrite,
                    InternalBufferSize = 64 * 1024,
                    Filter = "*"
                };

                watcher.Created += OnFileChanged;
                watcher.Changed += OnFileChanged;
                watcher.Renamed += OnFileRenamed;
                watcher.Error += OnWatcherError;
                watcher.EnableRaisingEvents = true;

                lock (_gate)
                {
                    if (_disposed)
                    {
                        watcher.Dispose();
                        return;
                    }

                    _watchers.Add(watcher);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"Pre-delete protection could not watch directory {root}: " +
                    $"{ex.GetType().Name}: {ex.Message}");
            }
        }

        CancellationToken token;
        lock (_gate)
        {
            token = _configurationCancellation.Token;
        }

        _ = Task.Run(() => RunInitialScanAsync(roots, token), token);
        StatusChanged?.Invoke(
            this,
            $"Pre-delete protection active for {roots.Length:N0} selected director{(roots.Length == 1 ? "y" : "ies")}.");
        System.Diagnostics.Trace.WriteLine(
            $"Pre-delete protection started: roots={string.Join(";", roots)}, " +
            $"maxFileBytes={MaximumFileBytes:N0}, maxCacheBytes={MaximumCacheBytes:N0}.");
    }

    private async Task RunInitialScanAsync(string[] roots, CancellationToken cancellationToken)
    {
        try
        {
            var candidates = new List<InitialFileCandidate>();
            var inspected = 0;

            foreach (var root in roots)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var options = new EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    IgnoreInaccessible = true,
                    ReturnSpecialDirectories = false,
                    AttributesToSkip = FileAttributes.ReparsePoint
                };

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*", options);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine(
                        $"Pre-delete initial scan could not enumerate {root}: {ex.Message}");
                    continue;
                }

                foreach (var file in files)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    inspected++;

                    if (inspected > MaximumInitialScanFiles)
                    {
                        System.Diagnostics.Trace.WriteLine(
                            $"Pre-delete initial scan reached its {MaximumInitialScanFiles:N0}-file metadata limit.");
                        break;
                    }

                    if (RecoveryMonitoringExclusions.IsExcludedPath(file) ||
                        !TryGetFileVersion(file, out var version) ||
                        version.Length <= 0 ||
                        version.Length > MaximumFileBytes)
                    {
                        continue;
                    }

                    lock (_gate)
                    {
                        if (_disposed || !IsProtectedPathLocked(file))
                        {
                            continue;
                        }

                        _observedVersions[NormalizeFilePath(file)] = version;
                    }

                    var normalized = NormalizeFilePath(file);
                    if (CacheMatchesVersion(normalized, version))
                    {
                        continue;
                    }

                    candidates.Add(new InitialFileCandidate(
                        normalized,
                        version,
                        TryGetLastWriteUtc(normalized)));
                }
            }

            // Process the most recently changed eligible files first, within strict
            // entry/byte limits. This is a bounded best-effort baseline, not a volume scan.
            candidates.Sort((left, right) => right.LastWriteTimeUtc.CompareTo(left.LastWriteTimeUtc));

            long plannedBytes;
            int plannedEntries;
            lock (_gate)
            {
                // Stale cached versions for files that changed while AlgoLassi was
                // closed will be replaced, so do not count those old versions against
                // the new baseline's entry/byte budget.
                var validEntries = _entries.Values
                    .Where(entry =>
                        _observedVersions.TryGetValue(entry.Path, out var observed) &&
                        observed.Length == entry.Length &&
                        observed.LastWriteTimeUtcTicks == entry.LastWriteTimeUtcTicks &&
                        CacheFileMatchesLength(entry))
                    .ToList();

                plannedBytes = validEntries.Sum(entry => entry.Length);
                plannedEntries = validEntries.Count;
            }

            var queued = 0;
            foreach (var candidate in candidates)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (queued >= MaximumInitialSnapshots)
                {
                    break;
                }

                lock (_gate)
                {
                    if (_disposed || !IsProtectedPathLocked(candidate.Path))
                    {
                        continue;
                    }
                }

                // A filesystem watcher may already have captured this version
                // since the baseline candidate list was assembled.
                if (CacheMatchesVersion(candidate.Path, candidate.Version))
                {
                    continue;
                }

                if (plannedEntries >= MaximumCacheEntries ||
                    candidate.Version.Length > MaximumCacheBytes - plannedBytes)
                {
                    continue;
                }

                plannedBytes += candidate.Version.Length;
                plannedEntries++;
                QueueSnapshot(candidate.Path);
                queued++;
            }

            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete initial scan queued {queued:N0} file snapshot(s) from " +
                $"{inspected:N0} inspected path(s); candidates outside byte/entry limits are skipped.");
        }
        catch (OperationCanceledException)
        {
            // Directory selection changed or the service stopped.
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete initial scan failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void OnFileChanged(object sender, FileSystemEventArgs e) =>
        QueueSnapshot(e.FullPath);

    private void OnFileRenamed(object sender, RenamedEventArgs e) =>
        QueueSnapshot(e.FullPath);

    private void OnWatcherError(object sender, ErrorEventArgs e) =>
        System.Diagnostics.Trace.WriteLine(
            $"Pre-delete protection watcher warning: {e.GetException().Message}");

    private void QueueSnapshot(string path)
    {
        if (RecoveryMonitoringExclusions.IsExcludedPath(path))
        {
            return;
        }

        string normalized;
        if (!TryNormalizeFilePath(path, out normalized) ||
            !TryGetFileVersion(normalized, out var version) ||
            version.Length <= 0 ||
            version.Length > MaximumFileBytes)
        {
            if (TryNormalizeFilePath(path, out normalized))
            {
                lock (_gate)
                {
                    _observedVersions.Remove(normalized);
                }
            }

            return;
        }

        CancellationTokenSource cancellation;

        lock (_gate)
        {
            if (_disposed || !_started || !IsProtectedPathLocked(normalized))
            {
                return;
            }

            _observedVersions[normalized] = version;

            if (_pending.TryGetValue(normalized, out var previous))
            {
                previous.Cancel();
            }

            cancellation = new CancellationTokenSource();
            _pending[normalized] = cancellation;
        }

        _ = Task.Run(() => RunQueuedSnapshotAsync(normalized, cancellation));
    }

    private async Task RunQueuedSnapshotAsync(
        string path,
        CancellationTokenSource cancellation)
    {
        var token = cancellation.Token;

        try
        {
            await Task.Delay(SnapshotDebounce, token).ConfigureAwait(false);
            await _captureSlots.WaitAsync(token).ConfigureAwait(false);

            try
            {
                if (!token.IsCancellationRequested)
                {
                    CaptureStableFile(path, token);
                }
            }
            finally
            {
                _captureSlots.Release();
            }
        }
        catch (OperationCanceledException)
        {
            // A newer file-change event superseded this capture.
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete snapshot attempt failed for {path}: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            lock (_gate)
            {
                if (_pending.TryGetValue(path, out var current) &&
                    ReferenceEquals(current, cancellation))
                {
                    _pending.Remove(path);
                }
            }

            cancellation.Dispose();
        }
    }

    private void CaptureStableFile(string path, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested ||
            RecoveryMonitoringExclusions.IsExcludedPath(path) ||
            !TryGetFileVersion(path, out var before) ||
            before.Length <= 0 ||
            before.Length > MaximumFileBytes)
        {
            return;
        }

        lock (_gate)
        {
            if (_disposed ||
                !IsProtectedPathLocked(path) ||
                !_observedVersions.TryGetValue(path, out var observed) ||
                observed != before)
            {
                return;
            }

            if (_entries.TryGetValue(path, out var existing) &&
                existing.Length == before.Length &&
                existing.LastWriteTimeUtcTicks == before.LastWriteTimeUtcTicks &&
                CacheFileMatchesLength(existing))
            {
                return;
            }
        }

        byte[] data;
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 128 * 1024,
                FileOptions.SequentialScan);

            if (stream.Length != before.Length)
            {
                return;
            }

            data = new byte[checked((int)before.Length)];
            stream.ReadExactly(data);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete snapshot could not read stable contents for {path}: " +
                $"{ex.GetType().Name}: {ex.Message}");
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (!TryGetFileVersion(path, out var after) || after != before)
        {
            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete snapshot skipped because the file changed during capture: {path}.");
            return;
        }

        var sha256 = Convert.ToHexString(SHA256.HashData(data));
        var cacheFileName = GetCacheFileName(path);
        var destination = Path.Combine(_cacheDirectory, cacheFileName);
        var temporary = destination + $".{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";

        lock (_gate)
        {
            if (_disposed ||
                !IsProtectedPathLocked(path) ||
                !_observedVersions.TryGetValue(path, out var observed) ||
                observed != before)
            {
                return;
            }

            try
            {
                File.WriteAllBytes(temporary, data);
                File.Move(temporary, destination, overwrite: true);

                _entries[path] = new PreDeleteSnapshotCacheEntry
                {
                    Path = path,
                    CacheFileName = cacheFileName,
                    Length = data.LongLength,
                    LastWriteTimeUtcTicks = before.LastWriteTimeUtcTicks,
                    CapturedAtUtc = DateTime.UtcNow,
                    Sha256 = sha256
                };

                PruneLocked(DateTime.UtcNow);
                SaveIndexLocked();
            }
            catch (Exception ex)
            {
                TryDeleteFile(temporary);
                System.Diagnostics.Trace.WriteLine(
                    $"Pre-delete snapshot could not save cache for {path}: " +
                    $"{ex.GetType().Name}: {ex.Message}");
                return;
            }
        }

        System.Diagnostics.Trace.WriteLine(
            $"Pre-delete snapshot captured: path={path}, size={data.LongLength:N0}, sha256={sha256}.");
    }

    private bool CacheMatchesVersion(string path, ObservedFileVersion version)
    {
        lock (_gate)
        {
            return _entries.TryGetValue(path, out var entry) &&
                   entry.Length == version.Length &&
                   entry.LastWriteTimeUtcTicks == version.LastWriteTimeUtcTicks &&
                   CacheFileMatchesLength(entry);
        }
    }

    private bool CacheFileMatchesLength(PreDeleteSnapshotCacheEntry entry)
    {
        try
        {
            var info = new FileInfo(Path.Combine(_cacheDirectory, entry.CacheFileName));
            return info.Exists && info.Length == entry.Length;
        }
        catch
        {
            return false;
        }
    }

    private void LoadIndex()
    {
        try
        {
            if (File.Exists(_indexPath))
            {
                var manifest = JsonSerializer.Deserialize<PreDeleteSnapshotCacheManifest>(
                    File.ReadAllText(_indexPath));

                if (manifest?.Entries is not null)
                {
                    lock (_gate)
                    {
                        foreach (var entry in manifest.Entries)
                        {
                            if (string.IsNullOrWhiteSpace(entry.Path) ||
                                string.IsNullOrWhiteSpace(entry.CacheFileName) ||
                                !string.Equals(
                                    Path.GetFileName(entry.CacheFileName),
                                    entry.CacheFileName,
                                    StringComparison.Ordinal) ||
                                entry.Length <= 0 ||
                                entry.Length > MaximumFileBytes ||
                                !File.Exists(Path.Combine(_cacheDirectory, entry.CacheFileName)))
                            {
                                continue;
                            }

                            var path = NormalizeFilePath(entry.Path);
                            _entries[path] = entry;
                        }

                        PruneLocked(DateTime.UtcNow);
                        SaveIndexLocked();
                    }
                }
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete cache index could not be loaded: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private void PruneLocked(DateTime nowUtc)
    {
        var expired = _entries
            .Where(pair =>
                nowUtc - pair.Value.CapturedAtUtc > CacheRetention ||
                !CacheFileMatchesLength(pair.Value))
            .Select(pair => pair.Key)
            .ToList();

        foreach (var path in expired)
        {
            RemoveEntryLocked(path);
        }

        long totalBytes = _entries.Values.Sum(entry => entry.Length);

        while (_entries.Count > MaximumCacheEntries || totalBytes > MaximumCacheBytes)
        {
            var oldest = _entries
                .OrderBy(pair => pair.Value.CapturedAtUtc)
                .FirstOrDefault();

            if (oldest.Value is null)
            {
                break;
            }

            totalBytes -= oldest.Value.Length;
            RemoveEntryLocked(oldest.Key);
        }
    }

    private void RemoveEntryLocked(string path)
    {
        if (!_entries.Remove(path, out var entry))
        {
            return;
        }

        TryDeleteFile(Path.Combine(_cacheDirectory, entry.CacheFileName));
    }

    private void SaveIndexLocked()
    {
        var temporary = _indexPath + ".tmp";

        try
        {
            var manifest = new PreDeleteSnapshotCacheManifest
            {
                Entries = _entries.Values
                    .OrderBy(entry => entry.Path, StringComparer.OrdinalIgnoreCase)
                    .Select(entry => entry.Clone())
                    .ToList()
            };

            File.WriteAllText(
                temporary,
                JsonSerializer.Serialize(
                    manifest,
                    new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporary, _indexPath, overwrite: true);
        }
        catch (Exception ex)
        {
            TryDeleteFile(temporary);
            System.Diagnostics.Trace.WriteLine(
                $"Pre-delete cache index could not be saved: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static string[] NormalizeProtectedDirectories(IEnumerable<string> directories)
    {
        var paths = new List<string>();

        foreach (var directory in directories)
        {
            if (string.IsNullOrWhiteSpace(directory))
            {
                continue;
            }

            try
            {
                var normalized = NormalizeDirectoryPath(directory);
                var root = Path.GetPathRoot(normalized);

                if (!Directory.Exists(normalized) ||
                    string.IsNullOrWhiteSpace(root) ||
                    string.Equals(
                        Path.TrimEndingDirectorySeparator(normalized),
                        Path.TrimEndingDirectorySeparator(root),
                        StringComparison.OrdinalIgnoreCase) ||
                    RecoveryMonitoringExclusions.IsExcludedPath(normalized))
                {
                    continue;
                }

                if (!paths.Any(existing => IsSameOrDescendant(normalized, existing)))
                {
                    paths.RemoveAll(existing => IsSameOrDescendant(existing, normalized));
                    paths.Add(normalized);
                }
            }
            catch
            {
                // Ignore invalid/stale paths, but keep other protected directories.
            }
        }

        return paths.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private bool IsProtectedPathLocked(string path) =>
        _protectedDirectories.Any(root => IsSameOrDescendant(path, root));

    private static string NormalizeDirectoryPath(string path)
    {
        var fullPath = Path.GetFullPath(path.Trim())
            .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        var root = Path.GetPathRoot(fullPath);

        return !string.IsNullOrWhiteSpace(root) &&
               string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase)
            ? root
            : fullPath.TrimEnd(Path.DirectorySeparatorChar);
    }

    private static string NormalizeFilePath(string path) =>
        Path.GetFullPath(path.Trim())
            .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

    private static bool TryNormalizeFilePath(string path, out string normalized)
    {
        normalized = string.Empty;

        try
        {
            normalized = NormalizeFilePath(path);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryGetFileVersion(string path, out ObservedFileVersion version)
    {
        version = default;

        try
        {
            var info = new FileInfo(path);
            info.Refresh();

            if (!info.Exists || (info.Attributes & FileAttributes.Directory) != 0)
            {
                return false;
            }

            version = new ObservedFileVersion(info.Length, info.LastWriteTimeUtc.Ticks);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static DateTime TryGetLastWriteUtc(string path)
    {
        try
        {
            return File.GetLastWriteTimeUtc(path);
        }
        catch
        {
            return DateTime.MinValue;
        }
    }

    private static string GetCacheFileName(string path)
    {
        var pathHash = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(path.ToUpperInvariant())));
        return pathHash + ".bin";
    }

    private static bool IsSameOrDescendant(string path, string directory)
    {
        if (string.Equals(path, directory, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var prefix = directory.EndsWith(Path.DirectorySeparatorChar)
            ? directory
            : directory + Path.DirectorySeparatorChar;

        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static void TryDeleteFile(string path)
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
            // Best-effort cache cleanup.
        }
    }

    private void DisposeWatchers(IEnumerable<FileSystemWatcher> watchers)
    {
        foreach (var watcher in watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Created -= OnFileChanged;
                watcher.Changed -= OnFileChanged;
                watcher.Renamed -= OnFileRenamed;
                watcher.Error -= OnWatcherError;
                watcher.Dispose();
            }
            catch
            {
                // Best-effort shutdown.
            }
        }
    }

    public void Dispose()
    {
        List<FileSystemWatcher> watchers;
        CancellationTokenSource cancellation;

        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _started = false;
            watchers = _watchers.ToList();
            _watchers.Clear();

            cancellation = _configurationCancellation;
            cancellation.Cancel();

            foreach (var pending in _pending.Values)
            {
                pending.Cancel();
            }

            _pending.Clear();
        }

        cancellation.Dispose();
        DisposeWatchers(watchers);
    }

    private readonly record struct ObservedFileVersion(
        long Length,
        long LastWriteTimeUtcTicks);

    private sealed record InitialFileCandidate(
        string Path,
        ObservedFileVersion Version,
        DateTime LastWriteTimeUtc);
}

internal sealed class PreDeleteSnapshotCacheManifest
{
    public List<PreDeleteSnapshotCacheEntry> Entries { get; set; } = [];
}

internal sealed class PreDeleteSnapshotCacheEntry
{
    public string Path { get; set; } = string.Empty;
    public string CacheFileName { get; set; } = string.Empty;
    public long Length { get; set; }
    public long LastWriteTimeUtcTicks { get; set; }
    public DateTime CapturedAtUtc { get; set; }
    public string Sha256 { get; set; } = string.Empty;

    public PreDeleteSnapshotCacheEntry Clone() => new()
    {
        Path = Path,
        CacheFileName = CacheFileName,
        Length = Length,
        LastWriteTimeUtcTicks = LastWriteTimeUtcTicks,
        CapturedAtUtc = CapturedAtUtc,
        Sha256 = Sha256
    };
}