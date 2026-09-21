namespace FileRecovery;

public sealed class RecycleBinMonitor : IDisposable
{
    private readonly RecycleBinService _service = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly object _gate = new();
    private HashSet<string> _knownItems = new(StringComparer.OrdinalIgnoreCase);
    private Task? _worker;
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
            _worker = Task.Run(MonitorAsync);
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
            _cts.Cancel();
        }

        try
        {
            _worker?.Wait(TimeSpan.FromSeconds(3));
        }
        catch
        {
            // Best effort shutdown.
        }

        _worker = null;
    }

    private async Task MonitorAsync()
    {
        // Establish a baseline first so opening the app does not announce
        // files that were already in the Recycle Bin.
        TryRefresh(baselineOnly: true);

        while (!_cts.IsCancellationRequested)
        {
            try
            {
                TryRefresh(baselineOnly: false);
                await Task.Delay(1500, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(this, $"Recycle Bin monitoring warning: {ex.Message}");

                try
                {
                    await Task.Delay(3000, _cts.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    private void TryRefresh(bool baselineOnly)
    {
        IReadOnlyList<RecoveryItem> items;

        try
        {
            items = _service.Scan();
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(this, $"Recycle Bin monitoring unavailable: {ex.Message}");
            return;
        }

        var current = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var item in items)
        {
            var key = BuildKey(item);
            current.Add(key);

            if (baselineOnly || _knownItems.Contains(key))
            {
                continue;
            }

            var directory = item.OriginalLocation;
            var record = new DeletionRecord
            {
                FullPath = Path.Combine(directory, item.Name),
                FileName = item.Name,
                DirectoryPath = directory,
                DeletedAtUtc = ParseDeletedDateUtc(item.DeletedDate),
                FileSizeBytes = ParseSize(item.Size),
                RecoveryStrength = "Strong"
            };

            DeletionDetected?.Invoke(this, new DeletionDetectedEventArgs(record));
        }

        _knownItems = current;
    }

    private static string BuildKey(RecoveryItem item) =>
        string.Join("|", item.Name, item.OriginalLocation, item.DeletedDate, item.Size);

    private static DateTime ParseDeletedDateUtc(string value)
    {
        if (DateTime.TryParse(
                value,
                System.Globalization.CultureInfo.CurrentCulture,
                System.Globalization.DateTimeStyles.AssumeLocal,
                out var local))
        {
            return local.ToUniversalTime();
        }

        return DateTime.UtcNow;
    }

    private static long? ParseSize(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var digits = new string(value.Where(c => char.IsDigit(c) || c == '.' || c == ',').ToArray());
        if (!double.TryParse(
                digits,
                System.Globalization.NumberStyles.Float | System.Globalization.NumberStyles.AllowThousands,
                System.Globalization.CultureInfo.CurrentCulture,
                out var number))
        {
            return null;
        }

        var multiplier =
            value.Contains("GB", StringComparison.OrdinalIgnoreCase) ? 1024d * 1024d * 1024d :
            value.Contains("MB", StringComparison.OrdinalIgnoreCase) ? 1024d * 1024d :
            value.Contains("KB", StringComparison.OrdinalIgnoreCase) ? 1024d :
            1d;

        try
        {
            return checked((long)(number * multiplier));
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}
