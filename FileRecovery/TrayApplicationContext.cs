using System.Threading;

namespace FileRecovery;

public sealed class TrayApplicationContext : ApplicationContext
{
    private readonly NotifyIcon _trayIcon;
    private readonly ContextMenuStrip _menu;
    private readonly ToolStripMenuItem _notificationsMenuItem;
    private readonly DeletionHistoryStore _history;
    private readonly RecoverySettings _settings;
    private readonly DeletionMonitor _monitor;
    private readonly UsnJournalMonitor _usnMonitor;
    private readonly RecycleBinMonitor _recycleBinMonitor;
    private readonly SynchronizationContext _uiContext;
    private Form1? _mainForm;
    private DeletionNotificationForm? _notificationForm;
    private bool _exiting;

    public TrayApplicationContext()
    {
        _uiContext = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
        _history = new DeletionHistoryStore();
        _settings = RecoverySettings.Load();
        _monitor = new DeletionMonitor();
        _usnMonitor = new UsnJournalMonitor(_settings);
        _recycleBinMonitor = new RecycleBinMonitor();

        _notificationsMenuItem = new ToolStripMenuItem("Notifications")
        {
            CheckOnClick = true,
            Checked = !_settings.NotificationsMuted
        };
        _notificationsMenuItem.Click += (_, _) =>
        {
            _settings.NotificationsMuted = !_notificationsMenuItem.Checked;
            _settings.Save();
        };

        _menu = new ContextMenuStrip();
        _menu.Items.Add("Open Recovery Center", null, (_, _) => OpenMainWindow());
        _menu.Items.Add(
            "Why must AlgoLassi stay running?",
            null,
            (_, _) => ShowMonitoringInformation());
        _menu.Items.Add(_notificationsMenuItem);
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add("Exit", null, (_, _) => ExitApplication());

        _trayIcon = new NotifyIcon
        {
            Icon = SystemIcons.Application,
            Text = "AlgoLassi: keep running in tray to monitor deletions",
            BalloonTipTitle = "AlgoLassi monitoring is active",
            BalloonTipText =
                "Keep AlgoLassi running in the system tray before deleting files. " +
                "Closing the Recovery Center window is safe; choosing Exit stops monitoring.",
            BalloonTipIcon = ToolTipIcon.Info,
            Visible = true,
            ContextMenuStrip = _menu
        };
        _trayIcon.DoubleClick += (_, _) => OpenMainWindow();

        _monitor.DeletionDetected += OnDeletionDetected;
        _monitor.StatusChanged += OnMonitorStatusChanged;
        _usnMonitor.DeletionDetected += OnDeletionDetected;
        _usnMonitor.StatusChanged += OnMonitorStatusChanged;
        _recycleBinMonitor.DeletionDetected += OnDeletionDetected;
        _recycleBinMonitor.StatusChanged += OnMonitorStatusChanged;
        // Arm the USN journals before FileSystemWatcher starts so a very early
        // Shift+Delete cannot be missed during application startup.
        _usnMonitor.Start();
        _monitor.Start();
        _recycleBinMonitor.Start();

        // The application starts resident in the tray, so explain the always-on
        // monitoring requirement even when the user never opens the Recovery Center.
        _trayIcon.ShowBalloonTip(10000);
    }

    private void ShowMonitoringInformation()
    {
        MessageBox.Show(
            "AlgoLassi monitors deletion events continuously while it is running in the Windows notification area (system tray).\r\n\r\n" +
            "Start AlgoLassi before deleting files and leave it running. You may close the Recovery Center window; " +
            "that only hides the window and monitoring continues in the tray.\r\n\r\n" +
            "Choose Exit from the tray menu or end the process, and monitoring stops. This is continuous background " +
            "monitoring, not a full-volume recovery scan every second. Recovery depends on the evidence Windows still " +
            "retains and is not guaranteed.",
            "Keep AlgoLassi Running",
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
    }

    private void OpenMainWindow()
    {
        if (_exiting)
        {
            return;
        }

        if (_mainForm is null || _mainForm.IsDisposed)
        {
            _mainForm = new Form1(
                _history,
                new RecycleBinService(),
                _usnMonitor);
            _mainForm.FormClosed += (_, _) =>
            {
                if (!_exiting)
                {
                    _mainForm = null;
                }
            };
        }

        if (!_mainForm.Visible)
        {
            _mainForm.Show();
        }

        if (_mainForm.WindowState == FormWindowState.Minimized)
        {
            _mainForm.WindowState = FormWindowState.Normal;
        }

        _mainForm.BringToFront();
        _mainForm.Activate();
    }

    private async Task attmp(DeletionDetectedEventArgs e)
    {
        try
        {
            const int fastAttempts = 5;

            // Give the freshly deleted MFT generation several cheap chances first.
            // These attempts deliberately do not enter the expensive $LogFile path.
            for (var attempt = 0; attempt < fastAttempts; attempt++)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS immediate live path fast snapshot attempt: " +
                    $"path={e.Record.FullPath}, attempt={attempt + 1}/{fastAttempts}.");

                if (await Task.Run(
                        () => _usnMonitor.TryCaptureRecentDeletionSnapshot(
                            e.Record,
                            allowHistoricalLogFileFallback: false)))
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS immediate live path fast snapshot succeeded: " +
                        $"path={e.Record.FullPath}, attempt={attempt + 1}.");

                    await Task.Run(() => _history.Upsert(e.Record));
                    return;
                }

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS immediate live path fast snapshot attempt failed: " +
                    $"path={e.Record.FullPath}, attempt={attempt + 1}/{fastAttempts}.");

                if (attempt < fastAttempts - 1)
                {
                    await Task.Delay(150);
                }
            }

            // Only one expensive $LogFile reconstruction is allowed for this
            // deletion event. The underlying reader is also cancelled after 45 seconds.
            using var fallbackCts =
                new CancellationTokenSource(TimeSpan.FromSeconds(45));

            System.Diagnostics.Debug.WriteLine(
                $"NTFS immediate live path starting SINGLE $LogFile fallback: " +
                $"path={e.Record.FullPath}.");

            if (await Task.Run(
                    () => _usnMonitor.TryCaptureRecentDeletionSnapshot(
                        e.Record,
                        allowHistoricalLogFileFallback: true,
                        cancellationToken: fallbackCts.Token)))
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS immediate live path $LogFile fallback succeeded: " +
                    $"path={e.Record.FullPath}.");

                await Task.Run(() => _history.Upsert(e.Record));
                return;
            }

            System.Diagnostics.Debug.WriteLine(
                $"NTFS immediate live path snapshot exhausted: " +
                $"path={e.Record.FullPath}. " +
                $"Five fast MFT/USN attempts + one $LogFile attempt failed.");
        }
        catch (OperationCanceledException)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS immediate live path snapshot cancelled: " +
                $"path={e.Record.FullPath}.");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS immediate live path snapshot worker failed: " +
                $"path={e.Record.FullPath}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private async void OnDeletionDetected(object? sender, DeletionDetectedEventArgs e)
    {
        if (RecoveryMonitoringExclusions.IsExcludedPath(e.Record.FullPath))
        {
            return;
        }

        bool wasExisting;

        try
        {
            // Persist the deletion immediately so FileSystemWatcher/USN lookup
            // latency can never prevent the deleted-file result from appearing.
            // NTFS identifiers are enriched separately below.
            wasExisting = await Task.Run(() => _history.Upsert(e.Record));
        }
        catch
        {
            // The history store is non-critical. Monitoring and notifications should
            // continue even if a background history update fails unexpectedly.
            return;
        }

        // FileSystemWatcher normally gives us the first live event, but the
        // USN monitor can be the first/only source when the watcher buffer is busy.
        // A fresh USN delete (known file reference and very recent timestamp) must
        // receive the same deletion-time snapshot treatment without turning an old
        // historical directory scan into hundreds of expensive captures.
        var isFreshUsnDelete =
            e.Record.FileReferenceNumber.HasValue &&
            e.Record.ParentFileReferenceNumber.HasValue &&
            e.Record.DeletedAtUtc != default &&
            Math.Abs((DateTime.UtcNow - e.Record.DeletedAtUtc).TotalSeconds) <= 30;

        if ((!e.Historical && !e.Record.FileReferenceNumber.HasValue || isFreshUsnDelete) &&
            !string.IsNullOrWhiteSpace(e.Record.FullPath) &&
            e.Record.NtfsDataSnapshot?.IsComplete != true)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS immediate live path triggered: path={e.Record.FullPath}, " +
                $"historyTime={e.Record.DeletedAtUtc:O}, " +
                $"historical={e.Historical}, " +
                $"fileRef={e.Record.FileReferenceNumber?.ToString() ?? "(unknown)"}, " +
                $"knownSize={e.Record.FileSizeBytes?.ToString("N0") ?? "(unknown)"}.");

            await attmp(e);
        }

        if (!e.Historical && !wasExisting && !_settings.NotificationsMuted)
        {
            _uiContext.Post(_ =>
            {
                if (!_exiting && !_settings.NotificationsMuted)
                {
                    ShowDeletionNotification(e.Record);
                }
            }, null);
        }
    }

    private void ShowDeletionNotification(DeletionRecord record)
    {
        _notificationForm?.Close();

        _notificationForm = new DeletionNotificationForm(record, () =>
        {
            _settings.NotificationsMuted = true;
            _settings.Save();
            _notificationsMenuItem.Checked = false;
        });

        _notificationForm.FormClosed += (_, _) =>
        {
            _notificationForm?.Dispose();
            _notificationForm = null;
        };

        _notificationForm.Show();
    }

    private void OnMonitorStatusChanged(object? sender, string message)
    {
        _uiContext.Post(_ =>
        {
            _trayIcon.Text = "AlgoLassi File Recovery";
            if (_mainForm is not null && !_mainForm.IsDisposed)
            {
                _mainForm.SetMonitorStatus(message);
            }
        }, null);
    }

    private void ExitApplication()
    {
        if (_exiting)
        {
            return;
        }

        _exiting = true;
        _monitor.Stop();
        _usnMonitor.Stop();
        _recycleBinMonitor.Stop();
        _notificationForm?.Close();

        if (_mainForm is not null && !_mainForm.IsDisposed)
        {
            _mainForm.CloseFromApplication();
        }

        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        _menu.Dispose();
        _monitor.Dispose();
        _usnMonitor.Dispose();
        _recycleBinMonitor.Dispose();

        ExitThread();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_exiting)
        {
            ExitApplication();
        }

        base.Dispose(disposing);
    }
}
