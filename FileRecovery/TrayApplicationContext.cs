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
        _menu.Items.Add(_notificationsMenuItem);
        _menu.Items.Add(new ToolStripSeparator());
        _menu.Items.Add("Exit", null, (_, _) => ExitApplication());

        _trayIcon = new NotifyIcon
        {
            Icon = SystemIcons.Application,
            Text = "AlgoLassi File Recovery",
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

    private async void OnDeletionDetected(object? sender, DeletionDetectedEventArgs e)
    {
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

        if (!e.Historical &&
            !e.Record.FileReferenceNumber.HasValue &&
            !string.IsNullOrWhiteSpace(e.Record.FullPath))
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    for (var attempt = 0; attempt < 5; attempt++)
                    {
                        if (_usnMonitor.TryResolveRecentDeletedFile(
                                e.Record.FullPath,
                                e.Record.DeletedAtUtc,
                                out var fileReferenceNumber,
                                out var parentFileReferenceNumber))
                        {
                            e.Record.FileReferenceNumber = fileReferenceNumber;
                            e.Record.ParentFileReferenceNumber = parentFileReferenceNumber;

                            // Upsert merges this enrichment into the existing
                            // watcher-created history row.
                            await Task.Run(() => _history.Upsert(e.Record));
                            return;
                        }

                        if (attempt < 4)
                        {
                            await Task.Delay(250);
                        }
                    }
                }
                catch
                {
                    // USN enrichment is best-effort; the original deletion
                    // history row must remain available.
                }
            });
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
