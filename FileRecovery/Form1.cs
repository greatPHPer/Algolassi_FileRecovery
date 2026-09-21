namespace FileRecovery;

public partial class Form1 : Form
{
    private readonly DeletionHistoryStore _history;
    private readonly RecycleBinService _recycleBinService;
    private bool _allowClose;

    public bool AllowClose
    {
        get => _allowClose;
        set => _allowClose = value;
    }

    public Form1(DeletionHistoryStore history, RecycleBinService recycleBinService)
    {
        _history = history;
        _recycleBinService = recycleBinService;

        InitializeComponent();
        _history.Changed += History_Changed;
    }

    private void Form1_Load(object? sender, EventArgs e)
    {
        RefreshFromHistory();
    }

    public void RefreshFromHistory()
    {
        if (IsDisposed)
        {
            return;
        }

        if (InvokeRequired)
        {
            BeginInvoke(RefreshFromHistory);
            return;
        }

        var directories = _history.GetRecentDirectories();
        var selected = lstDirectories.SelectedItem as string;

        lstDirectories.BeginUpdate();
        try
        {
            lstDirectories.Items.Clear();
            lstDirectories.Items.Add("All recent deletions");
            foreach (var directory in directories)
            {
                lstDirectories.Items.Add(directory);
            }

            var preferredIndex = 0;
            if (!string.IsNullOrWhiteSpace(selected))
            {
                for (var i = 0; i < lstDirectories.Items.Count; i++)
                {
                    if (string.Equals(lstDirectories.Items[i]?.ToString(), selected, StringComparison.OrdinalIgnoreCase))
                    {
                        preferredIndex = i;
                        break;
                    }
                }
            }

            lstDirectories.SelectedIndex = preferredIndex;
        }
        finally
        {
            lstDirectories.EndUpdate();
        }

        ShowHistoryRows();
    }

    public void SetMonitorStatus(string message)
    {
        if (IsDisposed)
        {
            return;
        }

        if (InvokeRequired)
        {
            BeginInvoke(() => SetMonitorStatus(message));
            return;
        }

        lblStatus.Text = "Monitoring status: " + message;
    }

    private void History_Changed(object? sender, EventArgs e)
    {
        if (IsDisposed)
        {
            return;
        }

        BeginInvoke(RefreshFromHistory);
    }

    private void lstDirectories_SelectedIndexChanged(object? sender, EventArgs e)
    {
        ShowHistoryRows();
    }

    private void btnShowHistory_Click(object? sender, EventArgs e)
    {
        ShowHistoryRows();
    }

    private void ShowHistoryRows()
    {
        var selectedDirectory = GetSelectedDirectory();

        var records = _history.GetRecent()
            .Where(record => selectedDirectory is null || IsDirectoryMatch(record.DirectoryPath, selectedDirectory))
            .Select(record => new RecoveryDisplayRow
            {
                Name = record.FileName,
                DeletedOn = record.DeletedAtUtc.ToLocalTime().ToString("g"),
                FileSize = record.FileSizeBytes.HasValue ? FormatSize(record.FileSizeBytes.Value) : "Unknown",
                RecoveryStrength = record.RecoveryStrength
            })
            .ToList();

        dgvResults.DataSource = records;
        btnRecover.Enabled = false;
        lblFiles.Text = $"Deleted files ({records.Count:N0})";
    }

    private async void btnScanDirectory_Click(object? sender, EventArgs e)
    {
        var selectedDirectory = GetSelectedDirectory();

        SetBusy(true, "Scanning the Windows Recycle Bin for matching deleted items...");

        try
        {
            var items = await Task.Run(() => _recycleBinService.Scan());

            var filtered = items
                .Where(item => selectedDirectory is null ||
                               IsDirectoryMatch(item.OriginalLocation, selectedDirectory))
                .Select(item => new RecoveryDisplayRow
                {
                    Name = item.Name,
                    DeletedOn = item.DeletedDate,
                    FileSize = item.Size,
                    RecoveryStrength = "Strong",
                    RecoverableItem = item
                })
                .ToList();

            dgvResults.DataSource = filtered;
            lblFiles.Text = $"Recoverable now ({filtered.Count:N0})";
            lblStatus.Text = filtered.Count == 0
                ? "No matching items are currently available in the Windows Recycle Bin."
                : $"Found {filtered.Count:N0} item(s) that Windows can currently restore.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Recycle Bin Scan Failed",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            ShowHistoryRows();
        }
        finally
        {
            SetBusy(false);
            UpdateRecoverButton();
        }
    }

    private void btnRecover_Click(object? sender, EventArgs e)
    {
        var selected = dgvResults.SelectedRows
            .Cast<DataGridViewRow>()
            .Select(row => row.DataBoundItem as RecoveryDisplayRow)
            .Where(row => row?.RecoverableItem is not null)
            .Select(row => row!.RecoverableItem!)
            .ToList();

        if (selected.Count == 0)
        {
            return;
        }

        var answer = MessageBox.Show(
            this,
            $"Restore {selected.Count:N0} selected item(s) to their original Windows locations?",
            "Confirm Restore",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (answer != DialogResult.Yes)
        {
            return;
        }

        SetBusy(true, "Restoring selected items...");

        try
        {
            var failures = new List<string>();

            foreach (var item in selected)
            {
                try
                {
                    _recycleBinService.Restore(item);
                }
                catch (Exception ex)
                {
                    failures.Add($"{item.Name}: {ex.Message}");
                }
            }

            if (failures.Count == 0)
            {
                lblStatus.Text = $"Restored {selected.Count:N0} item(s).";
            }
            else
            {
                MessageBox.Show(
                    this,
                    string.Join(Environment.NewLine, failures.Take(8)),
                    "Some Items Could Not Be Restored",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }

            _ = RefreshScanAsync();
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async Task RefreshScanAsync()
    {
        try
        {
            await Task.Delay(150);
            if (!IsDisposed)
            {
                await InvokeAsync(() => btnScanDirectory_Click(null, EventArgs.Empty));
            }
        }
        catch
        {
            // UI refresh is best-effort.
        }
    }

    private void btnClearHistory_Click(object? sender, EventArgs e)
    {
        var answer = MessageBox.Show(
            this,
            "Clear the recorded deletion history? This does not restore or delete any files.",
            "Clear History",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (answer != DialogResult.Yes)
        {
            return;
        }

        _history.Clear();
        RefreshFromHistory();
    }

    private void dgvResults_SelectionChanged(object? sender, EventArgs e)
    {
        UpdateRecoverButton();
    }

    private void UpdateRecoverButton()
    {
        btnRecover.Enabled = !IsBusy && dgvResults.SelectedRows
            .Cast<DataGridViewRow>()
            .Any(row => row.DataBoundItem is RecoveryDisplayRow { RecoverableItem: not null });
    }

    private void SetBusy(bool busy, string? status = null)
    {
        lstDirectories.Enabled = !busy;
        btnScanDirectory.Enabled = !busy;
        btnShowHistory.Enabled = !busy;
        btnClearHistory.Enabled = !busy;
        dgvResults.Enabled = !busy;
        btnRecover.Enabled = !busy && btnRecover.Enabled;
        UseWaitCursor = busy;

        if (!string.IsNullOrWhiteSpace(status))
        {
            lblStatus.Text = status;
        }
    }

    private string? GetSelectedDirectory()
    {
        var value = lstDirectories.SelectedItem?.ToString();
        return string.IsNullOrWhiteSpace(value) || value == "All recent deletions"
            ? null
            : value;
    }

    private static bool IsDirectoryMatch(string candidate, string directory)
    {
        var left = NormalizePath(candidate).TrimEnd(Path.DirectorySeparatorChar);
        var right = NormalizePath(directory).TrimEnd(Path.DirectorySeparatorChar);

        return string.Equals(left, right, StringComparison.OrdinalIgnoreCase)
            || left.StartsWith(right + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string value) =>
        value.Trim().Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024d:0.#} KB";
        if (bytes < 1024L * 1024L * 1024L) return $"{bytes / (1024d * 1024d):0.#} MB";
        return $"{bytes / (1024d * 1024d * 1024d):0.#} GB";
    }

    private bool IsBusy => !btnScanDirectory.Enabled;

    private void Form1_FormClosing(object? sender, FormClosingEventArgs e)
    {
        if (_allowClose)
        {
            return;
        }

        e.Cancel = true;
        Hide();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _history.Changed -= History_Changed;
        }

        base.Dispose(disposing);
    }
}
