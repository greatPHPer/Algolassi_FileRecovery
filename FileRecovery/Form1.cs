namespace FileRecovery;

public partial class Form1 : Form
{
    private sealed record RecoveryItemDescriptor(
        string Name,
        string OriginalLocation,
        string DeletedDate,
        string Size);


    private readonly DeletionHistoryStore _history;
    private readonly RecycleBinService _recycleBinService;
    private readonly MftCandidateScanner _mftCandidateScanner = new();
    private readonly NtfsByteRecoveryService _ntfsRecoveryService = new();
    private bool _allowClose;
    private bool _refreshInProgress;
    private bool _historyRefreshPending;
    private bool _suppressDirectorySelectionChanged;
    private bool _suppressGridSelectionChanged;

    public void CloseFromApplication()
    {
        _allowClose = true;
        Close();
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
            QueueHistoryRefresh();
            return;
        }

        if (_refreshInProgress)
        {
            return;
        }

        _refreshInProgress = true;
        try
        {
            var directories = _history.GetRecentDirectories();
            var selected = lstDirectories.SelectedItem as string;

            _suppressDirectorySelectionChanged = true;
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
                        if (string.Equals(
                            lstDirectories.Items[i]?.ToString(),
                            selected,
                            StringComparison.OrdinalIgnoreCase))
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
                _suppressDirectorySelectionChanged = false;
            }

            // Rebind the grid once per refresh. The directory selection event above
            // is intentionally suppressed so it cannot trigger a second rebind.
            ShowHistoryRows();
        }
        finally
        {
            _refreshInProgress = false;
        }
    }

    private void QueueHistoryRefresh()
    {
        if (IsDisposed || _historyRefreshPending)
        {
            return;
        }

        _historyRefreshPending = true;

        BeginInvoke(new Action(() =>
        {
            _historyRefreshPending = false;

            if (!IsDisposed)
            {
                RefreshFromHistory();
            }
        }));
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

        var statusText = "Monitoring status: " + message;
        if (string.Equals(lblStatus.Text, statusText, StringComparison.Ordinal))
        {
            return;
        }

        lblStatus.Text = statusText;
    }

    private void History_Changed(object? sender, EventArgs e)
    {
        QueueHistoryRefresh();
    }

    private void lstDirectories_SelectedIndexChanged(object? sender, EventArgs e)
    {
        if (_suppressDirectorySelectionChanged)
        {
            return;
        }

        ShowHistoryRows();
    }

    private void btnShowHistory_Click(object? sender, EventArgs e)
    {
        ShowHistoryRows();
    }

    private void ShowHistoryRows()
    {
        if (IsDisposed)
        {
            return;
        }

        var selectedDirectory = GetSelectedDirectory();
        var selectedHistoryIds = dgvResults.SelectedRows
            .Cast<DataGridViewRow>()
            .Select(row => (row.DataBoundItem as RecoveryDisplayRow)?.HistoryId)
            .Where(id => id.HasValue)
            .Select(id => id!.Value)
            .ToHashSet();

        Guid? firstVisibleHistoryId = null;
        var previousFirstVisibleRow = -1;

        if (dgvResults.RowCount > 0 && dgvResults.FirstDisplayedScrollingRowIndex >= 0)
        {
            previousFirstVisibleRow = dgvResults.FirstDisplayedScrollingRowIndex;
            firstVisibleHistoryId =
                (dgvResults.Rows[previousFirstVisibleRow].DataBoundItem as RecoveryDisplayRow)?.HistoryId;
        }

        var records = _history.GetRecent()
            .Where(record => selectedDirectory is null ||
                             IsDirectoryMatch(record.DirectoryPath, selectedDirectory))
            .Select(record => new RecoveryDisplayRow
            {
                HistoryId = record.Id,
                Name = record.FileName,
                DeletedOn = record.DeletedAtUtc.ToLocalTime().ToString("g"),
                FileSize = record.FileSizeBytes.HasValue
                    ? FormatSize(record.FileSizeBytes.Value)
                    : "Unknown",
                RecoveryStrength = record.RecoveryStrength
            })
            .ToList();

        _suppressGridSelectionChanged = true;
        try
        {
            SuspendLayout();
            dgvResults.SuspendLayout();
            try
            {
                dgvResults.DataSource = records;
                dgvResults.ClearSelection();

                if (selectedHistoryIds.Count > 0)
                {
                    foreach (DataGridViewRow row in dgvResults.Rows)
                    {
                        if (row.DataBoundItem is RecoveryDisplayRow displayRow &&
                            displayRow.HistoryId.HasValue &&
                            selectedHistoryIds.Contains(displayRow.HistoryId.Value))
                        {
                            row.Selected = true;
                        }
                    }
                }

                // Restore the same logical viewport after rebinding. Using the row's
                // history ID keeps the user's position even when new records are
                // inserted at the top of the history list.
                var restoredFirstVisibleRow = -1;

                if (firstVisibleHistoryId.HasValue)
                {
                    foreach (DataGridViewRow row in dgvResults.Rows)
                    {
                        if (row.DataBoundItem is RecoveryDisplayRow displayRow &&
                            displayRow.HistoryId == firstVisibleHistoryId.Value)
                        {
                            restoredFirstVisibleRow = row.Index;
                            break;
                        }
                    }
                }

                if (restoredFirstVisibleRow < 0 &&
                    previousFirstVisibleRow >= 0 &&
                    dgvResults.RowCount > 0)
                {
                    restoredFirstVisibleRow =
                        Math.Min(previousFirstVisibleRow, dgvResults.RowCount - 1);
                }

                if (restoredFirstVisibleRow >= 0 &&
                    restoredFirstVisibleRow < dgvResults.RowCount)
                {
                    dgvResults.FirstDisplayedScrollingRowIndex = restoredFirstVisibleRow;
                }

                lblFiles.Text = $"Deleted files ({records.Count:N0})";
            }
            finally
            {
                dgvResults.ResumeLayout();
                ResumeLayout(true);
            }
        }
        finally
        {
            _suppressGridSelectionChanged = false;
        }

        // Apply the final button state once, after the grid has finished binding.
        UpdateRecoverButton();
    }

    private async void btnScanDirectory_Click(object? sender, EventArgs e)
    {
        var selectedDirectory = GetSelectedDirectory();

        SetBusy(true, "Scanning the Windows Recycle Bin for matching deleted items...");

        try
        {
            var items = await RunInStaAsync(() => _recycleBinService.Scan());

            var filtered = items
                .Where(item => selectedDirectory is null ||
                               IsDirectoryMatch(item.OriginalLocation, selectedDirectory))
                .Select(item => new RecoveryDisplayRow
                {
                    Name = item.Name,
                    DeletedOn = item.DeletedDate,
                    FileSize = item.Size,
                    RecoveryStrength = "Strong",
                    Evidence = $"Windows Recycle Bin item; original location: {item.OriginalLocation}",
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



    private async void btnScanNtfs_Click(object? sender, EventArgs e)
    {
        var selectedDirectory = GetSelectedDirectory();
        var root = selectedDirectory is null
            ? GetDefaultNtfsRoot()
            : Path.GetPathRoot(selectedDirectory);

        if (string.IsNullOrWhiteSpace(root))
        {
            MessageBox.Show(
                this,
                "Select a recent deletion directory first, or record a deletion so the source volume can be identified.",
                "NTFS Scan",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        var answer = MessageBox.Show(
            this,
            $"Scan the NTFS volume {root} for deleted-file metadata candidates? This reads filesystem metadata only and does not write to the source volume.",
            "NTFS Deleted-File Scan",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (answer != DialogResult.Yes)
        {
            return;
        }

        SetBusy(true, $"Scanning NTFS deleted-file metadata on {root}...");
        try
        {
            var candidates = await Task.Run(() => _mftCandidateScanner.Scan(root));

            var filtered = candidates
                .Where(candidate =>
                    selectedDirectory is null ||
                    string.IsNullOrWhiteSpace(candidate.DirectoryPath) ||
                    IsDirectoryMatch(candidate.DirectoryPath, selectedDirectory))
                .Select(candidate => new RecoveryDisplayRow
                {
                    Name = candidate.Name,
                    DeletedOn = candidate.LastUsnTimestampUtc.ToLocalTime().ToString("g"),
                    FileSize = candidate.DataStreamFound
                        ? FormatSize(candidate.FileSizeBytes)
                        : "Unknown",
                    RecoveryStrength = candidate.Strength.ToString(),
                    Evidence = BuildCandidateEvidence(candidate),
                    RecoveryCandidate = candidate
                })
                .ToList();

            dgvResults.DataSource = filtered;
            lblFiles.Text = $"NTFS candidates ({filtered.Count:N0})";
            lblStatus.Text = filtered.Count == 0
                ? "No deleted-file metadata candidates were returned for this volume."
                : $"Found {filtered.Count:N0} deleted-file metadata candidate(s). No file contents were recovered yet.";
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show(
                this,
                "NTFS deleted-file enumeration requires administrator privileges on this system. Run AlgoLassi File Recovery as Administrator for this scan.",
                "Administrator Access Required",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            lblStatus.Text = "NTFS scan requires administrator privileges.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                ex.Message,
                "NTFS Scan Failed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            lblStatus.Text = "NTFS scan failed.";
        }
        finally
        {
            SetBusy(false);
            UpdateRecoverButton();
        }
    }

    private static string BuildCandidateEvidence(RecoveryCandidate candidate)
    {
        var parts = new List<string>();

        if (!string.IsNullOrWhiteSpace(candidate.DataEvidence))
        {
            parts.Add(candidate.DataEvidence);
        }

        if (!string.IsNullOrWhiteSpace(candidate.DirectoryPath))
        {
            parts.Add($"Parent: {candidate.DirectoryPath}");
        }

        return parts.Count == 0
            ? candidate.Evidence
            : string.Join(" ", parts);
    }

    private string? GetDefaultNtfsRoot()
    {
        var firstDirectory = _history.GetRecentDirectories().FirstOrDefault();
        return string.IsNullOrWhiteSpace(firstDirectory)
            ? null
            : Path.GetPathRoot(firstDirectory);
    }

    private async void btnRecover_Click(object? sender, EventArgs e)
    {
        var rows = dgvResults.SelectedRows
            .Cast<DataGridViewRow>()
            .Select(row => row.DataBoundItem as RecoveryDisplayRow)
            .Where(row => row is not null)
            .Cast<RecoveryDisplayRow>()
            .ToList();

        if (rows.Count == 0)
        {
            return;
        }

        var candidates = rows
            .Where(row => row.RecoveryCandidate is not null)
            .Select(row => row.RecoveryCandidate!)
            .ToList();

        var recycleItems = rows
            .Where(row => row.RecoverableItem is not null)
            .Select(row => row.RecoverableItem!)
            .ToList();

        if (candidates.Count > 0 && recycleItems.Count > 0)
        {
            MessageBox.Show(
                this,
                "Select either NTFS candidates or Windows Recycle Bin items, not both at once.",
                "Recovery Selection",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (candidates.Count > 0)
        {
            await RecoverNtfsCandidatesAsync(candidates);
            return;
        }

        if (recycleItems.Count > 0)
        {
            await RestoreRecycleBinItemsAsync(recycleItems);
            return;
        }

        // History rows contain only the persisted deletion record. Resolve the
        // selected record against the current Recycle Bin before attempting restore.
        await RestoreHistoryRowsAsync(rows);
    }

    private async Task RestoreHistoryRowsAsync(IReadOnlyList<RecoveryDisplayRow> rows)
    {
        var selectedIds = rows
            .Select(row => row.HistoryId)
            .Where(id => id.HasValue)
            .Select(id => id!.Value)
            .ToHashSet();

        if (selectedIds.Count == 0)
        {
            MessageBox.Show(
                this,
                "The selected row is not currently associated with a recoverable item.",
                "Recovery Selection",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        var historyRecords = _history.GetRecent()
            .Where(record => selectedIds.Contains(record.Id))
            .ToList();

        var selectedItems = await RunInStaAsync(() =>
        {
            var availableItems = _recycleBinService.Scan();

            return historyRecords
                .Select(record =>
                {
                    var expectedFullPath = NormalizePath(record.FullPath);
                    return availableItems.FirstOrDefault(item =>
                        string.Equals(
                            NormalizePath(Path.Combine(item.OriginalLocation, item.Name)),
                            expectedFullPath,
                            StringComparison.OrdinalIgnoreCase));
                })
                .Where(item => item is not null)
                .Cast<RecoveryItem>()
                .ToList();
        });

        if (selectedItems.Count == 0)
        {
            MessageBox.Show(
                this,
                "The selected deleted file is no longer available in the Windows Recycle Bin.",
                "Recovery Selection",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (selectedItems.Count != historyRecords.Count)
        {
            MessageBox.Show(
                this,
                $"Only {selectedItems.Count:N0} of {historyRecords.Count:N0} selected history item(s) are currently available in the Windows Recycle Bin.",
                "Recovery Selection",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        await RestoreRecycleBinItemsAsync(selectedItems);
    }

    private async Task RecoverNtfsCandidatesAsync(IReadOnlyList<RecoveryCandidate> candidates)
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Choose a recovery destination on a different drive or volume from the deleted files.",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true
        };

        if (dialog.ShowDialog(this) != DialogResult.OK ||
            string.IsNullOrWhiteSpace(dialog.SelectedPath))
        {
            return;
        }

        var destinationDirectory = dialog.SelectedPath;
        SetBusy(true, "Recovering selected deleted-file data to the chosen destination...");

        try
        {
            var result = await Task.Run(() =>
            {
                var failures = new List<string>();
                var successes = new List<RecoveryResult>();

                foreach (var candidate in candidates)
                {
                    try
                    {
                        successes.Add(_ntfsRecoveryService.Recover(
                            candidate,
                            destinationDirectory));
                    }
                    catch (Exception ex)
                    {
                        failures.Add($"{candidate.Name}: {ex.Message}");
                    }
                }

                return (successes, failures);
            });

            if (result.failures.Count > 0)
            {
                var message = $"Recovered: {result.successes.Count:N0}" +
                              Environment.NewLine +
                              $"Failed: {result.failures.Count:N0}" +
                              Environment.NewLine +
                              Environment.NewLine +
                              string.Join(Environment.NewLine, result.failures.Take(8));

                MessageBox.Show(
                    this,
                    message,
                    "NTFS Recovery Results",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
            else
            {
                MessageBox.Show(
                    this,
                    $"Recovered {result.successes.Count:N0} item(s) to:{Environment.NewLine}{destinationDirectory}",
                    "NTFS Recovery Results",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }

            lblStatus.Text = result.failures.Count == 0
                ? $"Recovered {result.successes.Count:N0} NTFS item(s) to the selected destination."
                : $"Recovered {result.successes.Count:N0} NTFS item(s); {result.failures.Count:N0} item(s) failed.";
        }
        finally
        {
            SetBusy(false);
            UpdateRecoverButton();
        }
    }

    private async Task RestoreRecycleBinItemsAsync(IReadOnlyList<RecoveryItem> items)
    {
        var answer = MessageBox.Show(
            this,
            $"Restore {items.Count:N0} selected item(s) to their original Windows locations?",
            "Confirm Restore",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (answer != DialogResult.Yes)
        {
            return;
        }

        // Keep Shell COM objects on the same worker thread that creates them.
        // The RecoveryItem instances shown in the grid were created during an
        // earlier background scan and must not be invoked from another apartment.
        var selectedItems = items
            .Select(item => new RecoveryItemDescriptor(
                item.Name,
                item.OriginalLocation,
                item.DeletedDate,
                item.Size))
            .ToList();

        SetBusy(true, "Restoring selected items...");

        try
        {
            var failures = await RunInStaAsync(() =>
            {
                var restoreFailures = new List<string>();
                var availableItems = _recycleBinService.Scan();

                foreach (var selected in selectedItems)
                {
                    try
                    {
                        var match = availableItems.FirstOrDefault(item =>
                            string.Equals(item.Name, selected.Name, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(item.OriginalLocation, selected.OriginalLocation, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(item.DeletedDate, selected.DeletedDate, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(item.Size, selected.Size, StringComparison.OrdinalIgnoreCase));

                        if (match is null)
                        {
                            throw new InvalidOperationException(
                                "The selected Recycle Bin item is no longer available.");
                        }

                        var destinationPath = GetRecycleBinRestorePath(match);
                        if (File.Exists(destinationPath) || Directory.Exists(destinationPath))
                        {
                            throw new InvalidOperationException(
                                $"Cannot restore because the original destination already exists:{Environment.NewLine}{destinationPath}{Environment.NewLine}{Environment.NewLine}" +
                                "Rename or move the existing item first, then try Recover Selected again.");
                        }

                        _recycleBinService.Restore(match);
                    }
                    catch (Exception ex)
                    {
                        restoreFailures.Add($"{selected.Name}: {ex.Message}");
                    }
                }

                return restoreFailures;
            });

            if (failures.Count == 0)
            {
                lblStatus.Text = $"Restored {items.Count:N0} item(s).";
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
        }
        finally
        {
            SetBusy(false);
            UpdateRecoverButton();
        }

        if (!IsDisposed)
        {
            await Task.Yield();
            if (!IsDisposed)
            {
                btnScanDirectory.PerformClick();
            }
        }
    }
    private static string GetRecycleBinRestorePath(RecoveryItem item)
    {
        if (string.IsNullOrWhiteSpace(item.OriginalLocation) ||
            item.OriginalLocation.Equals("(Unavailable)", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Windows did not provide the original location for this Recycle Bin item.");
        }

        return Path.Combine(item.OriginalLocation, item.Name);
    }

    private static Task<T> RunInStaAsync<T>(Func<T> action)
    {
        ArgumentNullException.ThrowIfNull(action);

        var completion = new TaskCompletionSource<T>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var thread = new Thread(() =>
        {
            try
            {
                completion.SetResult(action());
            }
            catch (Exception ex)
            {
                completion.SetException(ex);
            }
        })
        {
            IsBackground = true,
            Name = "AlgoLassi File Recovery - Shell STA"
        };

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        return completion.Task;
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
    }

    private void dgvResults_SelectionChanged(object? sender, EventArgs e)
    {
        if (_suppressGridSelectionChanged)
        {
            return;
        }

        UpdateRecoverButton();
    }

    private void UpdateRecoverButton()
    {
        var rows = dgvResults.SelectedRows
            .Cast<DataGridViewRow>()
            .Select(row => row.DataBoundItem as RecoveryDisplayRow)
            .Where(row => row is not null)
            .Cast<RecoveryDisplayRow>()
            .ToList();

        var hasCandidates = rows.Any(row => row.RecoveryCandidate is not null);
        var hasRecycleItems = rows.Any(row => row.RecoverableItem is not null);

        btnRecover.Enabled = !IsBusy
            && rows.Count > 0
            && !(hasCandidates && hasRecycleItems);
    }

    private void SetBusy(bool busy, string? status = null)
    {
        lstDirectories.Enabled = !busy;
        btnScanDirectory.Enabled = !busy;
        btnShowHistory.Enabled = !busy;
        btnClearHistory.Enabled = !busy;
        btnScanNtfs.Enabled = !busy;
        dgvResults.Enabled = true;
        btnRecover.Enabled = !busy && btnRecover.Enabled;
        UseWaitCursor = false;

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
}
