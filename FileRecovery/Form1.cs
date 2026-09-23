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
    private readonly UsnJournalMonitor _usnMonitor;
    private readonly MftCandidateScanner _mftCandidateScanner = new();
    private readonly NtfsByteRecoveryService _ntfsRecoveryService = new();
    private bool _allowClose;
    private bool _refreshInProgress;
    private bool _historyRefreshPending;
    private bool _suppressDirectorySelectionChanged;
    private bool _suppressGridSelectionChanged;
    private bool _operationInProgress;

    public void CloseFromApplication()
    {
        _allowClose = true;
        Close();
    }

    public Form1(
        DeletionHistoryStore history,
        RecycleBinService recycleBinService,
        UsnJournalMonitor usnMonitor)
    {
        _history = history;
        _recycleBinService = recycleBinService;
        _usnMonitor = usnMonitor;

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

    private void btnSkipRecycleBin_Click(object? sender, EventArgs e)
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

        var historyRows = rows
            .Where(row => row.HistoryId.HasValue)
            .ToList();

        if (historyRows.Count != rows.Count)
        {
            MessageBox.Show(
                this,
                "Skip Recycle Bin is available for deletion history rows only.",
                "Recovery Selection",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        _ = RestoreHistoryRowsAsync(historyRows, skipRecycleBin: true);
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

        var historyRows = rows
            .Where(row => row.HistoryId.HasValue)
            .ToList();

        var candidates = rows
            .Where(row => row.RecoveryCandidate is not null)
            .Select(row => row.RecoveryCandidate!)
            .ToList();

        var recycleItems = rows
            .Where(row => row.RecoverableItem is not null)
            .Select(row => row.RecoverableItem!)
            .ToList();

        // History rows are resolved separately because they do not carry a live
        // Recycle Bin object or an NTFS candidate.
        if (historyRows.Count > 0)
        {
            if (historyRows.Count != rows.Count)
            {
                MessageBox.Show(
                    this,
                    "Select either history rows or live recovery results, not both at once.",
                    "Recovery Selection",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            await RestoreHistoryRowsAsync(historyRows);
            return;
        }

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
        }
    }

    private async Task<List<DeletionRecord>> ResolveMissingNtfsReferencesAsync(
        IReadOnlyList<DeletionRecord> records)
    {
        var resolved = new List<DeletionRecord>();

        foreach (var record in records)
        {
            if (record.FileReferenceNumber.HasValue &&
                record.ParentFileReferenceNumber.HasValue)
            {
                continue;
            }

            // Do not perform a recovery-time journal enumeration here. The
            // background USN monitor already caches recent deletion records.
            // Give that monitor a short window to observe the deletion, then
            // let the bounded raw MFT fallback handle anything still unresolved.
            for (var attempt = 0; attempt < 5; attempt++)
            {
                if (_usnMonitor.TryResolveCachedRecentDeletedFile(
                        record.FullPath,
                        record.DeletedAtUtc,
                        out var fileReferenceNumber,
                        out var parentFileReferenceNumber))
                {
                    record.FileReferenceNumber = fileReferenceNumber;
                    record.ParentFileReferenceNumber = parentFileReferenceNumber;
                    resolved.Add(record);
                    break;
                }

                if (attempt < 4)
                {
                    await Task.Delay(250).ConfigureAwait(true);
                }
            }
        }

        foreach (var record in resolved)
        {
            await Task.Run(() => _history.Upsert(record)).ConfigureAwait(true);
        }

        return resolved;
    }

    private async Task RestoreHistoryRowsAsync(
        IReadOnlyList<RecoveryDisplayRow> rows,
        bool skipRecycleBin = false)
    {
        try
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
                    "The selected row is not currently associated with a recoverable history record.",
                    "Recovery Selection",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            var historyRecords = _history.GetRecent()
                .Where(record => selectedIds.Contains(record.Id))
                .ToList();

            if (historyRecords.Count == 0)
            {
                MessageBox.Show(
                    this,
                    "The selected deletion history record could not be found.",
                    "Recovery Selection",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            Dictionary<Guid, RecoveryItem> recycleResolution = [];
            List<DeletionRecord> missingRecords;

            if (skipRecycleBin)
            {
                SetBusy(
                    true,
                    "Skipping the Windows Recycle Bin and going directly to NTFS recovery...");

                missingRecords = historyRecords;
            }
            else
            {
                // First try the normal Windows Recycle Bin path. This covers ordinary
                // Delete operations where the item was sent to the Recycle Bin.
                SetBusy(
                    true,
                    "Checking the Windows Recycle Bin for the selected deleted file...");

                var recycleResolutionTask = RunInStaAsync(() =>
                {
                    var availableItems = _recycleBinService.Scan();
                    var matches = new Dictionary<Guid, RecoveryItem>();

                    foreach (var record in historyRecords)
                    {
                        var expectedFullPath = NormalizePath(record.FullPath);

                        var match = availableItems.FirstOrDefault(item =>
                            string.Equals(
                                NormalizePath(Path.Combine(item.OriginalLocation, item.Name)),
                                expectedFullPath,
                                StringComparison.OrdinalIgnoreCase));

                        if (match is not null)
                        {
                            matches[record.Id] = match;
                        }
                    }

                    return matches;
                });

                // Shell automation must never hold Recover Selected indefinitely.
                // Keep the timeout decision off the WinForms synchronization context.
                var recycleOutcome = await ResolveRecycleBinMatchesWithTimeoutAsync(
                    recycleResolutionTask);

                recycleResolution = recycleOutcome.Matches;

                if (recycleOutcome.TimedOut)
                {
                    lblStatus.Text =
                        "Recycle Bin lookup timed out after 15 seconds; continuing with NTFS recovery.";
                }
                else if (recycleOutcome.Error is not null)
                {
                    lblStatus.Text =
                        $"Recycle Bin lookup failed ({recycleOutcome.Error.GetType().Name}); continuing with NTFS recovery.";
                }

                missingRecords = historyRecords
                    .Where(record => !recycleResolution.ContainsKey(record.Id))
                    .ToList();
            }

            var recycleItems = historyRecords
                .Where(record => recycleResolution.ContainsKey(record.Id))
                .Select(record => recycleResolution[record.Id])
                .ToList();

            if (missingRecords.Count == 0)
            {
                await RestoreRecycleBinItemsAsync(recycleItems);
                return;
            }

            SetBusy(true, "Searching NTFS metadata for Shift+Delete deleted-file data...");

            // Items that were deleted with Shift+Delete do not exist in the Recycle
            // Bin. Search the NTFS MFT for retained metadata/data-stream evidence.
            var ntfsCandidates = new List<RecoveryCandidate>();
            var unavailable = new List<DeletionRecord>();

            foreach (var group in missingRecords.GroupBy(
                         record => Path.GetPathRoot(record.FullPath),
                         StringComparer.OrdinalIgnoreCase))
            {
                var root = group.Key;
                if (string.IsNullOrWhiteSpace(root))
                {
                    unavailable.AddRange(group);
                    continue;
                }

                try
                {
                    // The FileSystemWatcher row is persisted immediately, while
                    // USN enrichment happens in the background. Re-check missing
                    // NTFS references here before treating the deletion as legacy.
                    var unresolvedReferenceRecords = group
                        .Where(record =>
                            !record.FileReferenceNumber.HasValue ||
                            !record.ParentFileReferenceNumber.HasValue)
                        .ToList();

                    if (unresolvedReferenceRecords.Count > 0)
                    {
                        lblStatus.Text =
                            $"Resolving NTFS references on {root} for {unresolvedReferenceRecords.Count:N0} selected item(s)...";

                        var resolvedRecords = await ResolveMissingNtfsReferencesAsync(
                            unresolvedReferenceRecords);

                        // ResolveMissingNtfsReferencesAsync mutates the matching
                        // records in this grouped list, so the direct/legacy split
                        // below sees the newly resolved references immediately.
                    }

                    var directRecords = group
                        .Where(record =>
                            record.FileReferenceNumber.HasValue &&
                            record.FileReferenceNumber.Value != 0)
                        .ToList();

                    var legacyRecords = group
                        .Where(record =>
                            !record.FileReferenceNumber.HasValue ||
                            !record.ParentFileReferenceNumber.HasValue)
                        .ToList();

                    // Keep the normal raw MFT fallback bounded. The USN re-check
                    // above is performed through the already-running monitor before
                    // legacy scanning is attempted.
                    // A historical lookup can enumerate a large journal and make
                    // Recover Selected appear hung. NTFS references are captured by
                    // the background USN monitor and merged into history separately.
                    if (directRecords.Count > 0)
                    {
                        var directTargets = directRecords
                            .Select(record => (
                                FullPath: NormalizePath(record.FullPath),
                                FileReferenceNumber: record.FileReferenceNumber!.Value,
                                ParentFileReferenceNumber: record.ParentFileReferenceNumber ?? 0,
                                DeletedAtUtc: record.DeletedAtUtc))
                            .ToList();

                        lblStatus.Text =
                            $"Reading exact NTFS MFT records on {root} for {directRecords.Count:N0} selected item(s)...";

                        var directCandidates = await Task.Run(() =>
                            _mftCandidateScanner.ScanForFileReferences(root, directTargets));

                        foreach (var record in directRecords)
                        {
                            var match = directCandidates.FirstOrDefault(candidate =>
                                candidate.FileReferenceNumber == record.FileReferenceNumber!.Value);

                            if (match is not null)
                            {
                                ntfsCandidates.Add(match);
                            }
                            else
                            {
                                unavailable.Add(record);
                            }
                        }
                    }

                    // Older history records may not have an NTFS file reference.
                    // Use the raw $MFT fallback instead of FSCTL_ENUM_USN_DATA. This
                    // scans retained NTFS FILE records directly, so it can also find
                    // deletions that happened before the USN journal existed.
                    if (legacyRecords.Count > 0)
                    {
                        var targetPaths = legacyRecords
                            .Select(record => NormalizePath(record.FullPath))
                            .Where(path => !string.IsNullOrWhiteSpace(path))
                            .Distinct(StringComparer.OrdinalIgnoreCase)
                            .ToList();

                        using var fallbackCts = new CancellationTokenSource(
                            TimeSpan.FromSeconds(20));

                        const long maxFallbackBytes = 512L * 1024L * 1024L;
                        var fallbackProgress = new SynchronousProgress<long>(
                            this,
                            bytesScanned =>
                            {
                                var scannedMb = bytesScanned / (1024d * 1024d);
                                var totalMb = maxFallbackBytes / (1024d * 1024d);
                                lblStatus.Text =
                                    $"Scanning the NTFS $MFT on {root}: {scannedMb:0} / {totalMb:0} MB for {legacyRecords.Count:N0} selected item(s)...";
                            });

                        lblStatus.Text =
                            $"Scanning the NTFS $MFT directly on {root} (up to 512 MB) for {legacyRecords.Count:N0} selected item(s)...";

                        var fallbackCandidates =
                            await _mftCandidateScanner.ScanRawMftForPathsAsync(
                                root,
                                targetPaths,
                                fallbackCts.Token,
                                maxBytesToScan: maxFallbackBytes,
                                progress: fallbackProgress);

                        foreach (var record in legacyRecords)
                        {
                            var match = fallbackCandidates.FirstOrDefault(candidate =>
                                string.Equals(
                                    NormalizePath(Path.Combine(
                                        candidate.DirectoryPath ?? string.Empty,
                                        candidate.Name)),
                                    NormalizePath(record.FullPath),
                                    StringComparison.OrdinalIgnoreCase));

                            if (match is not null)
                            {
                                ntfsCandidates.Add(match);
                            }
                            else
                            {
                                unavailable.Add(record);
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    lblStatus.Text = $"NTFS recovery access denied on {root}: {ex.Message}";

                    MessageBox.Show(
                        this,
                        $"NTFS recovery for {root} requires administrator privileges or the SeBackupPrivilege could not be enabled.{Environment.NewLine}{Environment.NewLine}{ex.Message}",
                        "Administrator Access Required",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    return;
                }
                catch (OperationCanceledException)
                {
                    lblStatus.Text = $"NTFS recovery scan timed out on {root}.";
                    MessageBox.Show(
                        this,
                        $"The bounded NTFS recovery scan on {root} was cancelled after its safety time limit. No unbounded filesystem scan was performed.",
                        "NTFS Recovery Timeout",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                    return;
                }
                catch (Exception ex)
                {
                    lblStatus.Text =
                        $"NTFS recovery scan failed on {root}: {ex.GetType().Name}: {ex.Message}";

                    MessageBox.Show(
                        this,
                        $"NTFS recovery scan failed for {root}:{Environment.NewLine}{Environment.NewLine}" +
                        $"{ex.GetType().Name}: {ex.Message}",
                        "NTFS Recovery Scan Failed",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return;
                }
            }

            if (recycleItems.Count > 0 && ntfsCandidates.Count > 0)
            {
                MessageBox.Show(
                    this,
                    "The selected files contain both Recycle Bin items and Shift+Delete candidates. Recover these groups separately.",
                    "Recovery Selection",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            if (ntfsCandidates.Count > 0)
            {
                await RecoverNtfsCandidatesAsync(ntfsCandidates);
                return;
            }

            if (unavailable.Count > 0)
            {
                var missingNtfsReferenceCount = unavailable.Count(
                    record => !record.FileReferenceNumber.HasValue);

                var referenceDetail = missingNtfsReferenceCount > 0
                    ? $"{Environment.NewLine}{Environment.NewLine}" +
                      $"{missingNtfsReferenceCount:N0} selected history item(s) do not contain an NTFS file reference. " +
                      "They were recorded before the direct NTFS reference tracking was available (or USN monitoring was not active)."
                    : string.Empty;

                MessageBox.Show(
                    this,
                    $"The selected deleted file(s) were not found in the Recycle Bin and no usable NTFS recovery candidate is currently available.{referenceDetail}{Environment.NewLine}{Environment.NewLine}" +
                    "For Shift+Delete files, recovery depends on the NTFS metadata and data clusters still being intact.",
                    "Recovery Not Available",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            await RestoreRecycleBinItemsAsync(recycleItems);
        }
        finally
        {
            if (!IsDisposed)
            {
                SetBusy(false);
                UpdateRecoverButton();
            }
        }
    }
    
    private static async Task<(
        Dictionary<Guid, RecoveryItem> Matches,
        bool TimedOut,
        Exception? Error)> ResolveRecycleBinMatchesWithTimeoutAsync(
            Task<Dictionary<Guid, RecoveryItem>> recycleResolutionTask)
    {
        var timeoutTask = Task.Delay(TimeSpan.FromSeconds(15));

        var completed = await Task.WhenAny(
                recycleResolutionTask,
                timeoutTask)
            .ConfigureAwait(false);

        if (completed != recycleResolutionTask)
        {
            return ([], true, null);
        }

        try
        {
            return (await recycleResolutionTask.ConfigureAwait(false), false, null);
        }
        catch (Exception ex)
        {
            // A failed or unavailable Shell lookup must not block Shift+Delete
            // recovery. Continue with the NTFS path instead, but expose the
            // failure stage to the Recovery Center status text.
            return ([], false, ex);
        }
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
        var allHistoryRows = rows.Count > 0 &&
                             rows.All(row => row.HistoryId.HasValue);

        btnRecover.Enabled = !_operationInProgress
            && rows.Count > 0
            && !(hasCandidates && hasRecycleItems);

        btnSkipRecycleBin.Enabled = !_operationInProgress
            && allHistoryRows;
    }

    private void SetBusy(bool busy, string? status = null)
    {
        _operationInProgress = busy;

        lstDirectories.Enabled = !busy;
        btnSkipRecycleBin.Enabled = !busy && dgvResults.SelectedRows.Count > 0 &&
                                    dgvResults.SelectedRows
                                        .Cast<DataGridViewRow>()
                                        .Select(row => row.DataBoundItem as RecoveryDisplayRow)
                                        .Where(row => row is not null)
                                        .Cast<RecoveryDisplayRow>()
                                        .All(row => row.HistoryId.HasValue);
        btnScanDirectory.Enabled = !busy;
        btnShowHistory.Enabled = !busy;
        btnClearHistory.Enabled = !busy;
        btnScanNtfs.Enabled = !busy;
        dgvResults.Enabled = true;
        UseWaitCursor = false;

        if (!string.IsNullOrWhiteSpace(status))
        {
            lblStatus.Text = status;
        }

        // Always calculate Recover Selected from the actual current selection.
        // Never preserve the button's previous Enabled value as state.
        UpdateRecoverButton();
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

    private bool IsBusy => _operationInProgress;

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
public sealed class SynchronousProgress<T>(Control control, Action<T> handler) : IProgress<T>
{
    public void Report(T value)
    {
        if (control.IsHandleCreated && !control.IsDisposed)
        {
            control.Invoke(() => handler(value));
        }
    }
}
