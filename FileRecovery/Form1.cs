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
    private readonly NtfsDeepFileRecoveryService _ntfsDeepFileRecoveryService = new();
    private readonly NtfsWholeVolumeTextRecoveryService _ntfsWholeVolumeTextRecoveryService = new();
    private bool _allowClose;
    private bool _refreshInProgress;
    private bool _historyRefreshPending;
    private bool _suppressDirectorySelectionChanged;
    private bool _suppressGridSelectionChanged;
    private bool _operationInProgress;
    private bool _ntfsResultsDisplayed;
    private bool _ntfsScanInProgress;
    private CancellationTokenSource? _ntfsScanCancellationSource;

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
        if (IsDisposed || _historyRefreshPending || _ntfsResultsDisplayed || _ntfsScanInProgress)
        {
            return;
        }

        _historyRefreshPending = true;

        BeginInvoke(new Action(() =>
        {
            _historyRefreshPending = false;

            if (!IsDisposed &&
                !_ntfsResultsDisplayed &&
                !_ntfsScanInProgress)
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

        var selectedDirectory = GetSelectedDirectory();
        if (!string.IsNullOrWhiteSpace(selectedDirectory))
        {
            txtScanPath.Text = selectedDirectory;
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

        _ntfsResultsDisplayed = false;

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



    private async void btnRawVolumeMarker_Click(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Select the live text file to verify against the raw volume",
            Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        var marker = Microsoft.VisualBasic.Interaction.InputBox(
            "Enter the exact marker text that is currently inside the selected file.",
            "Raw volume marker diagnostic",
            "");

        if (string.IsNullOrWhiteSpace(marker))
        {
            return;
        }

        SetBusy(true, "Testing the raw NTFS volume for the live file marker...");

        try
        {
            var root = Path.GetPathRoot(dialog.FileName);
            if (string.IsNullOrWhiteSpace(root))
            {
                throw new InvalidOperationException(
                    "The selected file is not on a valid Windows volume.");
            }

            var totalVolumeBytes = new DriveInfo(root).TotalSize;
            var progress = new SynchronousProgress<long>(
                this,
                bytesScanned =>
                {
                    lblStatus.Text =
                        $"Raw volume marker test... " +
                        $"{bytesScanned / (1024d * 1024d * 1024d):0.00} / " +
                        $"{totalVolumeBytes / (1024d * 1024d * 1024d):0.00} GB scanned";
                });

            var result =
                _ntfsWholeVolumeTextRecoveryService.FindMarkerOnVolume(
                    dialog.FileName,
                    marker,
                    CancellationToken.None,
                    progress);

            if (result.Found)
            {
                MessageBox.Show(
                    this,
                    $"Marker FOUND in the raw E: volume.\r\n\r\n" +
                    $"Encoding: {result.Encoding}\r\n" +
                    $"Byte offset: {result.Offset:N0}\r\n" +
                    $"Scanned: {result.ScannedBytes:N0} bytes",
                    "Raw Volume Marker Test",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show(
                    this,
                    $"Marker was NOT found in the raw NTFS volume.\r\n\r\n" +
                    $"Scanned: {result.ScannedBytes:N0} bytes",
                    "Raw Volume Marker Test",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                ex.Message,
                "Raw Volume Marker Test Failed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void btnBrowseScanPath_Click(object? sender, EventArgs e)
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Select the directory whose deleted NTFS files you want to scan.",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = false
        };

        var currentPath = txtScanPath.Text.Trim();
        if (Directory.Exists(currentPath))
        {
            dialog.SelectedPath = currentPath;
        }

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            txtScanPath.Text = dialog.SelectedPath;
            lstDirectories.SelectedIndex = -1;
        }
    }

    private async void btnScanNtfs_Click(object? sender, EventArgs e)
    {
        var scanDirectory = NormalizePath(txtScanPath.Text);

        if (string.IsNullOrWhiteSpace(scanDirectory))
        {
            var selectedDirectory = GetSelectedDirectory();
            if (!string.IsNullOrWhiteSpace(selectedDirectory))
            {
                scanDirectory = NormalizePath(selectedDirectory);
                txtScanPath.Text = scanDirectory;
            }
        }

        if (string.IsNullOrWhiteSpace(scanDirectory) ||
            !Directory.Exists(scanDirectory))
        {
            MessageBox.Show(
                this,
                "Select an existing directory with Browse... before starting the NTFS deleted-file scan.",
                "NTFS Scan",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        var root = Path.GetPathRoot(scanDirectory);
        if (string.IsNullOrWhiteSpace(root))
        {
            MessageBox.Show(
                this,                "The selected directory is not on a valid Windows volume.",
                "NTFS Scan",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var includeSubdirectories = chkScanSubdirectories.Checked;

        var answer = MessageBox.Show(
            this,
            $"Scan deleted NTFS metadata under:\r\n\r\n{scanDirectory}\r\n\r\n" +
            (includeSubdirectories
                ? "Include all subdirectories."
                : "Scan this directory only, not its subdirectories.") +
            "\r\n\r\nThis reads filesystem metadata only and does not write to the source volume.",
            "NTFS Deleted-File Scan",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (answer != DialogResult.Yes)
        {
            return;
        }

        _ntfsScanInProgress = true;
        using var ntfsScanCancellationSource = new CancellationTokenSource();
        _ntfsScanCancellationSource = ntfsScanCancellationSource;
        var scanCancellationToken = ntfsScanCancellationSource.Token;

        SetBusy(
            true,
            $"Scanning deleted NTFS metadata under {scanDirectory}...");

        try
        {
            var deletedRecords = await Task.Run(
                () => _usnMonitor.ScanDeletedDirectory(
                    scanDirectory,
                    includeSubdirectories,
                    scanCancellationToken),
                scanCancellationToken);

            // The background monitor can observe a deletion immediately while this
            // on-demand historical journal reconstruction can still miss that same
            // event because parent-path resolution is timing-sensitive. First repair
            // any history rows under the selected directory that still lack the exact
            // NTFS references, then use the recent subset for live-evidence annotation.
            var recentHistoryCutoffUtc = DateTime.UtcNow.AddMinutes(-15);
            var historyRecords = _history.GetRecent()
                .Where(record =>
                    IsDirectoryMatch(record.DirectoryPath, scanDirectory))
                .OrderByDescending(record => record.DeletedAtUtc)
                .ToList();

            // ScanDeletedDirectory() already reconstructs the historical USN journal for
            // the selected directory. If a history row predates this application session,
            // copy the exact historical file/parent reference from that journal result
            // before falling back to the direct journal resolver below. This avoids the
            // old logic where the matching path was excluded from resolution merely because
            // ScanDeletedDirectory() had already seen it.
            var journalMatchesByPath = deletedRecords
                .GroupBy(
                    record => NormalizePath(record.FullPath),
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group
                        .OrderByDescending(record => record.DeletedAtUtc)
                        .ToList(),
                    StringComparer.OrdinalIgnoreCase);

            var journalReferenceMatches = 0;

            foreach (var record in historyRecords)
            {
                scanCancellationToken.ThrowIfCancellationRequested();
                if (record.FileReferenceNumber.HasValue &&
                    record.ParentFileReferenceNumber.HasValue)
                {
                    continue;
                }

                if (!journalMatchesByPath.TryGetValue(
                        NormalizePath(record.FullPath),
                        out var journalMatches))
                {
                    continue;
                }

                var match = journalMatches
                    .OrderBy(candidate =>
                        Math.Abs((candidate.DeletedAtUtc - record.DeletedAtUtc).TotalMinutes))
                    .FirstOrDefault();

                if (match is null)
                {
                    continue;
                }

                var deltaMinutes = Math.Abs(
                    (match.DeletedAtUtc - record.DeletedAtUtc).TotalMinutes);

                // The journal and persisted history timestamps should describe the same
                // deletion event. Keep the match deliberately narrow so a later deletion
                // of the same path cannot be assigned to an older history row.
                if (deltaMinutes > 5)
                {
                    continue;
                }

                record.FileReferenceNumber = match.FileReferenceNumber;
                record.ParentFileReferenceNumber = match.ParentFileReferenceNumber;
                journalReferenceMatches++;

                await Task.Run(() => _history.Upsert(record)).ConfigureAwait(true);
            }

            System.Diagnostics.Debug.WriteLine(
                $"NTFS historical journal-reference merge: " +
                $"journalRecords={deletedRecords.Count:N0}, " +
                $"historyRows={historyRecords.Count:N0}, " +
                $"resolved={journalReferenceMatches:N0}.");

            var historyNeedingResolution = historyRecords
                .Where(record =>
                    !record.FileReferenceNumber.HasValue ||
                    !record.ParentFileReferenceNumber.HasValue)
                .ToList();

            if (historyNeedingResolution.Count > 0)
            {
                await ResolveMissingNtfsReferencesAsync(historyNeedingResolution, scanCancellationToken);
            }

            historyRecords = _history.GetRecent()
                .Where(record =>
                    IsDirectoryMatch(record.DirectoryPath, scanDirectory))
                .OrderByDescending(record => record.DeletedAtUtc)
                .ToList();

            var recentHistoryRecords = historyRecords
                .Where(record =>
                    record.DeletedAtUtc >= recentHistoryCutoffUtc &&
                    record.FileReferenceNumber.HasValue)
                .ToList();

            var historyRecordsWithReferences = historyRecords
                .Where(record =>
                    record.FileReferenceNumber.HasValue &&
                    record.ParentFileReferenceNumber.HasValue)
                .ToList();

            var recentLiveUsnDeletes = _usnMonitor.GetRecentDeletedFiles(
                scanDirectory,
                includeSubdirectories,
                TimeSpan.FromMinutes(15));

            var rootPath = Path.GetPathRoot(scanDirectory)!;

            var targetRecords = deletedRecords
                .Select(record => (
                    record.FullPath,
                    record.FileReferenceNumber,
                    record.ParentFileReferenceNumber,
                    record.DeletedAtUtc))
                .ToList();

            var targetPaths = targetRecords
                .Select(target => NormalizePath(target.FullPath))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var mergedLiveHistoryCount = 0;
            var mergedLiveUsnCount = 0;

            foreach (var record in recentLiveUsnDeletes)
            {
                scanCancellationToken.ThrowIfCancellationRequested();
                var normalizedPath = NormalizePath(record.FullPath);
                if (!targetPaths.Add(normalizedPath))
                {
                    continue;
                }

                targetRecords.Add((
                    record.FullPath,
                    record.FileReferenceNumber,
                    record.ParentFileReferenceNumber,
                    record.DeletedAtUtc));

                mergedLiveUsnCount++;
            }

            foreach (var record in historyRecordsWithReferences)
            {
                scanCancellationToken.ThrowIfCancellationRequested();
                var normalizedPath = NormalizePath(record.FullPath);
                if (!targetPaths.Add(normalizedPath))
                {
                    continue;
                }

                targetRecords.Add((
                    record.FullPath,
                    record.FileReferenceNumber!.Value,
                    record.ParentFileReferenceNumber!.Value,
                    record.DeletedAtUtc));

                mergedLiveHistoryCount++;
            }

            if (mergedLiveHistoryCount > 0 || mergedLiveUsnCount > 0)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS scan merged deletion references: usnCache={mergedLiveUsnCount:N0}, " +
                    $"history={mergedLiveHistoryCount:N0}.");
            }
            else
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS scan deletion-reference merge: usnCache={recentLiveUsnDeletes.Count:N0}, " +
                    $"historyReferences={historyRecordsWithReferences.Count:N0}, none merged.");
            }

            var recentTargetRecordsByPath = recentHistoryRecords
                .Select(record => (
                    FullPath: NormalizePath(record.FullPath),
                    DeletedAtUtc: record.DeletedAtUtc))
                .Concat(
                    recentLiveUsnDeletes.Select(record => (
                        FullPath: NormalizePath(record.FullPath),
                        DeletedAtUtc: record.DeletedAtUtc)))
                .GroupBy(
                    target => target.FullPath,
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group
                        .OrderByDescending(target => target.DeletedAtUtc)
                        .First(),
                    StringComparer.OrdinalIgnoreCase);

            var directLiveCandidates = new List<RecoveryCandidate>();

            if (recentTargetRecordsByPath.Count > 0)
            {
                try
                {
                    // A recent deletion can be present in history before its exact
                    // file reference is enriched. Query the current MFT/USN view by
                    // exact path for only those recent targets. The timestamp guard
                    // prevents an unrelated older deletion of the same path from
                    // being promoted.
                    var pathCandidates = await Task.Run(
                        () => _mftCandidateScanner.ScanForPaths(
                            rootPath,
                            recentTargetRecordsByPath.Keys.ToList(),
                            scanCancellationToken,
                            maxPages: 128),
                        scanCancellationToken);

                    directLiveCandidates = pathCandidates
                        .Where(candidate =>
                            recentTargetRecordsByPath.TryGetValue(
                                NormalizePath(candidate.FullPath),
                                out var target) &&
                            (target.DeletedAtUtc == default ||
                             candidate.LastUsnTimestampUtc == default ||
                             Math.Abs(
                                 (candidate.LastUsnTimestampUtc - target.DeletedAtUtc)
                                     .TotalMinutes) <= 5))
                        .ToList();

                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS live path lookup: requested={recentTargetRecordsByPath.Count:N0}, " +
                        $"scannedCandidates={pathCandidates.Count:N0}, " +
                        $"timestampTrusted={directLiveCandidates.Count:N0}.");
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS live path lookup failed: {ex.GetType().Name}: {ex.Message}");
                }
            }

            var candidates = (await Task.Run(
                    () => _mftCandidateScanner.ScanForFileReferences(
                        rootPath,
                        targetRecords,
                        scanCancellationToken),
                    scanCancellationToken))
                .ToList();

            var candidatePaths = candidates
                .Select(candidate => NormalizePath(candidate.FullPath))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var directCandidate in directLiveCandidates)
            {
                if (candidatePaths.Add(NormalizePath(directCandidate.FullPath)))
                {
                    candidates.Add(directCandidate);
                }
            }

            var missingDataCandidates = candidates
                .Where(candidate => !candidate.DataStreamFound)
                .ToList();

            var missingDataPaths = missingDataCandidates
                .Select(candidate => candidate.FullPath)
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (missingDataPaths.Count > 0)
            {
                lblStatus.Text =
                    $"Found {candidates.Count:N0} candidate(s); exhaustively scanning the NTFS $MFT for retained deleted records ({missingDataPaths.Count:N0} item(s))...";

                var fallbackCandidates =
                    await _mftCandidateScanner.ScanRawMftForPathsAsync(
                        rootPath,
                        missingDataPaths,
                        scanCancellationToken,
                        maxBytesToScan: long.MaxValue,
                        targetReferences: missingDataCandidates
                            .Where(candidate => candidate.FileReferenceNumber != 0)
                            .Select(candidate => (
                                FullPath: candidate.FullPath,
                                FileReferenceNumber: candidate.FileReferenceNumber,
                                ParentFileReferenceNumber: candidate.ParentFileReferenceNumber,
                                DeletedAtUtc: candidate.LastUsnTimestampUtc))
                            .ToList());

                if (fallbackCandidates.Count > 0)
                {
                    var fallbackByPath = fallbackCandidates
                        .Where(candidate => candidate.DataStreamFound)
                        .GroupBy(candidate => candidate.FullPath, StringComparer.OrdinalIgnoreCase)
                        .ToDictionary(
                            group => group.Key,
                            group => group.First(),
                            StringComparer.OrdinalIgnoreCase);

                    candidates = candidates
                        .Select(candidate =>
                            candidate.DataStreamFound ||
                            !fallbackByPath.TryGetValue(candidate.FullPath, out var fallback)
                                ? candidate
                                : fallback)
                        .ToList();
                }
            }

            // A live deletion can be observed reliably by AlgoLassi while the
            // application is running even when the original MFT record is already
            // reused, moved to the Recycle Bin, or otherwise no longer matches the
            // historical file-reference sequence. Do not weaken MFT sequence checks
            // to force such a record through. Instead, retain the trusted live event
            // as a metadata-only candidate so the NTFS scan still shows the evidence.
            var liveEvidenceSources = recentHistoryRecords
                .Where(record =>
                    record.FileReferenceNumber.HasValue &&
                    record.ParentFileReferenceNumber.HasValue)
                .Select(record => new
                {
                    FullPath = NormalizePath(record.FullPath),
                    FileReferenceNumber = record.FileReferenceNumber!.Value,
                    ParentFileReferenceNumber = record.ParentFileReferenceNumber!.Value,
                    FileName = record.FileName,
                    DirectoryPath = record.DirectoryPath,
                    DeletedAtUtc = record.DeletedAtUtc
                })
                .Concat(
                    recentLiveUsnDeletes
                        .Where(record =>
                            record.FileReferenceNumber != 0 &&
                            record.ParentFileReferenceNumber != 0)
                        .Select(record => new
                        {
                            FullPath = NormalizePath(record.FullPath),
                            record.FileReferenceNumber,
                            record.ParentFileReferenceNumber,
                            record.FileName,
                            record.DirectoryPath,
                            record.DeletedAtUtc
                        }))
                .GroupBy(
                    source => source.FullPath,
                    StringComparer.OrdinalIgnoreCase)
                .Select(group => group
                    .OrderByDescending(source => source.DeletedAtUtc)
                    .First())
                .ToList();

            var liveEvidenceCandidateCount = 0;

            foreach (var source in liveEvidenceSources)
            {
                scanCancellationToken.ThrowIfCancellationRequested();
                var candidatePath = NormalizePath(source.FullPath);
                if (!candidatePaths.Add(candidatePath))
                {
                    continue;
                }

                var directoryPath = string.IsNullOrWhiteSpace(source.DirectoryPath)
                    ? Path.GetDirectoryName(source.FullPath) ?? string.Empty
                    : NormalizePath(source.DirectoryPath);

                candidates.Add(new RecoveryCandidate
                {
                    FileReferenceNumber = source.FileReferenceNumber,
                    ParentFileReferenceNumber = source.ParentFileReferenceNumber,
                    Name = source.FileName,
                    DirectoryPath = directoryPath,
                    LastUsnTimestampUtc = source.DeletedAtUtc,
                    Strength = RecoveryStrength.Weak,
                    Evidence =
                        "AlgoLassi observed this deletion while the application was running, " +
                        "but the current NTFS MFT record could not be safely matched to the " +
                        "historical file reference.",
                    DataStreamFound = false,
                    DataEvidence =
                        "No current NTFS $DATA stream was retained under the original " +
                        "file reference. The file may have been moved to the Recycle Bin, " +
                        "its MFT entry may have been reused, or its deleted metadata may " +
                        "no longer be available.",
                });

                liveEvidenceCandidateCount++;
            }

            System.Diagnostics.Debug.WriteLine(
                $"NTFS live evidence candidates: added={liveEvidenceCandidateCount:N0}, " +
                $"trustedSources={liveEvidenceSources.Count:N0}, totalCandidates={candidates.Count:N0}.");

            // A metadata-only candidate may have a valid historical deletion
            // record with the original byte length even though its current MFT $DATA
            // stream is gone. Carry that size into the candidate so exact-size deep
            // carving can be attempted for formats such as plain text.
            foreach (var candidate in candidates.Where(candidate => candidate.FileSizeBytes <= 0))
            {
                // Prefer the exact historical MFT file reference because the current
                // candidate path can differ in formatting (for example, \\?\\ prefixes)
                // or can point at a reused MFT record whose current name/path is no
                // longer the deleted file's original path. Fall back to the canonical
                // path match only when no exact historical reference match is available.
                var referenceMatch = candidate.FileReferenceNumber != 0
                    ? historyRecords
                        .Where(record =>
                            record.FileReferenceNumber.HasValue &&
                            record.FileReferenceNumber.Value == candidate.FileReferenceNumber &&
                            record.FileSizeBytes.HasValue)
                        .OrderBy(record =>
                            Math.Abs(
                                (record.DeletedAtUtc - candidate.LastUsnTimestampUtc)
                                    .TotalMinutes))
                        .FirstOrDefault()
                    : null;

                var sizeMatch = referenceMatch ?? historyRecords
                    .Where(record =>
                        record.FileSizeBytes.HasValue &&
                        string.Equals(
                            NormalizeForComparison(record.FullPath),
                            NormalizeForComparison(candidate.FullPath),
                            StringComparison.OrdinalIgnoreCase))
                    .OrderBy(record =>
                        Math.Abs(
                            (record.DeletedAtUtc - candidate.LastUsnTimestampUtc)
                                .TotalMinutes))
                    .FirstOrDefault();

                if (sizeMatch?.FileSizeBytes is long knownSize &&
                    knownSize > 0 &&
                    (candidate.LastUsnTimestampUtc == default ||
                     Math.Abs(
                         (sizeMatch.DeletedAtUtc - candidate.LastUsnTimestampUtc)
                             .TotalMinutes) <= 5))
                {
                    candidate.FileSizeBytes = knownSize;

                    var matchKind = referenceMatch is not null
                        ? "file-reference"
                        : "path";

                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS candidate size enrichment: match={matchKind}, " +
                        $"path={candidate.FullPath}, fileRef={candidate.FileReferenceNumber}, " +
                        $"size={knownSize:N0} bytes.");
                }
                else if (candidate.FileSizeBytes <= 0 &&
                         candidate.FileReferenceNumber != 0 &&
                         candidate.ParentFileReferenceNumber != 0)
                {
                    var historicalMftReader = new NtfsMftDataReader();

                    if (historicalMftReader.TryReadHistoricalFileNameSize(
                        rootPath,
                        candidate.FileReferenceNumber,
                        candidate.ParentFileReferenceNumber,
                        candidate.Name,
                        out var historicalSize) &&
                        historicalSize > 0)
                    {
                        candidate.FileSizeBytes = historicalSize;

                        System.Diagnostics.Debug.WriteLine(
                            $"NTFS candidate size enrichment: match=historical-$FILE_NAME, " +
                            $"path={candidate.FullPath}, fileRef={candidate.FileReferenceNumber}, " +
                            $"size={historicalSize:N0} bytes.");
                    }
                }
            }

            var liveHistoryByPath = recentHistoryRecords
                .Where(record => record.FileReferenceNumber.HasValue)
                .GroupBy(
                    record => NormalizePath(record.FullPath),
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group.First(),
                    StringComparer.OrdinalIgnoreCase);

            var filtered = candidates
                .Select(candidate =>
                {
                    liveHistoryByPath.TryGetValue(
                        NormalizePath(candidate.FullPath),
                        out var liveHistory);

                    var evidence = BuildCandidateEvidence(candidate);

                    if (liveHistory is not null)
                    {
                        evidence = string.Join(
                            " ",
                            new[]
                            {
                                evidence,
                                "Live deletion history: AlgoLassi observed this deletion while the application was running."
                            }.Where(text => !string.IsNullOrWhiteSpace(text)));
                    }
                    else if (recentTargetRecordsByPath.ContainsKey(NormalizePath(candidate.FullPath)))
                    {
                        evidence = string.Join(
                            " ",
                            new[]
                            {
                                evidence,
                                "Recent deletion evidence: the current NTFS/MFT view matched a deletion recorded by AlgoLassi within the last 15 minutes."
                            }.Where(text => !string.IsNullOrWhiteSpace(text)));
                    }

                    return new RecoveryDisplayRow
                    {
                        Name = candidate.Name,
                        DeletedOn = candidate.LastUsnTimestampUtc.ToLocalTime().ToString("g"),
                        FileSize = candidate.DataStreamFound
                            ? FormatSize(candidate.FileSizeBytes)
                            : liveHistory?.FileSizeBytes is long historySize
                                ? FormatSize(historySize)
                                : "Unknown",
                        RecoveryStrength = candidate.Strength.ToString(),
                        Evidence = evidence,
                        RecoveryCandidate = candidate
                    };
                })
                .ToList();

            _suppressGridSelectionChanged = true;
            try
            {
                dgvResults.DataSource = null;
                dgvResults.Rows.Clear();
                dgvResults.DataSource = filtered;
                dgvResults.ClearSelection();
                dgvResults.Refresh();
            }
            finally
            {
                _suppressGridSelectionChanged = false;
            }

            _ntfsResultsDisplayed = true;
            lblFiles.Text = $"NTFS candidates ({filtered.Count:N0})";
            lblStatus.Text = filtered.Count == 0
                ? $"No deleted-file metadata candidates were found under {scanDirectory}."
                : mergedLiveHistoryCount > 0 ||
                  mergedLiveUsnCount > 0 ||
                  directLiveCandidates.Count > 0 ||
                  liveEvidenceCandidateCount > 0
                    ? $"Found {filtered.Count:N0} deleted-file candidate(s) under {scanDirectory}; " +
                      $"{mergedLiveUsnCount + mergedLiveHistoryCount + directLiveCandidates.Count + liveEvidenceCandidateCount:N0} recent live deletion evidence item(s) were included."
                    : $"Found {filtered.Count:N0} deleted-file candidate(s) under {scanDirectory}.";
        }
        catch (OperationCanceledException) when (_ntfsScanCancellationSource?.IsCancellationRequested == true)
        {
            _ntfsResultsDisplayed = false;
            lblStatus.Text = "NTFS scan stopped by user.";
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
            _ntfsScanCancellationSource = null;
            _ntfsScanInProgress = false;
            SetBusy(false);
            UpdateRecoverButton();
        }
    }

    private void btnStopNtfsScan_Click(object? sender, EventArgs e)
    {
        if (!_ntfsScanInProgress || _ntfsScanCancellationSource is null)
        {
            return;
        }

        if (!_ntfsScanCancellationSource.IsCancellationRequested)
        {
            lblStatus.Text = "Stopping NTFS deleted-file scan...";
            btnStopNtfsScan.Enabled = false;
            _ntfsScanCancellationSource.Cancel();
        }
    }

    private static string NormalizeForComparison(string path)
    {
        var normalized = NormalizePath(path);

        while (normalized.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }

        while (normalized.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }

        return normalized;
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

    private async void btnSkipRecycleBin_Click(object? sender, EventArgs e)
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

        var ntfsRows = rows
            .Where(row => row.RecoveryCandidate is not null)
            .ToList();

        // In NTFS deleted-files-scan mode the item has already bypassed
        // the Windows Recycle Bin, so "Skip Recycle Bin" acts as the
        // direct NTFS recovery action for the selected candidates.
        if (ntfsRows.Count == rows.Count)
        {
            await RecoverNtfsCandidatesAsync(
                ntfsRows
                    .Select(row => row.RecoveryCandidate!)
                    .ToList());
            return;
        }

        if (historyRows.Count == rows.Count)
        {
            await RestoreHistoryRowsAsync(historyRows, skipRecycleBin: true);
            return;
        }

        MessageBox.Show(
            this,
            "Select either deletion-history items or NTFS deleted-file candidates, not a mixture of both.",
            "Recovery Selection",
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
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
        IReadOnlyList<DeletionRecord> records,
        CancellationToken cancellationToken = default)
    {
        var resolved = new List<DeletionRecord>();
        var unresolved = new List<DeletionRecord>();
        var recentCutoffUtc = DateTime.UtcNow.AddMinutes(-15);

        foreach (var record in records)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (record.FileReferenceNumber.HasValue &&
                record.ParentFileReferenceNumber.HasValue)
            {
                continue;
            }

            var resolvedFromLiveMonitor = false;

            // Fresh deletions are first given a short opportunity to resolve from
            // the monitor/cache path. Historical journal scanning is only used when
            // that live path cannot resolve the record.
            if (record.DeletedAtUtc == default ||
                record.DeletedAtUtc >= recentCutoffUtc)
            {
                for (var attempt = 0; attempt < 5; attempt++)
                {
                    if (_usnMonitor.TryResolveRecentDeletedFileBounded(
                            record.FullPath,
                            record.DeletedAtUtc,
                            out var fileReferenceNumber,
                            out var parentFileReferenceNumber))
                    {
                        record.FileReferenceNumber = fileReferenceNumber;
                        record.ParentFileReferenceNumber = parentFileReferenceNumber;
                        resolved.Add(record);
                        resolvedFromLiveMonitor = true;
                        break;
                    }

                    if (attempt < 4)
                    {
                        await Task.Delay(200, cancellationToken).ConfigureAwait(true);
                    }
                }
            }

            if (!resolvedFromLiveMonitor)
            {
                unresolved.Add(record);
            }
        }

        // A deletion that happened before this application session cannot be in the
        // in-memory USN cache. Resolve all remaining history rows in one journal pass
        // instead of rescanning the entire journal separately for every file.
        if (unresolved.Count > 0)
        {
            var targets = unresolved
                .Select(record => (record.FullPath, record.DeletedAtUtc))
                .ToList();

            var historicalMatches = await Task.Run(
                    () => _usnMonitor.ResolveHistoricalDeletionsFromJournal(
                        targets,
                        scanCancellationToken))
                .ConfigureAwait(true);

            var matchesByPath = historicalMatches
                .GroupBy(
                    match => NormalizePath(match.FullPath),
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group
                        .OrderByDescending(match => match.DeletedAtUtc)
                        .First(),
                    StringComparer.OrdinalIgnoreCase);

            foreach (var record in unresolved)
            {
                if (!matchesByPath.TryGetValue(
                        NormalizePath(record.FullPath),
                        out var match))
                {
                    continue;
                }

                record.FileReferenceNumber = match.FileReferenceNumber;
                record.ParentFileReferenceNumber = match.ParentFileReferenceNumber;
                resolved.Add(record);
            }

            System.Diagnostics.Debug.WriteLine(
                $"NTFS historical reference resolution: requested={unresolved.Count:N0}, " +
                $"resolved={historicalMatches.Count:N0}, " +
                $"stillMissing={unresolved.Count - resolved.Count:N0}.");
        }

        foreach (var record in resolved)
        {
            cancellationToken.ThrowIfCancellationRequested();
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
                            !string.IsNullOrWhiteSpace(item.OriginalLocation) &&
                            !item.OriginalLocation.Equals(
                                "(Unavailable)",
                                StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(
                                NormalizePath(Path.Combine(item.OriginalLocation, item.Name)),
                                expectedFullPath,
                                StringComparison.OrdinalIgnoreCase));

                        if (match is null)
                        {
                            // Fallback only when Shell does not expose the original
                            // location. Name + deletion metadata is less precise,
                            // so use it only after the path-based match fails.
                            match = availableItems.FirstOrDefault(item =>
                                string.Equals(item.Name, record.FileName, StringComparison.OrdinalIgnoreCase) &&
                                string.Equals(item.DeletedDate, record.DeletedAtUtc.ToLocalTime().ToString("g"), StringComparison.OrdinalIgnoreCase));
                        }

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

                        var directCandidates =
                            _mftCandidateScanner.ScanForFileReferences(root, directTargets);

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

    private async Task<(List<RecoveryResult> successes, List<string> failures)> recvr(
        IReadOnlyList<RecoveryCandidate> candidates,
        string? destinationDirectory)
    {
        var failures = new List<string>();
        var successes = new List<RecoveryResult>();
        var forensicMarkers = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var forensicMarkerDeclined = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(destinationDirectory))
        {
            failures.Add("Recovery destination was not selected.");
            return (successes, failures);
        }

        foreach (var candidate in candidates)
        {
            try
            {
                if (candidate.DataStreamFound)
                {
                    successes.Add(_ntfsRecoveryService.Recover(
                        candidate,
                        destinationDirectory));
                    continue;
                }

                // A fresh deletion can leave the resident $DATA stream in the
                // normal MFT record even when the regular data-stream lookup did not
                // promote that record to DataStreamFound. Try that source before
                // historical slack or free-space carving.
                if (candidate.FileReferenceNumber != 0 &&
                    candidate.ParentFileReferenceNumber != 0)
                {
                    var freshMftReader = new NtfsMftDataReader();

                    if (freshMftReader.TryReadResidentDataForDeletedReference(
                        candidate.FullPath,
                        candidate.FileReferenceNumber,
                        candidate.ParentFileReferenceNumber,
                        candidate.Name,
                        candidate.FullPath,
                        out var freshResidentData) &&
                        freshResidentData.Length > 0)
                    {
                        var destinationPath =
                            RecoveryDestinationPolicy.CreateSafeFilePath(
                                destinationDirectory,
                                candidate.Name);

                        try
                        {
                            File.WriteAllBytes(destinationPath, freshResidentData);
                        }
                        catch
                        {
                            try
                            {
                                File.Delete(destinationPath);
                            }
                            catch
                            {
                                // Preserve the original recovery failure.
                            }

                            throw;
                        }

                        candidate.FileSizeBytes = freshResidentData.Length;

                        successes.Add(new RecoveryResult
                        {
                            Success = true,
                            SourcePath = candidate.FullPath,
                            DestinationPath = destinationPath,
                            BytesRecovered = freshResidentData.Length,
                            Evidence =
                                $"Recovered {freshResidentData.Length:N0} byte(s) from the " +
                                "resident $DATA stream retained in the deleted file's MFT " +
                                "record. The filename and parent reference were validated " +
                                "against the deleted-file reference."
                        });

                        continue;
                    }
                }

                // A reused MFT segment can still retain the deleted file's resident
                // $DATA attribute in record slack. Try that forensic source before
                // scanning free clusters, especially for tiny files whose original
                // content was probably resident.
                if (candidate.FileReferenceNumber != 0 &&
                    candidate.ParentFileReferenceNumber != 0)
                {
                    var historicalMftReader = new NtfsMftDataReader();

                    if (historicalMftReader.TryReadHistoricalResidentData(
                        candidate.FullPath,
                        candidate.FileReferenceNumber,
                        candidate.ParentFileReferenceNumber,
                        candidate.Name,
                        out var historicalData,
                        out var usedHeuristicHistoricalEvidence) &&
                        historicalData.Length > 0)
                    {
                        var destinationPath =
                            RecoveryDestinationPolicy.CreateSafeFilePath(
                                destinationDirectory,
                                candidate.Name);

                        try
                        {
                            File.WriteAllBytes(destinationPath, historicalData);
                        }
                        catch
                        {
                            try
                            {
                                File.Delete(destinationPath);
                            }
                            catch
                            {
                                // Preserve the original recovery failure.
                            }

                            throw;
                        }

                        candidate.FileSizeBytes = historicalData.Length;

                        successes.Add(new RecoveryResult
                        {
                            Success = true,
                            SourcePath = candidate.FullPath,
                            DestinationPath = destinationPath,
                            BytesRecovered = historicalData.Length,
                            Evidence = usedHeuristicHistoricalEvidence
                                ? $"Recovered {historicalData.Length:N0} byte(s) from " +
                                  "historical resident $DATA retained in reused MFT record " +
                                  "slack. The exact historical filename was found near a " +
                                  "plausible resident $DATA attribute; the parent reference " +
                                  "could not be structurally validated, so this result is " +
                                  "heuristic."
                                : $"Recovered {historicalData.Length:N0} byte(s) from " +
                                  "historical resident $DATA retained in the reused MFT " +
                                  "record's slack. The source was matched by historical " +
                                  "file name and parent reference; the current MFT sequence " +
                                  "was not treated as the deleted file."
                        });

                        continue;
                    }
                }

                // Before broad free-space carving, inspect slack in currently
                // allocated files under the deleted file's original directory.
                // This can retain fragments of recently deleted small text files
                // after their clusters were reallocated, without scanning/reading
                // the active file bodies as candidate data.
                var slackRootPath = GetSourceVolumeRoot(candidate.FullPath);
                var slackDirectory = candidate.DirectoryPath;
                if (string.IsNullOrWhiteSpace(slackDirectory))
                {
                    slackDirectory = Path.GetDirectoryName(candidate.FullPath);
                }

                if (!string.IsNullOrWhiteSpace(slackDirectory) &&
                    Directory.Exists(slackDirectory))
                {
                    var slackReader = new NtfsMftDataReader();

                    if (!string.IsNullOrWhiteSpace(slackRootPath) &&
                        slackReader.TryReadAllocatedFileSlack(
                        slackRootPath,
                        slackDirectory,
                        Path.GetExtension(candidate.Name),
                        long.MaxValue,
                        progress: null,
                        cancellationToken: scanCancellationToken,
                        out var slackData,
                        out var slackSourceFile) &&
                        slackData.Length > 0)
                    {
                        var destinationPath =
                            RecoveryDestinationPolicy.CreateSafeFilePath(
                                destinationDirectory,
                                candidate.Name);

                        try
                        {
                            File.WriteAllBytes(destinationPath, slackData);
                        }
                        catch
                        {
                            try
                            {
                                File.Delete(destinationPath);
                            }
                            catch
                            {
                                // Preserve the original recovery failure.
                            }

                            throw;
                        }

                        candidate.FileSizeBytes = slackData.Length;

                        successes.Add(new RecoveryResult
                        {
                            Success = true,
                            SourcePath = candidate.FullPath,
                            DestinationPath = destinationPath,
                            BytesRecovered = slackData.Length,
                            Evidence =
                                $"Recovered {slackData.Length:N0} byte(s) from allocated " +
                                $"file slack in '{slackSourceFile}'. The bytes were found " +
                                "after the current file's logical EOF, so this is heuristic " +
                                "evidence of retained deleted data rather than an exact " +
                                "historical file-identity match."
                        });

                        continue;
                    }
                }

                // Plain-text files do not contain a reliable end marker.
                // Prefer an exact size already known from NTFS/history. When no trusted
                // size is available, use a user-supplied unique content marker for a
                // forensic whole-volume search. Never guess a file boundary by selecting
                // an arbitrary large text-like region elsewhere on the volume.
                if (!candidate.DataStreamFound &&
                    Path.GetExtension(candidate.Name).Equals(
                        ".txt",
                        StringComparison.OrdinalIgnoreCase))
                {
                    Exception? exactSizeFailure = null;

                    if (candidate.FileSizeBytes > 0)
                    {
                        try
                        {
                            var exactProgress = new SynchronousProgress<long>(
                                this,
                                bytesScanned =>
                                {
                                    lblStatus.Text =
                                        $"Exact-size text recovery for {candidate.Name}... " +
                                        $"{bytesScanned / (1024d * 1024d * 1024d):0.00} GB free space scanned";
                                });

                            exactProgress.Report(0);

                            var exactRecovery = _ntfsDeepFileRecoveryService.Recover(
                                candidate,
                                destinationDirectory,
                                scanCancellationToken,
                                NtfsDeepFileRecoveryService.DefaultMaxBytesToScan,
                                exactProgress,
                                candidate.FileSizeBytes);

                            successes.Add(exactRecovery);
                            continue;
                        }
                        catch (Exception ex)
                        {
                            exactSizeFailure = ex;

                            System.Diagnostics.Debug.WriteLine(
                                $"Exact-size text recovery failed for {candidate.FullPath}: {ex.Message}");
                        }
                    }

                    var markerKey = NormalizePath(candidate.FullPath);
                    var enteredMarker = Microsoft.VisualBasic.Interaction.InputBox(
                        $"The original size of '{candidate.Name}' could not be recovered from NTFS metadata.\r\n\r\n" +
                        "Enter a unique text string that was definitely contained in the deleted file. " +
                        "AlgoLassi will search the entire raw source volume for that marker.\r\n\r\n" +
                        "This mode is forensic/heuristic: plain-text files do not contain a reliable " +
                        "file boundary, so the result may be only a partial fragment.\r\n\r\n" +
                        "Leave this blank to stop recovery for this file.",
                        "Forensic text marker",
                        "");

                    if (string.IsNullOrWhiteSpace(enteredMarker))
                    {
                        var reason = exactSizeFailure is null
                            ? string.Empty
                            : $" Exact-size recovery failed: {exactSizeFailure.Message}";

                        failures.Add(
                            $"{candidate.Name}: no original size was available and no forensic text marker was supplied.{reason}");
                        continue;
                    }

                    try
                    {
                        var wholeVolumeRoot = GetSourceVolumeRoot(candidate.FullPath);
                        if (string.IsNullOrWhiteSpace(wholeVolumeRoot))
                        {
                            failures.Add(
                                $"{candidate.Name}: the source volume could not be determined for forensic text recovery.");
                            continue;
                        }

                        var totalVolumeBytes = new DriveInfo(wholeVolumeRoot).TotalSize;
                        var forensicProgress = new SynchronousProgress<long>(
                            this,
                            bytesScanned =>
                            {
                                lblStatus.Text =
                                    $"Forensic full-volume text scan for {candidate.Name}... " +
                                    $"{bytesScanned / (1024d * 1024d * 1024d):0.00} / " +
                                    $"{totalVolumeBytes / (1024d * 1024d * 1024d):0.00} GB scanned";
                            });

                        forensicProgress.Report(0);

                        var forensicRecovery = _ntfsWholeVolumeTextRecoveryService.Recover(
                            candidate,
                            destinationDirectory,
                            enteredMarker,
                            scanCancellationToken,
                            forensicProgress);

                        var partialPath = PreserveForensicRecoveryFile(
                            forensicRecovery.DestinationPath,
                            destinationDirectory,
                            candidate.Name);

                        var reason = exactSizeFailure is null
                            ? string.Empty
                            : $" Exact-size recovery failed first: {exactSizeFailure.Message}";

                        failures.Add(
                            $"{candidate.Name}: forensic marker scan recovered " +
                            $"{forensicRecovery.BytesRecovered:N0} byte(s). " +
                            $"This is heuristic/partial evidence, not an exact reconstruction.{reason} " +
                            $"Preserved copy: {partialPath}");

                        continue;
                    }
                    catch (Exception ex)
                    {
                        var reason = exactSizeFailure is null
                            ? string.Empty
                            : $" Exact-size recovery failed first: {exactSizeFailure.Message}";

                        failures.Add(
                            $"{candidate.Name}: forensic marker scan failed: {ex.Message}.{reason}");
                        continue;
                    }
                }

                // If an exact historical size is already known from NTFS metadata,
                // retain the normal structural/free-space carver below.
                // The retained MFT metadata may be insufficient for this candidate,
                // but structural carving can still recover many formats without an
                // original size. Plain text is now handled separately above: exact-size
                // recovery is preferred, while marker-only recovery is explicitly heuristic.
                if (!NtfsDeepFileRecoveryService.SupportsDeepCarving(
                        candidate.Name,
                        candidate.FileSizeBytes))
                {
                    failures.Add(
                        $"{candidate.Name}: deep NTFS carving is not supported for " +
                        $"'{Path.GetExtension(candidate.Name)}'.");
                    continue;
                }

                var maxDeepCarveBytes =
                    NtfsDeepFileRecoveryService.DefaultMaxBytesToScan;

                var carveProgress = new SynchronousProgress<long>(
                    this,
                    bytesScanned =>
                    {
                        var scannedMb = bytesScanned / (1024d * 1024d);

                        lblStatus.Text =
                            maxDeepCarveBytes == long.MaxValue
                                ? $"Deep-scanning all NTFS free space for {candidate.Name}... " +
                                  $"{scannedMb:0} MB scanned"
                                : $"Deep-scanning NTFS free space for {candidate.Name}... " +
                                  $"{scannedMb:0} / " +
                                  $"{maxDeepCarveBytes / (1024d * 1024d):0} MB";
                    });

                carveProgress.Report(0);

                var carved = _ntfsDeepFileRecoveryService.Recover(
                    candidate,
                    destinationDirectory,
                    scanCancellationToken,
                    maxDeepCarveBytes,
                    carveProgress,
                    candidate.FileSizeBytes);

                successes.Add(carved);
            }
            catch (Exception ex)
            {
                failures.Add($"{candidate.Name}: {ex.Message}");
            }
        }

        return (successes, failures);
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
            var result = await recvr(candidates, destinationDirectory);

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
            UpdateRecoverButton();        }
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
                        // The original path + name is the stable identity we used
                        // when the history row was matched to the Recycle Bin. Do not
                        // require Shell-formatted date/size strings to be identical across
                        // two separate Shell.Application enumerations.
                        var expectedPath = NormalizePath(
                            Path.Combine(selected.OriginalLocation, selected.Name));

                        var match = availableItems.FirstOrDefault(item =>
                            string.Equals(
                                NormalizePath(Path.Combine(item.OriginalLocation, item.Name)),
                                expectedPath,
                                StringComparison.OrdinalIgnoreCase));

                        // Some Windows Shell configurations can temporarily omit the
                        // Original location column. Retain a conservative metadata
                        // fallback rather than sending an otherwise recoverable item
                        // into the NTFS deleted-record path.
                        if (match is null)
                        {
                            match = availableItems.FirstOrDefault(item =>
                                string.Equals(item.Name, selected.Name, StringComparison.OrdinalIgnoreCase) &&
                                string.Equals(item.DeletedDate, selected.DeletedDate, StringComparison.OrdinalIgnoreCase) &&
                                string.Equals(item.Size, selected.Size, StringComparison.OrdinalIgnoreCase));
                        }

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
        var allNtfsRows = rows.Count > 0 &&
                          rows.All(row => row.RecoveryCandidate is not null);

        btnRecover.Enabled = !_operationInProgress
            && rows.Count > 0
            && !(hasCandidates && hasRecycleItems);

        btnSkipRecycleBin.Enabled = !_operationInProgress
            && (allHistoryRows || allNtfsRows);
    }

    private void SetBusy(bool busy, string? status = null)
    {
        _operationInProgress = busy;

        lstDirectories.Enabled = !busy;
        var selectedRows = dgvResults.SelectedRows
            .Cast<DataGridViewRow>()
            .Select(row => row.DataBoundItem as RecoveryDisplayRow)
            .Where(row => row is not null)
            .Cast<RecoveryDisplayRow>()
            .ToList();

        var allHistoryRows = selectedRows.Count > 0 &&
                             selectedRows.All(row => row.HistoryId.HasValue);
        var allNtfsRows = selectedRows.Count > 0 &&
                          selectedRows.All(row => row.RecoveryCandidate is not null);

        btnSkipRecycleBin.Enabled = !busy &&
                                    (allHistoryRows || allNtfsRows);
        btnScanDirectory.Enabled = !busy;
        btnShowHistory.Enabled = !busy;
        btnClearHistory.Enabled = !busy;
        btnScanNtfs.Enabled = !busy;
        txtScanPath.Enabled = !busy;
        btnBrowseScanPath.Enabled = !busy;
        chkScanSubdirectories.Enabled = !busy;
        btnStopNtfsScan.Enabled = _ntfsScanInProgress && busy &&
                                  _ntfsScanCancellationSource is not null &&
                                  !_ntfsScanCancellationSource.IsCancellationRequested;
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

    private static string PreserveForensicRecoveryFile(
        string sourcePath,
        string destinationDirectory,
        string originalName)
    {
        if (string.IsNullOrWhiteSpace(sourcePath) ||
            !File.Exists(sourcePath))
        {
            throw new InvalidOperationException(
                "The raw-volume forensic scan did not produce a recoverable output file.");
        }

        var forensicName = $"{originalName}.forensic.partial";
        var destinationPath = RecoveryDestinationPolicy.CreateSafeFilePath(
            destinationDirectory,
            forensicName);

        File.Move(sourcePath, destinationPath);

        return destinationPath;
    }

    private static void TryDeleteRecoveredFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"Could not delete heuristic recovery output '{path}': {ex.Message}");
        }
    }

    private static string? GetSourceVolumeRoot(string path)
    {
        var normalized = path.Trim();

        while (normalized.StartsWith(@"\\?\", StringComparison.Ordinal) ||
               normalized.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }

        var root = Path.GetPathRoot(normalized);

        if (root is { Length: 2 } &&
            root[1] == ':')
        {
            root += Path.DirectorySeparatorChar;
        }

        return root;
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
            control.Invoke(() =>
            {
                handler(value);
                Application.DoEvents();
            });
        }
    }
}