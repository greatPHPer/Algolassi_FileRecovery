namespace FileRecovery;

public partial class Form1 : Form
{
    private sealed record RecoveryItemDescriptor(
        string Name,
        string OriginalLocation,
        string DeletedDate,
        string Size);

    private sealed record DirectoryPathSegment(string Label, string DirectoryPath);

    private readonly DeletionHistoryStore _history;
    private readonly RecycleBinService _recycleBinService;
    private readonly UsnJournalMonitor _usnMonitor;
    private readonly MftCandidateScanner _mftCandidateScanner = new();
    private readonly NtfsByteRecoveryService _ntfsRecoveryService = new();
    private readonly NtfsDeepFileRecoveryService _ntfsDeepFileRecoveryService = new();
    private readonly NtfsWholeVolumeTextRecoveryService _ntfsWholeVolumeTextRecoveryService = new();
    private bool _allowClose;
    private bool _refreshInProgress;
    private int _historyRowsRefreshVersion;
    private bool _historyRefreshPending;
    private bool _suppressDirectorySelectionChanged;
    private bool _suppressGridSelectionChanged;
    private bool _operationInProgress;
    private bool _ntfsResultsDisplayed;
    private bool _ntfsScanInProgress;

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

    private void btnManageIgnoredDirectories_Click(object? sender, EventArgs e)
    {
        using var dialog = new IgnoredDirectoriesForm();
        dialog.ShowDialog(this);
        RefreshFromHistory();
        lblStatus.Text = $"Ignored directory settings loaded ({RecoveryMonitoringExclusions.GetIgnoredDirectories().Count:N0} path(s)).";
    }

    private void lstDirectories_DrawItem(object? sender, DrawItemEventArgs e)
    {
        if (e.Index < 0 || e.Index >= lstDirectories.Items.Count)
        {
            return;
        }

        e.DrawBackground();

        var itemText = lstDirectories.Items[e.Index]?.ToString() ?? string.Empty;
        if (string.Equals(itemText, "All recent deletions", StringComparison.OrdinalIgnoreCase))
        {
            TextRenderer.DrawText(
                e.Graphics,
                itemText,
                e.Font,
                e.Bounds,
                (e.State & DrawItemState.Selected) != 0
                    ? SystemColors.HighlightText
                    : lstDirectories.ForeColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
            e.DrawFocusRectangle();
            return;
        }

        var segments = BuildDirectoryPathSegments(itemText);
        var x = e.Bounds.Left + 4;
        var buttonY = e.Bounds.Top + Math.Max(2, (e.Bounds.Height - 23) / 2);

        foreach (var segment in segments)
        {
            var desiredWidth = GetDirectorySegmentButtonWidth(segment.Label, e.Font);
            if (x >= e.Bounds.Right - 2)
            {
                break;
            }

            var visibleWidth = Math.Min(desiredWidth, e.Bounds.Right - x - 2);
            if (visibleWidth <= 0)
            {
                break;
            }

            var buttonBounds = new Rectangle(x, buttonY, visibleWidth, 23);
            using (var background = new SolidBrush(SystemColors.Control))
            using (var border = new Pen(SystemColors.ControlDark))
            {
                e.Graphics.FillRectangle(background, buttonBounds);
                e.Graphics.DrawRectangle(border, buttonBounds);
            }

            if (visibleWidth > 12)
            {
                var textBounds = Rectangle.Inflate(buttonBounds, -6, 0);
                TextRenderer.DrawText(
                    e.Graphics,
                    segment.Label,
                    e.Font,
                    textBounds,
                    SystemColors.ControlText,
                    TextFormatFlags.HorizontalCenter |
                    TextFormatFlags.VerticalCenter |
                    TextFormatFlags.NoPrefix |
                    TextFormatFlags.EndEllipsis |
                    TextFormatFlags.NoPadding);
            }

            x += desiredWidth;
            if (segment != segments[^1])
            {
                var slashBounds = new Rectangle(x, e.Bounds.Top, 14, e.Bounds.Height);
                TextRenderer.DrawText(
                    e.Graphics,
                    "/",
                    e.Font,
                    slashBounds,
                    (e.State & DrawItemState.Selected) != 0
                        ? SystemColors.HighlightText
                        : lstDirectories.ForeColor,
                    TextFormatFlags.HorizontalCenter |
                    TextFormatFlags.VerticalCenter |
                    TextFormatFlags.NoPrefix);
                x += 14;
            }
        }

        e.DrawFocusRectangle();
    }

    private void lstDirectories_MouseDown(object? sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Left)
        {
            return;
        }

        var index = lstDirectories.IndexFromPoint(e.Location);
        if (index < 0 || index >= lstDirectories.Items.Count)
        {
            return;
        }

        var itemText = lstDirectories.Items[index]?.ToString();
        if (string.IsNullOrWhiteSpace(itemText) ||
            string.Equals(itemText, "All recent deletions", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var segment = FindDirectorySegmentAtX(itemText, e.X);
        if (segment is null)
        {
            return;
        }

        lstDirectories.SelectedIndex = index;

        var menu = new ContextMenuStrip();
        menu.Items.Add(
            "Ignore directory",
            null,
            (_, _) => IgnoreDirectoryFromBreadcrumb(segment.DirectoryPath));

        // WinForms may continue processing the click/close sequence after Closed fires.
        // Disposing synchronously here can make that same sequence access a disposed
        // ContextMenuStrip and throw ObjectDisposedException. Dispose on the next UI turn.
        menu.Closed += (_, _) =>
        {
            if (!lstDirectories.IsDisposed && lstDirectories.IsHandleCreated)
            {
                lstDirectories.BeginInvoke(new Action(menu.Dispose));
            }
        };

        menu.Show(lstDirectories, e.Location);
    }

    private DirectoryPathSegment? FindDirectorySegmentAtX(string path, int mouseX)
    {
        var x = lstDirectories.ClientRectangle.Left + 4;
        var segments = BuildDirectoryPathSegments(path);

        foreach (var segment in segments)
        {
            var width = GetDirectorySegmentButtonWidth(segment.Label, lstDirectories.Font);
            if (mouseX >= x && mouseX < x + width)
            {
                return segment;
            }

            x += width + 14;
        }

        return null;
    }

    private static IReadOnlyList<DirectoryPathSegment> BuildDirectoryPathSegments(string path)
    {
        var normalized = NormalizePath(path);
        var root = Path.GetPathRoot(normalized);
        if (string.IsNullOrWhiteSpace(root))
        {
            return [];
        }

        var result = new List<DirectoryPathSegment>
        {
            new(root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root)
        };

        var current = root;
        var remaining = normalized[root.Length..];
        var components = remaining.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);

        foreach (var component in components)
        {
            current = Path.Combine(current, component);
            result.Add(new DirectoryPathSegment(component, current));
        }

        return result;
    }

    private static int GetDirectorySegmentButtonWidth(string label, Font font)
    {
        var textWidth = TextRenderer.MeasureText(
            label,
            font,
            new Size(1000, 30),
            TextFormatFlags.NoPadding).Width;

        return Math.Max(30, textWidth + 14);
    }

    private void IgnoreDirectoryFromBreadcrumb(string directoryPath)
    {
        var normalized = Path.GetFullPath(directoryPath);
        var root = Path.GetPathRoot(normalized);
        if (!string.IsNullOrWhiteSpace(root) &&
            string.Equals(normalized, root, StringComparison.OrdinalIgnoreCase))
        {
            var confirm = MessageBox.Show(
                this,
                $"Ignore the entire {root} volume? All deletion paths on this volume will be excluded from automatic monitoring and new history entries.",
                "Confirm Entire Volume Exclusion",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);

            if (confirm != DialogResult.Yes)
            {
                return;
            }
        }

        if (!RecoveryMonitoringExclusions.AddIgnoredDirectory(normalized))
        {
            MessageBox.Show(
                this,
                "This directory is already ignored, or the path cannot be added.",
                "Directory Not Added",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        RefreshFromHistory();
        lblStatus.Text = $"Ignoring {normalized} and all its subdirectories for automatic monitoring.";
    }

    private async void ShowHistoryRows()
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

        // Complete NTFS snapshots may be numerous and expensive to clone/filter.
        // Retrieve and project history off the UI thread so ignoring a large volume
        // does not freeze the Recovery Center.
        var refreshVersion = ++_historyRowsRefreshVersion;
        List<RecoveryDisplayRow> records;
        try
        {
            records = await Task.Run(() => _history.GetRecent()
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
                .ToList());
        }
        catch (Exception ex)
        {
            if (!IsDisposed && refreshVersion == _historyRowsRefreshVersion)
            {
                lblStatus.Text = $"Could not refresh deletion history: {ex.Message}";
            }

            return;
        }

        // Ignore stale results if another selection/refresh started while this
        // background query was running.
        if (IsDisposed || refreshVersion != _historyRowsRefreshVersion)
        {
            return;
        }

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

    private async void btnTargetedHistorical_Click(object? sender, EventArgs e)
    {
        var fullPath = Microsoft.VisualBasic.Interaction.InputBox(
            "Enter the full path of the deleted file.",
            "Targeted Historical NTFS Recovery",
            @"E:\TestRecovery\SizeTests\test-prestart-v21-utf16-1mb.txt");

        if (string.IsNullOrWhiteSpace(fullPath))
        {
            return;
        }

        if (!File.Exists(fullPath))
        {
            // The deleted file is normally absent. We only require that its path
            // contains a valid Windows volume root; existence of the source file
            // would defeat the purpose of this historical-recovery diagnostic.
            var root = Path.GetPathRoot(fullPath);
            if (string.IsNullOrWhiteSpace(root))
            {
                MessageBox.Show(
                    this,
                    "Enter a valid Windows path, for example E:\\TestRecovery\\SizeTests\\deleted.txt.",
                    "Targeted Historical NTFS Recovery",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }
        }

        var fileReferenceText = Microsoft.VisualBasic.Interaction.InputBox(
            "Enter the exact historical NTFS file reference number.",
            "Targeted Historical NTFS Recovery",
            "6192449488110940");

        if (!ulong.TryParse(fileReferenceText, out var fileReferenceNumber) ||
            fileReferenceNumber == 0)
        {
            MessageBox.Show(
                this,
                "The NTFS file reference number is invalid.",
                "Targeted Historical NTFS Recovery",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var parentReferenceText = Microsoft.VisualBasic.Interaction.InputBox(
            "Enter the exact historical NTFS parent file reference number.",
            "Targeted Historical NTFS Recovery",
            "6473924465786916");

        if (!ulong.TryParse(parentReferenceText, out var parentFileReferenceNumber) ||
            parentFileReferenceNumber == 0)
        {
            MessageBox.Show(
                this,
                "The NTFS parent file reference number is invalid.",
                "Targeted Historical NTFS Recovery",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var fileSizeText = Microsoft.VisualBasic.Interaction.InputBox(
            "Enter the exact historical file size in bytes.",
            "Targeted Historical NTFS Recovery",
            "1048576");

        if (!long.TryParse(fileSizeText, out var historicalFileSize) ||
            historicalFileSize <= 0 ||
            historicalFileSize > int.MaxValue)
        {
            MessageBox.Show(
                this,
                "The historical file size is invalid.",
                "Targeted Historical NTFS Recovery",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var fileName = Path.GetFileName(fullPath);
        var directory = Path.GetDirectoryName(fullPath) ?? string.Empty;

        var candidate = new RecoveryCandidate
        {
            FileReferenceNumber = fileReferenceNumber,
            ParentFileReferenceNumber = parentFileReferenceNumber,
            Name = fileName,
            DirectoryPath = directory,
            LastUsnTimestampUtc = DateTime.MinValue,
            Strength = RecoveryStrength.Weak,
            Evidence =
                "Targeted historical NTFS recovery using an exact historical " +
                "file reference and parent reference supplied for diagnostic recovery.",
            DataStreamFound = false,
            DataStreamResident = false,
            FileSizeBytes = historicalFileSize,
            ValidDataLengthBytes = historicalFileSize,
            ResidentData = null,
            DataExtents = [],
            ExtentAllocations = [],
            FreeDataClusterCount = 0,
            AllocatedDataClusterCount = 0,
            DataEvidence =
                "The target is being recovered directly from historical NTFS evidence " +
                "without scanning the USN journal or current deleted-file candidate list."
        };

        var rootPath = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(rootPath) ||
            !string.Equals(
                new DriveInfo(rootPath).DriveFormat,
                "NTFS",
                StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show(
                this,
                "The target path must be on an NTFS volume.",
                "Targeted Historical NTFS Recovery",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var confirmation = MessageBox.Show(
            this,
            $"Targeted historical recovery will use:{Environment.NewLine}{Environment.NewLine}" +
            $"File: {fullPath}{Environment.NewLine}" +
            $"File reference: {fileReferenceNumber}{Environment.NewLine}" +
            $"Parent reference: {parentFileReferenceNumber}{Environment.NewLine}" +
            $"Historical size: {historicalFileSize:N0} bytes{Environment.NewLine}{Environment.NewLine}" +
            "This skips the historical USN-directory scan and goes directly to " +
            "historical NTFS recovery sources.",
            "Confirm Targeted Historical Recovery",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (confirmation != DialogResult.Yes)
        {
            return;
        }

        await RunTargetedHistoricalRecoveryAsync(candidate);
    }

    private async Task RunTargetedHistoricalRecoveryAsync(
        RecoveryCandidate candidate)
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Choose the recovery destination for this targeted historical recovery.",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true
        };

        if (dialog.ShowDialog(this) != DialogResult.OK ||
            string.IsNullOrWhiteSpace(dialog.SelectedPath))
        {
            return;
        }

        var destinationDirectory = dialog.SelectedPath;
        var completionStatus =
            "Targeted historical recovery ended without recovering the target.";
        SetBusy(true, $"Recovering {candidate.Name} directly from historical NTFS $LogFile...");

        System.Diagnostics.Trace.WriteLine(
            $"NTFS targeted historical recovery started: path={candidate.FullPath}, " +
            $"fileRef={candidate.FileReferenceNumber}, " +
            $"parentRef={candidate.ParentFileReferenceNumber}, " +
            $"expectedSize={candidate.FileSizeBytes:N0}, destination={destinationDirectory}.");

        try
        {
            // This diagnostic path is intentionally isolated from the generic
            // NTFS candidate pipeline. It must not scan unrelated MFT records,
            // enumerate candidate paths, or run the broad historical enrichment
            // stages before testing the targeted $LogFile reconstruction.
            var progress = new Progress<string>(message =>
                SetBusy(true, message));

            var recovered = await Task.Run(
                () =>
                {
                    return TryRecoverFromHistoricalLogFileData(
                        candidate,
                        destinationDirectory,
                        progress,
                        CancellationToken.None,
                        out var result)
                        ? result
                        : null;
                },
                CancellationToken.None).ConfigureAwait(true);

            if (recovered is not null)
            {
                completionStatus =
                    $"Targeted historical recovery succeeded from $LogFile: {recovered.BytesRecovered:N0} byte(s).";
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS targeted historical recovery completed: path={candidate.FullPath}, " +
                    $"stage=historical-logfile, result=success, bytes={recovered.BytesRecovered:N0}, " +
                    $"destination={recovered.DestinationPath}.");

                MessageBox.Show(
                    this,
                    $"Recovered {recovered.BytesRecovered:N0} byte(s) to:{Environment.NewLine}{recovered.DestinationPath}{Environment.NewLine}{Environment.NewLine}" +
                    recovered.Evidence,
                    "Targeted Historical NTFS Recovery",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            System.Diagnostics.Trace.WriteLine(
                $"NTFS targeted historical recovery: $LogFile reconstruction MISS; " +
                $"historical mapping-pair search finished without reconstructing target; " +
                $"path={candidate.FullPath}, fileRef={candidate.FileReferenceNumber}, " +
                $"expectedSize={candidate.FileSizeBytes:N0}; entering optional marker diagnostic.");

            var marker = Microsoft.VisualBasic.Interaction.InputBox(
                $"The targeted historical $LogFile reconstruction did not recover '{candidate.Name}'.\r\n\r\n" +
                "The historical mapping-pair search for this target has finished without reconstructing the file.\r\n\r\n" +
                "Optional diagnostic only: enter an exact, distinctive text string from a deleted TEXT file on the same volume. " +
                "This checks whether that text marker remains in $LogFile and, if you approve, in raw-volume bytes; " +
                "it does NOT reconstruct this JPG.\r\n\r\n" +
                "Click OK with an empty box, or Cancel, to end this targeted recovery operation now.",
                "Targeted Historical Recovery — Optional Marker Diagnostic",
                "");

            if (string.IsNullOrWhiteSpace(marker))
            {
                completionStatus =
                    "Targeted recovery ended: $LogFile reconstruction missed; marker and raw-volume marker checks skipped.";
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS targeted historical recovery ended: path={candidate.FullPath}, " +
                    $"fileRef={candidate.FileReferenceNumber}, result=miss, " +
                    $"historicalMappingPairSearch=completed-no-reconstruction, " +
                    $"markerFallback=skipped, rawVolumeMarkerScan=skipped, " +
                    $"reason=empty-or-cancelled-marker; no further JPG reconstruction was scheduled.");

                MessageBox.Show(
                    this,
                    "The targeted $LogFile reconstruction has finished and did not recover the target. " +
                    "Its historical mapping-pair search is complete.\r\n\r\n" +
                    "No marker was supplied, so the optional marker diagnostics were skipped. " +
                    "This ends this targeted recovery operation; it does not continue into another JPG reconstruction pass.",
                    "Targeted Historical NTFS Recovery Ended",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            var root = Path.GetPathRoot(candidate.FullPath);
            if (string.IsNullOrWhiteSpace(root))
            {
                throw new InvalidOperationException(
                    "The targeted file path does not have a valid source volume root.");
            }

            var markerService = new NtfsLogFileHistoricalDataService();
            if (markerService.TryFindMarkerInHistoricalLogFile(
                    root,
                    marker,
                    out var logMarkerEvidence))
            {
                completionStatus =
                    "Targeted JPG reconstruction missed; marker found in retained $LogFile; raw-volume marker scan skipped.";
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS targeted marker diagnostic completed: path={candidate.FullPath}, " +
                    $"stage=historical-logfile-marker, markerFound=true, " +
                    $"targetFileRecovered=false, rawVolumeMarkerScan=skipped, evidence={logMarkerEvidence}");

                MessageBox.Show(
                    this,
                    "The marker was found in the retained NTFS $LogFile, but targeted reconstruction still did not produce the complete file.\r\n\r\n" +
                    logMarkerEvidence,
                    "Targeted Historical NTFS Recovery",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            System.Diagnostics.Trace.WriteLine(
                $"NTFS targeted marker diagnostic: path={candidate.FullPath}, " +
                $"stage=historical-logfile-marker, markerFound=false; asking whether to run raw-volume marker-only scan.");

            var proceed = MessageBox.Show(
                this,
                "The marker was not found in the retained NTFS $LogFile.\r\n\r\n" +
                "A raw-volume marker scan would read the entire source volume. This checks only for the supplied text marker; " +
                "it does not reconstruct the JPG.",
                "Targeted Historical Recovery",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2);

            if (proceed != DialogResult.Yes)
            {
                completionStatus =
                    "Targeted JPG reconstruction missed; raw-volume marker-only scan declined.";
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS targeted marker diagnostic ended: path={candidate.FullPath}, " +
                    $"stage=raw-volume-marker, result=skipped-by-user, targetFileRecovered=false.");
                return;
            }

            var totalVolumeBytes = new DriveInfo(root).TotalSize;
            var forensicProgress = new SynchronousProgress<long>(
                this,
                bytesScanned =>
                {
                    lblStatus.Text =
                        $"Targeted raw-volume marker scan... " +
                        $"{bytesScanned / (1024d * 1024d * 1024d):0.00} / " +
                        $"{totalVolumeBytes / (1024d * 1024d * 1024d):0.00} GB scanned";
                });

            System.Diagnostics.Trace.WriteLine(
                $"NTFS targeted marker diagnostic started: path={candidate.FullPath}, " +
                $"stage=raw-volume-marker-only, markerLength={marker.Length}, " +
                $"volume={root}; this scan does not reconstruct the target file.");

            var forensicResult =
                _ntfsWholeVolumeTextRecoveryService.FindMarkerOnVolume(
                    candidate.FullPath,
                    marker,
                    CancellationToken.None,
                    forensicProgress);

            completionStatus = forensicResult.Found
                ? "Targeted JPG reconstruction missed; marker found on raw volume; JPG not reconstructed."
                : "Targeted JPG reconstruction missed; marker not found on raw volume.";

            System.Diagnostics.Trace.WriteLine(
                $"NTFS targeted marker diagnostic completed: path={candidate.FullPath}, " +
                $"stage=raw-volume-marker-only, markerFound={forensicResult.Found}, " +
                $"scannedBytes={forensicResult.ScannedBytes:N0}, targetFileRecovered=false.");

            MessageBox.Show(
                this,
                forensicResult.Found
                    ? $"Marker FOUND at byte offset {forensicResult.Offset:N0}.\r\nEncoding: {forensicResult.Encoding}"
                    : $"Marker was NOT found in the raw source volume.\r\nScanned: {forensicResult.ScannedBytes:N0} bytes.",
                "Targeted Raw-Volume Marker Test",
                forensicResult.Found
                    ? MessageBoxButtons.OK
                    : MessageBoxButtons.OK,
                forensicResult.Found
                    ? MessageBoxIcon.Information
                    : MessageBoxIcon.Warning);
        }
        catch (Exception ex)
        {
            completionStatus = $"Targeted historical recovery failed: {ex.GetType().Name}.";
            System.Diagnostics.Trace.WriteLine(
                $"NTFS targeted historical recovery failed: path={candidate.FullPath}, " +
                $"fileRef={candidate.FileReferenceNumber}, " +
                $"exception={ex.GetType().Name}: {ex.Message}");

            MessageBox.Show(
                this,
                $"{ex.GetType().Name}: {ex.Message}",
                "Targeted Historical Recovery Failed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        finally
        {
            SetBusy(false, completionStatus);
            UpdateRecoverButton();
            System.Diagnostics.Trace.WriteLine(
                $"NTFS targeted historical recovery status finalized: path={candidate.FullPath}, " +
                $"status={completionStatus}");
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

        SetBusy(
            true,
            $"Scanning deleted NTFS metadata under {scanDirectory}...");

        _ntfsScanInProgress = true;

        try
        {
            // Capture recent historical deletions while the USN journal is being
            // enumerated. This avoids waiting for the entire journal scan to finish
            // before reading the deleted MFT record and its $DATA stream.
            var historicalSnapshotCutoffUtc = DateTime.UtcNow.AddMinutes(-15);
            var historicalSnapshotRecords = new List<DeletionRecord>();

            var deletedRecords = _usnMonitor.ScanDeletedDirectory(
                scanDirectory,
                includeSubdirectories,
                CancellationToken.None,
                deletedRecord =>
                {
                    if (deletedRecord.DeletedAtUtc < historicalSnapshotCutoffUtc)
                    {
                        return;
                    }

                    try
                    {
                        if (_usnMonitor.TryCaptureHistoricalDeletionSnapshot(
                                deletedRecord,
                                out var snapshotRecord))
                        {
                            historicalSnapshotRecords.Add(snapshotRecord);
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine(
                            $"NTFS historical deletion snapshot failed: " +
                            $"{deletedRecord.FullPath}: {ex.GetType().Name}: {ex.Message}");
                    }
                });

            foreach (var snapshotRecord in historicalSnapshotRecords)
            {
                _history.Upsert(snapshotRecord);
            }

            System.Diagnostics.Debug.WriteLine(
                $"NTFS historical deletion snapshots: " +
                $"recentRecords={deletedRecords.Count(record => record.DeletedAtUtc >= historicalSnapshotCutoffUtc):N0}, " +
                $"captured={historicalSnapshotRecords.Count:N0}.");

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

            // Give recent deletions one direct USN-journal-tail snapshot attempt before
            // the broader historical scan. This is independent of the background monitor
            // cursor, so a large journal backlog cannot delay deletion-time $DATA capture.
            foreach (var recentRecord in historyRecords.Where(record =>
                         record.DeletedAtUtc >= recentHistoryCutoffUtc))
            {
                if (recentRecord.NtfsDataSnapshot?.IsComplete == true)
                {
                    continue;
                }

                try
                {
                    if (_usnMonitor.TryCaptureRecentDeletionSnapshot(recentRecord))
                    {
                        await Task.Run(() => _history.Upsert(recentRecord))
                            .ConfigureAwait(true);
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS recent deletion snapshot retry failed: " +
                        $"{recentRecord.FullPath}: {ex.GetType().Name}: {ex.Message}");
                }
            }

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
                await ResolveMissingNtfsReferencesAsync(historyNeedingResolution);
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

            var historicalFileSizesByPath = historyRecords
                .Where(record => record.FileSizeBytes.HasValue)
                .GroupBy(
                    record => NormalizePath(record.FullPath),
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group
                        .OrderByDescending(record => record.DeletedAtUtc)
                        .Select(record => record.FileSizeBytes!.Value)
                        .First(),
                    StringComparer.OrdinalIgnoreCase);

            var targetRecords = deletedRecords
                .Select(record => (
                    record.FullPath,
                    record.FileReferenceNumber,
                    record.ParentFileReferenceNumber,
                    FileSizeBytes: historicalFileSizesByPath.TryGetValue(
                        NormalizePath(record.FullPath),
                        out var historicalFileSize)
                        ? historicalFileSize
                        : 0L,
                    record.DeletedAtUtc))
                .ToList();

            var targetPaths = targetRecords
                .Select(target => NormalizePath(target.FullPath))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var mergedLiveHistoryCount = 0;
            var mergedLiveUsnCount = 0;

            foreach (var record in recentLiveUsnDeletes)
            {
                var normalizedPath = NormalizePath(record.FullPath);
                if (!targetPaths.Add(normalizedPath))
                {
                    continue;
                }

                targetRecords.Add((
                    record.FullPath,
                    record.FileReferenceNumber,
                    record.ParentFileReferenceNumber,
                    FileSizeBytes: 0L,
                    record.DeletedAtUtc));

                mergedLiveUsnCount++;
            }

            foreach (var record in historyRecordsWithReferences)
            {
                var normalizedPath = NormalizePath(record.FullPath);
                if (!targetPaths.Add(normalizedPath))
                {
                    continue;
                }

                targetRecords.Add((
                    record.FullPath,
                    record.FileReferenceNumber!.Value,
                    record.ParentFileReferenceNumber!.Value,
                    FileSizeBytes: record.FileSizeBytes ?? 0L,
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
                    var pathCandidates = _mftCandidateScanner.ScanForPaths(
                        rootPath,
                        recentTargetRecordsByPath.Keys.ToList(),
                        CancellationToken.None,
                        maxPages: 128);

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

            var candidates = _mftCandidateScanner.ScanForFileReferences(
                rootPath,
                targetRecords,
                CancellationToken.None)
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

            // Give every missing-data candidate, including plain-text files, one
            // targeted raw-MFT pass before falling back to marker-based carving.
            // Also include deletion references from the USN/history records even
            // when ScanForFileReferences() failed to produce a current candidate.
            // This is important when the MFT sequence has already gone stale/reused:
            // the historical segment may still contain useful $DATA slack even
            // though it was not returned as a normal deleted candidate.
            var exhaustiveMftCandidates = missingDataCandidates.ToList();

            var rawMftTargetPaths = exhaustiveMftCandidates
                .Select(candidate => NormalizePath(candidate.FullPath))
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var historicalRawMftTargets = targetRecords
                .Where(target =>
                    !string.IsNullOrWhiteSpace(target.FullPath) &&
                    target.FileReferenceNumber is ulong fileReferenceNumber &&
                    fileReferenceNumber != 0 &&
                    target.ParentFileReferenceNumber is ulong parentFileReferenceNumber &&
                    parentFileReferenceNumber != 0 &&
                    !candidates.Any(candidate =>
                        string.Equals(
                            NormalizePath(candidate.FullPath),
                            NormalizePath(target.FullPath),
                            StringComparison.OrdinalIgnoreCase) &&
                        candidate.DataStreamFound &&
                        target.FileSizeBytes is long historicalSize &&
                        historicalSize > 0 &&
                        candidate.FileSizeBytes > 0 &&
                        candidate.FileSizeBytes == historicalSize))
                .Select(target => (
                    FullPath: NormalizePath(target.FullPath),
                    FileReferenceNumber: target.FileReferenceNumber is ulong fileReferenceNumber
                        ? fileReferenceNumber
                        : 0UL,
                    ParentFileReferenceNumber: target.ParentFileReferenceNumber is ulong parentFileReferenceNumber
                        ? parentFileReferenceNumber
                        : 0UL,
                    FileSizeBytes: target.FileSizeBytes is long fileSizeBytes
                        ? fileSizeBytes
                        : 0L,
                    DeletedAtUtc: target.DeletedAtUtc))
                .GroupBy(
                    target => target.FullPath,
                    StringComparer.OrdinalIgnoreCase)
                .Select(group => group
                    .OrderByDescending(target => target.DeletedAtUtc)
                    .First())
                .ToList();

            // Historical USN/MFT targets can reach the raw-MFT scanner without a
            // persisted file size. Recover the exact historical size from $LogFile
            // before the raw-MFT pass so historical MFT-slack $DATA matching can use
            // a trusted size constraint. This is deliberately limited to historical
            // targets that still have an unresolved size; it avoids invoking the
            // whole-volume forensic marker scan merely to discover the file length.
            if (historicalRawMftTargets.Any(target => target.FileSizeBytes <= 0))
            {
                var historicalLogFileSizeReader = new NtfsLogFileHistoricalSizeService();
                var maximumHistoricalFileSize = new DriveInfo(rootPath).TotalSize;

                for (var i = 0; i < historicalRawMftTargets.Count; i++)
                {
                    var historicalTarget = historicalRawMftTargets[i];

                    if (historicalTarget.FileSizeBytes > 0)
                    {
                        continue;
                    }

                    try
                    {
                        if (historicalLogFileSizeReader.TryRecoverFileSize(
                            rootPath,
                            Path.GetFileName(historicalTarget.FullPath),
                            historicalTarget.ParentFileReferenceNumber,
                            maximumHistoricalFileSize,
                            out var historicalLogFileSize,
                            out var historicalLogFileEvidence) &&
                            historicalLogFileSize > 0)
                        {
                            historicalRawMftTargets[i] = (
                                historicalTarget.FullPath,
                                historicalTarget.FileReferenceNumber,
                                historicalTarget.ParentFileReferenceNumber,
                                historicalLogFileSize,
                                historicalTarget.DeletedAtUtc);

                            System.Diagnostics.Trace.WriteLine(
                                $"NTFS historical raw-MFT target size enrichment: " +
                                $"match=$LogFile, path={historicalTarget.FullPath}, " +
                                $"fileRef={historicalTarget.FileReferenceNumber}, " +
                                $"size={historicalLogFileSize:N0} bytes, " +
                                $"evidence={historicalLogFileEvidence}");
                        }
                        else
                        {
                            System.Diagnostics.Trace.WriteLine(
                                $"NTFS historical raw-MFT target $LogFile size lookup: " +
                                $"no match for path={historicalTarget.FullPath}, " +
                                $"fileRef={historicalTarget.FileReferenceNumber}. " +
                                $"{historicalLogFileEvidence}");
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Trace.WriteLine(
                            $"NTFS historical raw-MFT target $LogFile size lookup failed: " +
                            $"path={historicalTarget.FullPath}, " +
                            $"fileRef={historicalTarget.FileReferenceNumber}, " +
                            $"exception={ex.GetType().Name}: {ex.Message}");
                    }
                }
            }

            foreach (var historicalTarget in historicalRawMftTargets)
            {
                rawMftTargetPaths.Add(historicalTarget.FullPath);
            }

            var historicalSizeByPath = historicalRawMftTargets
                .Where(target => target.FileSizeBytes > 0)
                .GroupBy(
                    target => NormalizePath(target.FullPath),
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    group => group.Key,
                    group => group
                        .Select(target => target.FileSizeBytes)
                        .OrderByDescending(size => size)
                        .First(),
                    StringComparer.OrdinalIgnoreCase);

            candidates = candidates
                .Select(candidate =>
                {
                    var path = NormalizePath(candidate.FullPath);

                    if (historicalSizeByPath.TryGetValue(path, out var trustedHistoricalSize) &&
                        trustedHistoricalSize > 0 &&
                        candidate.FileSizeBytes <= 0)
                    {
                        System.Diagnostics.Trace.WriteLine(
                            $"NTFS candidate historical-size handoff: " +
                            $"path={candidate.FullPath}, " +
                            $"fileRef={candidate.FileReferenceNumber}, " +
                            $"previousSize={candidate.FileSizeBytes:N0}, " +
                            $"historicalSize={trustedHistoricalSize:N0}. " +
                            "Propagating the trusted $LogFile historical size into the recovery candidate.");

                        return new RecoveryCandidate
                        {
                            FileReferenceNumber = candidate.FileReferenceNumber,
                            ParentFileReferenceNumber = candidate.ParentFileReferenceNumber,
                            Name = candidate.Name,
                            DirectoryPath = candidate.DirectoryPath,
                            LastUsnTimestampUtc = candidate.LastUsnTimestampUtc,
                            Strength = candidate.Strength,
                            Evidence = string.Join(
                                " ",
                                new[]
                                {
                                    candidate.Evidence,
                                    $"Trusted historical NTFS $LogFile size: {trustedHistoricalSize:N0} byte(s)."
                                }.Where(text => !string.IsNullOrWhiteSpace(text))),
                            DataStreamFound = candidate.DataStreamFound,
                            DataStreamResident = candidate.DataStreamResident,
                            FileSizeBytes = trustedHistoricalSize,
                            ValidDataLengthBytes = candidate.ValidDataLengthBytes,
                            NtfsDataSnapshot = candidate.NtfsDataSnapshot?.Clone(),
                            ResidentData = candidate.ResidentData,
                            DataExtents = candidate.DataExtents,
                            ExtentAllocations = candidate.ExtentAllocations,
                            FreeDataClusterCount = candidate.FreeDataClusterCount,
                            AllocatedDataClusterCount = candidate.AllocatedDataClusterCount,
                            DataEvidence = candidate.DataEvidence
                        };
                    }

                    if (!candidate.DataStreamFound ||
                        !historicalSizeByPath.TryGetValue(path, out var historicalSize) ||
                        historicalSize <= 0 ||
                        candidate.FileSizeBytes <= 0 ||
                        candidate.FileSizeBytes == historicalSize)
                    {
                        return candidate;
                    }

                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS current candidate quarantined for historical-size mismatch: " +
                        $"path={candidate.FullPath}, " +
                        $"fileRef={candidate.FileReferenceNumber}, " +
                        $"currentSize={candidate.FileSizeBytes:N0}, " +
                        $"historicalSize={historicalSize:N0}.");

                    return new RecoveryCandidate
                    {
                        FileReferenceNumber = candidate.FileReferenceNumber,
                        ParentFileReferenceNumber = candidate.ParentFileReferenceNumber,
                        Name = candidate.Name,
                        DirectoryPath = candidate.DirectoryPath,
                        LastUsnTimestampUtc = candidate.LastUsnTimestampUtc,
                        Strength = candidate.Strength,
                        Evidence = string.Join(
                            " ",
                            new[]
                            {
                                candidate.Evidence,
                                "The retained current MFT $DATA size conflicted with trusted historical deletion size, so the current stream was quarantined and will not be used for recovery."
                            }.Where(text => !string.IsNullOrWhiteSpace(text))),
                        DataStreamFound = false,
                        DataStreamResident = false,
                        FileSizeBytes = historicalSize,
                        ValidDataLengthBytes = 0,
                        NtfsDataSnapshot = candidate.NtfsDataSnapshot?.Clone(),
                        ResidentData = null,
                        DataExtents = [],
                        ExtentAllocations = [],
                        FreeDataClusterCount = 0,
                        AllocatedDataClusterCount = 0,
                        DataEvidence = string.Empty
                    };
                })
                .ToList();

            var rawMftReferences = historicalRawMftTargets
                .Concat(
                    exhaustiveMftCandidates
                        .Where(candidate => candidate.FileReferenceNumber != 0)
                        .Select(candidate => (
                            FullPath: NormalizePath(candidate.FullPath),
                            FileReferenceNumber: candidate.FileReferenceNumber,
                            ParentFileReferenceNumber: candidate.ParentFileReferenceNumber,
                            FileSizeBytes: candidate.FileSizeBytes,
                            DeletedAtUtc: candidate.LastUsnTimestampUtc)))
                .GroupBy(
                    target => target.FullPath,
                    StringComparer.OrdinalIgnoreCase)
                .Select(group =>
                {
                    var historicalTarget = group
                        .Where(target =>
                            historicalRawMftTargets.Any(historical =>
                                string.Equals(
                                    NormalizePath(historical.FullPath),
                                    target.FullPath,
                                    StringComparison.OrdinalIgnoreCase) &&
                                historical.FileReferenceNumber == target.FileReferenceNumber))
                        .OrderByDescending(target => target.FileSizeBytes)
                        .ThenByDescending(target => target.DeletedAtUtc)
                        .FirstOrDefault();

                    return historicalTarget.FileReferenceNumber != 0
                        ? historicalTarget
                        : group
                            .OrderByDescending(target => target.FileSizeBytes)
                            .ThenByDescending(target => target.DeletedAtUtc)
                            .First();
                })
                .ToList();

            System.Diagnostics.Trace.WriteLine(
                $"NTFS raw-MFT target handoff: pathTargets={missingDataCandidates.Count:N0}, " +
                $"historicalTargets={historicalRawMftTargets.Count:N0}, " +
                $"combinedTargets={rawMftReferences.Count:N0}.");

            foreach (var target in rawMftReferences)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS raw-MFT target: path={target.FullPath}, " +
                    $"fileRef={target.FileReferenceNumber}, " +
                    $"parentRef={target.ParentFileReferenceNumber}, " +
                    $"deletedAtUtc={target.DeletedAtUtc:O}.");
            }

            var missingDataPaths = rawMftTargetPaths
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (missingDataCandidates.Count != exhaustiveMftCandidates.Count)
            {
                var deferredTextCount =
                    missingDataCandidates.Count - exhaustiveMftCandidates.Count;

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS raw MFT fallback: {deferredTextCount:N0} plain-text " +
                    "candidate(s) remain for marker-driven forensic recovery after the raw-MFT pass.");
            }

            if (missingDataPaths.Count > 0)
            {
                lblStatus.Text =
                    $"Found {candidates.Count:N0} candidate(s); scanning the NTFS $MFT for retained deleted records ({missingDataPaths.Count:N0} item(s))...";

                var fallbackCandidates =
                    await _mftCandidateScanner.ScanRawMftForPathsAsync(
                        rootPath,
                        missingDataPaths,
                        CancellationToken.None,
                        maxBytesToScan: long.MaxValue,
                        targetReferences: rawMftReferences);

                if (fallbackCandidates.Count > 0)
                {
                    var fallbackHistoricalSizeByPath = rawMftReferences
                        .Where(target => target.FileSizeBytes > 0)
                        .GroupBy(
                            target => NormalizePath(target.FullPath),
                            StringComparer.OrdinalIgnoreCase)
                        .ToDictionary(
                            group => group.Key,
                            group => group
                                .Select(target => target.FileSizeBytes)
                                .OrderByDescending(size => size)
                                .First(),
                            StringComparer.OrdinalIgnoreCase);

                    var fallbackByPath = fallbackCandidates
                        .Where(candidate => candidate.DataStreamFound)
                        .Where(candidate =>
                        {
                            var path = NormalizePath(candidate.FullPath);

                            if (!fallbackHistoricalSizeByPath.TryGetValue(path, out var expectedSize) ||
                                expectedSize <= 0 ||
                                candidate.FileSizeBytes <= 0)
                            {
                                return true;
                            }

                            var matches = candidate.FileSizeBytes == expectedSize;

                            if (!matches)
                            {
                                System.Diagnostics.Trace.WriteLine(
                                    $"NTFS raw-MFT fallback candidate rejected for historical-size mismatch: " +
                                    $"path={candidate.FullPath}, " +
                                    $"candidateSize={candidate.FileSizeBytes:N0}, " +
                                    $"historicalSize={expectedSize:N0}.");
                            }

                            return matches;
                        })
                        .GroupBy(candidate => candidate.FullPath, StringComparer.OrdinalIgnoreCase)
                        .ToDictionary(
                            group => group.Key,
                            group => group.First(),
                            StringComparer.OrdinalIgnoreCase);

                    candidates = candidates
                        .Select(candidate =>
                        {
                            if (!fallbackByPath.TryGetValue(candidate.FullPath, out var fallback))
                            {
                                return candidate;
                            }

                            if (!candidate.DataStreamFound)
                            {
                                return fallback;
                            }

                            // A structurally validated historical raw-MFT candidate
                            // must replace a conflicting current/reused stream even
                            // when the current candidate reports DataStreamFound=true.
                            if (fallback.FileSizeBytes > 0 &&
                                candidate.FileSizeBytes > 0 &&
                                fallback.FileSizeBytes != candidate.FileSizeBytes)
                            {
                                System.Diagnostics.Trace.WriteLine(
                                    $"NTFS raw-MFT fallback candidate replaced conflicting current stream: " +
                                    $"path={candidate.FullPath}, " +
                                    $"currentSize={candidate.FileSizeBytes:N0}, " +
                                    $"historicalSize={fallback.FileSizeBytes:N0}.");

                                return fallback;
                            }

                            return candidate;
                        })
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

            // Prefer the exact persisted NTFS deletion snapshot when the
            // candidate's historical file reference or path matches a deletion record.
            // The snapshot was captured at delete time, before MFT sequence reuse.
            foreach (var candidate in candidates)
            {
                // When the candidate has an authoritative NTFS file reference,
                // require the deletion snapshot to belong to that exact reference.
                // Falling back to path/time here can attach a snapshot from another
                // deletion of the same filename.
                var snapshotMatch = candidate.FileReferenceNumber != 0
                    ? historyRecords
                        .Where(record =>
                            record.FileReferenceNumber.HasValue &&
                            record.FileReferenceNumber.Value == candidate.FileReferenceNumber &&
                            record.NtfsDataSnapshot is not null)
                        .OrderBy(record =>
                            Math.Abs(
                                (record.DeletedAtUtc - candidate.LastUsnTimestampUtc)
                                    .TotalMinutes))
                        .FirstOrDefault()
                    : historyRecords
                        .Where(record =>
                            !record.FileReferenceNumber.HasValue &&
                            record.NtfsDataSnapshot is not null &&
                            string.Equals(
                                NormalizeForComparison(record.FullPath),
                                NormalizeForComparison(candidate.FullPath),
                                StringComparison.OrdinalIgnoreCase))
                        .OrderBy(record =>
                            Math.Abs(
                                (record.DeletedAtUtc - candidate.LastUsnTimestampUtc)
                                    .TotalMinutes))
                        .FirstOrDefault();

                if (snapshotMatch?.NtfsDataSnapshot is not null &&
                    (candidate.LastUsnTimestampUtc == default ||
                     Math.Abs(
                         (snapshotMatch.DeletedAtUtc - candidate.LastUsnTimestampUtc)
                             .TotalMinutes) <= 5))
                {
                    candidate.NtfsDataSnapshot = snapshotMatch.NtfsDataSnapshot.Clone();

                    if (candidate.FileSizeBytes <= 0 &&
                        candidate.NtfsDataSnapshot.FileSizeBytes >= 0)
                    {
                        candidate.FileSizeBytes =
                            candidate.NtfsDataSnapshot.FileSizeBytes;
                    }

                    if (candidate.NtfsDataSnapshot.IsComplete)
                    {
                        candidate.Strength = RecoveryStrength.Strong;
                    }

                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS candidate snapshot enrichment: path={candidate.FullPath}, " +
                        $"fileRef={candidate.FileReferenceNumber}, " +
                        $"captured={candidate.NtfsDataSnapshot.IsComplete}, " +
                        $"size={candidate.NtfsDataSnapshot.FileSizeBytes:N0}, " +
                        $"snapshotFile={candidate.NtfsDataSnapshot.DataFileName ?? "(none)"}.");
                }
            }

            // Carry the trusted historical deletion size into every matching
            // candidate. This also detects a reused/current MFT record whose retained
            // $DATA stream reports a different size than the historical deletion.
            foreach (var candidate in candidates)
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
                    var previousSize = candidate.FileSizeBytes;
                    candidate.FileSizeBytes = knownSize;

                    var matchKind = referenceMatch is not null
                        ? "file-reference"
                        : "path";

                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS candidate size enrichment: match={matchKind}, " +
                        $"path={candidate.FullPath}, fileRef={candidate.FileReferenceNumber}, " +
                        $"size={knownSize:N0} bytes, previousSize={previousSize:N0}.");
                }

                if (candidate.FileSizeBytes <= 0 &&
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
                        FileSize = candidate.FileSizeBytes > 0
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
            _ntfsScanInProgress = false;
            SetBusy(false);
            UpdateRecoverButton();
        }
    }

    private static string GetRecycleBinOriginalLocation(RecoveryDisplayRow row)
    {
        var evidence = row.Evidence ?? string.Empty;
        const string marker = "original location: ";

        var start = evidence.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            return string.Empty;
        }

        start += marker.Length;
        var end = evidence.IndexOf('.', start);
        return end > start
            ? evidence[start..end].Trim()
            : evidence[start..].Trim();
    }

    private static DateTime ParseRecycleBinDeletedDate(string value)
    {
        return DateTime.TryParse(
            value,
            System.Globalization.CultureInfo.CurrentCulture,
            System.Globalization.DateTimeStyles.AllowWhiteSpaces,
            out var parsed)
            ? parsed.ToUniversalTime()
            : DateTime.MinValue;
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

        if (candidate.NtfsDataSnapshot?.IsComplete == true)
        {
            parts.Add(
                $"NTFS deletion snapshot retained {candidate.NtfsDataSnapshot.CapturedByteCount:N0} byte(s) at delete time.");
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
        IReadOnlyList<DeletionRecord> records)
    {
        var resolved = new List<DeletionRecord>();
        var unresolved = new List<DeletionRecord>();
        var recentCutoffUtc = DateTime.UtcNow.AddMinutes(-15);

        foreach (var record in records)
        {
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
                        await Task.Delay(200).ConfigureAwait(true);
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

            var historicalMatches =
                _usnMonitor.ResolveHistoricalDeletionsFromJournal(
                    targets,
                    CancellationToken.None);

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

                recycleResolution = ResolveRecycleBinMatches(historyRecords);

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
                                FileSizeBytes: record.FileSizeBytes ?? 0L,
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
                                // The delete-time snapshot is the strongest source
                                // for a freshly deleted file. Attach it to the candidate
                                // so recovery uses the bytes captured before later NTFS
                                // cluster reuse can change the raw data.
                                if (record.NtfsDataSnapshot?.IsComplete == true)
                                {
                                    match.NtfsDataSnapshot =
                                        record.NtfsDataSnapshot.Clone();

                                    if (match.FileSizeBytes <= 0)
                                    {
                                        match.FileSizeBytes =
                                            match.NtfsDataSnapshot.FileSizeBytes;
                                    }

                                    System.Diagnostics.Debug.WriteLine(
                                        $"NTFS recovery candidate: attached complete delete-time snapshot " +
                                        $"path={record.FullPath}, fileRef={record.FileReferenceNumber}, " +
                                        $"bytes={match.NtfsDataSnapshot.CapturedByteCount:N0}.");
                                }

                                ntfsCandidates.Add(match);
                            }
                            else
                            {
                                // Keep the exact historical reference even when the reused
                                // current MFT record no longer produces a normal candidate.
                                // This lets recovery-time $LogFile reconstruction operate
                                // without another whole-volume/history scan.
                                var metadataCandidate = new RecoveryCandidate
                                {
                                    FileReferenceNumber = record.FileReferenceNumber!.Value,
                                    ParentFileReferenceNumber =
                                        record.ParentFileReferenceNumber ?? 0,
                                    Name = record.FileName,
                                    DirectoryPath = string.IsNullOrWhiteSpace(record.DirectoryPath)
                                        ? Path.GetDirectoryName(record.FullPath) ?? string.Empty
                                        : NormalizePath(record.DirectoryPath),
                                    LastUsnTimestampUtc = record.DeletedAtUtc,
                                    Strength = RecoveryStrength.Weak,
                                    Evidence =
                                        "The historical deletion record retained the exact NTFS " +
                                        "file reference, but the current MFT no longer exposes " +
                                        "a matching live record. Historical NTFS evidence will " +
                                        "be attempted before marker-driven fallback.",
                                    DataStreamFound = false,
                                    DataStreamResident = false,
                                    FileSizeBytes = record.FileSizeBytes ?? 0L,
                                    ValidDataLengthBytes = 0,
                                    ResidentData = null,
                                    DataExtents = [],
                                    ExtentAllocations = [],
                                    FreeDataClusterCount = 0,
                                    AllocatedDataClusterCount = 0,
                                    DataEvidence =
                                        "No current NTFS $DATA stream was retained under the " +
                                        "historical file reference."
                                };

                                if (record.NtfsDataSnapshot?.IsComplete == true)
                                {
                                    metadataCandidate.NtfsDataSnapshot =
                                        record.NtfsDataSnapshot.Clone();

                                    if (metadataCandidate.FileSizeBytes <= 0)
                                    {
                                        metadataCandidate.FileSizeBytes =
                                            metadataCandidate.NtfsDataSnapshot.FileSizeBytes;
                                    }
                                }

                                ntfsCandidates.Add(metadataCandidate);
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
                                // Legacy candidates can also benefit from a
                                // persisted delete-time snapshot when the selected
                                // history record already has one.
                                if (record.NtfsDataSnapshot?.IsComplete == true)
                                {
                                    match.NtfsDataSnapshot =
                                        record.NtfsDataSnapshot.Clone();

                                    if (match.FileSizeBytes <= 0)
                                    {
                                        match.FileSizeBytes =
                                            match.NtfsDataSnapshot.FileSizeBytes;
                                    }

                                    System.Diagnostics.Debug.WriteLine(
                                        $"NTFS legacy candidate: attached complete delete-time snapshot " +
                                        $"path={record.FullPath}, bytes={match.NtfsDataSnapshot.CapturedByteCount:N0}.");
                                }

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
    
    private Dictionary<Guid, RecoveryItem> ResolveRecycleBinMatches(
        IReadOnlyList<DeletionRecord> historyRecords)
    {
        var availableItems = _recycleBinService.Scan();
        var matches = new Dictionary<Guid, RecoveryItem>();

        foreach (var record in historyRecords)
        {
            var expectedFullPath = NormalizePath(record.FullPath);

            // Multiple Recycle Bin entries can have the exact same
            // filename and original folder. Pick the entry whose Shell
            // deletion time is closest to the selected history record.
            var match = FindBestRecycleBinMatch(
                availableItems,
                expectedFullPath,
                record.DeletedAtUtc);

            if (match is null)
            {
                // Fallback only when Shell does not expose the original
                // location. Require the exact displayed deletion timestamp
                // so duplicate same-name entries are not silently mixed.
                match = availableItems.FirstOrDefault(item =>
                    string.Equals(
                        item.Name,
                        record.FileName,
                        StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(
                        item.DeletedDate,
                        record.DeletedAtUtc.ToLocalTime().ToString("g"),
                        StringComparison.OrdinalIgnoreCase));
            }

            if (match is not null)
            {
                matches[record.Id] = match;
            }
        }

        return matches;
    }

    private static RecoveryItem? FindBestRecycleBinMatch(
        IReadOnlyList<RecoveryItem> availableItems,
        string expectedFullPath,
        DateTime deletedAtUtc)
    {
        var pathMatches = availableItems
            .Where(item =>
                !string.IsNullOrWhiteSpace(item.OriginalLocation) &&
                !item.OriginalLocation.Equals(
                    "(Unavailable)",
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    NormalizePath(Path.Combine(item.OriginalLocation, item.Name)),
                    expectedFullPath,
                    StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (pathMatches.Count == 0)
        {
            return null;
        }

        if (pathMatches.Count == 1 || deletedAtUtc == default)
        {
            return pathMatches.Count == 1 ? pathMatches[0] : null;
        }

        var expectedLocalTime = deletedAtUtc.ToLocalTime();

        var datedMatches = pathMatches
            .Select(item =>
            {
                var parsed = DateTime.TryParse(
                    item.DeletedDate,
                    System.Globalization.CultureInfo.CurrentCulture,
                    System.Globalization.DateTimeStyles.AllowWhiteSpaces,
                    out var parsedDate);

                return new
                {
                    Item = item,
                    Parsed = parsed,
                    Delta = parsed
                        ? Math.Abs((parsedDate - expectedLocalTime).TotalMilliseconds)
                        : double.MaxValue
                };
            })
            .Where(match => match.Parsed)
            .OrderBy(match => match.Delta)
            .ToList();

        if (datedMatches.Count == 0)
        {
            // Several identical path entries without usable dates are ambiguous.
            // Do not silently restore the wrong deleted instance.
            return null;
        }

        return datedMatches[0].Item;
    }

    private static bool TryRecoverFromNtfsSnapshot(
        RecoveryCandidate candidate,
        string destinationDirectory,
        out RecoveryResult result)
    {
        result = new RecoveryResult();

        var snapshot = candidate.NtfsDataSnapshot;
        if (snapshot is null ||
            !snapshot.IsComplete ||
            string.IsNullOrWhiteSpace(snapshot.DataFileName))
        {
            return false;
        }

        var store = new NtfsDeletionSnapshotStore();

        if (!store.TryLoad(snapshot.DataFileName, out var data))
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS deletion snapshot recovery: snapshot file is unavailable. " +
                $"path={candidate.FullPath}, file={snapshot.DataFileName}.");
            return false;
        }

        if (data.LongLength != snapshot.FileSizeBytes ||
            data.LongLength != snapshot.CapturedByteCount)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS deletion snapshot recovery: size mismatch. " +
                $"path={candidate.FullPath}, expected={snapshot.FileSizeBytes:N0}, " +
                $"captured={snapshot.CapturedByteCount:N0}, actual={data.LongLength:N0}.");
            return false;
        }

        if (candidate.FileSizeBytes > 0 &&
            snapshot.FileSizeBytes != candidate.FileSizeBytes)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS deletion snapshot recovery rejected for historical-size mismatch: " +
                $"path={candidate.FullPath}, " +
                $"candidateSize={candidate.FileSizeBytes:N0}, " +
                $"snapshotSize={snapshot.FileSizeBytes:N0}.");
            return false;
        }

        if (!string.IsNullOrWhiteSpace(snapshot.Sha256))
        {
            var actualHash = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(data));

            if (!string.Equals(
                    actualHash,
                    snapshot.Sha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS deletion snapshot recovery: hash mismatch. " +
                    $"path={candidate.FullPath}, expected={snapshot.Sha256}, actual={actualHash}.");
                return false;
            }
        }

        RecoveryDestinationPolicy.Validate(
            candidate.FullPath,
            destinationDirectory);

        var destinationPath =
            RecoveryDestinationPolicy.CreateSafeFilePath(
                destinationDirectory,
                candidate.Name);

        try
        {
            File.WriteAllBytes(destinationPath, data);
        }
        catch
        {
            try
            {
                if (File.Exists(destinationPath))
                {
                    File.Delete(destinationPath);
                }
            }
            catch
            {
                // Preserve the original write failure.
            }

            throw;
        }

        result = new RecoveryResult
        {
            Success = true,
            SourcePath = candidate.FullPath,
            DestinationPath = destinationPath,
            BytesRecovered = data.LongLength,
            Evidence =
                $"Recovered {data.LongLength:N0} byte(s) from an NTFS $DATA snapshot " +
                "captured immediately when the deletion was observed by the USN monitor."
        };

        System.Diagnostics.Debug.WriteLine(
            $"NTFS deletion snapshot recovery succeeded: path={candidate.FullPath}, " +
            $"bytes={data.LongLength:N0}, destination={destinationPath}.");

        return true;
    }

    private static bool TryRecoverFromHistoricalLogFileData(
        RecoveryCandidate candidate,
        string destinationDirectory,
        IProgress<string>? progress,
        CancellationToken cancellationToken,
        out RecoveryResult result)
    {
        result = new RecoveryResult();

        if (candidate.FileReferenceNumber == 0 ||
            candidate.ParentFileReferenceNumber == 0 ||
            string.IsNullOrWhiteSpace(candidate.FullPath) ||
            string.IsNullOrWhiteSpace(candidate.Name))
        {
            return false;
        }

        var sourceRoot = Path.GetPathRoot(candidate.FullPath);
        if (string.IsNullOrWhiteSpace(sourceRoot))
        {
            return false;
        }

        try
        {
            var service = new NtfsLogFileHistoricalDataService();
            const long maxCaptureBytes = int.MaxValue;

            progress?.Report(
                $"Preparing historical NTFS $LogFile recovery for {candidate.Name}...");

            if (!service.TryRecoverFileData(
                    sourceRoot,
                    candidate.FileReferenceNumber,
                    candidate.Name,
                    candidate.FileSizeBytes,
                    maxCaptureBytes,
                    out var data,
                    out var evidence,
                    progress,
                    cancellationToken) ||
                data.Length == 0)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS recovery-time $LogFile historical data MISS: " +
                    $"path={candidate.FullPath}, " +
                    $"fileRef={candidate.FileReferenceNumber}, " +
                    $"expectedSize={candidate.FileSizeBytes:N0}, " +
                    $"evidence={evidence}");
                return false;
            }

            if (candidate.FileSizeBytes > 0 &&
                data.LongLength != candidate.FileSizeBytes)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS recovery-time $LogFile historical data rejected for size mismatch: " +
                    $"path={candidate.FullPath}, " +
                    $"fileRef={candidate.FileReferenceNumber}, " +
                    $"candidateSize={candidate.FileSizeBytes:N0}, " +
                    $"recoveredSize={data.LongLength:N0}.");
                return false;
            }

            RecoveryDestinationPolicy.Validate(
                candidate.FullPath,
                destinationDirectory);

            var destinationPath =
                RecoveryDestinationPolicy.CreateSafeFilePath(
                    destinationDirectory,
                    candidate.Name);

            File.WriteAllBytes(destinationPath, data);

            candidate.FileSizeBytes = data.LongLength;

            result = new RecoveryResult
            {
                Success = true,
                SourcePath = candidate.FullPath,
                DestinationPath = destinationPath,
                BytesRecovered = data.LongLength,
                Evidence =
                    $"Recovered {data.LongLength:N0} byte(s) from exact NTFS $LogFile " +
                    $"historical reconstruction. {evidence}"
            };

            System.Diagnostics.Trace.WriteLine(
                $"NTFS recovery-time $LogFile historical data recovery succeeded: " +
                $"path={candidate.FullPath}, " +
                $"fileRef={candidate.FileReferenceNumber}, " +
                $"size={data.LongLength:N0}, " +
                $"destination={destinationPath}.");

            return true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS recovery-time $LogFile historical data recovery failed: " +
                $"path={candidate.FullPath}, " +
                $"fileRef={candidate.FileReferenceNumber}, " +
                $"exception={ex.GetType().Name}: {ex.Message}");
            return false;
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
        var vssHistoricalRecovery = new VssHistoricalFileRecoveryService();

        if (string.IsNullOrWhiteSpace(destinationDirectory))
        {
            failures.Add("Recovery destination was not selected.");
            return (successes, failures);
        }

        foreach (var candidate in candidates)
        {
            try
            {
                var vssEvidence = string.Empty;

                // An existing Volume Shadow Copy created before deletion is an
                // authoritative historical source. Try it before journal/file-record
                // reconstruction because it can preserve the complete file directly.
                if (candidate.FileReferenceNumber != 0 &&
                    candidate.ParentFileReferenceNumber != 0 &&
                    candidate.LastUsnTimestampUtc != default &&
                    vssHistoricalRecovery.TryRecoverFile(
                        candidate,
                        destinationDirectory,
                        out var vssRecovery,
                        out vssEvidence))
                {
                    successes.Add(vssRecovery);
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(vssEvidence))
                {
                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS VSS historical recovery unavailable: " +
                        $"path={candidate.FullPath}, " +
                        $"fileRef={candidate.FileReferenceNumber}, " +
                        $"reason={vssEvidence}");
                }

                // A complete delete-time NTFS snapshot is the highest-fidelity source for
                // a freshly deleted file. It was captured before later MFT generation reuse or
                // cluster reuse could change the bytes, so Recovery Center must consume it before
                // attempting any reconstructive source such as $LogFile.
                if (TryRecoverFromNtfsSnapshot(
                        candidate,
                        destinationDirectory,
                        out var snapshotRecovery))
                {
                    successes.Add(snapshotRecovery);
                    continue;
                }

                // The current MFT can be reused while exact historical
                // $LogFile transaction evidence still retains the original bytes.
                // Try that evidence before asking for a text marker. The historical
                // service validates the exact file reference and can infer the file
                // size from the same historical MFT generation when the normal
                // $FILE_NAME size is unavailable.
                if (!candidate.DataStreamFound &&
                    candidate.FileReferenceNumber != 0 &&
                    candidate.ParentFileReferenceNumber != 0)
                {
                    var historicalLogProgress =
                        new Progress<string>(message =>
                            SetBusy(
                                true,
                                message));

                    var historicalLogResult =
                        await Task.Run(
                            () =>
                            {
                                var recovered =
                                    TryRecoverFromHistoricalLogFileData(
                                        candidate,
                                        destinationDirectory,
                                        historicalLogProgress,
                                        CancellationToken.None,
                                        out var recoveryResult);

                                return (Recovered: recovered, Result: recoveryResult);
                            },
                            CancellationToken.None)
                            .ConfigureAwait(true);

                    if (historicalLogResult.Recovered)
                    {
                        successes.Add(historicalLogResult.Result);
                        continue;
                    }
                }

                if (candidate.DataStreamFound)
                {
                    successes.Add(_ntfsRecoveryService.Recover(
                        candidate,
                        destinationDirectory));
                    continue;
                }

                // Re-check the complete default NTFS $DATA stream at recovery time.
                // The scan can legitimately retain only metadata when the MFT record
                // changes between scan and recovery. When the trusted file reference,
                // parent reference and historical path still validate, recover directly
                // from the retained resident/nonresident $DATA stream before any heuristic
                // or carving path is considered.
                if (candidate.FileReferenceNumber != 0 &&
                    candidate.ParentFileReferenceNumber != 0)
                {
                    var directMftReader = new NtfsMftDataReader();
                    var directDataStream = new NtfsDataStreamInfo();

                    var directDataFound = directMftReader.TryReadDataStreamForDeletedReference(
                        candidate.FullPath,
                        candidate.FileReferenceNumber,
                        candidate.ParentFileReferenceNumber,
                        candidate.Name,
                        candidate.FullPath,
                        candidate.LastUsnTimestampUtc,
                        out directDataStream);

                    if (directDataFound &&
                        directDataStream.Found)
                    {
                        if (candidate.FileSizeBytes > 0 &&
                            directDataStream.FileSizeBytes > 0 &&
                            directDataStream.FileSizeBytes != candidate.FileSizeBytes)
                        {
                            System.Diagnostics.Debug.WriteLine(
                                $"NTFS recovery-time $DATA size mismatch: " +
                                $"path={candidate.FullPath}, candidateSize={candidate.FileSizeBytes:N0}, " +
                                $"streamSize={directDataStream.FileSizeBytes:N0}.");
                        }
                        else
                        {
                            var directCandidate = new RecoveryCandidate
                            {
                                FileReferenceNumber = candidate.FileReferenceNumber,
                                ParentFileReferenceNumber = candidate.ParentFileReferenceNumber,
                                Name = candidate.Name,
                                DirectoryPath = candidate.DirectoryPath,
                                LastUsnTimestampUtc = candidate.LastUsnTimestampUtc,
                                Strength = candidate.Strength,
                                Evidence = candidate.Evidence,
                                DataStreamFound = directDataStream.Found,
                                DataStreamResident = directDataStream.IsResident,
                                FileSizeBytes = directDataStream.FileSizeBytes,
                                ValidDataLengthBytes = directDataStream.ValidDataLengthBytes,
                                ResidentData = directDataStream.ResidentData,
                                DataExtents = directDataStream.Extents,
                                ExtentAllocations = [],
                                FreeDataClusterCount = 0,
                                AllocatedDataClusterCount = 0,
                                DataEvidence = directDataStream.Evidence
                            };

                            successes.Add(_ntfsRecoveryService.Recover(
                                directCandidate,
                                destinationDirectory));
                            continue;
                        }
                    }

                    if (!directDataFound)
                    {
                        System.Diagnostics.Debug.WriteLine(
                            $"NTFS recovery-time $DATA unavailable: " +
                            $"path={candidate.FullPath}, fileRef={candidate.FileReferenceNumber}, " +
                            $"parentRef={candidate.ParentFileReferenceNumber}, " +
                            $"candidateSize={candidate.FileSizeBytes:N0}, " +
                            $"reason={directDataStream.Evidence}");
                    }
                }

                // When the current MFT record has been reused, the deleted file's
                // nonresident $DATA attribute can still survive in MFT slack. Probe the
                // exact historical file reference directly before resident/slack fallbacks.
                if (candidate.FileReferenceNumber != 0 &&
                    candidate.ParentFileReferenceNumber != 0)
                {
                    var historicalNonResidentScanner = new MftCandidateScanner();

                    if (historicalNonResidentScanner.TryReadHistoricalNonResidentDataForReference(
                        candidate.FullPath,
                        candidate.FileReferenceNumber,
                        candidate.ParentFileReferenceNumber,
                        candidate.Name,
                        candidate.FileSizeBytes,
                        out var historicalNonResidentData) &&
                        historicalNonResidentData.Found &&
                        !historicalNonResidentData.IsResident &&
                        historicalNonResidentData.Extents.Count > 0)
                    {
                        var historicalCandidate = new RecoveryCandidate
                        {
                            FileReferenceNumber = candidate.FileReferenceNumber,
                            ParentFileReferenceNumber = candidate.ParentFileReferenceNumber,
                            Name = candidate.Name,
                            DirectoryPath = candidate.DirectoryPath,
                            LastUsnTimestampUtc = candidate.LastUsnTimestampUtc,
                            Strength = candidate.Strength,
                            Evidence = candidate.Evidence,
                            DataStreamFound = true,
                            DataStreamResident = false,
                            FileSizeBytes = historicalNonResidentData.FileSizeBytes,
                            ValidDataLengthBytes = historicalNonResidentData.ValidDataLengthBytes,
                            ResidentData = null,
                            DataExtents = historicalNonResidentData.Extents,
                            ExtentAllocations = [],
                            FreeDataClusterCount = 0,
                            AllocatedDataClusterCount = 0,
                            DataEvidence = historicalNonResidentData.Evidence
                        };

                        successes.Add(_ntfsRecoveryService.Recover(
                            historicalCandidate,
                            destinationDirectory));
                        continue;
                    }
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
                        candidate.LastUsnTimestampUtc,
                        out var freshResidentData) &&
                        freshResidentData.Length > 0)
                    {
                        if (candidate.FileSizeBytes > 0 &&
                            freshResidentData.LongLength != candidate.FileSizeBytes)
                        {
                            System.Diagnostics.Trace.WriteLine(
                                $"NTFS fresh resident recovery rejected for historical-size mismatch: " +
                                $"path={candidate.FullPath}, " +
                                $"candidateSize={candidate.FileSizeBytes:N0}, " +
                                $"residentBytes={freshResidentData.LongLength:N0}.");
                        }
                        else
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
                        if (candidate.FileSizeBytes > 0 &&
                            historicalData.LongLength != candidate.FileSizeBytes)
                        {
                            System.Diagnostics.Trace.WriteLine(
                                $"NTFS historical resident recovery rejected for historical-size mismatch: " +
                                $"path={candidate.FullPath}, " +
                                $"candidateSize={candidate.FileSizeBytes:N0}, " +
                                $"residentBytes={historicalData.LongLength:N0}.");
                        }
                        else
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
                }

                // Do not use generic allocated-file slack as a successful recovery source here.
                // It is not tied strongly enough to the deleted file's identity and can
                // return unrelated bytes from another live file in the same directory.
                // Continue to the marker-driven forensic or structural free-space recovery
                // paths instead. This keeps a successful result tied to the deleted
                // candidate rather than accepting a coincidental text-like slack prefix.

                // Plain text has no intrinsic file boundary, so it must never be
                // automatically accepted from arbitrary free clusters merely because the
                // candidate size is known. A known size alone can still match unrelated
                // live/deleted text such as an old source-file copy.
                // Require a distinctive user-supplied marker before whole-volume text
                // recovery is attempted.
                if (Path.GetExtension(candidate.Name).Equals(
                        ".txt",
                        StringComparison.OrdinalIgnoreCase))
                {
                    var markerKey = NormalizePath(candidate.FullPath);
                    string? forensicMarker = null;

                    if (!forensicMarkers.TryGetValue(markerKey, out forensicMarker) &&
                        !forensicMarkerDeclined.Contains(markerKey))
                    {
                        var enteredMarker = Microsoft.VisualBasic.Interaction.InputBox(
                            $"Enter a distinctive text string that you know was inside '{candidate.Name}'.\r\n\r\n" +
                            "This is the marker TEXT input, not a recovery confirmation. " +
                            "Type the exact text (at least 4 bytes) and click OK to start the full-volume forensic scan.\r\n\r\n" +
                            "Click Cancel, or click OK with an empty box, to skip the forensic scan.",
                            "Enter forensic marker",
                            "");

                        if (string.IsNullOrWhiteSpace(enteredMarker))
                        {
                            forensicMarkerDeclined.Add(markerKey);
                        }
                        else
                        {
                            forensicMarker = enteredMarker;
                            forensicMarkers[markerKey] = enteredMarker;
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(forensicMarker))
                    {
                        var wholeVolumeRoot = GetSourceVolumeRoot(candidate.FullPath);
                        if (string.IsNullOrWhiteSpace(wholeVolumeRoot))
                        {
                            failures.Add(
                                $"{candidate.Name}: the source volume could not be determined for the whole-volume forensic scan.");
                            continue;
                        }

                        var logMarkerService = new NtfsLogFileHistoricalDataService();

                        try
                        {
                            var markerFoundInLog = logMarkerService.TryFindMarkerInHistoricalLogFile(
                                wholeVolumeRoot,
                                forensicMarker,
                                out var logMarkerEvidence);

                            var proceedWithFullVolume = markerFoundInLog
                                ? MessageBox.Show(
                                    this,
                                    "The marker was found in NTFS $LogFile, but that only confirms a possible historical text fragment; it does not recover the complete file.\r\n\r\n" +
                                    "A separate raw-volume scan may still find the text in volume data. It reads the entire source volume and can take a long time.\r\n\r\n" +
                                    "Continue with the full-volume scan?",
                                    "Marker Found in NTFS $LogFile",
                                    MessageBoxButtons.YesNo,
                                    MessageBoxIcon.Warning,
                                    MessageBoxDefaultButton.Button2)
                                : MessageBox.Show(
                                    this,
                                    "The marker was not found in the retained NTFS $LogFile.\r\n\r\n" +
                                    "Starting the raw-volume forensic scan will read the entire source volume and can take a long time.\r\n\r\n" +
                                    "Start the full-volume scan now?",
                                    "Start Full-Volume Forensic Scan",
                                    MessageBoxButtons.YesNo,
                                    MessageBoxIcon.Question,
                                    MessageBoxDefaultButton.Button2);

                            if (proceedWithFullVolume != DialogResult.Yes)
                            {
                                failures.Add(
                                    $"{candidate.Name}: raw-volume marker scan was skipped by the user. " +
                                    $"markerFoundInLog={markerFoundInLog}; {logMarkerEvidence}");
                                continue;
                            }
                        }
                        catch (Exception ex)
                        {
                            var proceedWithFullVolume = MessageBox.Show(
                                this,
                                $"The NTFS $LogFile marker diagnostic failed:\r\n\r\n{ex.Message}\r\n\r\n" +
                                "Start the raw-volume forensic scan anyway?",
                                "NTFS $LogFile Marker Diagnostic Failed",
                                MessageBoxButtons.YesNo,
                                MessageBoxIcon.Warning,
                                MessageBoxDefaultButton.Button2);

                            if (proceedWithFullVolume != DialogResult.Yes)
                            {
                                failures.Add(
                                    $"{candidate.Name}: the NTFS $LogFile marker diagnostic failed and the full-volume forensic scan was skipped: {ex.Message}");
                                continue;
                            }
                        }

                        var totalVolumeBytes = new DriveInfo(wholeVolumeRoot).TotalSize;
                        var forensicProgress = new SynchronousProgress<long>(
                            this,
                            bytesScanned =>
                            {
                                lblStatus.Text =
                                    $"Forensic full-volume scan for {candidate.Name}... " +
                                    $"{bytesScanned / (1024d * 1024d * 1024d):0.00} / " +
                                    $"{totalVolumeBytes / (1024d * 1024d * 1024d):0.00} GB scanned";
                            });

                        try
                        {
                            forensicProgress.Report(0);

                            var forensicRecovery = _ntfsWholeVolumeTextRecoveryService.Recover(
                                candidate,
                                destinationDirectory,
                                forensicMarker,
                                CancellationToken.None,
                                forensicProgress);

                            successes.Add(forensicRecovery);
                            continue;
                        }
                        catch (Exception ex)
                        {
                            failures.Add(
                                $"{candidate.Name}: whole-volume forensic scan failed: {ex.Message}");
                            continue;
                        }
                    }
                }

                // Plain-text recovery is handled only by the marker-driven path above.
                // Never fall through to generic free-space carving for .txt candidates.
                if (Path.GetExtension(candidate.Name).Equals(
                        ".txt",
                        StringComparison.OrdinalIgnoreCase))
                {
                    failures.Add(
                        forensicMarkerDeclined.Contains(NormalizePath(candidate.FullPath))
                            ? candidate.FileSizeBytes > 0
                                ? $"{candidate.Name}: no retained NTFS $DATA evidence was available for the known " +
                                  $"{candidate.FileSizeBytes:N0}-byte file, and the marker-driven forensic scan was skipped. " +
                                  "Enter a distinctive marker from the deleted file to search the raw volume."
                                : $"{candidate.Name}: no retained NTFS $DATA evidence was available and the forensic marker scan " +
                                  "was skipped. Provide a distinctive marker from the deleted file."
                            : candidate.FileSizeBytes > 0
                                ? $"{candidate.Name}: no retained NTFS $DATA evidence was available for the known " +
                                  $"{candidate.FileSizeBytes:N0}-byte file; the marker-driven forensic recovery did not produce a result."
                                : $"{candidate.Name}: no retained NTFS $DATA evidence was available; the marker-driven forensic " +
                                  "recovery did not produce a result.");
                    continue;
                }

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
                    CancellationToken.None,
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

                var clipboardDiagnostic =
                    $"AlgoLassi NTFS RECOVERY FAILED/RESULT" +
                    Environment.NewLine +
                    $"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}" +
                    Environment.NewLine +
                    $"Destination: {destinationDirectory}" +
                    Environment.NewLine +
                    Environment.NewLine +
                    message;

                System.Diagnostics.Trace.WriteLine(
                    Environment.NewLine +
                    "========== ALGOLASSI RECOVERY RESULT ==========" +
                    Environment.NewLine +
                    clipboardDiagnostic +
                    Environment.NewLine +
                    "========== END ALGOLASSI RECOVERY RESULT ==========");

                try
                {
                    Clipboard.SetText(clipboardDiagnostic);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Trace.WriteLine(
                        $"AlgoLassi recovery clipboard copy failed: {ex.GetType().Name}: {ex.Message}");
                }

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
        btnManageIgnoredDirectories.Enabled = !busy;
        txtScanPath.Enabled = !busy;
        btnBrowseScanPath.Enabled = !busy;
        chkScanSubdirectories.Enabled = !busy;
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

    private static string? GetSourceVolumeRoot(string path)
    {
        var normalized = path.Trim();

        while (normalized.StartsWith(@"\\?\", StringComparison.Ordinal) ||
               normalized.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }

        return Path.GetPathRoot(normalized);
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