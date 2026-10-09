namespace FileRecovery;

public sealed class ProtectedFoldersForm : Form
{
    private const decimal BytesPerGiB = 1024m * 1024m * 1024m;

    private readonly ListBox _directories;
    private readonly Button _removeButton;
    private readonly TextBox _storagePath;
    private readonly NumericUpDown _maximumFileSizeGiB;
    private readonly NumericUpDown _totalStorageLimitGiB;

    public IReadOnlyList<string> ProtectedDirectories =>
        _directories.Items.Cast<string>().ToList();

    public string StorageDirectory => _storagePath.Text.Trim();

    public long MaximumFileSizeBytes =>
        checked((long)(_maximumFileSizeGiB.Value * BytesPerGiB));

    public long TotalStorageLimitBytes =>
        checked((long)(_totalStorageLimitGiB.Value * BytesPerGiB));

    public ProtectedFoldersForm(
        IEnumerable<string> directories,
        string storageDirectory,
        long maximumFileSizeBytes,
        long totalStorageLimitBytes)
    {
        Text = "Manage Pre-delete Protected Folders";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimizeBox = false;
        MaximizeBox = false;
        MinimumSize = new Size(710, 570);
        ClientSize = new Size(780, 620);

        var instructions = new Label
        {
            AutoSize = false,
            Location = new Point(16, 14),
            Size = new Size(748, 68),
            Text =
                "Choose folders where AlgoLassi should keep rolling copies of files before deletion. " +
                "Files are captured with streamed I/O, not one giant memory buffer. " +
                "Protection is best-effort and is not a substitute for a separate backup."
        };

        var storageLabel = new Label
        {
            AutoSize = true,
            Location = new Point(16, 91),
            Text = "Protected storage location (prefer another physical drive)"
        };

        _storagePath = new TextBox
        {
            Location = new Point(16, 115),
            Size = new Size(610, 28),
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
            ReadOnly = true,
            Text = string.IsNullOrWhiteSpace(storageDirectory)
                ? new RecoverySettings().EffectivePreDeleteStorageDirectory
                : Path.GetFullPath(storageDirectory)
        };

        var browseStorageButton = new Button
        {
            Location = new Point(636, 113),
            Size = new Size(128, 32),
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
            Text = "Choose location..."
        };
        browseStorageButton.Click += (_, _) => ChooseStorageDirectory();

        var maxFileLabel = new Label
        {
            AutoSize = true,
            Location = new Point(16, 157),
            Text = "Maximum individual file size"
        };

        _maximumFileSizeGiB = new NumericUpDown
        {
            Location = new Point(16, 181),
            Size = new Size(120, 28),
            Minimum = 1,
            Maximum = 1024,
            Increment = 1,
            DecimalPlaces = 0,
            Value = ToGiBCeiling(maximumFileSizeBytes, 10)
        };

        var maxFileUnit = new Label
        {
            AutoSize = true,
            Location = new Point(144, 185),
            Text = "GiB per file"
        };

        var totalLimitLabel = new Label
        {
            AutoSize = true,
            Location = new Point(380, 157),
            Text = "Total protected-storage limit"
        };

        _totalStorageLimitGiB = new NumericUpDown
        {
            Location = new Point(380, 181),
            Size = new Size(120, 28),
            Minimum = 1,
            Maximum = 4096,
            Increment = 1,
            DecimalPlaces = 0,
            Value = ToGiBCeiling(totalStorageLimitBytes, 50)
        };
        _totalStorageLimitGiB.ValueChanged += (_, _) => ClampIndividualFileLimit();

        var totalLimitUnit = new Label
        {
            AutoSize = true,
            Location = new Point(508, 185),
            Text = "GiB total"
        };

        var storageWarning = new Label
        {
            AutoSize = false,
            Location = new Point(16, 219),
            Size = new Size(748, 47),
            Text =
                "The total limit includes both the rolling cache and preserved snapshots. When full, new protection is skipped " +
                "rather than deleting existing recoverable copies. Files exceeding the individual limit are not protected."
        };

        var directoriesLabel = new Label
        {
            AutoSize = true,
            Location = new Point(16, 273),
            Text = "Folders to protect"
        };

        var addButton = new Button
        {
            Location = new Point(16, 296),
            Size = new Size(140, 32),
            Text = "Add folder..."
        };
        addButton.Click += (_, _) => AddFolder();

        _removeButton = new Button
        {
            Location = new Point(166, 296),
            Size = new Size(150, 32),
            Text = "Remove selected"
        };
        _removeButton.Click += (_, _) => RemoveSelectedFolder();

        _directories = new ListBox
        {
            Location = new Point(16, 339),
            Size = new Size(748, 205),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
            HorizontalScrollbar = true
        };

        var saveButton = new Button
        {
            Location = new Point(504, 565),
            Size = new Size(125, 34),
            Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
            Text = "Save"
        };
        saveButton.Click += (_, _) => SaveSettings();

        var cancelButton = new Button
        {
            Location = new Point(639, 565),
            Size = new Size(125, 34),
            Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
            Text = "Cancel",
            DialogResult = DialogResult.Cancel
        };

        Controls.Add(instructions);
        Controls.Add(storageLabel);
        Controls.Add(_storagePath);
        Controls.Add(browseStorageButton);
        Controls.Add(maxFileLabel);
        Controls.Add(_maximumFileSizeGiB);
        Controls.Add(maxFileUnit);
        Controls.Add(totalLimitLabel);
        Controls.Add(_totalStorageLimitGiB);
        Controls.Add(totalLimitUnit);
        Controls.Add(storageWarning);
        Controls.Add(directoriesLabel);
        Controls.Add(addButton);
        Controls.Add(_removeButton);
        Controls.Add(_directories);
        Controls.Add(saveButton);
        Controls.Add(cancelButton);

        AcceptButton = saveButton;
        CancelButton = cancelButton;

        foreach (var directory in NormalizeDirectories(directories))
        {
            _directories.Items.Add(directory);
        }

        ClampIndividualFileLimit();
        UpdateButtons();
    }

    private void ChooseStorageDirectory()
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Choose a folder with enough free space for rolling copies and preserved snapshots",
            ShowNewFolderButton = true,
            SelectedPath = Directory.Exists(_storagePath.Text)
                ? _storagePath.Text
                : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
        };

        if (dialog.ShowDialog(this) == DialogResult.OK &&
            !string.IsNullOrWhiteSpace(dialog.SelectedPath))
        {
            _storagePath.Text = Path.GetFullPath(dialog.SelectedPath.Trim());
        }
    }

    private void ClampIndividualFileLimit()
    {
        var maxAllowed = Math.Min(1024m, _totalStorageLimitGiB.Value);
        _maximumFileSizeGiB.Maximum = Math.Max(1m, maxAllowed);

        if (_maximumFileSizeGiB.Value > _maximumFileSizeGiB.Maximum)
        {
            _maximumFileSizeGiB.Value = _maximumFileSizeGiB.Maximum;
        }
    }

    private void SaveSettings()
    {
        if (string.IsNullOrWhiteSpace(_storagePath.Text) ||
            !Directory.Exists(_storagePath.Text))
        {
            MessageBox.Show(
                this,
                "Choose an existing storage folder before saving.",
                "Storage Location Required",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(_storagePath.Text));
            if (!string.IsNullOrWhiteSpace(root) &&
                string.Equals(
                    Path.TrimEndingDirectorySeparator(root),
                    Path.TrimEndingDirectorySeparator(_storagePath.Text),
                    StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show(
                    this,
                    "Choose a folder on the drive, not the entire drive root.",
                    "Choose a Specific Folder",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            // Confirm that the selected folder can be written. The service performs
            // a second check when applying settings because storage may change.
            var probe = Path.Combine(
                _storagePath.Text,
                $".algolassi-write-test-{Environment.ProcessId}-{Guid.NewGuid():N}.tmp");
            using (new FileStream(
                       probe,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       1,
                       FileOptions.DeleteOnClose))
            {
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                $"The selected storage folder is not writable: {ex.Message}",
                "Storage Location Unavailable",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        DialogResult = DialogResult.OK;
        Close();
    }

    private void AddFolder()
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "Select a folder to protect against accidental deletion",
            ShowNewFolderButton = true
        };

        if (dialog.ShowDialog(this) != DialogResult.OK ||
            string.IsNullOrWhiteSpace(dialog.SelectedPath))
        {
            return;
        }

        string normalized;
        try
        {
            normalized = Path.GetFullPath(dialog.SelectedPath.Trim())
                .TrimEnd(Path.DirectorySeparatorChar);
        }
        catch
        {
            MessageBox.Show(
                this,
                "The selected folder path is invalid.",
                "Folder Not Added",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var root = Path.GetPathRoot(normalized);
        if (!Directory.Exists(normalized) ||
            string.IsNullOrWhiteSpace(root) ||
            string.Equals(
                Path.TrimEndingDirectorySeparator(normalized),
                Path.TrimEndingDirectorySeparator(root),
                StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show(
                this,
                "Select a specific folder, not an entire drive.",
                "Folder Not Added",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (RecoveryMonitoringExclusions.IsExcludedPath(normalized))
        {
            MessageBox.Show(
                this,
                "This folder is ignored by AlgoLassi or is inside its own internal storage. Choose a different folder.",
                "Folder Not Added",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (_directories.Items.Cast<string>().Any(existing =>
                string.Equals(existing, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            MessageBox.Show(
                this,
                "That folder is already protected.",
                "Folder Already Added",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        _directories.Items.Add(normalized);
        UpdateButtons();
    }

    private void RemoveSelectedFolder()
    {
        if (_directories.SelectedItem is not string selected)
        {
            return;
        }

        _directories.Items.Remove(selected);
        UpdateButtons();
    }

    private void UpdateButtons() =>
        _removeButton.Enabled = _directories.SelectedIndex >= 0;

    private static decimal ToGiBCeiling(long bytes, decimal fallback)
    {
        if (bytes <= 0)
        {
            return fallback;
        }

        var value = Math.Ceiling(bytes / BytesPerGiB);
        return Math.Clamp(value, 1m, 4096m);
    }

    private static IEnumerable<string> NormalizeDirectories(IEnumerable<string> directories)
    {
        var result = new List<string>();

        foreach (var path in directories)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            try
            {
                var normalized = Path.GetFullPath(path.Trim())
                    .TrimEnd(Path.DirectorySeparatorChar);
                if (Directory.Exists(normalized) &&
                    !RecoveryMonitoringExclusions.IsExcludedPath(normalized) &&
                    !result.Any(existing =>
                        string.Equals(existing, normalized, StringComparison.OrdinalIgnoreCase)))
                {
                    result.Add(normalized);
                }
            }
            catch
            {
                // Ignore stale/invalid persisted paths in the editor.
            }
        }

        return result.OrderBy(path => path, StringComparer.OrdinalIgnoreCase);
    }
}