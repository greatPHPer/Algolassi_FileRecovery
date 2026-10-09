namespace FileRecovery;

public sealed class ProtectedFoldersForm : Form
{
    private readonly ListBox _directories;
    private readonly Button _removeButton;

    public IReadOnlyList<string> ProtectedDirectories =>
        _directories.Items.Cast<string>().ToList();

    public ProtectedFoldersForm(IEnumerable<string> directories)
    {
        Text = "Manage Pre-delete Protected Folders";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimizeBox = false;
        MaximizeBox = false;
        MinimumSize = new Size(600, 400);
        ClientSize = new Size(700, 470);

        var instructions = new Label
        {
            AutoSize = false,
            Location = new Point(16, 14),
            Size = new Size(668, 76),
            Text =
                "Choose folders where AlgoLassi should keep rolling copies of eligible files before deletion. " +
                "Selected folders are scanned when monitoring starts and watched for changes. " +
                "Files larger than 25 MB are skipped; the local cache is limited to 512 MB and entries expire after 7 days. " +
                "Protection is best-effort, not a guarantee against every fast write/delete sequence."
        };

        var addButton = new Button
        {
            Location = new Point(16, 102),
            Size = new Size(140, 32),
            Text = "Add folder..."
        };
        addButton.Click += (_, _) => AddFolder();

        _removeButton = new Button
        {
            Location = new Point(166, 102),
            Size = new Size(150, 32),
            Text = "Remove selected"
        };
        _removeButton.Click += (_, _) => RemoveSelectedFolder();

        _directories = new ListBox
        {
            Location = new Point(16, 146),
            Size = new Size(668, 244),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
            HorizontalScrollbar = true
        };

        var saveButton = new Button
        {
            Location = new Point(424, 414),
            Size = new Size(125, 34),
            Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
            Text = "Save",
            DialogResult = DialogResult.OK
        };

        var cancelButton = new Button
        {
            Location = new Point(559, 414),
            Size = new Size(125, 34),
            Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
            Text = "Cancel",
            DialogResult = DialogResult.Cancel
        };

        Controls.Add(instructions);
        Controls.Add(addButton);
        Controls.Add(_removeButton);
        Controls.Add(_directories);
        Controls.Add(saveButton);
        Controls.Add(cancelButton);

        AcceptButton = saveButton;
        CancelButton = cancelButton;

        foreach (var path in NormalizeDirectories(directories))
        {
            _directories.Items.Add(path);
        }

        UpdateButtons();
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
                var normalized = Path.GetFullPath(path.Trim());
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