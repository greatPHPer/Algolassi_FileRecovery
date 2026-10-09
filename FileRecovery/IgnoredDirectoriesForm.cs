namespace FileRecovery;

public sealed class IgnoredDirectoriesForm : Form
{
    private readonly TextBox _pathInput;
    private readonly ListBox _directories;
    private readonly Button _addButton;
    private readonly Button _removeButton;
    private readonly Button _closeButton;

    public IgnoredDirectoriesForm()
    {
        Text = "Manage Ignored Directories";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimizeBox = false;
        MaximizeBox = false;
        MinimumSize = new Size(560, 380);
        ClientSize = new Size(620, 430);

        var instructions = new Label
        {
            AutoSize = false,
            Location = new Point(16, 14),
            Size = new Size(588, 42),
            Text =
                "Ignored directories and their subdirectories are excluded from automatic deletion monitoring and new history entries. " +
                "Previously saved history is hidden while a path is ignored and can reappear if you remove the exclusion."
        };

        _pathInput = new TextBox
        {
            Location = new Point(16, 65),
            Size = new Size(470, 27),
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right,
            PlaceholderText = @"Enter a full directory path, e.g. C:\ProgramData\McAfee\WPs"
        };
        _pathInput.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                AddDirectory();
            }
        };

        _addButton = new Button
        {
            Location = new Point(494, 63),
            Size = new Size(110, 30),
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
            Text = "Add directory"
        };
        _addButton.Click += (_, _) => AddDirectory();

        _directories = new ListBox
        {
            Location = new Point(16, 106),
            Size = new Size(588, 244),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
            HorizontalScrollbar = true
        };

        _removeButton = new Button
        {
            Location = new Point(16, 366),
            Size = new Size(155, 32),
            Anchor = AnchorStyles.Bottom | AnchorStyles.Left,
            Text = "Remove selected"
        };
        _removeButton.Click += (_, _) => RemoveSelectedDirectory();

        _closeButton = new Button
        {
            Location = new Point(504, 366),
            Size = new Size(100, 32),
            Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
            Text = "Close",
            DialogResult = DialogResult.OK
        };
        _closeButton.Click += (_, _) => Close();

        Controls.Add(instructions);
        Controls.Add(_pathInput);
        Controls.Add(_addButton);
        Controls.Add(_directories);
        Controls.Add(_removeButton);
        Controls.Add(_closeButton);

        AcceptButton = _addButton;
        CancelButton = _closeButton;

        RefreshDirectories();
    }

    private void AddDirectory()
    {
        var enteredPath = _pathInput.Text.Trim();
        if (string.IsNullOrWhiteSpace(enteredPath) ||
            !Path.IsPathFullyQualified(enteredPath))
        {
            MessageBox.Show(
                this,
                "Enter a full directory path, such as C:\\ProgramData\\McAfee\\WPs.",
                "Invalid Directory Path",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        string normalizedPath;
        try
        {
            normalizedPath = Path.GetFullPath(enteredPath);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                $"The directory path is invalid: {ex.Message}",
                "Invalid Directory Path",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var root = Path.GetPathRoot(normalizedPath);
        if (!string.IsNullOrWhiteSpace(root) &&
            string.Equals(
                Path.TrimEndingDirectorySeparator(normalizedPath),
                Path.TrimEndingDirectorySeparator(root),
                StringComparison.OrdinalIgnoreCase))
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

        if (!RecoveryMonitoringExclusions.AddIgnoredDirectory(normalizedPath))
        {
            MessageBox.Show(
                this,
                "This directory is already ignored, or the path cannot be added. Check the path and try again.",
                "Directory Not Added",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        _pathInput.Clear();
        RefreshDirectories();
    }

    private void RemoveSelectedDirectory()
    {
        if (_directories.SelectedItem is not string selectedPath)
        {
            MessageBox.Show(
                this,
                "Select an ignored directory first.",
                "No Directory Selected",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        var confirm = MessageBox.Show(
            this,
            $"Stop ignoring this directory and its subdirectories?\r\n\r\n{selectedPath}\r\n\r\n" +
            "Future deletion events under this path will be monitored again.",
            "Remove Directory Exclusion",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button2);

        if (confirm != DialogResult.Yes)
        {
            return;
        }

        RecoveryMonitoringExclusions.RemoveIgnoredDirectory(selectedPath);
        RefreshDirectories();
    }

    private void RefreshDirectories()
    {
        _directories.BeginUpdate();
        try
        {
            _directories.Items.Clear();
            foreach (var path in RecoveryMonitoringExclusions.GetIgnoredDirectories())
            {
                _directories.Items.Add(path);
            }
        }
        finally
        {
            _directories.EndUpdate();
        }

        _removeButton.Enabled = _directories.Items.Count > 0;
    }
}
