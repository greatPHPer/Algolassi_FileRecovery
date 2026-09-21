namespace FileRecovery;

public partial class Form1 : Form
{
    private readonly RecycleBinService _recycleBinService = new();
    private List<RecoveryItem> _items = [];

    public Form1()
    {
        InitializeComponent();
    }

    private void Form1_Load(object? sender, EventArgs e)
    {
        dgvResults.DataSource = new List<RecoveryItem>();
        btnRestore.Enabled = false;
    }

    private void btnScan_Click(object? sender, EventArgs e)
    {
        SetBusy(true, "Scanning the Windows Recycle Bin...");

        try
        {
            _items = _recycleBinService.Scan().ToList();
            dgvResults.DataSource = _items;
            lblStatus.Text = _items.Count == 0
                ? "No items are currently available in the Recycle Bin."
                : $"Found {_items.Count:N0} item(s). Select one or more items to restore.";
        }
        catch (Exception ex)
        {
            dgvResults.DataSource = new List<RecoveryItem>();
            MessageBox.Show(
                this,
                ex.Message,
                "Recycle Bin Scan Failed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            lblStatus.Text = "Scan failed. Please try again.";
        }
        finally
        {
            SetBusy(false);
            UpdateRestoreButton();
        }
    }

    private void btnRestore_Click(object? sender, EventArgs e)
    {
        var selectedItems = dgvResults.SelectedRows
            .Cast<DataGridViewRow>()
            .Select(row => row.DataBoundItem as RecoveryItem)
            .Where(item => item is not null)
            .Cast<RecoveryItem>()
            .ToList();

        if (selectedItems.Count == 0)
        {
            return;
        }

        var answer = MessageBox.Show(
            this,
            $"Restore {selectedItems.Count:N0} selected item(s) to their original locations?",
            "Confirm Restore",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (answer != DialogResult.Yes)
        {
            return;
        }

        SetBusy(true, "Restoring selected item(s)...");
        int restored = 0;
        var failures = new List<string>();

        try
        {
            foreach (var item in selectedItems)
            {
                try
                {
                    _recycleBinService.Restore(item);
                    restored++;
                }
                catch (Exception ex)
                {
                    failures.Add($"{item.Name}: {ex.Message}");
                }
            }

            var message = $"Restored: {restored:N0}";
            if (failures.Count > 0)
            {
                message += Environment.NewLine + Environment.NewLine
                    + string.Join(Environment.NewLine, failures.Take(5));
                if (failures.Count > 5)
                {
                    message += Environment.NewLine + $"...and {failures.Count - 5:N0} more.";
                }

                MessageBox.Show(this, message, "Restore Results", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }

            lblStatus.Text = failures.Count == 0
                ? $"{message}. Rescanning..."
                : $"{message}. Rescanning...";
        }
        finally
        {
            SetBusy(false);
            btnScan.PerformClick();
        }
    }

    private void dgvResults_SelectionChanged(object? sender, EventArgs e)
    {
        UpdateRestoreButton();
    }

    private void UpdateRestoreButton()
    {
        btnRestore.Enabled = !IsBusy && dgvResults.SelectedRows.Count > 0;
    }

    private void SetBusy(bool busy, string? status = null)
    {
        btnScan.Enabled = !busy;
        dgvResults.Enabled = !busy;
        btnRestore.Enabled = !busy && dgvResults.SelectedRows.Count > 0;
        UseWaitCursor = busy;

        if (!string.IsNullOrWhiteSpace(status))
        {
            lblStatus.Text = status;
        }
    }

    private bool IsBusy => !btnScan.Enabled;
}