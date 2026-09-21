#nullable enable

namespace FileRecovery;

partial class Form1
{
    private System.ComponentModel.IContainer? components = null;
    private Label lblTitle = null!;
    private Label lblSubtitle = null!;
    private Label lblDirectories = null!;
    private ListBox lstDirectories = null!;
    private Button btnScanDirectory = null!;
    private Button btnScanNtfs = null!;
    private Button btnShowHistory = null!;
    private Button btnClearHistory = null!;
    private Label lblFiles = null!;
    private DataGridView dgvResults = null!;
    private DataGridViewTextBoxColumn colName = null!;
    private DataGridViewTextBoxColumn colDeleted = null!;
    private DataGridViewTextBoxColumn colSize = null!;
    private DataGridViewTextBoxColumn colStrength = null!;
    private DataGridViewTextBoxColumn colEvidence = null!;
    private Button btnRecover = null!;
    private Label lblStatus = null!;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            components?.Dispose();
        }

        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        components = new System.ComponentModel.Container();
        lblTitle = new Label();
        lblSubtitle = new Label();
        lblDirectories = new Label();
        lstDirectories = new ListBox();
        btnScanDirectory = new Button();
        btnScanNtfs = new Button();
        btnShowHistory = new Button();
        btnClearHistory = new Button();
        lblFiles = new Label();
        dgvResults = new DataGridView();
        colName = new DataGridViewTextBoxColumn();
        colDeleted = new DataGridViewTextBoxColumn();
        colSize = new DataGridViewTextBoxColumn();
        colStrength = new DataGridViewTextBoxColumn();
        colEvidence = new DataGridViewTextBoxColumn();
        btnRecover = new Button();
        lblStatus = new Label();

        ((System.ComponentModel.ISupportInitialize)dgvResults).BeginInit();
        SuspendLayout();

        lblTitle.AutoSize = true;
        lblTitle.Font = new Font("Segoe UI", 18F, FontStyle.Bold);
        lblTitle.Location = new Point(24, 18);
        lblTitle.Name = "lblTitle";
        lblTitle.Size = new Size(286, 32);
        lblTitle.Text = "AlgoLassi File Recovery";

        lblSubtitle.AutoSize = true;
        lblSubtitle.ForeColor = Color.DimGray;
        lblSubtitle.Location = new Point(27, 56);
        lblSubtitle.Size = new Size(730, 15);
        lblSubtitle.Text = "Resident monitoring is active in the system tray. Select a recent deletion location to inspect recoverable items.";

        lblDirectories.AutoSize = true;
        lblDirectories.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
        lblDirectories.Location = new Point(24, 94);
        lblDirectories.Size = new Size(164, 19);
        lblDirectories.Text = "Recent directories";

        lstDirectories.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left;
        lstDirectories.FormattingEnabled = true;
        lstDirectories.HorizontalScrollbar = true;
        lstDirectories.IntegralHeight = false;
        lstDirectories.ItemHeight = 20;
        lstDirectories.Location = new Point(24, 122);
        lstDirectories.Name = "lstDirectories";
        lstDirectories.Size = new Size(300, 447);
        lstDirectories.SelectedIndexChanged += lstDirectories_SelectedIndexChanged;

        btnScanDirectory.Location = new Point(344, 82);
        btnScanDirectory.Size = new Size(190, 36);
        btnScanDirectory.Text = "Scan Recycle Bin";
        btnScanDirectory.UseVisualStyleBackColor = true;
        btnScanDirectory.Click += btnScanDirectory_Click;

        btnScanNtfs.Location = new Point(344, 122);
        btnScanNtfs.Size = new Size(190, 36);
        btnScanNtfs.Text = "Scan NTFS Deleted Files";
        btnScanNtfs.UseVisualStyleBackColor = true;
        btnScanNtfs.Click += btnScanNtfs_Click;

        btnShowHistory.Location = new Point(546, 82);
        btnShowHistory.Size = new Size(170, 36);
        btnShowHistory.Text = "Show Delete History";
        btnShowHistory.UseVisualStyleBackColor = true;
        btnShowHistory.Click += btnShowHistory_Click;

        btnClearHistory.Location = new Point(728, 82);
        btnClearHistory.Size = new Size(132, 36);
        btnClearHistory.Text = "Clear History";
        btnClearHistory.UseVisualStyleBackColor = true;
        btnClearHistory.Click += btnClearHistory_Click;

        lblFiles.AutoSize = true;
        lblFiles.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
        lblFiles.Location = new Point(344, 171);
        lblFiles.Size = new Size(113, 19);
        lblFiles.Text = "Deleted files";

        dgvResults.AllowUserToAddRows = false;
        dgvResults.AllowUserToDeleteRows = false;
        dgvResults.AllowUserToResizeRows = false;
        dgvResults.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        dgvResults.AutoGenerateColumns = false;
        dgvResults.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        dgvResults.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
        dgvResults.Columns.AddRange(new DataGridViewColumn[] { colName, colDeleted, colSize, colStrength, colEvidence });
        dgvResults.Location = new Point(344, 199);
        dgvResults.MultiSelect = true;
        dgvResults.Name = "dgvResults";
        dgvResults.ReadOnly = true;
        dgvResults.RowHeadersVisible = false;
        dgvResults.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        dgvResults.Size = new Size(662, 408);
        dgvResults.SelectionChanged += dgvResults_SelectionChanged;

        colName.DataPropertyName = "Name";
        colName.HeaderText = "Filename";
        colName.MinimumWidth = 180;
        colName.FillWeight = 33F;

        colDeleted.DataPropertyName = "DeletedOn";
        colDeleted.HeaderText = "Deleted on";
        colDeleted.MinimumWidth = 150;
        colDeleted.FillWeight = 25F;

        colSize.DataPropertyName = "FileSize";
        colSize.HeaderText = "Filesize";
        colSize.MinimumWidth = 90;
        colSize.FillWeight = 15F;

        colStrength.DataPropertyName = "RecoveryStrength";
        colStrength.HeaderText = "Recovery strength";
        colStrength.MinimumWidth = 130;
        colStrength.FillWeight = 16F;

        colEvidence.DataPropertyName = "Evidence";
        colEvidence.HeaderText = "Evidence";
        colEvidence.MinimumWidth = 220;
        colEvidence.FillWeight = 30F;

        btnRecover.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        btnRecover.Enabled = false;
        btnRecover.Location = new Point(846, 582);
        btnRecover.Size = new Size(160, 36);
        btnRecover.Text = "Restore Selected";
        btnRecover.UseVisualStyleBackColor = true;
        btnRecover.Click += btnRecover_Click;

        lblStatus.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        lblStatus.AutoEllipsis = true;
        lblStatus.ForeColor = Color.DimGray;
        lblStatus.Location = new Point(24, 589);
        lblStatus.Size = new Size(805, 24);
        lblStatus.Text = "Monitoring status: starting...";

        AutoScaleDimensions = new SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(1030, 635);
        Controls.Add(lblStatus);
        Controls.Add(btnRecover);
        Controls.Add(dgvResults);
        Controls.Add(lblFiles);
        Controls.Add(btnClearHistory);
        Controls.Add(btnShowHistory);
        Controls.Add(btnScanNtfs);
        Controls.Add(btnScanDirectory);
        Controls.Add(lstDirectories);
        Controls.Add(lblDirectories);
        Controls.Add(lblSubtitle);
        Controls.Add(lblTitle);
        MinimumSize = new Size(860, 560);
        Name = "Form1";
        StartPosition = FormStartPosition.CenterScreen;
        Text = "AlgoLassi File Recovery";
        FormClosing += Form1_FormClosing;
        Load += Form1_Load;

        ((System.ComponentModel.ISupportInitialize)dgvResults).EndInit();
        ResumeLayout(false);
        PerformLayout();
    }
}
