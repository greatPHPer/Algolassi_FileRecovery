namespace FileRecovery;

partial class Form1
{
    private System.ComponentModel.IContainer? components = null;
    private Label lblTitle = null!;
    private Label lblDescription = null!;
    private Button btnScan = null!;
    private Button btnRestore = null!;
    private DataGridView dgvResults = null!;
    private DataGridViewTextBoxColumn colName = null!;
    private DataGridViewTextBoxColumn colOriginalLocation = null!;
    private DataGridViewTextBoxColumn colDeleted = null!;
    private DataGridViewTextBoxColumn colSize = null!;
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
        lblDescription = new Label();
        btnScan = new Button();
        btnRestore = new Button();
        dgvResults = new DataGridView();
        colName = new DataGridViewTextBoxColumn();
        colOriginalLocation = new DataGridViewTextBoxColumn();
        colDeleted = new DataGridViewTextBoxColumn();
        colSize = new DataGridViewTextBoxColumn();
        lblStatus = new Label();
        ((System.ComponentModel.ISupportInitialize)dgvResults).BeginInit();
        SuspendLayout();

        lblTitle.AutoSize = true;
        lblTitle.Font = new Font("Segoe UI", 18F, FontStyle.Bold);
        lblTitle.Location = new Point(24, 20);
        lblTitle.Name = "lblTitle";
        lblTitle.Size = new Size(260, 32);
        lblTitle.Text = "AlgoLassi File Recovery";

        lblDescription.AutoSize = true;
        lblDescription.Font = new Font("Segoe UI", 9.5F);
        lblDescription.Location = new Point(27, 59);
        lblDescription.Size = new Size(640, 34);
        lblDescription.Text = "v0.1 scans the Windows Recycle Bin and restores selected items using the Windows Shell.";

        btnScan.Location = new Point(24, 105);
        btnScan.Name = "btnScan";
        btnScan.Size = new Size(145, 36);
        btnScan.Text = "Scan Recycle Bin";
        btnScan.UseVisualStyleBackColor = true;
        btnScan.Click += btnScan_Click;

        btnRestore.Enabled = false;
        btnRestore.Location = new Point(181, 105);
        btnRestore.Name = "btnRestore";
        btnRestore.Size = new Size(150, 36);
        btnRestore.Text = "Restore Selected";
        btnRestore.UseVisualStyleBackColor = true;
        btnRestore.Click += btnRestore_Click;

        dgvResults.AllowUserToAddRows = false;
        dgvResults.AllowUserToDeleteRows = false;
        dgvResults.AllowUserToResizeRows = false;
        dgvResults.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        dgvResults.AutoGenerateColumns = false;
        dgvResults.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        dgvResults.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
        dgvResults.Columns.AddRange(new DataGridViewColumn[] { colName, colOriginalLocation, colDeleted, colSize });
        dgvResults.Location = new Point(24, 157);
        dgvResults.MultiSelect = true;
        dgvResults.Name = "dgvResults";
        dgvResults.ReadOnly = true;
        dgvResults.RowHeadersVisible = false;
        dgvResults.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        dgvResults.Size = new Size(952, 415);
        dgvResults.SelectionChanged += dgvResults_SelectionChanged;

        colName.DataPropertyName = "Name";
        colName.HeaderText = "Name";
        colName.FillWeight = 26F;
        colName.MinimumWidth = 160;

        colOriginalLocation.DataPropertyName = "OriginalLocation";
        colOriginalLocation.HeaderText = "Original Location";
        colOriginalLocation.FillWeight = 34F;
        colOriginalLocation.MinimumWidth = 200;

        colDeleted.DataPropertyName = "DeletedDate";
        colDeleted.HeaderText = "Deleted";
        colDeleted.FillWeight = 20F;
        colDeleted.MinimumWidth = 130;

        colSize.DataPropertyName = "Size";
        colSize.HeaderText = "Size";
        colSize.FillWeight = 12F;
        colSize.MinimumWidth = 80;

        lblStatus.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        lblStatus.AutoEllipsis = true;
        lblStatus.Location = new Point(24, 584);
        lblStatus.Name = "lblStatus";
        lblStatus.Size = new Size(952, 23);
        lblStatus.Text = "Ready. Click Scan Recycle Bin to begin.";

        AutoScaleDimensions = new SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(1000, 625);
        Controls.Add(lblStatus);
        Controls.Add(dgvResults);
        Controls.Add(btnRestore);
        Controls.Add(btnScan);
        Controls.Add(lblDescription);
        Controls.Add(lblTitle);
        MinimumSize = new Size(760, 480);
        Name = "Form1";
        StartPosition = FormStartPosition.CenterScreen;
        Text = "AlgoLassi File Recovery";
        Load += Form1_Load;
        ((System.ComponentModel.ISupportInitialize)dgvResults).EndInit();
        ResumeLayout(false);
        PerformLayout();
    }
}