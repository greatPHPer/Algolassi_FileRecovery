namespace FileRecovery;

public sealed class DeletionNotificationForm : Form
{
    private readonly Action _muteAction;
    private readonly Label _summaryLabel;
    private readonly Label _fileLabel;
    private readonly Button _muteButton;
    private readonly System.Windows.Forms.Timer _animationTimer;
    private readonly System.Windows.Forms.Timer _displayTimer;
    private int _targetX;
    private int _hiddenX;
    private int _phase;

    public DeletionNotificationForm(DeletionRecord record, Action muteAction)
    {
        _muteAction = muteAction;

        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.Manual;
        TopMost = true;
        BackColor = Color.FromArgb(28, 31, 36);
        ForeColor = Color.White;
        Size = new Size(390, 104);
        Padding = new Padding(14);

        var title = new Label
        {
            AutoSize = true,
            Font = new Font("Segoe UI", 10F, FontStyle.Bold),
            Text = "🗑  1 file deleted",
            Location = new Point(14, 12)
        };

        _summaryLabel = title;

        _fileLabel = new Label
        {
            AutoEllipsis = true,
            Font = new Font("Segoe UI", 9F),
            ForeColor = Color.FromArgb(222, 226, 230),
            Location = new Point(14, 40),
            Size = new Size(255, 22),
            Text = FormatFileLine(record)
        };

        _muteButton = new Button
        {
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(48, 53, 61),
            ForeColor = Color.White,
            Text = "Mute",
            Size = new Size(78, 30),
            Location = new Point(294, 35),
            TabStop = false
        };
        _muteButton.FlatAppearance.BorderColor = Color.FromArgb(82, 89, 99);
        _muteButton.Click += (_, _) =>
        {
            _muteAction();
            CloseAnimated();
        };

        Controls.Add(_summaryLabel);
        Controls.Add(_fileLabel);
        Controls.Add(_muteButton);

        _animationTimer = new System.Windows.Forms.Timer { Interval = 15 };
        _animationTimer.Tick += OnAnimationTick;

        _displayTimer = new System.Windows.Forms.Timer { Interval = 4500 };
        _displayTimer.Tick += (_, _) =>
        {
            _displayTimer.Stop();
            BeginSlideOut();
        };

        Shown += (_, _) => BeginSlideIn();
    }

    public void BeginSlideIn()
    {
        var area = Screen.PrimaryScreen?.WorkingArea
            ?? Screen.FromControl(this).WorkingArea;

        _targetX = area.Right - Width - 18;
        _hiddenX = area.Right + 8;
        Left = _hiddenX;
        Top = area.Bottom - Height - 18;
        _phase = 1;
        _animationTimer.Start();
    }

    private void BeginSlideOut()
    {
        _phase = -1;
        _animationTimer.Start();
    }

    private void OnAnimationTick(object? sender, EventArgs e)
    {
        if (_phase == 1)
        {
            Left -= Math.Max(12, (Left - _targetX) / 3);
            if (Left <= _targetX)
            {
                Left = _targetX;
                _animationTimer.Stop();
                _displayTimer.Start();
            }
        }
        else if (_phase == -1)
        {
            Left += 28;
            if (Left >= _hiddenX)
            {
                Close();
            }
        }
    }

    private void CloseAnimated() 
    {
        _displayTimer.Stop();
        BeginSlideOut();
    }

    private static string FormatFileLine(DeletionRecord record)
    {
        var size = record.FileSizeBytes.HasValue
            ? $" • {FormatSize(record.FileSizeBytes.Value)}"
            : string.Empty;

        return $"{record.FileName}{size}";
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024d:0.#} KB";
        if (bytes < 1024L * 1024L * 1024L) return $"{bytes / (1024d * 1024d):0.#} MB";
        return $"{bytes / (1024d * 1024d * 1024d):0.#} GB";
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _animationTimer.Stop();
            _displayTimer.Stop();
            _animationTimer.Dispose();
            _displayTimer.Dispose();
        }

        base.Dispose(disposing);
    }
}
