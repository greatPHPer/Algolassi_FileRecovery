namespace FileRecovery;

/// <summary>
/// Owner-drawn directory list with WinForms double buffering enabled to reduce
/// flicker while breadcrumb buttons are repainted.
/// </summary>
public sealed class BufferedDirectoryListBox : ListBox
{
    public BufferedDirectoryListBox()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
        SetStyle(
            ControlStyles.OptimizedDoubleBuffer |
            ControlStyles.AllPaintingInWmPaint,
            true);
        UpdateStyles();
    }
}
