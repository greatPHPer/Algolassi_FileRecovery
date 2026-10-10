namespace FileRecovery;

public sealed class BufferedDataGridView : DataGridView
{
    public BufferedDataGridView()
    {
        DoubleBuffered = true;
        ResizeRedraw = true;
    }
}
