using System.Diagnostics;
using System.Text;

namespace FileRecovery;

internal sealed class BoundedFileTraceListener : TraceListener
{
    private const long MaxBytes = 20L * 1024L * 1024L;
    private readonly string _filePath;
    private readonly object _gate = new();

    public BoundedFileTraceListener(string filePath)
    {
        _filePath = filePath;
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
    }

    public override void Write(string? message)
    {
        Append(message ?? string.Empty);
    }

    public override void WriteLine(string? message)
    {
        Append((message ?? string.Empty) + Environment.NewLine);
    }

    private void Append(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return;
        }

        lock (_gate)
        {
            try
            {
                var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
                var bytes = encoding.GetBytes(text);

                var currentLength = File.Exists(_filePath)
                    ? new FileInfo(_filePath).Length
                    : 0;

                if (currentLength + bytes.LongLength > MaxBytes)
                {
                    File.WriteAllText(
                        _filePath,
                        $"[{DateTime.UtcNow:O}] Diagnostic log rotated after reaching {MaxBytes:N0} bytes.{Environment.NewLine}",
                        encoding);
                }

                using var stream = new FileStream(
                    _filePath,
                    FileMode.Append,
                    FileAccess.Write,
                    FileShare.ReadWrite);

                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
            catch
            {
                // Diagnostics must never interfere with recovery.
            }
        }
    }
}
