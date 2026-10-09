using System.Diagnostics;
using System.Text;

namespace FileRecovery;

internal sealed class RecoveryDiagnosticTraceListener : TraceListener
{
    private const long MaxBytes = 10L * 1024L * 1024L;

    private static readonly string[] Keywords =
    [
        "USN historical directory MATCH",
        "USN historical directory scan summary",
        "NTFS historical journal-reference merge",
        "NTFS historical deletion snapshots",
        "NTFS scan deletion-reference merge",
        "NTFS candidate size enrichment",
        "NTFS raw-MFT target handoff",
        "NTFS raw-MFT target:",
        "NTFS historical",
        "NTFS recovery candidate start",
        "NTFS recovery path checkpoint",
        "NTFS deep carve starting",
        "NTFS RECOVERY FAILURE",
        "NTFS $LogFile historical",
        "NTFS $LogFile marker diagnostic",
        "NTFS recovery-time $LogFile",
        "UpdateNonresidentValue",
        "historical nonresident value",
        "historical-only MFT",
        "historical target direct slack",
        "Historical USN/MFT segment matched",
        "NTFS raw MFT fallback",
        "no retained NTFS $DATA evidence",
        "NTFS MFT scan",
        "MFT segment",
        "historicalSlack"
    ];

    private readonly string _filePath;
    private readonly object _gate = new();

    public RecoveryDiagnosticTraceListener(string filePath)
    {
        _filePath = filePath;
        Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
    }

    public override void Write(string? message)
    {
        AppendIfRelevant(message ?? string.Empty);
    }

    public override void WriteLine(string? message)
    {
        AppendIfRelevant(message ?? string.Empty);
    }

    private void AppendIfRelevant(string text)
    {
        if (string.IsNullOrWhiteSpace(text) ||
            !Keywords.Any(keyword =>
                text.Contains(keyword, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        lock (_gate)
        {
            try
            {
                var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
                var line = $"[{DateTime.UtcNow:O}] {text}{Environment.NewLine}";
                var bytes = encoding.GetBytes(line);

                var currentLength = File.Exists(_filePath)
                    ? new FileInfo(_filePath).Length
                    : 0;

                if (currentLength + bytes.LongLength > MaxBytes)
                {
                    File.WriteAllText(
                        _filePath,
                        $"[{DateTime.UtcNow:O}] Recovery diagnostic log rotated after reaching {MaxBytes:N0} bytes.{Environment.NewLine}",
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
