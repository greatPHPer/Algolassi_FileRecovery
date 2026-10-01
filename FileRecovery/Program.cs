using System.Diagnostics;

namespace FileRecovery;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ConfigureDiagnosticLogging();

        ApplicationConfiguration.Initialize();
        Application.Run(new TrayApplicationContext());
    }

    private static void ConfigureDiagnosticLogging()
    {
        try
        {
            // Keep the very verbose NTFS diagnostics out of Visual Studio Output.
            // The bounded listener rotates at 20 MB so diagnostics cannot consume
            // gigabytes of disk space.
            var logDirectory = Directory.Exists(@"D:\TestRecovery4")
                ? @"D:\TestRecovery4"
                : Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "AlgoLassi",
                    "FileRecovery");

            var logPath = Path.Combine(
                logDirectory,
                "AlgoLassi-FileRecovery-debug.txt");

            var recoveryLogPath = Path.Combine(
                logDirectory,
                "AlgoLassi-FileRecovery-recovery.txt");

            Trace.Listeners.Clear();
            Trace.Listeners.Add(new BoundedFileTraceListener(logPath));

            // Keep only the recovery-stage diagnostics in a separate small log.
            // This prevents a verbose 122 GB forensic scan from rotating away
            // the important USN/MFT evidence collected earlier in the same scan.
            var recoveryListener = new RecoveryDiagnosticTraceListener(recoveryLogPath);
            Trace.Listeners.Add(recoveryListener);
            Debug.Listeners.Add(recoveryListener);

            Trace.AutoFlush = true;

            Trace.WriteLine(
                $"[{DateTime.UtcNow:O}] AlgoLassi diagnostic logging started: {logPath}");
            Trace.WriteLine(
                $"[{DateTime.UtcNow:O}] AlgoLassi recovery-stage logging started: {recoveryLogPath}");
        }
        catch
        {
            // Diagnostics must never prevent the recovery application from starting.
        }
    }
}
