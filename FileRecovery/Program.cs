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

            Debug.Listeners.Clear();
            Debug.Listeners.Add(new BoundedFileTraceListener(logPath));
            Debug.AutoFlush = true;

            Debug.WriteLine(
                $"[{DateTime.UtcNow:O}] AlgoLassi diagnostic logging started: {logPath}");
        }
        catch
        {
            // Diagnostics must never prevent the recovery application from starting.
        }
    }
}
