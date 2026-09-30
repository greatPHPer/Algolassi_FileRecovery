using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace FileRecovery;

/// <summary>
/// Attempts authoritative recovery from existing Windows Volume Shadow Copies.
/// A snapshot is eligible only when it belongs to the source volume and was
/// created no later than the recorded deletion time.
/// </summary>
public sealed class VssHistoricalFileRecoveryService
{
    private const int PowerShellTimeoutMilliseconds = 15_000;
    private const long MaximumRecoveredFileBytes = 256L * 1024L * 1024L;

    private readonly Dictionary<string, SnapshotInfo[]> _snapshotCache =
        new(StringComparer.OrdinalIgnoreCase);

    public bool TryRecoverFile(
        RecoveryCandidate candidate,
        string destinationDirectory,
        out RecoveryResult result,
        out string evidence)
    {
        result = new RecoveryResult();
        evidence = string.Empty;

        if (candidate is null ||
            string.IsNullOrWhiteSpace(candidate.FullPath) ||
            string.IsNullOrWhiteSpace(candidate.Name) ||
            candidate.LastUsnTimestampUtc == default)
        {
            evidence = "VSS recovery requires a candidate path and historical deletion timestamp.";
            return false;
        }

        var sourceRoot = GetSourceVolumeRoot(candidate.FullPath);
        if (string.IsNullOrWhiteSpace(sourceRoot))
        {
            evidence = "VSS recovery could not determine the source volume root.";
            return false;
        }

        SnapshotInfo[] snapshots;
        try
        {
            if (!_snapshotCache.TryGetValue(sourceRoot, out snapshots!))
            {
                snapshots = QuerySnapshots(sourceRoot);
                _snapshotCache[sourceRoot] = snapshots;
            }
        }
        catch (Exception ex)
        {
            evidence = $"VSS snapshot enumeration failed: {ex.GetType().Name}: {ex.Message}";
            return false;
        }

        if (snapshots.Length == 0)
        {
            evidence = $"No existing Volume Shadow Copy was found for {sourceRoot}.";
            return false;
        }

        foreach (var snapshot in snapshots
                     .Where(item =>
                         item.InstallDateUtc <= candidate.LastUsnTimestampUtc)
                     .OrderByDescending(item => item.InstallDateUtc))
        {
            var relativePath = Path.GetRelativePath(
                sourceRoot,
                candidate.FullPath);

            if (relativePath.StartsWith("..", StringComparison.Ordinal))
            {
                continue;
            }

            var snapshotPath = CombineSnapshotPath(
                snapshot.DeviceObject,
                relativePath);

            if (!File.Exists(snapshotPath))
            {
                continue;
            }

            try
            {
                var fileInfo = new FileInfo(snapshotPath);

                if (fileInfo.Length <= 0 ||
                    fileInfo.Length > MaximumRecoveredFileBytes)
                {
                    continue;
                }

                if (candidate.FileSizeBytes > 0 &&
                    fileInfo.Length != candidate.FileSizeBytes)
                {
                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS VSS recovery: size mismatch. " +
                        $"path={candidate.FullPath}, snapshot={snapshot.InstallDateUtc:O}, " +
                        $"candidateSize={candidate.FileSizeBytes:N0}, " +
                        $"snapshotSize={fileInfo.Length:N0}.");
                    continue;
                }

                RecoveryDestinationPolicy.Validate(
                    candidate.FullPath,
                    destinationDirectory);

                var destinationPath =
                    RecoveryDestinationPolicy.CreateSafeFilePath(
                        destinationDirectory,
                        candidate.Name);

                try
                {
                    CopyFileAndFlush(
                        snapshotPath,
                        destinationPath);
                }
                catch
                {
                    try
                    {
                        if (File.Exists(destinationPath))
                        {
                            File.Delete(destinationPath);
                        }
                    }
                    catch
                    {
                        // Preserve the original write failure.
                    }

                    throw;
                }

                candidate.FileSizeBytes = fileInfo.Length;

                result = new RecoveryResult
                {
                    Success = true,
                    SourcePath = candidate.FullPath,
                    DestinationPath = destinationPath,
                    BytesRecovered = fileInfo.Length,
                    Evidence =
                        $"Recovered {fileInfo.Length:N0} byte(s) from an existing Windows " +
                        $"Volume Shadow Copy created at {snapshot.InstallDateUtc:O}, " +
                        "before the recorded deletion time. The exact historical path " +
                        "existed in that snapshot."
                };

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS VSS historical file recovery succeeded: " +
                    $"path={candidate.FullPath}, " +
                    $"fileRef={candidate.FileReferenceNumber}, " +
                    $"deleteTime={candidate.LastUsnTimestampUtc:O}, " +
                    $"snapshotTime={snapshot.InstallDateUtc:O}, " +
                    $"snapshot={snapshot.DeviceObject}, " +
                    $"size={fileInfo.Length:N0}, " +
                    $"destination={destinationPath}.");

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS VSS historical file recovery failed for snapshot " +
                    $"{snapshot.InstallDateUtc:O}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        evidence =
            $"Existing VSS snapshots were found for {sourceRoot}, but none contained " +
            $"the exact historical path with a matching file size at or before " +
            $"{candidate.LastUsnTimestampUtc:O}.";
        return false;
    }

    private static SnapshotInfo[] QuerySnapshots(string sourceRoot)
    {
        var volumeName = GetVolumeName(sourceRoot);

        if (string.IsNullOrWhiteSpace(volumeName))
        {
            throw new IOException(
                $"Could not resolve the volume GUID for {sourceRoot}.");
        }

        var escapedVolume =
            volumeName.Replace(
                "'",
                "''",
                StringComparison.Ordinal);

        var script =
            "$ErrorActionPreference='Stop'; " +
            $"$v='{escapedVolume}'; " +
            "@(Get-CimInstance Win32_ShadowCopy | " +
            "Where-Object { $_.VolumeName -eq $v } | " +
            "ForEach-Object { " +
            "[pscustomobject]@{ " +
            "DeviceObject=$_.DeviceObject; " +
            "VolumeName=$_.VolumeName; " +
            "InstallDateUtc=$_.InstallDate.ToUniversalTime().ToString('O') " +
            "} }) | ConvertTo-Json -Compress";

        var json = RunPowerShell(script);

        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            using var document = JsonDocument.Parse(json);

            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                return ParseSnapshotArray(
                    new[] { document.RootElement });
            }

            if (document.RootElement.ValueKind != JsonValueKind.Array)
            {
                return [];
            }

            return ParseSnapshotArray(
                document.RootElement.EnumerateArray());
        }
        catch (JsonException ex)
        {
            throw new IOException(
                $"Windows returned invalid VSS snapshot data: {ex.Message}",
                ex);
        }
    }

    private static SnapshotInfo[] ParseSnapshotArray(
        IEnumerable<JsonElement> elements)
    {
        var snapshots = new List<SnapshotInfo>();

        foreach (var element in elements)
        {
            var deviceObject = element.TryGetProperty(
                    "DeviceObject",
                    out var deviceProperty)
                ? deviceProperty.GetString()
                : null;

            var volumeName = element.TryGetProperty(
                    "VolumeName",
                    out var volumeProperty)
                ? volumeProperty.GetString()
                : null;

            var installDateText = element.TryGetProperty(
                    "InstallDateUtc",
                    out var installProperty)
                ? installProperty.GetString()
                : null;

            if (string.IsNullOrWhiteSpace(deviceObject) ||
                string.IsNullOrWhiteSpace(volumeName) ||
                string.IsNullOrWhiteSpace(installDateText) ||
                !DateTimeOffset.TryParse(
                    installDateText,
                    null,
                    System.Globalization.DateTimeStyles.RoundtripKind,
                    out var installDateUtc))
            {
                continue;
            }

            snapshots.Add(
                new SnapshotInfo(
                    deviceObject,
                    volumeName,
                    installDateUtc));
        }

        return snapshots
            .OrderByDescending(item => item.InstallDateUtc)
            .ToArray();
    }

    private static string RunPowerShell(string script)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments =
                "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
                "-Command " +
                QuotePowerShellArgument(script),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        using var process = new Process
        {
            StartInfo = startInfo
        };

        if (!process.Start())
        {
            throw new InvalidOperationException(
                "Could not start Windows PowerShell to enumerate VSS snapshots.");
        }

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(PowerShellTimeoutMilliseconds))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Best effort.
            }

            throw new TimeoutException(
                "Windows PowerShell timed out while enumerating VSS snapshots.");
        }

        var output = outputTask.GetAwaiter().GetResult();
        var error = errorTask.GetAwaiter().GetResult();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"PowerShell VSS query failed with exit code {process.ExitCode}: " +
                $"{error.Trim()}");
        }

        return output.Trim();
    }

    private static string QuotePowerShellArgument(string script)
    {
        var escaped =
            script.Replace(
                "'",
                "''",
                StringComparison.Ordinal);

        return $"\"& {{ {escaped} }}\"";
    }

    private static string GetVolumeName(string root)
    {
        var normalizedRoot =
            root.EndsWith(
                Path.DirectorySeparatorChar)
                ? root
                : root + Path.DirectorySeparatorChar;

        var buffer = new StringBuilder(128);

        return GetVolumeNameForVolumeMountPoint(
                normalizedRoot,
                buffer,
                buffer.Capacity)
            ? buffer.ToString()
            : string.Empty;
    }

    private static string CombineSnapshotPath(
        string deviceObject,
        string relativePath)
    {
        var cleanDevice =
            deviceObject.TrimEnd(
                '\',
                '/');

        return Path.Combine(
            cleanDevice,
            relativePath);
    }

    private static void CopyFileAndFlush(
        string sourcePath,
        string destinationPath)
    {
        using var source = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 1024 * 1024,
            FileOptions.SequentialScan);

        using var destination = new FileStream(
            destinationPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 1024 * 1024,
            FileOptions.SequentialScan);

        source.CopyTo(
            destination,
            1024 * 1024);

        destination.Flush(flushToDisk: true);

        if (destination.Length != source.Length)
        {
            throw new IOException(
                $"VSS copy size mismatch: source={source.Length:N0}, " +
                $"destination={destination.Length:N0}.");
        }
    }

    private static string? GetSourceVolumeRoot(string path) =>
        Path.GetPathRoot(
            path.Trim());

    private sealed record SnapshotInfo(
        string DeviceObject,
        string VolumeName,
        DateTimeOffset InstallDateUtc);

    [System.Runtime.InteropServices.DllImport(
        "kernel32.dll",
        CharSet = System.Runtime.InteropServices.CharSet.Unicode,
        SetLastError = true)]
    private static extern bool GetVolumeNameForVolumeMountPoint(
        string lpszVolumeMountPoint,
        StringBuilder lpszVolumeName,
        int cchBufferLength);
}
