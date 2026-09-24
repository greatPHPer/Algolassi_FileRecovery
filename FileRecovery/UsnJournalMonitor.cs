using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class UsnJournalMonitor : IDisposable
{
    private const uint FsctlQueryUsnJournal = 0x000900F4;
    private const uint FsctlReadUsnJournal = 0x000900BB;
    private const uint FsctlEnumUsnData = 0x000900B3;
    private const uint FsctlCreateUsnJournal = 0x000900E7;

    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileReadAttributes = 0x00000080;
    private const int ErrorJournalDeleteInProgress = 1178;
    private const int ErrorJournalNotActive = 1179;
    private const int ErrorJournalEntryDeleted = 1181;
    private const int ErrorFileNotFound = 2;

    private const uint UsnReasonFileDelete = 0x00000200;
    private const uint FileAttributeDirectory = 0x00000010;
    private const int UsnRecordV2MinimumLength = 60;

    private readonly RecoverySettings _settings;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _gate = new();
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<ulong, string>> _parentPathCaches =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _accessDeniedUntilUtc =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<RecentDeletedRecord> _recentDeletedRecords = new();

    private const int RecentDeletedRecordLimit = 512;

    private Task? _worker;
    private bool _started;

    public event EventHandler<DeletionDetectedEventArgs>? DeletionDetected;
    public event EventHandler<string>? StatusChanged;

    public UsnJournalMonitor(RecoverySettings settings)
    {
        _settings = settings;
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_started)
            {
                return;
            }

            if (!IsAdministrator())
            {
                StatusChanged?.Invoke(
                    this,
                    "USN monitoring is disabled because administrator privileges are required. Run AlgoLassi File Recovery as Administrator to enable it.");
                return;
            }

            try
            {
                WindowsPrivilege.EnableSeBackupPrivilege();
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(
                    this,
                    $"USN monitoring could not enable SeBackupPrivilege: {ex.Message}");
                return;
            }

            // Arm every NTFS journal before the FileSystemWatcher starts producing
            // deletion records. This closes the startup race where a file could be
            // Shift+Deleted before the background USN worker had established its
            // first cursor, leaving the history row without an NTFS reference.
            ArmInitialCursors();

            _started = true;
            _worker = Task.Run(MonitorAllVolumesAsync);
        }
    }

    private void ArmInitialCursors()
    {
        foreach (var drive in GetNtfsFixedDrives())
        {
            if (_cts.IsCancellationRequested)
            {
                return;
            }

            var volumeKey = drive.RootDirectory.FullName.TrimEnd(Path.DirectorySeparatorChar);

            try
            {
                using var volumeHandle = CreateFile(
                    $@"\\.\{volumeKey[..2]}",
                    GenericRead,
                    FileShareRead | FileShareWrite | FileShareDelete,
                    IntPtr.Zero,
                    OpenExisting,
                    FileFlagBackupSemantics,
                    IntPtr.Zero);

                if (volumeHandle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                if (!TryQueryJournal(volumeHandle, out var journal, out var queryError))
                {
                    if (queryError == ErrorFileNotFound ||
                        queryError == ErrorJournalNotActive)
                    {
                        if (!TryCreateJournal(volumeHandle, volumeKey, out journal))
                        {
                            continue;
                        }
                    }
                    else
                    {
                        continue;
                    }
                }

                if (!_settings.UsnCursors.TryGetValue(volumeKey, out var cursor) ||
                    cursor.JournalId != journal.JournalId ||
                    cursor.NextUsn <= 0)
                {
                    _settings.UsnCursors[volumeKey] = new VolumeJournalCursor
                    {
                        JournalId = journal.JournalId,
                        NextUsn = journal.NextUsn
                    };
                    _settings.Save();

                    StatusChanged?.Invoke(
                        this,
                        $"USN journal armed for {volumeKey}. New deletions will be tracked.");
                }
            }
            catch (UnauthorizedAccessException)
            {
                ReportAccessDenied(volumeKey);
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 5)
            {
                ReportAccessDenied(volumeKey);
            }
            catch (Exception ex)
            {
                StatusChanged?.Invoke(
                    this,
                    $"USN monitoring warning for {volumeKey}: {ex.Message}");
            }
        }
    }

    public void Stop()
    {
        lock (_gate)
        {
            if (!_started)
            {
                return;
            }

            _started = false;
            _cts.Cancel();
        }

        try
        {
            _worker?.Wait(TimeSpan.FromSeconds(3));
        }
        catch
        {
            // Best effort shutdown.
        }

        _worker = null;
    }

    private async Task MonitorAllVolumesAsync()
    {
        if (!IsAdministrator())
        {
            StatusChanged?.Invoke(
                this,
                "USN monitoring is disabled because administrator privileges are required. Run AlgoLassi File Recovery as Administrator to enable it.");
            return;
        }

        while (!_cts.IsCancellationRequested)
        {
            foreach (var drive in GetNtfsFixedDrives())
            {
                if (_cts.IsCancellationRequested)
                {
                    break;
                }

                var volumeKey = drive.RootDirectory.FullName.TrimEnd(Path.DirectorySeparatorChar);
                if (_accessDeniedUntilUtc.TryGetValue(volumeKey, out var retryAfterUtc) &&
                    retryAfterUtc > DateTime.UtcNow)
                {
                    continue;
                }

                try
                {
                    ReadVolume(drive);
                    _accessDeniedUntilUtc.TryRemove(volumeKey, out _);
                }
                catch (UnauthorizedAccessException)
                {
                    ReportAccessDenied(volumeKey);
                }
                catch (Win32Exception ex) when (ex.NativeErrorCode == 5)
                {
                    ReportAccessDenied(volumeKey);
                }
                catch (Exception ex)
                {
                    StatusChanged?.Invoke(this, $"USN monitoring warning for {volumeKey}: {ex.Message}");
                }
            }

            try
            {
                await Task.Delay(750, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private void ReportAccessDenied(string volumeKey)
    {
        _accessDeniedUntilUtc[volumeKey] = DateTime.UtcNow.AddSeconds(30);
        StatusChanged?.Invoke(
            this,
            $"USN monitoring for {volumeKey} requires administrator privileges. Retrying in 30 seconds.");
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (identity is null)
        {
            return false;
        }

        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void ReadVolume(DriveInfo drive)
    {
        var volumeKey = drive.RootDirectory.FullName.TrimEnd(Path.DirectorySeparatorChar);
        using var volumeHandle = CreateFile(
            $"\\\\.\\{volumeKey[..2]}",
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);

        if (volumeHandle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        if (!TryQueryJournal(volumeHandle, out var journal, out var queryError))
        {
            if (queryError == ErrorFileNotFound ||
                queryError == ErrorJournalNotActive)
            {
                if (!TryCreateJournal(volumeHandle, volumeKey, out journal))
                {
                    return;
                }
            }
            else
            {
                return;
            }
        }

        var cache = _parentPathCaches.GetOrAdd(
            volumeKey,
            _ => new ConcurrentDictionary<ulong, string>());

        if (!_settings.UsnCursors.TryGetValue(volumeKey, out var cursor) ||
            cursor.JournalId != journal.JournalId ||
            cursor.NextUsn <= 0)
        {
            cursor = new VolumeJournalCursor
            {
                JournalId = journal.JournalId,
                NextUsn = journal.NextUsn
            };

            _settings.UsnCursors[volumeKey] = cursor;
            _settings.Save();
            StatusChanged?.Invoke(this, $"USN journal armed for {volumeKey}. New deletions will be tracked even after restart.");
            return;
        }

        if (cursor.NextUsn < journal.FirstUsn || cursor.NextUsn < journal.LowestValidUsn)
        {
            cursor.NextUsn = journal.NextUsn;
            cursor.JournalId = journal.JournalId;
            _settings.Save();
            StatusChanged?.Invoke(this, $"USN history gap detected on {volumeKey}; journal cursor reset.");
            return;
        }

        if (cursor.NextUsn >= journal.NextUsn)
        {
            return;
        }

        var nextUsn = cursor.NextUsn;
        const int maxBatchesPerVolumePerCycle = 8;
        var batchesRead = 0;

        while (!_cts.IsCancellationRequested &&
               nextUsn < journal.NextUsn &&
               batchesRead < maxBatchesPerVolumePerCycle)
        {
            batchesRead++;

            var records = ReadRecords(volumeHandle, journal.JournalId, nextUsn, out var returnedNextUsn);

            if (returnedNextUsn <= nextUsn)
            {
                break;
            }

            foreach (var record in records)
            {
                if ((record.Reason & UsnReasonFileDelete) == 0 ||
                    (record.FileAttributes & 0x10) != 0 ||
                    string.IsNullOrWhiteSpace(record.FileName))
                {
                    continue;
                }

                var directory = cache.TryGetValue(record.ParentFileReferenceNumber, out var knownPath)
                    ? knownPath
                    : ResolveParentDirectory(volumeHandle, record.ParentFileReferenceNumber);

                if (!string.IsNullOrWhiteSpace(directory))
                {
                    cache[record.ParentFileReferenceNumber] = directory;
                }

                if (string.IsNullOrWhiteSpace(directory))
                {
                    directory = "(Parent directory unavailable)";
                }

                var recordPath = Path.Combine(directory, record.FileName);

                _recentDeletedRecords.Enqueue(
                    new RecentDeletedRecord(
                        record.FileReferenceNumber,
                        record.ParentFileReferenceNumber,
                        record.FileName,
                        string.IsNullOrWhiteSpace(directory) ||
                        directory.Equals("(Parent directory unavailable)", StringComparison.OrdinalIgnoreCase)
                            ? null
                            : directory,
                        record.TimestampUtc));

                while (_recentDeletedRecords.Count > RecentDeletedRecordLimit &&
                       _recentDeletedRecords.TryDequeue(out _))
                {
                }

                var deletion = new DeletionRecord
                {
                    FileReferenceNumber = record.FileReferenceNumber,
                    ParentFileReferenceNumber = record.ParentFileReferenceNumber,
                    FullPath = recordPath,
                    FileName = record.FileName,
                    DirectoryPath = directory,
                    DeletedAtUtc = record.TimestampUtc,
                    FileSizeBytes = null,
                    RecoveryStrength = "Weak"
                };

                DeletionDetected?.Invoke(this, new DeletionDetectedEventArgs(deletion, historical: true));
            }

            nextUsn = returnedNextUsn;
            cursor.NextUsn = nextUsn;
            cursor.JournalId = journal.JournalId;
            _settings.UsnCursors[volumeKey] = cursor;
            _settings.Save();

            if (records.Count == 0)
            {
                break;
            }
        }

        if (!_cts.IsCancellationRequested &&
            batchesRead >= maxBatchesPerVolumePerCycle &&
            nextUsn < journal.NextUsn)
        {
            System.Diagnostics.Debug.WriteLine(
                $"USN monitor yielding {volumeKey} after {batchesRead} read batch(es); " +
                $"cursor={nextUsn}, journalNext={journal.NextUsn}.");
        }
    }

    private bool TryCreateJournal(
        SafeFileHandle volumeHandle,
        string volumeKey,
        out JournalInfo journal)
    {
        journal = default;

        var request = new CreateUsnJournalData
        {
            MaximumSize = 64UL * 1024UL * 1024UL,
            AllocationDelta = 16UL * 1024UL * 1024UL
        };

        var input = StructureToBytes(request);

        if (!DeviceIoControl(
                volumeHandle,
                FsctlCreateUsnJournal,
                input,
                (uint)input.Length,
                null,
                0,
                out _,
                IntPtr.Zero))
        {
            var error = Marshal.GetLastWin32Error();
            StatusMessageForJournalFailure(volumeKey, error);
            return false;
        }

        if (!TryQueryJournal(volumeHandle, out journal, out var queryError))
        {
            StatusMessageForJournalFailure(volumeKey, queryError);
            return false;
        }

        StatusChanged?.Invoke(
            this,
            $"USN journal created and active on {volumeKey}.");

        return true;
    }

    private void StatusMessageForJournalFailure(string volumeKey, int error)
    {
        if (error == 5)
        {
            StatusChanged?.Invoke(
                this,
                $"USN journal for {volumeKey} could not be created because administrator privileges are required.");
        }
        else if (error != 0)
        {
            StatusChanged?.Invoke(
                this,
                $"USN journal for {volumeKey} is unavailable (error {error}).");
        }
    }

    private static bool TryQueryJournal(
        SafeFileHandle volumeHandle,
        out JournalInfo journal,
        out int errorCode)
    {
        journal = default;
        errorCode = 0;
        var output = new byte[64];

        if (!DeviceIoControl(
                volumeHandle,
                FsctlQueryUsnJournal,
                null,
                0,
                output,
                (uint)output.Length,
                out var bytesReturned,
                IntPtr.Zero))
        {
            var error = Marshal.GetLastWin32Error();
            errorCode = error;

            if (error == ErrorFileNotFound ||
                error == ErrorJournalDeleteInProgress ||
                error == ErrorJournalNotActive)
            {
                return false;
            }

            throw new Win32Exception(
                error,
                $"FSCTL_QUERY_USN_JOURNAL failed (error {error}).");
        }

        if (bytesReturned < 60)
        {
            return false;
        }

        journal = new JournalInfo(
            BinaryPrimitives.ReadUInt64LittleEndian(output.AsSpan(0, 8)),
            BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(8, 8)),
            BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(16, 8)),
            BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(24, 8)));

        return true;
    }

    public bool TryResolveCachedRecentDeletedFile(
        string fullPath,
        DateTime deletedAtUtc,
        out ulong fileReferenceNumber,
        out ulong parentFileReferenceNumber)
    {
        fileReferenceNumber = 0;
        parentFileReferenceNumber = 0;

        var normalizedTarget = NormalizePath(fullPath);

        var cached = _recentDeletedRecords
            .ToArray()
            .OrderBy(item =>
                Math.Abs((item.TimestampUtc - deletedAtUtc).TotalMilliseconds))
            .FirstOrDefault(item =>
            {
                if (deletedAtUtc != default &&
                    Math.Abs((item.TimestampUtc - deletedAtUtc).TotalMinutes) > 5)
                {
                    return false;
                }

                var candidatePath = item.DirectoryPath is null
                    ? string.Empty
                    : NormalizePath(Path.Combine(
                        item.DirectoryPath,
                        item.FileName));

                return string.Equals(
                    candidatePath,
                    normalizedTarget,
                    StringComparison.OrdinalIgnoreCase)
                    || (item.DirectoryPath is null &&
                        string.Equals(
                            item.FileName,
                            Path.GetFileName(normalizedTarget),
                            StringComparison.OrdinalIgnoreCase));
            });

        if (cached.FileReferenceNumber == 0 ||
            cached.ParentFileReferenceNumber == 0)
        {
            return false;
        }

        fileReferenceNumber = cached.FileReferenceNumber;
        parentFileReferenceNumber = cached.ParentFileReferenceNumber;
        return true;
    }

    public bool TryResolveRecentDeletedFile(
        string fullPath,
        DateTime deletedAtUtc,
        out ulong fileReferenceNumber,
        out ulong parentFileReferenceNumber)
    {
        fileReferenceNumber = 0;
        parentFileReferenceNumber = 0;

        // Prefer records already observed by the background USN monitor.
        if (TryResolveCachedRecentDeletedFile(
                fullPath,
                deletedAtUtc,
                out fileReferenceNumber,
                out parentFileReferenceNumber))
        {
            return true;
        }

        if (!IsAdministrator())
        {
            return false;
        }

        var normalizedTarget = NormalizePath(fullPath);
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(root) ||
            !string.Equals(
                new DriveInfo(root).DriveFormat,
                "NTFS",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var volumeKey = root.TrimEnd(Path.DirectorySeparatorChar);
        using var volumeHandle = CreateFile(
            $@"\\.\{volumeKey[..2]}",
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);

        if (volumeHandle.IsInvalid)
        {
            return false;
        }

        if (!TryQueryJournal(volumeHandle, out var journal, out _))
        {
            return false;
        }

        // StartUsn must be an actual USN from the journal; USNs are sequence
        // numbers, not byte offsets. Prefer the monitor's last valid cursor;
        // otherwise start at the first readable journal USN.
        var searchStart = journal.FirstUsn;

        if (_settings.UsnCursors.TryGetValue(volumeKey, out var cursor) &&
            cursor.JournalId == journal.JournalId &&
            cursor.NextUsn >= journal.FirstUsn &&
            cursor.NextUsn <= journal.NextUsn)
        {
            searchStart = cursor.NextUsn;
        }

        var nextUsn = searchStart;
        var iterations = 0;

        while (nextUsn < journal.NextUsn && iterations++ < 256)
        {
            var records = ReadRecords(
                volumeHandle,
                journal.JournalId,
                nextUsn,
                out var returnedNextUsn);

            if (returnedNextUsn <= nextUsn)
            {
                break;
            }

            foreach (var record in records)
            {
                if ((record.Reason & UsnReasonFileDelete) == 0 ||
                    (record.FileAttributes & 0x10) != 0 ||
                    string.IsNullOrWhiteSpace(record.FileName))
                {
                    continue;
                }

                var directory = ResolveParentDirectory(
                    volumeHandle,
                    record.ParentFileReferenceNumber);

                if (string.IsNullOrWhiteSpace(directory))
                {
                    continue;
                }

                var candidatePath = NormalizePath(
                    Path.Combine(directory, record.FileName));

                if (!string.Equals(
                        candidatePath,
                        normalizedTarget,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // The journal timestamp must be reasonably close to the deletion
                // event being resolved. This prevents matching an older deletion
                // of a file with the same name/path.
                if (deletedAtUtc != default &&
                    Math.Abs((record.TimestampUtc - deletedAtUtc).TotalMinutes) > 5)
                {
                    continue;
                }

                fileReferenceNumber = record.FileReferenceNumber;
                parentFileReferenceNumber = record.ParentFileReferenceNumber;

                _parentPathCaches.GetOrAdd(
                    volumeKey,
                    _ => new ConcurrentDictionary<ulong, string>())[record.ParentFileReferenceNumber] = directory;

                return true;
            }

            nextUsn = returnedNextUsn;
        }

        return false;
    }

    public bool TryResolveRecentDeletedFileBounded(
        string fullPath,
        DateTime deletedAtUtc,
        out ulong fileReferenceNumber,
        out ulong parentFileReferenceNumber)
    {
        if (TryResolveCachedRecentDeletedFile(
                fullPath,
                deletedAtUtc,
                out fileReferenceNumber,
                out parentFileReferenceNumber))
        {
            return true;
        }

        fileReferenceNumber = 0;
        parentFileReferenceNumber = 0;

        if (!IsAdministrator())
        {
            return false;
        }

        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(root) ||
            !string.Equals(
                new DriveInfo(root).DriveFormat,
                "NTFS",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var volumeKey = root.TrimEnd(Path.DirectorySeparatorChar);
        using var volumeHandle = CreateFile(
            $@"\\.\{volumeKey[..2]}",
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);

        if (volumeHandle.IsInvalid ||
            !TryQueryJournal(volumeHandle, out var journal, out _))
        {
            return false;
        }

        var normalizedTarget = NormalizePath(fullPath);

        // READ_USN_JOURNAL requires StartUsn to identify a journal position;
        // it is not safe to manufacture a recent USN by subtracting from
        // NextUsn. Use the monitor's actual cursor when it is a valid journal
        // position, then fall back to bounded FSCTL_ENUM_USN_DATA over the
        // recent USN range if the monitor cursor has already reached the tail.
        var searchStart = journal.FirstUsn;

        if (_settings.UsnCursors.TryGetValue(volumeKey, out var cursor) &&
            cursor.JournalId == journal.JournalId &&
            cursor.NextUsn >= journal.FirstUsn &&
            cursor.NextUsn <= journal.NextUsn)
        {
            searchStart = cursor.NextUsn;
        }

        if (searchStart < journal.NextUsn)
        {
            var nextUsn = searchStart;
            const int maxBatches = 8;

            for (var batch = 0;
                 batch < maxBatches &&
                 nextUsn < journal.NextUsn;
                 batch++)
            {
                var records = ReadRecords(
                    volumeHandle,
                    journal.JournalId,
                    nextUsn,
                    out var returnedNextUsn);

                System.Diagnostics.Debug.WriteLine(
                    $"Bounded USN lookup: target={normalizedTarget}, batch={batch + 1}, " +
                    $"start={nextUsn}, journalNext={journal.NextUsn}, " +
                    $"records={records.Count}, returnedNext={returnedNextUsn}.");

                if (returnedNextUsn <= nextUsn)
                {
                    break;
                }

                foreach (var record in records)
                {
                    if (TryMatchDeletedRecord(
                            volumeHandle,
                            volumeKey,
                            record,
                            normalizedTarget,
                            deletedAtUtc,
                            out fileReferenceNumber,
                            out parentFileReferenceNumber))
                    {
                        return true;
                    }
                }

                nextUsn = returnedNextUsn;
            }
        }

        // The recovery-time bounded lookup is read-only with respect to the
        // monitor cursor. If the background worker already consumed the journal
        // tail, enumerate only the recent USN range without inventing a StartUsn.
        const long recentUsnWindow = 10_000_000;
        var lowUsn = Math.Max(
            journal.FirstUsn,
            journal.NextUsn - recentUsnWindow);

        return TryResolveRecentUsnEnumData(
            volumeHandle,
            volumeKey,
            lowUsn,
            journal.NextUsn,
            normalizedTarget,
            deletedAtUtc,
            out fileReferenceNumber,
            out parentFileReferenceNumber);
    }

    private bool TryMatchDeletedRecord(
        SafeFileHandle volumeHandle,
        string volumeKey,
        UsnRecord record,
        string normalizedTarget,
        DateTime deletedAtUtc,
        out ulong fileReferenceNumber,
        out ulong parentFileReferenceNumber)
    {
        fileReferenceNumber = 0;
        parentFileReferenceNumber = 0;

        if ((record.Reason & UsnReasonFileDelete) == 0 ||
            (record.FileAttributes & FileAttributeDirectory) != 0 ||
            string.IsNullOrWhiteSpace(record.FileName))
        {
            return false;
        }

        if (deletedAtUtc != default &&
            Math.Abs((record.TimestampUtc - deletedAtUtc).TotalMinutes) > 5)
        {
            return false;
        }

        var cache = _parentPathCaches.GetOrAdd(
            volumeKey,
            _ => new ConcurrentDictionary<ulong, string>());

        var directory = cache.TryGetValue(
            record.ParentFileReferenceNumber,
            out var knownPath)
            ? knownPath
            : ResolveParentDirectory(
                volumeHandle,
                record.ParentFileReferenceNumber);

        if (!string.IsNullOrWhiteSpace(directory))
        {
            cache[record.ParentFileReferenceNumber] = directory;
        }

        if (string.IsNullOrWhiteSpace(directory))
        {
            if (!string.Equals(
                    record.FileName,
                    Path.GetFileName(normalizedTarget),
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }
        else
        {
            var candidatePath = NormalizePath(
                Path.Combine(directory, record.FileName));

            if (!string.Equals(
                    candidatePath,
                    normalizedTarget,
                    StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        fileReferenceNumber = record.FileReferenceNumber;
        parentFileReferenceNumber = record.ParentFileReferenceNumber;

        _recentDeletedRecords.Enqueue(
            new RecentDeletedRecord(
                fileReferenceNumber,
                parentFileReferenceNumber,
                record.FileName,
                directory,
                record.TimestampUtc));

        while (_recentDeletedRecords.Count > RecentDeletedRecordLimit &&
               _recentDeletedRecords.TryDequeue(out _))
        {
        }

        return true;
    }

    private bool TryResolveRecentUsnEnumData(
        SafeFileHandle volumeHandle,
        string volumeKey,
        long lowUsn,
        long highUsn,
        string normalizedTarget,
        DateTime deletedAtUtc,
        out ulong fileReferenceNumber,
        out ulong parentFileReferenceNumber)
    {
        fileReferenceNumber = 0;
        parentFileReferenceNumber = 0;

        if (lowUsn >= highUsn)
        {
            return false;
        }

        ulong startFileReferenceNumber = 0;
        const int maxPages = 32;

        for (var page = 0; page < maxPages; page++)
        {
            var request = new MftEnumDataV0
            {
                StartFileReferenceNumber = startFileReferenceNumber,
                LowUsn = lowUsn,
                HighUsn = highUsn
            };

            var input = StructureToBytes(request);
            var output = new byte[1024 * 1024];

            if (!DeviceIoControl(
                    volumeHandle,
                    FsctlEnumUsnData,
                    input,
                    (uint)input.Length,
                    output,
                    (uint)output.Length,
                    out var bytesReturned,
                    IntPtr.Zero))
            {
                var error = Marshal.GetLastWin32Error();

                if (error == ErrorJournalDeleteInProgress ||
                    error == ErrorJournalNotActive ||
                    error == ErrorJournalEntryDeleted)
                {
                    return false;
                }

                System.Diagnostics.Debug.WriteLine(
                    $"Bounded USN enum fallback failed: error={error}, lowUsn={lowUsn}, highUsn={highUsn}.");
                return false;
            }

            if (bytesReturned < sizeof(ulong))
            {
                return false;
            }

            var nextStart = BinaryPrimitives.ReadUInt64LittleEndian(
                output.AsSpan(0, 8));

            var offset = 8;

            while (offset + 4 <= bytesReturned)
            {
                var recordLength = BinaryPrimitives.ReadUInt32LittleEndian(
                    output.AsSpan(offset, 4));

                if (recordLength < UsnRecordV2MinimumLength ||
                    recordLength > bytesReturned - offset)
                {
                    break;
                }

                var recordSpan = output.AsSpan(
                    offset,
                    checked((int)recordLength));

                var majorVersion = BinaryPrimitives.ReadUInt16LittleEndian(
                    recordSpan.Slice(4, 2));

                if (majorVersion == 2)
                {
                    var recordFileReferenceNumber =
                        BinaryPrimitives.ReadUInt64LittleEndian(
                            recordSpan.Slice(8, 8));
                    var recordParentFileReferenceNumber =
                        BinaryPrimitives.ReadUInt64LittleEndian(
                            recordSpan.Slice(16, 8));
                    var timestampFileTime =
                        BinaryPrimitives.ReadInt64LittleEndian(
                            recordSpan.Slice(32, 8));
                    var reason =
                        BinaryPrimitives.ReadUInt32LittleEndian(
                            recordSpan.Slice(40, 4));
                    var fileAttributes =
                        BinaryPrimitives.ReadUInt32LittleEndian(
                            recordSpan.Slice(52, 4));
                    var nameLength =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            recordSpan.Slice(56, 2));
                    var nameOffset =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            recordSpan.Slice(58, 2));

                    if (nameOffset + nameLength <= recordSpan.Length)
                    {
                        DateTime timestampUtc;

                        try
                        {
                            timestampUtc = DateTime.FromFileTimeUtc(timestampFileTime);
                        }
                        catch
                        {
                            timestampUtc = DateTime.UtcNow;
                        }

                        var name = System.Text.Encoding.Unicode.GetString(
                            recordSpan.Slice(nameOffset, nameLength));

                        if (TryMatchDeletedRecord(
                                volumeHandle,
                                volumeKey,
                                new UsnRecord(
                                    recordFileReferenceNumber,
                                    recordParentFileReferenceNumber,
                                    reason,
                                    fileAttributes,
                                    name,
                                    timestampUtc),
                                normalizedTarget,
                                deletedAtUtc,
                                out fileReferenceNumber,
                                out parentFileReferenceNumber))
                        {
                            return true;
                        }
                    }
                }

                offset += checked((int)recordLength);
            }

            if (nextStart <= startFileReferenceNumber)
            {
                break;
            }

            startFileReferenceNumber = nextStart;

            if (bytesReturned <= sizeof(ulong))
            {
                break;
            }
        }

        return false;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MftEnumDataV0
    {
        public ulong StartFileReferenceNumber;
        public long LowUsn;
        public long HighUsn;
    }

    private static string NormalizePath(string path) =>
        path.Trim().Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

    private static List<UsnRecord> ReadRecords(
        SafeFileHandle volumeHandle,
        ulong journalId,
        long startUsn,
        out long nextUsn)
    {
        // Use the V0 NTFS input layout here. The V1 extension adds
        // MinMajorVersion/MaxMajorVersion, and Windows can reject the larger
        // input buffer with ERROR_INVALID_PARAMETER (87) for NTFS journals.
        var request = new ReadUsnJournalRequest
        {
            StartUsn = startUsn,
            ReasonMask = UsnReasonFileDelete,
            ReturnOnlyOnClose = 0,
            // This is a bounded historical lookup, not a live wait for new
            // journal entries. BytesToWaitFor = 0 means do not wait for new data.
            Timeout = 0,
            BytesToWaitFor = 0,
            UsnJournalId = journalId
        };

        var input = StructureToBytes(request);
        var output = new byte[1024 * 1024];
        nextUsn = startUsn;

        if (!DeviceIoControl(
                volumeHandle,
                FsctlReadUsnJournal,
                input,
                (uint)input.Length,
                output,
                (uint)output.Length,
                out var bytesReturned,
                IntPtr.Zero))
        {
            var error = Marshal.GetLastWin32Error();

            if (error == ErrorJournalDeleteInProgress ||
                error == ErrorJournalNotActive ||
                error == ErrorJournalEntryDeleted)
            {
                return [];
            }

            throw new Win32Exception(
                error,
                $"FSCTL_READ_USN_JOURNAL failed (error {error}) at USN {startUsn} for journal {journalId}.");
        }

        if (bytesReturned < sizeof(long))
        {
            return [];
        }

        nextUsn = BinaryPrimitives.ReadInt64LittleEndian(output.AsSpan(0, 8));

        var records = new List<UsnRecord>();
        var offset = 8;

        while (offset + 4 <= bytesReturned)
        {
            var recordLength = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(offset, 4));
            if (recordLength < UsnRecordV2MinimumLength ||
                recordLength > bytesReturned - offset)
            {
                break;
            }

            var recordSpan = output.AsSpan(offset, checked((int)recordLength));
            var majorVersion = BinaryPrimitives.ReadUInt16LittleEndian(recordSpan.Slice(4, 2));
            if (majorVersion != 2)
            {
                offset += checked((int)recordLength);
                continue;
            }

            var fileReference = BinaryPrimitives.ReadUInt64LittleEndian(recordSpan.Slice(8, 8));
            var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(recordSpan.Slice(16, 8));
            var timestampFileTime = BinaryPrimitives.ReadInt64LittleEndian(recordSpan.Slice(32, 8));
            var reason = BinaryPrimitives.ReadUInt32LittleEndian(recordSpan.Slice(40, 4));
            var fileAttributes = BinaryPrimitives.ReadUInt32LittleEndian(recordSpan.Slice(52, 4));
            var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(recordSpan.Slice(56, 2));
            var nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(recordSpan.Slice(58, 2));

            if (nameOffset + nameLength <= recordSpan.Length)
            {
                var name = System.Text.Encoding.Unicode.GetString(
                    recordSpan.Slice(nameOffset, nameLength));

                DateTime timestampUtc;
                try
                {
                    timestampUtc = DateTime.FromFileTimeUtc(timestampFileTime);
                }
                catch
                {
                    timestampUtc = DateTime.UtcNow;
                }

                records.Add(new UsnRecord(
                    fileReference,
                    parentReference,
                    reason,
                    fileAttributes,
                    name,
                    timestampUtc));
            }

            offset += checked((int)recordLength);
        }

        return records;
    }

    private static string? ResolveParentDirectory(SafeFileHandle volumeHandle, ulong parentFileReference)
    {
        var descriptor = new FileIdDescriptor
        {
            Size = (uint)Marshal.SizeOf<FileIdDescriptor>(),
            Type = 0,
            FileId = unchecked((long)parentFileReference)
        };

        var directoryHandle = OpenFileById(
            volumeHandle,
            ref descriptor,
            FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            FileFlagBackupSemantics);

        if (directoryHandle == IntPtr.Zero ||
            directoryHandle == new IntPtr(-1))
        {
            return null;
        }

        try
        {
            var builder = new System.Text.StringBuilder(1024);
            var length = GetFinalPathNameByHandle(
                directoryHandle,
                builder,
                (uint)builder.Capacity,
                0);

            if (length == 0)
            {
                return null;
            }

            if (length >= builder.Capacity)
            {
                builder = new System.Text.StringBuilder((int)length + 1);
                length = GetFinalPathNameByHandle(
                    directoryHandle,
                    builder,
                    (uint)builder.Capacity,
                    0);
            }

            if (length == 0)
            {
                return null;
            }

            return NormalizeFinalPath(builder.ToString());
        }
        finally
        {
            CloseHandle(directoryHandle);
        }
    }

    private static string NormalizeFinalPath(string path)
    {
        if (path.StartsWith(@"\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[8..];
        }

        if (path.StartsWith(@"\\?\\", StringComparison.OrdinalIgnoreCase))
        {
            return path[4..];
        }

        return path;
    }

    private static IReadOnlyList<DriveInfo> GetNtfsFixedDrives()
    {
        var drives = new List<DriveInfo>();

        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.IsReady &&
                    drive.DriveType == DriveType.Fixed &&
                    string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                {
                    drives.Add(drive);
                }
            }
            catch
            {
                // Drive availability can change during enumeration.
            }
        }

        return drives;
    }

    private static byte[] StructureToBytes<T>(T value) where T : struct
    {
        var size = Marshal.SizeOf<T>();
        var bytes = new byte[size];
        var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);

        try
        {
            Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), fDeleteOld: false);
            return bytes;
        }
        finally
        {
            handle.Free();
        }
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }

    private readonly record struct JournalInfo(
        ulong JournalId,
        long FirstUsn,
        long NextUsn,
        long LowestValidUsn);

    private readonly record struct RecentDeletedRecord(
        ulong FileReferenceNumber,
        ulong ParentFileReferenceNumber,
        string FileName,
        string? DirectoryPath,
        DateTime TimestampUtc);

    private readonly record struct UsnRecord(
        ulong FileReferenceNumber,
        ulong ParentFileReferenceNumber,
        uint Reason,
        uint FileAttributes,
        string FileName,
        DateTime TimestampUtc);

    [StructLayout(LayoutKind.Sequential)]
    private struct CreateUsnJournalData
    {
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ReadUsnJournalRequest
    {
        public long StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalId;
    }

    [StructLayout(LayoutKind.Explicit, Size = 24)]
    private struct FileIdDescriptor
    {
        [FieldOffset(0)]
        public uint Size;

        [FieldOffset(4)]
        public int Type;

        [FieldOffset(8)]
        public long FileId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        byte[]? lpInBuffer,
        uint nInBufferSize,
        byte[]? lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenFileById(
        SafeFileHandle hVolumeHint,
        ref FileIdDescriptor lpFileId,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwFlagsAndAttributes);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandle(
        IntPtr hFile,
        System.Text.StringBuilder lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
