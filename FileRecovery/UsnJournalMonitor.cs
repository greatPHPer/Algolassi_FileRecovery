using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class UsnJournalMonitor : IDisposable
{
    private const uint FsctlQueryUsnJournal = 0x000900F4;
    private const uint FsctlReadUsnJournal = 0x000900BB;

    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileReadAttributes = 0x00000080;
    private const int ErrorJournalEntryDeleted = 1177;

    private const uint UsnReasonFileDelete = 0x00000200;
    private const int UsnRecordV2MinimumLength = 60;

    private readonly RecoverySettings _settings;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _gate = new();
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<ulong, string>> _parentPathCaches =
        new(StringComparer.OrdinalIgnoreCase);

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

            _started = true;
            _worker = Task.Run(MonitorAllVolumesAsync);
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
        while (!_cts.IsCancellationRequested)
        {
            foreach (var drive in GetNtfsFixedDrives())
            {
                if (_cts.IsCancellationRequested)
                {
                    break;
                }

                try
                {
                    ReadVolume(drive);
                }
                catch (UnauthorizedAccessException)
                {
                    StatusChanged?.Invoke(this, $"USN monitoring for {drive.RootDirectory.FullName} requires administrator privileges.");
                }
                catch (Win32Exception ex) when (ex.NativeErrorCode == 5)
                {
                    StatusChanged?.Invoke(this, $"USN monitoring for {drive.RootDirectory.FullName} requires administrator privileges.");
                }
                catch (Exception ex)
                {
                    StatusChanged?.Invoke(this, $"USN monitoring warning for {drive.RootDirectory.FullName}: {ex.Message}");
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

        if (!TryQueryJournal(volumeHandle, out var journal))
        {
            return;
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
        while (!_cts.IsCancellationRequested && nextUsn < journal.NextUsn)
        {
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

                var deletion = new DeletionRecord
                {
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
    }

    private static bool TryQueryJournal(SafeFileHandle volumeHandle, out JournalInfo journal)
    {
        journal = default;
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
            if (error == 2 || error == 1178)
            {
                return false;
            }

            throw new Win32Exception(error);
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

    private static List<UsnRecord> ReadRecords(
        SafeFileHandle volumeHandle,
        ulong journalId,
        long startUsn,
        out long nextUsn)
    {
        var request = new ReadUsnJournalRequest
        {
            StartUsn = startUsn,
            ReasonMask = UsnReasonFileDelete,
            ReturnOnlyOnClose = 0,
            Timeout = 1,
            BytesToWaitFor = 1,
            UsnJournalId = journalId,
            MinMajorVersion = 2,
            MaxMajorVersion = 2
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

            if (error == ErrorJournalEntryDeleted)
            {
                return [];
            }

            throw new Win32Exception(error);
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

    private static IEnumerable<DriveInfo> GetNtfsFixedDrives()
    {
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.IsReady &&
                    drive.DriveType == DriveType.Fixed &&
                    string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                {
                    yield return drive;
                }
            }
            catch
            {
                // Drive availability can change during enumeration.
            }
        }
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

    private readonly record struct UsnRecord(
        ulong FileReferenceNumber,
        ulong ParentFileReferenceNumber,
        uint Reason,
        uint FileAttributes,
        string FileName,
        DateTime TimestampUtc);

    [StructLayout(LayoutKind.Sequential)]
    private struct ReadUsnJournalRequest
    {
        public long StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalId;
        public ushort MinMajorVersion;
        public ushort MaxMajorVersion;
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
