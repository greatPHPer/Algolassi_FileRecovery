using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

/// <summary>
/// Conservative forensic helper for extracting a historical file size from the
/// NTFS $LogFile transaction journal. This does not attempt to replay the NTFS
/// transaction log. It searches the currently retained log payload for a
/// structurally valid $FILE_NAME value matching the deleted file name and parent.
///
/// $LogFile is a finite circular journal, so absence of a match is normal.
/// </summary>
public sealed class NtfsLogFileHistoricalSizeService
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagSequentialScan = 0x08000000;

    private const int BufferSize = 1024 * 1024;
    private const uint NtfsFileNameAttributeType = 0x30;
    private const int ParentReferenceOffset = 0;
    private const int AllocatedSizeOffset = 40;
    private const int RealSizeOffset = 48;
    private const int NameLengthOffset = 64;
    private const int NameNamespaceOffset = 65;
    private const int NameOffset = 66;

    public bool TryRecoverFileSize(
        string rootPath,
        string expectedFileName,
        ulong expectedParentFileReferenceNumber,
        long maximumValidFileSize,
        out long fileSizeBytes,
        out string evidence)
    {
        fileSizeBytes = 0;
        evidence = string.Empty;

        if (string.IsNullOrWhiteSpace(rootPath) ||
            string.IsNullOrWhiteSpace(expectedFileName) ||
            expectedParentFileReferenceNumber == 0 ||
            maximumValidFileSize <= 0)
        {
            return false;
        }

        var root = Path.GetPathRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        var volumeName = root.TrimEnd(Path.DirectorySeparatorChar);
        var logFilePath = Path.Combine(
            volumeName + Path.DirectorySeparatorChar,
            "$LogFile");

        var expectedNameBytes = System.Text.Encoding.Unicode.GetBytes(expectedFileName);
        if (expectedNameBytes.Length == 0)
        {
            return false;
        }

        WindowsPrivilege.EnableSeBackupPrivilege();

        try
        {
            using var handle = CreateFile(
                logFilePath,
                GenericRead,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics | FileFlagSequentialScan,
                IntPtr.Zero);

            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                evidence = $"Could not open NTFS $LogFile for read-only forensic inspection. Win32 error={error}.";
                return false;
            }

            if (!GetFileSizeEx(handle, out var logFileSize) || logFileSize <= 0)
            {
                evidence = "NTFS $LogFile did not report a readable size.";
                return false;
            }

            // Keep enough overlap to reconstruct a complete $FILE_NAME value if
            // the UTF-16 filename or its preceding 66-byte header crosses a chunk.
            var overlapLength = Math.Max(expectedNameBytes.Length + NameOffset + 16, 256);
            var previousTail = Array.Empty<byte>();
            long scannedBytes = 0;
            long bestSize = 0;
            long matchCount = 0;

            while (scannedBytes < logFileSize)
            {
                var remaining = logFileSize - scannedBytes;
                var bytesToRead = (int)Math.Min(BufferSize, remaining);
                var buffer = new byte[bytesToRead];

                ReadFileExact(handle, buffer, scannedBytes);

                var window = new byte[previousTail.Length + buffer.Length];
                if (previousTail.Length > 0)
                {
                    Buffer.BlockCopy(previousTail, 0, window, 0, previousTail.Length);
                }

                Buffer.BlockCopy(
                    buffer,
                    0,
                    window,
                    previousTail.Length,
                    buffer.Length);

                var windowAbsoluteOffset = scannedBytes - previousTail.Length;

                for (var searchOffset = 0;
                     searchOffset + expectedNameBytes.Length <= window.Length;
                     searchOffset++)
                {
                    if (!window.AsSpan(
                            searchOffset,
                            expectedNameBytes.Length)
                        .SequenceEqual(expectedNameBytes))
                    {
                        continue;
                    }

                    var valueOffset = searchOffset - NameOffset;
                    if (valueOffset < 0 ||
                        valueOffset + NameOffset + expectedNameBytes.Length > window.Length)
                    {
                        continue;
                    }

                    var candidateSize = TryReadFileNameValue(
                        window,
                        valueOffset,
                        expectedFileName,
                        expectedParentFileReferenceNumber,
                        maximumValidFileSize);

                    if (candidateSize <= 0)
                    {
                        continue;
                    }

                    matchCount++;
                    if (candidateSize > bestSize)
                    {
                        bestSize = candidateSize;
                    }

                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS $LogFile historical $FILE_NAME match: " +
                        $"fileName={expectedFileName}, size={candidateSize:N0}, " +
                        $"offset={windowAbsoluteOffset + searchOffset:N0}.");
                }

                scannedBytes = checked(scannedBytes + buffer.Length);

                previousTail = buffer.Length <= overlapLength
                    ? buffer
                    : buffer.AsSpan(buffer.Length - overlapLength).ToArray();
            }

            if (bestSize <= 0)
            {
                evidence =
                    $"NTFS $LogFile was scanned completely ({logFileSize:N0} bytes), " +
                    $"but no structurally valid $FILE_NAME size was found for " +
                    $"'{expectedFileName}' with the expected parent reference.";
                return false;
            }

            fileSizeBytes = bestSize;
            evidence =
                $"Recovered historical file size {bestSize:N0} bytes from NTFS $LogFile " +
                $"($FILE_NAME evidence; {matchCount:N0} matching log payload occurrence(s)).";

            return true;
        }
        catch (Exception ex)
        {
            evidence =
                $"NTFS $LogFile historical-size inspection failed: " +
                $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private static long TryReadFileNameValue(
        byte[] buffer,
        int valueOffset,
        string expectedFileName,
        ulong expectedParentFileReferenceNumber,
        long maximumValidFileSize)
    {
        if (valueOffset < 0 ||
            valueOffset + NameOffset > buffer.Length)
        {
            return 0;
        }

        var storedNameLength = buffer[valueOffset + NameLengthOffset];
        var nameNamespace = buffer[valueOffset + NameNamespaceOffset];

        if (storedNameLength == 0 ||
            nameNamespace > 3 ||
            storedNameLength != expectedFileName.Length)
        {
            return 0;
        }

        var nameByteLength = checked(storedNameLength * 2);
        if (NameOffset + nameByteLength > buffer.Length - valueOffset)
        {
            return 0;
        }

        var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(
            buffer.AsSpan(
                valueOffset + ParentReferenceOffset,
                sizeof(ulong)));

        if (parentReference != expectedParentFileReferenceNumber)
        {
            return 0;
        }

        var storedName = System.Text.Encoding.Unicode.GetString(
            buffer,
            valueOffset + NameOffset,
            nameByteLength);

        if (!string.Equals(
                storedName,
                expectedFileName,
                StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        var allocatedSize = BinaryPrimitives.ReadInt64LittleEndian(
            buffer.AsSpan(
                valueOffset + AllocatedSizeOffset,
                sizeof(long)));

        var realSize = BinaryPrimitives.ReadInt64LittleEndian(
            buffer.AsSpan(
                valueOffset + RealSizeOffset,
                sizeof(long)));

        if (realSize < 0 ||
            allocatedSize < 0 ||
            realSize > allocatedSize ||
            realSize > maximumValidFileSize)
        {
            return 0;
        }

        return realSize;
    }

    private static void ReadFileExact(
        SafeFileHandle handle,
        byte[] buffer,
        long offset)
    {
        if (buffer.Length == 0)
        {
            return;
        }

        if (!SetFilePointerEx(handle, offset, IntPtr.Zero, 0))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Could not seek NTFS $LogFile to byte offset {offset:N0}.");
        }

        using var completionEvent = new ManualResetEvent(initialState: false);

        var overlapped = new NativeOverlapped
        {
            OffsetLow = unchecked((int)(offset & 0xFFFFFFFF)),
            OffsetHigh = unchecked((int)(offset >> 32)),
            HEvent = completionEvent.SafeWaitHandle.DangerousGetHandle()
        };

        var overlappedPtr = Marshal.AllocHGlobal(
            Marshal.SizeOf<NativeOverlapped>());

        try
        {
            Marshal.StructureToPtr(
                overlapped,
                overlappedPtr,
                fDeleteOld: false);

            var bufferHandle = GCHandle.Alloc(
                buffer,
                GCHandleType.Pinned);

            try
            {
                var started = ReadFile(
                    handle,
                    bufferHandle.AddrOfPinnedObject(),
                    checked((uint)buffer.Length),
                    IntPtr.Zero,
                    overlappedPtr);

                if (!started)
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != 997)
                    {
                        throw new Win32Exception(
                            error,
                            $"Could not read NTFS $LogFile at byte offset {offset:N0}.");
                    }
                }

                completionEvent.WaitOne();

                if (!GetOverlappedResult(
                        handle,
                        overlappedPtr,
                        out var bytesRead,
                        bWait: false))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        $"Could not complete NTFS $LogFile read at byte offset {offset:N0}.");
                }

                if (bytesRead != (uint)buffer.Length)
                {
                    throw new EndOfStreamException(
                        $"NTFS $LogFile returned {bytesRead:N0} byte(s) instead of {buffer.Length:N0}.");
                }
            }
            finally
            {
                bufferHandle.Free();
            }
        }
        finally
        {
            Marshal.FreeHGlobal(overlappedPtr);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOverlapped
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public int OffsetLow;
        public int OffsetHigh;
        public IntPtr HEvent;
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
    private static extern bool GetFileSizeEx(
        SafeFileHandle hFile,
        out long lpFileSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        IntPtr lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetOverlappedResult(
        SafeFileHandle hFile,
        IntPtr lpOverlapped,
        out uint lpNumberOfBytesTransferred,
        [MarshalAs(UnmanagedType.Bool)] bool bWait);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        IntPtr lpBuffer,
        uint nNumberOfBytesToRead,
        IntPtr lpNumberOfBytesRead,
        IntPtr lpOverlapped);
}
