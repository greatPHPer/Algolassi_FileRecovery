using System.Text;
using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class NtfsMftDataReader
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const int ErrorIoPending = 997;

    private const uint NtfsAttributeList = 0x20;
    private const uint NtfsAttributeData = 0x80;
    private const uint NtfsAttributeEnd = 0xFFFFFFFF;
    private const byte NonResidentForm = 1;
    private const int MaxAttributeListBytes = 16 * 1024 * 1024;
    private const int RawReadBufferSize = 1024 * 1024;

    private IReadOnlyList<NtfsDataExtent>? _mftExtents;

    public bool TryReadHistoricalResidentData(
        string rootPath,
        ulong fileReferenceNumber,
        ulong expectedParentFileReferenceNumber,
        string expectedFileName,
        out byte[] data,
        out bool usedHeuristicMatch)
    {
        data = [];
        usedHeuristicMatch = false;

        if (string.IsNullOrWhiteSpace(rootPath) ||
            fileReferenceNumber == 0 ||
            string.IsNullOrWhiteSpace(expectedFileName))
        {
            return false;
        }

        var root = GetNtfsVolumeRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        try
        {
            WindowsPrivilege.EnableSeBackupPrivilege();

            var volumeInfo = new NtfsVolumeInspector().Inspect(root);
            using var rawMftVolumeHandle = CreateVolumeHandle(
                volumeInfo.RootPath,
                overlapped: true);

            var segmentNumber = fileReferenceNumber & 0x0000FFFFFFFFFFFFUL;

            // This is deliberately a forensic slack read. We do not accept the
            // current MFT sequence as the historical record because the USN sequence
            // is already known to be stale for these reused segments.
            var record = ReadMftRecordByExtentMap(
                rawMftVolumeHandle,
                volumeInfo,
                segmentNumber,
                expectedSequenceNumber: 0,
                expectedBaseFileReference: 0);

            if (record is null)
            {
                return false;
            }

            var slackStart = FindAttributeSlackStart(record);
            if (slackStart < 0 || slackStart >= record.Length)
            {
                return false;
            }

            var expectedNameBytes = Encoding.Unicode.GetBytes(expectedFileName);
            if (expectedNameBytes.Length == 0)
            {
                return false;
            }

            var historicalFileNameOffset = FindHistoricalFileNameValue(
                record,
                slackStart,
                expectedNameBytes,
                expectedParentFileReferenceNumber,
                out var historicalFileSize);

            if (historicalFileNameOffset < 0 || historicalFileSize < 0)
            {
                // A reused MFT record can retain the filename bytes while the
                // surrounding $FILE_NAME header has already been overwritten.
                // In that case the fully structural match above is unavailable,
                // but an exact UTF-16 filename anchor is still useful forensic
                // evidence. Try the nearby slack for a plausible resident
                // unnamed $DATA attribute before giving up.
                if (TryFindResidentDataNearRawFileName(
                        record,
                        slackStart,
                        expectedNameBytes,
                        out var heuristicData,
                        out var rawNameOffset,
                        out var heuristicDataAttributeOffset))
                {
                    data = heuristicData;
                    usedHeuristicMatch = true;

                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS heuristic resident $DATA evidence: segment={segmentNumber}, " +
                        $"fileName={expectedFileName}, parentRef={expectedParentFileReferenceNumber}, " +
                        $"size={data.Length:N0}, rawNameOffset={rawNameOffset}, " +
                        $"dataAttributeOffset={heuristicDataAttributeOffset}.");

                    return true;
                }

                return false;
            }

            // Resident $DATA is small and fully contained in the MFT record.
            // After record reuse, the old slack is not guaranteed to preserve the
            // original attribute sequence. Search the slack byte-for-byte for a
            // plausible resident unnamed $DATA attribute whose length matches the
            // historical $FILE_NAME size and is physically close to that filename.
            const int maxRelatedSlackDistance = 1024;

            for (var attributeOffset = slackStart;
                 attributeOffset + 24 <= record.Length;
                 attributeOffset++)
            {
                var type = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(attributeOffset, 4));

                if (type != NtfsAttributeData)
                {
                    continue;
                }

                var attributeLength = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(attributeOffset + 4, 4));

                if (attributeLength < 24 ||
                    attributeOffset + attributeLength > record.Length)
                {
                    continue;
                }

                var formCode = record[attributeOffset + 8];
                var nameLength = record[attributeOffset + 9];

                if (formCode != 0 || nameLength != 0)
                {
                    continue;
                }

                var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(attributeOffset + 16, 4));

                var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                    record.AsSpan(attributeOffset + 20, 2));

                if (valueLength == 0 ||
                    valueLength != (ulong)historicalFileSize ||
                    valueLength > (uint)MaxAttributeListBytes ||
                    valueOffset < 24 ||
                    valueOffset >= attributeLength ||
                    valueLength > attributeLength - valueOffset ||
                    Math.Abs(attributeOffset - historicalFileNameOffset) > maxRelatedSlackDistance)
                {
                    continue;
                }

                data = record.AsSpan(
                        attributeOffset + valueOffset,
                        checked((int)valueLength))
                    .ToArray();
                usedHeuristicMatch = false;

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS historical resident $DATA evidence: segment={segmentNumber}, " +
                    $"fileName={expectedFileName}, parentRef={expectedParentFileReferenceNumber}, " +
                    $"size={data.Length:N0}, dataAttributeOffset={attributeOffset}, " +
                    $"fileNameOffset={historicalFileNameOffset}.");

                return true;
            }

        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS historical resident $DATA lookup failed: " +
                $"{ex.GetType().Name}: {ex.Message}");
        }

        return false;
    }

    private static int FindAttributeSlackStart(byte[] record)
    {
        if (record.Length < 24)
        {
            return -1;
        }

        var firstAttributeOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            record.AsSpan(20, 2));

        if (firstAttributeOffset < 24 ||
            firstAttributeOffset >= record.Length)
        {
            return -1;
        }

        var offset = (int)firstAttributeOffset;
        while (offset + 16 <= record.Length)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(
                record.AsSpan(offset, 4));

            if (type == NtfsAttributeEnd)
            {
                return offset + 4;
            }

            var attributeLength = BinaryPrimitives.ReadUInt32LittleEndian(
                record.AsSpan(offset + 4, 4));

            if (attributeLength < 24 ||
                offset + attributeLength > record.Length)
            {
                return -1;
            }

            offset += checked((int)attributeLength);
        }

        return -1;
    }

    private static bool TryFindResidentDataNearRawFileName(
        byte[] record,
        int slackStart,
        byte[] expectedNameBytes,
        out byte[] data,
        out int rawNameOffset,
        out int dataAttributeOffset)
    {
        data = [];
        rawNameOffset = -1;
        dataAttributeOffset = -1;

        if (slackStart < 0 ||
            slackStart >= record.Length ||
            expectedNameBytes.Length == 0)
        {
            return false;
        }

        const int maxRelatedSlackDistance = 1024;
        const int minimumDataLength = 1;

        var bestDistance = int.MaxValue;
        byte[]? bestData = null;
        var bestNameOffset = -1;
        var bestAttributeOffset = -1;

        for (var nameOffset = slackStart;
             nameOffset + expectedNameBytes.Length <= record.Length;
             nameOffset++)
        {
            if (!record.AsSpan(
                    nameOffset,
                    expectedNameBytes.Length)
                .SequenceEqual(expectedNameBytes))
            {
                continue;
            }

            for (var attributeOffset = slackStart;
                 attributeOffset + 24 <= record.Length;
                 attributeOffset++)
            {
                var distance = Math.Abs(attributeOffset - nameOffset);
                if (distance > maxRelatedSlackDistance ||
                    distance >= bestDistance)
                {
                    continue;
                }

                var type = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(attributeOffset, 4));

                if (type != NtfsAttributeData)
                {
                    continue;
                }

                var attributeLength = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(attributeOffset + 4, 4));

                if (attributeLength < 24 ||
                    attributeOffset + attributeLength > record.Length)
                {
                    continue;
                }

                var formCode = record[attributeOffset + 8];
                var nameLength = record[attributeOffset + 9];

                if (formCode != 0 || nameLength != 0)
                {
                    continue;
                }

                var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(attributeOffset + 16, 4));

                var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                    record.AsSpan(attributeOffset + 20, 2));

                if (valueLength < minimumDataLength ||
                    valueLength > (uint)MaxAttributeListBytes ||
                    valueOffset < 24 ||
                    valueOffset >= attributeLength ||
                    valueLength > attributeLength - valueOffset)
                {
                    continue;
                }

                bestData = record.AsSpan(
                        attributeOffset + valueOffset,
                        checked((int)valueLength))
                    .ToArray();

                bestDistance = distance;
                bestNameOffset = nameOffset;
                bestAttributeOffset = attributeOffset;
            }
        }

        if (bestData is null)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS heuristic resident $DATA search: no raw filename/data pair found. " +
                $"slackStart={slackStart}, expectedName={Encoding.Unicode.GetString(expectedNameBytes)}.");
            return false;
        }

        data = bestData;
        rawNameOffset = bestNameOffset;
        dataAttributeOffset = bestAttributeOffset;
        return true;
    }

    private static int FindHistoricalFileNameValue(
        byte[] record,
        int slackStart,
        byte[] expectedNameBytes,
        ulong expectedParentFileReferenceNumber,
        out long historicalFileSize)
    {
        historicalFileSize = -1;

        const int parentOffset = 0;
        const int allocatedSizeOffset = 40;
        const int realSizeOffset = 48;
        const int fileNameFlagsOffset = 56;
        const int fileNameLengthOffset = 64;
        const int fileNameNamespaceOffset = 65;
        const int fileNameOffset = 66;

        if (slackStart < 0 ||
            slackStart >= record.Length ||
            expectedNameBytes.Length == 0)
        {
            return -1;
        }

        var examinedNameByteMatches = 0;
        var parentMatches = 0;

        // Search by the retained $FILE_NAME value structure rather than only
        // finding raw UTF-16 bytes and reconstructing the value backwards.
        // Reused MFT records can leave slack with partial/unaligned remnants,
        // so scan every byte and validate the complete structure.
        for (var valueOffset = slackStart;
             valueOffset + fileNameOffset + expectedNameBytes.Length <= record.Length;
             valueOffset++)
        {
            var storedNameLength = record[valueOffset + fileNameLengthOffset];
            var nameNamespace = record[valueOffset + fileNameNamespaceOffset];

            if (storedNameLength != expectedNameBytes.Length / 2 ||
                nameNamespace > 3)
            {
                continue;
            }

            var nameBytes = checked(storedNameLength * 2);
            if (valueOffset + fileNameOffset + nameBytes > record.Length)
            {
                continue;
            }

            if (!record.AsSpan(
                    valueOffset + fileNameOffset,
                    nameBytes)
                .SequenceEqual(expectedNameBytes))
            {
                continue;
            }

            examinedNameByteMatches++;

            var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(
                record.AsSpan(
                    valueOffset + parentOffset,
                    sizeof(ulong)));

            if (parentReference != expectedParentFileReferenceNumber)
            {
                continue;
            }

            parentMatches++;

            var allocatedSize = BinaryPrimitives.ReadInt64LittleEndian(
                record.AsSpan(
                    valueOffset + allocatedSizeOffset,
                    sizeof(long)));

            var realSize = BinaryPrimitives.ReadInt64LittleEndian(
                record.AsSpan(
                    valueOffset + realSizeOffset,
                    sizeof(long)));

            var flags = BinaryPrimitives.ReadUInt32LittleEndian(
                record.AsSpan(
                    valueOffset + fileNameFlagsOffset,
                    sizeof(uint)));
            if (realSize < 0 ||
                allocatedSize < 0 ||
                realSize > allocatedSize ||
                realSize > MaxAttributeListBytes)
            {
                continue;
            }

            historicalFileSize = realSize;

            System.Diagnostics.Debug.WriteLine(
                $"NTFS historical $FILE_NAME structure match: " +
                $"offset={valueOffset}, fileNameSize={storedNameLength}, " +
                $"namespace={nameNamespace}, parentRef={parentReference}, " +
                $"size={realSize}, allocated={allocatedSize}, flags=0x{flags:X8}.");

            return valueOffset;
        }

        System.Diagnostics.Debug.WriteLine(
            $"NTFS historical $FILE_NAME structure search: " +
            $"slackStart={slackStart}, recordLength={record.Length}, " +
            $"rawNameMatches={examinedNameByteMatches}, " +
            $"parentMatches={parentMatches}, expectedParent={expectedParentFileReferenceNumber}, " +
            $"expectedName={Encoding.Unicode.GetString(expectedNameBytes)}.");

        return -1;
    }

    public bool TryReadAllocatedFileSlack(
        string rootPath,
        string scanDirectory,
        string expectedExtension,
        long maxBytesToScan,
        IProgress<long>? progress,
        CancellationToken cancellationToken,
        out byte[] data,
        out string? sourceFile)
    {
        data = [];
        sourceFile = null;

        if (string.IsNullOrWhiteSpace(rootPath) ||
            string.IsNullOrWhiteSpace(scanDirectory) ||
            maxBytesToScan <= 0)
        {
            return false;
        }

        var root = GetNtfsVolumeRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        try
        {
            WindowsPrivilege.EnableSeBackupPrivilege();

            var volumeInfo = new NtfsVolumeInspector().Inspect(root);
            using var volumeHandle = CreateVolumeHandle(
                volumeInfo.RootPath,
                overlapped: false);

            var normalizedDirectory = scanDirectory.Trim();

            while (normalizedDirectory.StartsWith(@"\\?\", StringComparison.Ordinal) ||
                   normalizedDirectory.StartsWith(@"\\.\", StringComparison.Ordinal))
            {
                normalizedDirectory = normalizedDirectory[4..];
            }

            normalizedDirectory = Path.GetFullPath(normalizedDirectory)
                .TrimEnd(Path.DirectorySeparatorChar);
            var extension = expectedExtension ?? string.Empty;

            long scannedBytes = 0;

            foreach (var path in Directory.EnumerateFiles(
                         normalizedDirectory,
                         "*",
                         SearchOption.AllDirectories))
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!string.IsNullOrWhiteSpace(extension) &&
                    !Path.GetExtension(path).Equals(
                        extension,
                        StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var fileInfo = new FileInfo(path);
                if (fileInfo.Length <= 0)
                {
                    continue;
                }

                var fileReferenceNumber = TryGetFileReferenceNumber(path);
                if (fileReferenceNumber == 0)
                {
                    continue;
                }

                var stream = ReadDefaultDataStream(
                    volumeInfo,
                    volumeHandle,
                    fileReferenceNumber,
                    expectedFileName: Path.GetFileName(path),
                    expectedParentFileReferenceNumber: null,
                    expectedFullPath: path);

                if (!stream.Found ||
                    stream.IsResident ||
                    stream.FileSizeBytes <= 0 ||
                    stream.Extents.Count == 0)
                {
                    continue;
                }

                var remainder = stream.FileSizeBytes % volumeInfo.BytesPerCluster;
                if (remainder == 0)
                {
                    continue;
                }

                var slackLength = checked(
                    (int)(volumeInfo.BytesPerCluster - remainder));

                if (slackLength <= 0)
                {
                    continue;
                }

                var lastDataCluster = (stream.FileSizeBytes - 1) /
                                      volumeInfo.BytesPerCluster;

                var lastExtent = stream.Extents
                    .Where(extent =>
                        lastDataCluster >= extent.VirtualClusterNumber &&
                        lastDataCluster <
                            extent.VirtualClusterNumber + extent.ClusterCount)
                    .FirstOrDefault();

                if (lastExtent is null || lastExtent.IsSparse)
                {
                    continue;
                }

                var physicalCluster = checked(
                    lastExtent.LogicalClusterNumber +
                    (lastDataCluster - lastExtent.VirtualClusterNumber));

                var physicalOffset = checked(
                    physicalCluster * (long)volumeInfo.BytesPerCluster +
                    remainder);

                scannedBytes = checked(scannedBytes + slackLength);
                progress?.Report(scannedBytes);

                var slack = new byte[slackLength];
                cancellationToken.ThrowIfCancellationRequested();

                ReadAt(
                    volumeHandle,
                    physicalOffset,
                    slack);

                if (!TryFindTextLikePrefix(
                        slack,
                        out var textLength))
                {
                    continue;
                }

                data = slack.AsSpan(0, textLength).ToArray();
                sourceFile = path;

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS allocated-file slack text hit: sourceFile={path}, " +
                    $"fileSize={stream.FileSizeBytes:N0}, slackBytes={slackLength:N0}, " +
                    $"recoveredBytes={data.Length:N0}, physicalOffset={physicalOffset:N0}.");

                return true;
            }

            System.Diagnostics.Debug.WriteLine(
                $"NTFS allocated-file slack scan complete: scannedSlackBytes={scannedBytes:N0}.");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS allocated-file slack scan failed: " +
                $"{ex.GetType().Name}: {ex.Message}");
        }

        return false;
    }

    private static bool TryFindTextLikePrefix(
        byte[] buffer,
        out int length)
    {
        length = 0;

        if (buffer.Length < 4)
        {
            return false;
        }

        const int minimumLength = 4;
        var candidateLength = 0;
        var position = 0;

        while (position < buffer.Length &&
               candidateLength < 64L * 1024L * 1024L)
        {
            var value = buffer[position];

            if (value == 0)
            {
                break;
            }

            if (value is >= 0x20 and <= 0x7E ||
                value is 0x09 or 0x0A or 0x0D)
            {
                candidateLength++;
                position++;
                continue;
            }

            if (value is >= 0xC2 and <= 0xF4)
            {
                var sequenceLength =
                    value <= 0xDF ? 2 :
                    value <= 0xEF ? 3 : 4;

                if (position + sequenceLength > buffer.Length)
                {
                    break;
                }

                for (var i = 1; i < sequenceLength; i++)
                {
                    if (buffer[position + i] < 0x80 ||
                        buffer[position + i] > 0xBF)
                    {
                        return candidateLength >= minimumLength
                            ? SetTextLength(candidateLength, out length)
                            : false;
                    }
                }

                candidateLength += sequenceLength;
                position += sequenceLength;
                continue;
            }

            break;
        }

        return candidateLength >= minimumLength &&
               SetTextLength(candidateLength, out length);
    }

    private static bool SetTextLength(int value, out int length)
    {
        length = value;
        return true;
    }

    private static ulong TryGetFileReferenceNumber(string path)
    {
        using var handle = File.OpenHandle(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);

        if (handle.IsInvalid)
        {
            return 0;
        }

        if (!GetFileInformationByHandle(
                handle,
                out var info))
        {
            return 0;
        }

        return ((ulong)info.FileIndexHigh << 32) |
               info.FileIndexLow;
    }

    public bool TryReadResidentDataForDeletedReference(
        string rootPath,
        ulong fileReferenceNumber,
        ulong expectedParentFileReferenceNumber,
        string expectedFileName,
        string? expectedFullPath,
        DateTime expectedDeletedAtUtc,
        out byte[] data)
    {
        data = [];

        if (string.IsNullOrWhiteSpace(rootPath) ||
            fileReferenceNumber == 0 ||
            expectedParentFileReferenceNumber == 0 ||
            string.IsNullOrWhiteSpace(expectedFileName))
        {
            return false;
        }

        var root = GetNtfsVolumeRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        try
        {
            WindowsPrivilege.EnableSeBackupPrivilege();

            var volumeInfo = new NtfsVolumeInspector().Inspect(root);
            using var volumeHandle = CreateVolumeHandle(
                volumeInfo.RootPath,
                overlapped: true);

            var segmentNumber = fileReferenceNumber & 0x0000FFFFFFFFFFFFUL;
            var sequenceNumber = (ushort)(fileReferenceNumber >> 48);

            var record = ReadMftRecordByExtentMap(
                volumeHandle,
                volumeInfo,
                segmentNumber,
                sequenceNumber,
                expectedBaseFileReference: fileReferenceNumber);

            var usedRelaxedReference = false;

            if (record is null)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS fresh resident $DATA: exact MFT reference did not validate. " +
                    $"fileRef={fileReferenceNumber}, segment={segmentNumber}, " +
                    $"expectedSequence={sequenceNumber}, expectedParent={expectedParentFileReferenceNumber}, " +
                    $"fileName={expectedFileName}.");

                record = ReadMftRecordByExtentMap(
                    volumeHandle,
                    volumeInfo,
                    segmentNumber,
                    expectedSequenceNumber: 0,
                    expectedBaseFileReference: 0);

                if (record is null)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS fresh resident $DATA: could not read current MFT segment={segmentNumber}.");
                    return false;
                }

                var currentSequence = BinaryPrimitives.ReadUInt16LittleEndian(
                    record.AsSpan(16, 2));
                var currentFlags = BinaryPrimitives.ReadUInt16LittleEndian(
                    record.AsSpan(22, 2));
                var currentBaseReference = BinaryPrimitives.ReadUInt64LittleEndian(
                    record.AsSpan(32, 8));
                var isInUse = (currentFlags & 0x0001) != 0;

                var fileNameMatches = !isInUse &&
                    HasMatchingFileNameEntry(
                    volumeHandle,
                    record,
                    expectedFileName,
                    expectedParentFileReferenceNumber,
                    expectedFullPath,
                    expectedSequenceNumber: sequenceNumber,
                    expectedDeletedAtUtc: expectedDeletedAtUtc);

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS fresh resident $DATA: relaxed record inspected. " +
                    $"segment={segmentNumber}, currentSequence={currentSequence}, " +
                    $"expectedSequence={sequenceNumber}, flags=0x{currentFlags:X4}, " +
                    $"inUse={isInUse}, baseRef={currentBaseReference}, fileNameParentMatch={fileNameMatches}.");

                if (!fileNameMatches)
                {
                    return false;
                }

                usedRelaxedReference = true;
            }

            var dataAttributes = FindUnnamedDataAttributes(
                record,
                volumeInfo);

            var residentAttributes = dataAttributes
                .Where(attribute =>
                    attribute.IsResident &&
                    attribute.ResidentData is { Length: > 0 })
                .ToList();

            if (residentAttributes.Count != 1)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS fresh resident $DATA lookup: segment={segmentNumber}, " +
                    $"residentAttributes={residentAttributes.Count}, " +
                    $"totalUnnamedDataAttributes={dataAttributes.Count}, " +
                    $"relaxedReference={usedRelaxedReference}.");
                return false;
            }

            data = residentAttributes[0].ResidentData!;

            System.Diagnostics.Debug.WriteLine(
                $"NTFS fresh resident $DATA evidence: segment={segmentNumber}, " +
                $"fileName={expectedFileName}, parentRef={expectedParentFileReferenceNumber}, " +
                $"size={data.Length:N0}, relaxedReference={usedRelaxedReference}.");

            return true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS fresh resident $DATA lookup failed: " +
                $"{ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private static void TraceHistoricalLogFileEvidence(
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        ulong fileReferenceNumber,
        string expectedFileName,
        ulong expectedParentFileReferenceNumber)
    {
        try
        {
            var logFileStream = new NtfsMftDataReader().ReadDefaultDataStream(
                volumeInfo,
                volumeHandle,
                2);

            if (!logFileStream.Found ||
                logFileStream.IsResident ||
                logFileStream.Extents.Count == 0)
            {                System.Diagnostics.Trace.WriteLine(
                    $"NTFS $LogFile parser: $LogFile mapping pairs unavailable. " +
                    $"found={logFileStream.Found}, resident={logFileStream.IsResident}, " +
                    $"extents={logFileStream.Extents.Count:N0}, evidence={logFileStream.Evidence}.");
                return;
            }

            const long maxDiagnosticBytes = 128L * 1024 * 1024;
            var nameBytes = Encoding.Unicode.GetBytes(expectedFileName);
            var referenceBytes = new byte[sizeof(ulong)];

            BinaryPrimitives.WriteUInt64LittleEndian(
                referenceBytes,
                fileReferenceNumber);

            // The first restart page contains the Log File Service geometry.
            // Read the first 128 KiB through the already validated $LogFile
            // mapping pairs rather than opening E:\$LogFile directly.
            var bootstrap = new byte[128 * 1024];
            var bootstrapRead = ReadMappedFileBytes(
                volumeHandle,
                volumeInfo.BytesPerCluster,
                logFileStream.Extents,
                0,
                bootstrap);

            if (bootstrapRead < 64)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS $LogFile parser: bootstrap read returned only {bootstrapRead:N0} bytes.");
                return;
            }

            var logPageSize = 0;
            var restartAreaOffset = -1;
            var recordHeaderLength = 48;
            var logPageDataOffset = 0;

            for (var candidatePageOffset = 0;
                 candidatePageOffset + 64 <= bootstrapRead;
                 candidatePageOffset += 512)
            {
                var signature =
                    Encoding.ASCII.GetString(
                        bootstrap,
                        candidatePageOffset,
                        4);

                if (signature != "RSTR" &&
                    signature != "CHKD" &&
                    signature != "BAAD")
                {
                    continue;
                }

                var candidateLogPageSize =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        bootstrap.AsSpan(candidatePageOffset + 20, 4));

                var candidateRestartOffset =
                    BinaryPrimitives.ReadUInt16LittleEndian(
                        bootstrap.AsSpan(candidatePageOffset + 24, 2));

                if (candidateLogPageSize < 512 ||
                    candidateLogPageSize > 1024 * 1024 ||
                    (candidateLogPageSize & (candidateLogPageSize - 1)) != 0 ||
                    candidateRestartOffset < 30 ||
                    candidateRestartOffset + 40 > candidateLogPageSize)
                {
                    continue;
                }

                var area = candidatePageOffset + candidateRestartOffset;
                if (area + 40 > bootstrapRead)
                {
                    continue;
                }

                var candidateRecordHeaderLength =
                    BinaryPrimitives.ReadUInt16LittleEndian(
                        bootstrap.AsSpan(area + 36, 2));

                var candidateDataOffset =
                    BinaryPrimitives.ReadUInt16LittleEndian(
                        bootstrap.AsSpan(area + 38, 2));

                if (candidateRecordHeaderLength < 48 ||
                    candidateRecordHeaderLength > 4096 ||
                    (candidateRecordHeaderLength % 8) != 0 ||
                    candidateDataOffset < candidateRecordHeaderLength ||
                    candidateDataOffset >= candidateLogPageSize)
                {
                    continue;
                }

                logPageSize = checked((int)candidateLogPageSize);
                restartAreaOffset = candidateRestartOffset;
                recordHeaderLength = candidateRecordHeaderLength;
                logPageDataOffset = candidateDataOffset;
                break;
            }

            if (logPageSize == 0)
            {
                System.Diagnostics.Trace.WriteLine(
                    "NTFS $LogFile parser: could not determine log page geometry.");
                return;
            }

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile parser geometry: " +
                $"fileSize={logFileStream.FileSizeBytes:N0}, " +
                $"pageSize={logPageSize:N0}, " +
                $"restartOffset={restartAreaOffset}, " +
                $"recordHeaderLength={recordHeaderLength}, " +
                $"dataOffset={logPageDataOffset}, " +
                $"targetFileRef={fileReferenceNumber}, " +
                $"targetSegment={fileReferenceNumber & 0x0000FFFFFFFFFFFFUL}.");

            var filenameOffsets = new List<long>();
            var referenceOffsets = new List<long>();
            var scannedBytes = 0L;
            var remainingBudget = Math.Min(
                Math.Max(0, logFileStream.FileSizeBytes),
                maxDiagnosticBytes);

            const int scanChunkSize = 4 * 1024 * 1024;

            for (var extentIndex = 0;
                 extentIndex < logFileStream.Extents.Count &&
                 remainingBudget > 0;
                 extentIndex++)
            {
                var extent = logFileStream.Extents[extentIndex];

                if (extent.LogicalClusterNumber < 0 ||
                    extent.ClusterCount <= 0)
                {
                    continue;
                }

                var extentBytes = checked(
                    Math.Min(
                        extent.ClusterCount * (long)volumeInfo.BytesPerCluster,
                        remainingBudget));

                for (long extentOffset = 0;
                     extentOffset < extentBytes &&
                     remainingBudget > 0;)
                {
                    var chunkLength = checked((int)Math.Min(
                        scanChunkSize,
                        Math.Min(
                            extentBytes - extentOffset,
                            remainingBudget)));

                    var chunk = new byte[chunkLength];

                    ReadRawClusters(
                        volumeHandle,
                        checked(
                            extent.LogicalClusterNumber +
                            extentOffset / volumeInfo.BytesPerCluster),
                        chunkLength,
                        volumeInfo.BytesPerCluster,
                        chunk,
                        0);

                    var absoluteChunkOffset =
                        checked(scannedBytes + extentOffset);

                    CollectPatternOffsets(
                        chunk,
                        nameBytes,
                        absoluteChunkOffset,
                        filenameOffsets);

                    CollectPatternOffsets(
                        chunk,
                        referenceBytes,
                        absoluteChunkOffset,
                        referenceOffsets);

                    extentOffset += chunkLength;
                    remainingBudget -= chunkLength;
                }

                scannedBytes = checked(
                    scannedBytes + extentBytes);
            }

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile parser: filenameOccurrences={filenameOffsets.Count}, " +
                $"fileReferenceOccurrences={referenceOffsets.Count}, " +
                $"scanned={scannedBytes:N0}.");

            var parsedRecords = 0;
            var matchingRecords = 0;
            var referenceMatchingRecords = 0;
            var targetAttributeIndexes = new HashSet<ushort>();

            var interestingOffsets = filenameOffsets
                .Concat(referenceOffsets)
                .Distinct()
                .OrderBy(offset => offset)
                .ToArray();

            foreach (var interestingOffset in interestingOffsets)
            {
                var pageNumber = interestingOffset / logPageSize;
                var pageStart = checked(pageNumber * logPageSize);
                var pageBuffer = new byte[logPageSize];

                var bytesRead = ReadMappedFileBytes(
                    volumeHandle,
                    volumeInfo.BytesPerCluster,
                    logFileStream.Extents,
                    pageStart,
                    pageBuffer);

                if (bytesRead != pageBuffer.Length)
                {
                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS $LogFile parser: could not read page for " +
                        $"interestingOffset={interestingOffset:N0}, page={pageNumber:N0}, " +
                        $"read={bytesRead:N0}/{pageBuffer.Length:N0}.");
                    continue;
                }

                try
                {
                    ApplyUpdateSequenceFixups(
                        pageBuffer,
                        checked((int)volumeInfo.BytesPerSector));
                }
                catch
                {
                    // Log pages use the same multi-sector fixup mechanism as
                    // other NTFS metadata records, but preserve the raw page
                    // when a particular page cannot be fixed.
                }

                if (pageBuffer[0] != (byte)'R' ||
                    pageBuffer[1] != (byte)'C' ||
                    pageBuffer[2] != (byte)'R' ||
                    pageBuffer[3] != (byte)'D')
                {
                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS $LogFile parser: page {pageNumber:N0} " +
                        $"does not have an RCRD signature.");
                    continue;
                }

                var nextRecordOffset =
                    BinaryPrimitives.ReadUInt16LittleEndian(
                        pageBuffer.AsSpan(24, 2));

                if (nextRecordOffset <= logPageDataOffset ||
                    nextRecordOffset > pageBuffer.Length)
                {
                    nextRecordOffset = checked((ushort)pageBuffer.Length);
                }

                var pageRelativeInterestingOffset =
                    checked((int)(interestingOffset - pageStart));

                var pageRelativeFilenameOffset =
                    filenameOffsets.Contains(interestingOffset)
                        ? pageRelativeInterestingOffset
                        : -1;

                var recordOffset = logPageDataOffset;

                while (recordOffset + recordHeaderLength <= nextRecordOffset)
                {
                    var clientDataLength =
                        BinaryPrimitives.ReadUInt32LittleEndian(
                            pageBuffer.AsSpan(recordOffset + 24, 4));

                    if (clientDataLength < 8 ||
                        clientDataLength > (uint)(nextRecordOffset - recordOffset - recordHeaderLength))
                    {
                        break;
                    }

                    var alignedRecordLength = Align8(
                        recordHeaderLength +
                        checked((int)clientDataLength));

                    if (alignedRecordLength <= 0 ||
                        recordOffset + alignedRecordLength > nextRecordOffset)
                    {
                        break;
                    }

                    var thisLsn =
                        BinaryPrimitives.ReadUInt64LittleEndian(
                            pageBuffer.AsSpan(recordOffset, 8));

                    var clientDataStart =
                        checked(recordOffset + recordHeaderLength);

                    var clientDataEnd =
                        checked(clientDataStart + (int)clientDataLength);

                    var containsFilename =
                        pageRelativeFilenameOffset >= clientDataStart &&
                        pageRelativeFilenameOffset + nameBytes.Length <= clientDataEnd;

                    var containsReference =
                        referenceOffsets.Any(offset =>
                            offset >= pageStart + clientDataStart &&
                            offset + referenceBytes.Length <= pageStart + clientDataEnd);

                    var redoOperation =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            pageBuffer.AsSpan(clientDataStart, 2));

                    var undoOperation =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            pageBuffer.AsSpan(clientDataStart + 2, 2));

                    // UpdateMappingPairs carries historical VCN-to-LCN mapping
                    // information for a nonresident attribute. When a target
                    // filename/reference is found on the same log page, inspect
                    // these records even when the target reference is not itself
                    // present in the mapping-pairs client data. Diagnostic only:
                    // this does not relax MFT sequence validation or enable carving.
                    if (redoOperation == 0x09 &&
                        clientDataLength >= 32)
                    {
                        var mappingTargetAttribute =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 12, 2));

                        var mappingLcnsToFollow =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 14, 2));

                        var mappingRecordTargetOffset =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 16, 2));

                        var mappingAttributeTargetOffset =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 18, 2));

                        var mappingClusterBlockOffset =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 20, 2));

                        var mappingTargetVcn =
                            BinaryPrimitives.ReadInt64LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 24, 8));

                        var mappingRedoOffset =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 4, 2));

                        var mappingRedoLength =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 6, 2));

                        var mappingRedoStart =
                            checked(clientDataStart + mappingRedoOffset);

                        var mappingRedoEnd = Math.Min(
                            clientDataEnd,
                            checked(mappingRedoStart + mappingRedoLength));

                        var mappingRedoBytes = mappingRedoStart < mappingRedoEnd
                            ? Convert.ToHexString(
                                pageBuffer.AsSpan(
                                    mappingRedoStart,
                                    Math.Min(64, mappingRedoEnd - mappingRedoStart)))
                            : string.Empty;

                        System.Diagnostics.Trace.WriteLine(
                            $"NTFS $LogFile MAPPING PAIRS: " +
                            $"interestingPage={pageNumber:N0}, " +
                            $"recordOffset={recordOffset}, " +
                            $"LSN=0x{thisLsn:X16}, " +
                            $"containsTargetReference={containsReference}, " +
                            $"containsTargetFilename={containsFilename}, " +
                            $"targetAttribute={mappingTargetAttribute}, " +
                            $"lcnsToFollow={mappingLcnsToFollow}, " +
                            $"recordTargetOffset={mappingRecordTargetOffset}, " +
                            $"attributeTargetOffset={mappingAttributeTargetOffset}, " +
                            $"clusterBlockOffset={mappingClusterBlockOffset}, " +
                            $"targetVcn={mappingTargetVcn}, " +
                            $"redoOffset={mappingRedoOffset}, " +
                            $"redoLength={mappingRedoLength}, " +
                            $"redoHex={mappingRedoBytes}.");
                    }

                    if (containsFilename || containsReference)
                    {
                        var redoOffset =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 4, 2));

                        var redoLength =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 6, 2));

                        var undoOffset =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 8, 2));

                        var undoLength =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 10, 2));

                        // NTFS_LOG_RECORD_HEADER fields after the redo/undo
                        // descriptors. TargetAttribute index 0 is the MFT itself;
                        // non-zero values identify an entry in the open-attribute table.
                        var targetAttribute =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 12, 2));

                        if (targetAttribute != 0)
                        {
                            targetAttributeIndexes.Add(targetAttribute);
                        }

                        var lcnsToFollow =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 14, 2));

                        var recordTargetOffset =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 16, 2));

                        var attributeTargetOffset =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 18, 2));

                        var clusterBlockOffset =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 20, 2));

                        var targetVcn =
                            BinaryPrimitives.ReadInt64LittleEndian(
                                pageBuffer.AsSpan(clientDataStart + 24, 8));

                        Func<ushort, string> operationName = operation =>
                            operation switch
                            {
                                0x02 => "InitializeFileRecordSegment",
                                0x03 => "DeallocateFileRecordSegment",
                                0x04 => "WriteEndOfFileRecordSegment",
                                0x05 => "CreateAttribute",
                                0x06 => "DeleteAttribute",
                                0x07 => "UpdateResidentValue",
                                0x08 => "UpdateNonresidentValue",
                                0x09 => "UpdateMappingPairs",                                0x0C => "AddIndexEntryRoot",
                                0x0D => "DeleteIndexEntryRoot",
                                0x0E => "AddIndexEntryAllocation",
                                0x0F => "DeleteIndexEntryAllocation",
                                0x13 => "UpdateFileNameRoot",
                                0x14 => "UpdateFileNameAllocation",
                                0x21 => "UpdateRecordDataRoot",
                                0x22 => "UpdateRecordDataAllocation",
                                _ => $"0x{operation:X4}"
                            };

                        var targetSegment =
                            fileReferenceNumber &
                            0x0000FFFFFFFFFFFFUL;

                        var targetMftOffset =
                            checked(
                                (long)targetSegment *
                                volumeInfo.BytesPerFileRecordSegment);

                        var expectedTargetMftVcn =
                            volumeInfo.BytesPerCluster > 0
                                ? targetMftOffset / volumeInfo.BytesPerCluster
                                : -1;

                        var targetVcnMatches =
                            targetAttribute == 0 &&
                            expectedTargetMftVcn >= 0 &&
                            targetVcn == expectedTargetMftVcn;

                        var targetKind = targetAttribute == 0
                            ? "MFT"
                            : $"openAttributeIndex={targetAttribute}";

                        parsedRecords++;

                        if (containsFilename)
                        {
                            matchingRecords++;
                        }

                        if (containsReference && !containsFilename)
                        {
                            referenceMatchingRecords++;
                        }

                        System.Diagnostics.Trace.WriteLine(
                            $"NTFS $LogFile TARGET RECORD: " +
                            $"matchBy={(containsFilename ? "filename" : "")}" +
                            $"{(containsFilename && containsReference ? "+" : "")}" +
                            $"{(containsReference ? "fileReference" : "")}, " +
                            $"interestingOffset={interestingOffset:N0}, " +
                            $"page={pageNumber:N0}, " +
                            $"recordOffset={recordOffset}, " +
                            $"LSN=0x{thisLsn:X16}, " +
                            $"clientDataLength={clientDataLength}, " +
                            $"redo={operationName(redoOperation)}, " +
                            $"undo={operationName(undoOperation)}, " +
                            $"redoOffset={redoOffset}, " +
                            $"redoLength={redoLength}, " +
                            $"undoOffset={undoOffset}, " +
                            $"undoLength={undoLength}, " +
                            $"targetAttribute={targetAttribute} ({targetKind}), " +
                            $"lcnsToFollow={lcnsToFollow}, " +
                            $"recordTargetOffset={recordTargetOffset}, " +
                            $"attributeTargetOffset={attributeTargetOffset}, " +
                            $"clusterBlockOffset={clusterBlockOffset}, " +
                            $"targetVcn={targetVcn}, " +
                            $"expectedTargetMftVcn={expectedTargetMftVcn}, " +
                            $"targetMftOffset={targetMftOffset}, " +
                            $"targetVcnMatches={targetVcnMatches}.");

                        if (containsReference && !containsFilename)
                        {
                            var referenceMatchOffset =
                                referenceOffsets
                                    .Where(offset =>
                                        offset >= pageStart + clientDataStart &&
                                        offset + referenceBytes.Length <= pageStart + clientDataEnd)
                                    .Select(offset =>
                                        checked((int)(offset - (pageStart + clientDataStart))))
                                    .FirstOrDefault(-1);

                            System.Diagnostics.Trace.WriteLine(
                                $"NTFS $LogFile REFERENCE MATCH: " +
                                $"referenceOffsetInClientData={referenceMatchOffset}, " +
                                $"fileRef={fileReferenceNumber}, " +
                                $"targetSegment={targetSegment}, " +
                                $"redo={operationName(redoOperation)}, " +
                                $"undo={operationName(undoOperation)}, " +
                                $"targetAttribute={targetAttribute}, " +
                                $"targetVcn={targetVcn}, " +
                                $"recordTargetOffset={recordTargetOffset}, " +
                                $"attributeTargetOffset={attributeTargetOffset}, " +
                                $"clusterBlockOffset={clusterBlockOffset}.");
                        }

                        if (redoOffset >= recordHeaderLength &&
                            redoOffset + redoLength <= clientDataLength)
                        {
                            var redoStart = clientDataStart + redoOffset;
                            var redoEnd = redoStart + redoLength;

                            if (redoEnd <= clientDataEnd)
                            {
                                var redoName = Encoding.Unicode.GetString(
                                    pageBuffer.AsSpan(
                                        redoStart,
                                        Math.Min(
                                            redoLength,
                                            Math.Max(
                                                0,
                                                clientDataEnd - redoStart))));

                                if (redoName.Contains(
                                        expectedFileName,
                                        StringComparison.OrdinalIgnoreCase))
                                {
                                    System.Diagnostics.Trace.WriteLine(
                                        $"NTFS $LogFile TARGET REDO contains filename: " +
                                        $"operation={operationName(redoOperation)}, " +
                                        $"recordOffset={recordOffset}, " +
                                        $"redoBytes={redoLength}.");
                                }
                            }
                        }
                    }

                    recordOffset = checked(
                        recordOffset + alignedRecordLength);
                }
            }

            TraceGlobalMappingPairRecords(
                volumeInfo,
                volumeHandle,
                logFileStream,
                logPageSize,
                logPageDataOffset,
                recordHeaderLength,
                targetAttributeIndexes,
                maxDiagnosticBytes);

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile parser summary: " +
                $"fileRef={fileReferenceNumber}, " +
                $"name={expectedFileName}, " +
                $"parentRef={expectedParentFileReferenceNumber}, " +
                $"filenameOccurrences={filenameOffsets.Count}, " +
                $"fileReferenceOccurrences={referenceOffsets.Count}, " +
                $"recordsContainingFilename={matchingRecords}, " +
                $"recordsContainingReference={referenceMatchingRecords}, " +
                $"recordsParsed={parsedRecords}.");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile parser failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static void TraceGlobalMappingPairRecords(
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        NtfsDataStreamInfo logFileStream,
        int logPageSize,
        int logPageDataOffset,
        int recordHeaderLength,
        IReadOnlySet<ushort> targetAttributeIndexes,
        long maxDiagnosticBytes)
    {
        if (targetAttributeIndexes.Count == 0 ||
            logPageSize <= 0 ||
            logPageDataOffset < recordHeaderLength)
        {
            return;
        }

        try
        {
            var scanLength = Math.Min(
                Math.Max(0, logFileStream.FileSizeBytes),
                maxDiagnosticBytes);

            const int scanChunkSize = 4 * 1024 * 1024;
            const int maximumLoggedMatches = 200;

            var mappingMatches = 0;
            var stoppedAtMatchLimit = false;

            for (long chunkOffset = 0;
                 chunkOffset < scanLength &&
                 !stoppedAtMatchLimit;)
            {
                var requestedChunkLength = checked((int)Math.Min(
                    scanChunkSize,
                    scanLength - chunkOffset));

                requestedChunkLength -=
                    requestedChunkLength % logPageSize;

                if (requestedChunkLength <= 0)
                {
                    break;
                }

                var chunk = new byte[requestedChunkLength];

                var bytesRead = ReadMappedFileBytes(
                    volumeHandle,
                    volumeInfo.BytesPerCluster,
                    logFileStream.Extents,
                    chunkOffset,
                    chunk);

                if (bytesRead < logPageSize)
                {
                    break;
                }

                var pageCount = bytesRead / logPageSize;

                for (var pageIndex = 0;
                     pageIndex < pageCount;
                     pageIndex++)
                {
                    var pageFileOffset = checked(
                        chunkOffset +
                        pageIndex * (long)logPageSize);

                    var pageBuffer = chunk.AsSpan(
                            checked(pageIndex * logPageSize),
                            logPageSize)
                        .ToArray();

                    try
                    {
                        ApplyUpdateSequenceFixups(
                            pageBuffer,
                            checked((int)volumeInfo.BytesPerSector));
                    }
                    catch
                    {
                        // Preserve the raw page if the fixup cannot be applied.
                    }

                    if (pageBuffer[0] != (byte)'R' ||
                        pageBuffer[1] != (byte)'C' ||
                        pageBuffer[2] != (byte)'R' ||
                        pageBuffer[3] != (byte)'D')
                    {
                        continue;
                    }

                    var nextRecordOffset =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            pageBuffer.AsSpan(24, 2));

                    if (nextRecordOffset <= logPageDataOffset ||
                        nextRecordOffset > pageBuffer.Length)
                    {
                        nextRecordOffset = checked(
                            (ushort)pageBuffer.Length);
                    }

                    for (var recordOffset = logPageDataOffset;
                         recordOffset + recordHeaderLength <= nextRecordOffset;)
                    {
                        var clientDataLength =
                            BinaryPrimitives.ReadUInt32LittleEndian(
                                pageBuffer.AsSpan(recordOffset + 24, 4));

                        if (clientDataLength < 8 ||
                            clientDataLength >
                            (uint)(nextRecordOffset -
                                   recordOffset -
                                   recordHeaderLength))
                        {
                            break;
                        }

                        var alignedRecordLength = Align8(
                            recordHeaderLength +
                            checked((int)clientDataLength));

                        if (alignedRecordLength <= 0 ||
                            recordOffset + alignedRecordLength >
                            nextRecordOffset)
                        {
                            break;
                        }

                        var clientDataStart =
                            checked(recordOffset + recordHeaderLength);

                        var clientDataEnd =
                            checked(
                                clientDataStart +
                                (int)clientDataLength);

                        var redoOperation =
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                pageBuffer.AsSpan(
                                    clientDataStart,
                                    2));

                        if (redoOperation == 0x09 &&
                            clientDataLength >= 32)
                        {
                            var targetAttribute =
                                BinaryPrimitives.ReadUInt16LittleEndian(
                                    pageBuffer.AsSpan(
                                        clientDataStart + 12,
                                        2));

                            if (targetAttributeIndexes.Contains(
                                    targetAttribute))
                            {
                                var lcnsToFollow =
                                    BinaryPrimitives.ReadUInt16LittleEndian(
                                        pageBuffer.AsSpan(
                                            clientDataStart + 14,
                                            2));

                                var recordTargetOffset =
                                    BinaryPrimitives.ReadUInt16LittleEndian(
                                        pageBuffer.AsSpan(
                                            clientDataStart + 16,
                                            2));

                                var attributeTargetOffset =
                                    BinaryPrimitives.ReadUInt16LittleEndian(
                                        pageBuffer.AsSpan(
                                            clientDataStart + 18,
                                            2));

                                var clusterBlockOffset =
                                    BinaryPrimitives.ReadUInt16LittleEndian(
                                        pageBuffer.AsSpan(
                                            clientDataStart + 20,
                                            2));

                                var targetVcn =
                                    BinaryPrimitives.ReadInt64LittleEndian(
                                        pageBuffer.AsSpan(
                                            clientDataStart + 24,
                                            8));

                                var redoOffset =
                                    BinaryPrimitives.ReadUInt16LittleEndian(
                                        pageBuffer.AsSpan(
                                            clientDataStart + 4,
                                            2));

                                var redoLength =
                                    BinaryPrimitives.ReadUInt16LittleEndian(
                                        pageBuffer.AsSpan(
                                            clientDataStart + 6,
                                            2));

                                var redoStart = checked(
                                    clientDataStart + redoOffset);

                                var redoEnd = Math.Min(
                                    clientDataEnd,
                                    checked(
                                        redoStart + redoLength));

                                var redoBytes =
                                    redoStart < redoEnd
                                        ? pageBuffer.AsSpan(
                                            redoStart,
                                            redoEnd - redoStart)
                                        : ReadOnlySpan<byte>.Empty;

                                var redoHex =
                                    redoBytes.Length > 0
                                        ? Convert.ToHexString(
                                            redoBytes[..Math.Min(
                                                64,
                                                redoBytes.Length)])
                                        : string.Empty;

                                var decodedRuns = "(decode failed)";

                                if (redoBytes.Length > 0)
                                {
                                    try
                                    {
                                        var extents =
                                            NtfsMappingPairsParser.Parse(
                                                redoBytes,
                                                targetVcn);

                                        decodedRuns = string.Join(
                                            "; ",
                                            extents
                                                .Take(32)
                                                .Select(extent =>
                                                    $"VCN={extent.VirtualClusterNumber}+" +
                                                    $"{extent.ClusterCount}" +
                                                    $" -> LCN={extent.LogicalClusterNumber}"));

                                        if (extents.Count > 32)
                                        {
                                            decodedRuns += "; ...";
                                        }
                                    }
                                    catch (Exception decodeEx)
                                    {
                                        decodedRuns =
                                            $"decode-error={decodeEx.GetType().Name}: " +
                                            decodeEx.Message;
                                    }
                                }

                                var lsn =
                                    BinaryPrimitives.ReadUInt64LittleEndian(
                                        pageBuffer.AsSpan(
                                            recordOffset,
                                            8));

                                var pageNumber =
                                    pageFileOffset / logPageSize;

                                System.Diagnostics.Trace.WriteLine(
                                    $"NTFS $LogFile GLOBAL MAPPING PAIRS: " +
                                    $"page={pageNumber:N0}, " +
                                    $"recordOffset={recordOffset}, " +
                                    $"fileOffset={pageFileOffset + recordOffset:N0}, " +
                                    $"LSN=0x{lsn:X16}, " +
                                    $"targetAttribute={targetAttribute}, " +
                                    $"lcnsToFollow={lcnsToFollow}, " +
                                    $"recordTargetOffset={recordTargetOffset}, " +
                                    $"attributeTargetOffset={attributeTargetOffset}, " +
                                    $"clusterBlockOffset={clusterBlockOffset}, " +
                                    $"targetVcn={targetVcn}, " +
                                    $"redoOffset={redoOffset}, " +
                                    $"redoLength={redoLength}, " +
                                    $"redoHex={redoHex}, " +
                                    $"decoded={decodedRuns}.");

                                mappingMatches++;

                                if (mappingMatches >= maximumLoggedMatches)
                                {
                                    stoppedAtMatchLimit = true;
                                    break;
                                }
                            }
                        }

                        recordOffset = checked(
                            recordOffset + alignedRecordLength);
                    }

                    if (stoppedAtMatchLimit)
                    {
                        break;
                    }
                }

                if (bytesRead < requestedChunkLength)
                {
                    break;
                }

                chunkOffset = checked(
                    chunkOffset + bytesRead);
            }

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile global mapping summary: " +
                $"targetAttributes={string.Join(
                    ",",
                    targetAttributeIndexes.OrderBy(x => x))}, " +
                $"mappingMatches={mappingMatches}, " +
                $"scanBytes={Math.Min(
                    Math.Max(0, logFileStream.FileSizeBytes),
                    maxDiagnosticBytes):N0}, " +
                $"stoppedAtMatchLimit={stoppedAtMatchLimit}.");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile global mapping scan failed: " +
                $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static int Align8(int value) =>
        checked((value + 7) & ~7);

    private static void CollectPatternOffsets(
        ReadOnlySpan<byte> buffer,
        ReadOnlySpan<byte> pattern,
        long absoluteBaseOffset,
        List<long> offsets)
    {
        if (pattern.Length == 0 ||
            buffer.Length < pattern.Length)
        {
            return;
        }

        for (var offset = 0;
             offset + pattern.Length <= buffer.Length;
             offset++)
        {
            if (buffer.Slice(
                    offset,
                    pattern.Length)
                .SequenceEqual(pattern))
            {
                offsets.Add(
                    checked(absoluteBaseOffset + offset));
            }
        }
    }

    private static string CountHistoricalLogOperations(ReadOnlySpan<byte> window)
    {
        var names = new[]
        {
            (Code: (ushort)0x0002, Name: "InitializeFileRecordSegment"),
            (Code: (ushort)0x0003, Name: "DeallocateFileRecordSegment"),
            (Code: (ushort)0x0005, Name: "CreateAttribute"),
            (Code: (ushort)0x0006, Name: "DeleteAttribute"),
            (Code: (ushort)0x0007, Name: "UpdateResidentValue"),
            (Code: (ushort)0x0008, Name: "UpdateNonresidentValue"),
            (Code: (ushort)0x0009, Name: "UpdateMappingPairs"),
            (Code: (ushort)0x0013, Name: "UpdateFileNameRoot"),
            (Code: (ushort)0x0014, Name: "UpdateFileNameAllocation")
        };

        var matches = new List<string>();

        foreach (var operation in names)
        {
            var littleEndianCode = new byte[sizeof(ushort)];
            BinaryPrimitives.WriteUInt16LittleEndian(
                littleEndianCode,
                operation.Code);

            var count = 0;
            for (var offset = 0;
                 offset + littleEndianCode.Length <= window.Length;
                 offset++)
            {
                if (window.Slice(
                        offset,
                        littleEndianCode.Length)
                    .SequenceEqual(littleEndianCode))
                {
                    count++;
                }
            }

            if (count > 0)
            {
                matches.Add($"{operation.Name}={count}");
            }
        }

        return matches.Count == 0
            ? "(none)"
            : string.Join(",", matches);
    }

    private static NtfsDataStreamInfo? TryReadHistoricalNonResidentDataFromSlack(
        NtfsVolumeInfo volumeInfo,
        byte[] record,
        string expectedFileName,
        ulong expectedParentFileReferenceNumber,
        DateTime expectedDeletedAtUtc)
    {
        if (expectedDeletedAtUtc == default ||
            string.IsNullOrWhiteSpace(expectedFileName))
        {
            return null;
        }

        var expectedNameBytes = Encoding.Unicode.GetBytes(expectedFileName);
        if (expectedNameBytes.Length == 0)
        {
            return null;
        }

        // The MFT segment has been reused. Current attributes may occupy only part
        // of the 1 KiB record, while stale bytes from the deleted generation can
        // remain elsewhere in the same record. Build ranges for current attributes
        // and search only outside those ranges.
        var currentAttributes = EnumerateAttributes(record)
            .Select(x => (Start: x.Offset, End: x.Offset + x.Length))
            .ToArray();

        bool IsInsideCurrentAttribute(int offset, int length)
        {
            var end = offset + length;
            return currentAttributes.Any(range =>
                offset < range.End &&
                end > range.Start);
        }

        var candidates = new List<(int ValueOffset, long FileSize, DateTime ModifiedAtUtc)>();

        for (var nameByteOffset = 0;
             nameByteOffset + expectedNameBytes.Length <= record.Length;
             nameByteOffset++)
        {
            if (!record.AsSpan(
                    nameByteOffset,
                    expectedNameBytes.Length)
                .SequenceEqual(expectedNameBytes))
            {
                continue;
            }

            var valueOffset = nameByteOffset - 66;
            const int minimumFileNameValueLength = 66;

            if (valueOffset < 0 ||
                valueOffset + minimumFileNameValueLength + expectedNameBytes.Length > record.Length ||
                IsInsideCurrentAttribute(
                    valueOffset,
                    minimumFileNameValueLength + expectedNameBytes.Length))
            {
                continue;
            }

            var storedNameLength = record[valueOffset + 64];
            var nameNamespace = record[valueOffset + 65];

            if (storedNameLength != expectedNameBytes.Length / 2 ||
                nameNamespace > 3 ||
                valueOffset + 66 + storedNameLength * 2 > record.Length)
            {
                continue;
            }

            var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(
                record.AsSpan(valueOffset, sizeof(ulong)));

            if (parentReference != expectedParentFileReferenceNumber)
            {
                continue;
            }

            var allocatedSize = BinaryPrimitives.ReadInt64LittleEndian(
                record.AsSpan(valueOffset + 40, sizeof(long)));

            var realSize = BinaryPrimitives.ReadInt64LittleEndian(
                record.AsSpan(valueOffset + 48, sizeof(long)));

            if (realSize <= 0 ||
                allocatedSize < realSize ||
                realSize > MaxAttributeListBytes)
            {
                continue;
            }

            DateTime modifiedAtUtc;
            try
            {
                modifiedAtUtc = DateTime.FromFileTimeUtc(
                    BinaryPrimitives.ReadInt64LittleEndian(
                        record.AsSpan(valueOffset + 16, sizeof(long))));
            }
            catch
            {
                continue;
            }

            var timestampDeltaMinutes =
                Math.Abs((modifiedAtUtc - expectedDeletedAtUtc).TotalMinutes);

            if (timestampDeltaMinutes > 5)
            {
                continue;
            }

            candidates.Add((valueOffset, realSize, modifiedAtUtc));
        }

        System.Diagnostics.Trace.WriteLine(
            $"NTFS historical MFT slack search: " +
            $"name={expectedFileName}, parentRef={expectedParentFileReferenceNumber}, " +
            $"rawNameCandidates={candidates.Count}, currentAttributeCount={currentAttributes.Length}.");

        if (candidates.Count == 0)
        {
            return null;
        }

        const int maxRelatedSlackDistance = 1024;
        DataAttributeDescriptor? bestDescriptor = null;
        var bestDistance = int.MaxValue;
        int bestNameOffset = -1;
        DateTime bestModifiedAtUtc = DateTime.MinValue;

        foreach (var candidate in candidates.OrderBy(x => Math.Abs(x.ValueOffset)))
        {
            for (var attributeOffset = 0;
                 attributeOffset + 64 <= record.Length;
                 attributeOffset++)
            {
                const int minimumNonResidentAttributeLength = 64;

                if (IsInsideCurrentAttribute(
                    attributeOffset,
                    minimumNonResidentAttributeLength))
                {
                    continue;
                }

                var type = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(attributeOffset, 4));

                if (type != NtfsAttributeData)
                {
                    continue;
                }

                var attributeLength = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(attributeOffset + 4, 4));

                if (attributeLength < 64 ||
                    attributeOffset + attributeLength > record.Length ||
                    IsInsideCurrentAttribute(
                        attributeOffset,
                        checked((int)attributeLength)))
                {
                    continue;
                }

                var formCode = record[attributeOffset + 8];
                var nameLength = record[attributeOffset + 9];

                if (formCode != NonResidentForm ||
                    nameLength != 0)
                {
                    continue;
                }

                var lowestVcn = BinaryPrimitives.ReadInt64LittleEndian(
                    record.AsSpan(attributeOffset + 16, sizeof(long)));

                if (lowestVcn != 0)
                {
                    continue;
                }

                var mappingPairsOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                    record.AsSpan(attributeOffset + 32, sizeof(ushort)));

                if (mappingPairsOffset < 64 ||
                    mappingPairsOffset >= attributeLength)
                {
                    continue;
                }

                var allocatedSize = BinaryPrimitives.ReadInt64LittleEndian(
                    record.AsSpan(attributeOffset + 40, sizeof(long)));

                var fileSize = BinaryPrimitives.ReadInt64LittleEndian(
                    record.AsSpan(attributeOffset + 48, sizeof(long)));

                var validDataLength = BinaryPrimitives.ReadInt64LittleEndian(
                    record.AsSpan(attributeOffset + 56, sizeof(long)));

                if (fileSize != candidate.FileSize ||
                    allocatedSize < fileSize ||
                    validDataLength < 0 ||
                    validDataLength > fileSize)
                {
                    continue;
                }

                var distance = Math.Abs(
                    attributeOffset - candidate.ValueOffset);

                if (distance > maxRelatedSlackDistance ||
                    distance >= bestDistance)
                {
                    continue;
                }

                IReadOnlyList<NtfsDataExtent> extents;
                try                {
                    extents = NtfsMappingPairsParser.Parse(
                        record.AsSpan(
                            attributeOffset + mappingPairsOffset,
                            checked((int)attributeLength - mappingPairsOffset)),
                        lowestVcn);
                }
                catch
                {
                    continue;
                }

                if (extents.Count == 0 ||
                    extents[0].VirtualClusterNumber != 0)
                {
                    continue;
                }

                long coveredClusters = 0;
                var expectedVcn = 0L;
                var validExtentLayout = true;

                foreach (var extent in extents)
                {
                    if (extent.VirtualClusterNumber != expectedVcn ||
                        extent.ClusterCount <= 0 ||
                        extent.LogicalClusterNumber < 0)
                    {
                        validExtentLayout = false;
                        break;
                    }

                    coveredClusters = checked(
                        coveredClusters + extent.ClusterCount);
                    expectedVcn = checked(
                        expectedVcn + extent.ClusterCount);
                }

                if (!validExtentLayout ||
                    checked(
                        coveredClusters *
                        (long)volumeInfo.BytesPerCluster) < fileSize)
                {
                    continue;
                }

                bestDescriptor = new DataAttributeDescriptor
                {
                    LowestVcn = lowestVcn,
                    IsResident = false,
                    FileSizeBytes = fileSize,
                    ValidDataLengthBytes = validDataLength,
                    Extents = extents
                };
                bestDistance = distance;
                bestNameOffset = candidate.ValueOffset;
                bestModifiedAtUtc = candidate.ModifiedAtUtc;
            }
        }

        if (bestDescriptor is null)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS historical MFT slack search: filename evidence found, " +
                $"but no correlated nonresident $DATA mapping pairs matched " +
                $"size={candidates[0].FileSize:N0}.");
            return null;
        }

        System.Diagnostics.Trace.WriteLine(
            $"NTFS historical MFT slack evidence: " +
            $"name={expectedFileName}, parentRef={expectedParentFileReferenceNumber}, " +
            $"modifiedAt={bestModifiedAtUtc:O}, deleteAt={expectedDeletedAtUtc:O}, " +
            $"fileSize={bestDescriptor.FileSizeBytes:N0}, " +
            $"nameOffset={bestNameOffset}, " +
            $"dataAttributeDistance={bestDistance}, " +
            $"extents={bestDescriptor.Extents.Count:N0}.");

        return new NtfsDataStreamInfo
        {
            Found = true,
            IsResident = false,
            FileSizeBytes = bestDescriptor.FileSizeBytes,
            ValidDataLengthBytes = bestDescriptor.ValidDataLengthBytes,
            Extents = bestDescriptor.Extents,
            Evidence =
                $"The deleted file's historical $FILE_NAME and nonresident $DATA mapping pairs " +
                $"were retained outside the current MFT attributes; filename, parent, timestamp, " +
                $"and file size all matched the USN deletion evidence."
        };
    }

    public bool TryReadHistoricalFileNameSize(
        string rootPath,
        ulong fileReferenceNumber,
        ulong expectedParentFileReferenceNumber,
        string expectedFileName,
        out long fileSizeBytes)
    {
        fileSizeBytes = 0;

        if (string.IsNullOrWhiteSpace(rootPath) ||
            fileReferenceNumber == 0 ||
            string.IsNullOrWhiteSpace(expectedFileName))
        {
            return false;
        }

        var root = Path.GetPathRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        try
        {
            WindowsPrivilege.EnableSeBackupPrivilege();

            var volumeInfo = new NtfsVolumeInspector().Inspect(root);
            using var rawMftVolumeHandle = CreateVolumeHandle(
                volumeInfo.RootPath,
                overlapped: true);

            var segmentNumber = fileReferenceNumber & 0x0000FFFFFFFFFFFFUL;

            // Do not use the historical sequence here. The purpose of this helper is
            // to inspect remnants of the historical $FILE_NAME attribute after the
            // segment has been reused. Acceptance still requires the historical
            // filename and parent reference to match.
            var record = ReadMftRecordByExtentMap(
                rawMftVolumeHandle,
                volumeInfo,
                segmentNumber,
                expectedSequenceNumber: 0,
                expectedBaseFileReference: 0);

            if (record is null)
            {
                return false;
            }

            var expectedNameBytes = Encoding.Unicode.GetBytes(expectedFileName);
            if (expectedNameBytes.Length == 0)
            {
                return false;
            }

            const int fileNameValueParentOffset = 0;
            const int fileNameValueAllocatedSizeOffset = 40;
            const int fileNameValueRealSizeOffset = 48;
            const int fileNameValueFlagsOffset = 56;
            const int fileNameValueLengthOffset = 64;
            const int fileNameValueNamespaceOffset = 65;
            const int fileNameValueNameOffset = 66;

            for (var nameOffset = 0;
                 nameOffset + expectedNameBytes.Length <= record.Length;
                 nameOffset += 2)
            {
                if (!record.AsSpan(
                        nameOffset,
                        expectedNameBytes.Length)
                    .SequenceEqual(expectedNameBytes))
                {
                    continue;
                }

                var valueOffset = nameOffset - fileNameValueNameOffset;
                if (valueOffset < 0 ||
                    valueOffset + fileNameValueNameOffset > record.Length)
                {
                    continue;
                }

                var storedNameLength = record[valueOffset + fileNameValueLengthOffset];
                var nameNamespace = record[valueOffset + fileNameValueNamespaceOffset];

                if (storedNameLength != expectedFileName.Length ||
                    nameNamespace > 3)
                {
                    continue;
                }

                var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(
                    record.AsSpan(
                        valueOffset + fileNameValueParentOffset,
                        sizeof(ulong)));

                if (parentReference != expectedParentFileReferenceNumber)
                {
                    continue;
                }

                var allocatedSize = BinaryPrimitives.ReadInt64LittleEndian(
                    record.AsSpan(
                        valueOffset + fileNameValueAllocatedSizeOffset,
                        sizeof(long)));

                var realSize = BinaryPrimitives.ReadInt64LittleEndian(
                    record.AsSpan(
                        valueOffset + fileNameValueRealSizeOffset,
                        sizeof(long)));

                if (realSize < 0 ||
                    allocatedSize < 0 ||
                    realSize > allocatedSize ||
                    realSize > MaxAttributeListBytes)
                {
                    continue;
                }

                var flags = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(
                        valueOffset + fileNameValueFlagsOffset,
                        sizeof(uint)));

                fileSizeBytes = realSize;

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS historical $FILE_NAME size evidence: segment={segmentNumber}, " +
                    $"fileName={expectedFileName}, parentRef={parentReference}, " +
                    $"size={realSize:N0}, allocated={allocatedSize:N0}, " +
                    $"namespace={nameNamespace}, flags=0x{flags:X8}.");

                return true;
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS historical $FILE_NAME size lookup failed: " +
                $"{ex.GetType().Name}: {ex.Message}");
        }

        return false;
    }

    /// <summary>
    /// Reads the default unnamed $DATA stream from an NTFS metadata-file MFT
    /// segment. This intentionally ignores the normal file-reference sequence
    /// validation because reserved metadata files are addressed by fixed segment
    /// numbers (for example, segment 2 is $LogFile).
    /// </summary>
    internal NtfsDataStreamInfo ReadMetadataFileDataStream(
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        ulong segmentNumber)
    {
        if (volumeInfo.BytesPerFileRecordSegment == 0 ||
            string.IsNullOrWhiteSpace(volumeInfo.RootPath))
        {
            return NotFound("The NTFS volume did not report usable MFT geometry.");
        }

        using var rawMftVolumeHandle = CreateVolumeHandle(
            volumeInfo.RootPath,
            overlapped: true);

        var record = ReadMftRecordByExtentMap(
            rawMftVolumeHandle,
            volumeInfo,
            segmentNumber,
            expectedSequenceNumber: 0,
            expectedBaseFileReference: 0);

        if (record is null)
        {
            return NotFound(
                $"Could not read NTFS metadata MFT segment {segmentNumber}.");
        }

        return ReadDefaultDataStreamFromMftRecord(
            volumeInfo,
            volumeHandle,
            rawMftVolumeHandle,
            segmentNumber,
            record);
    }

    public bool TryCaptureDeletedData(
        string rootPath,
        ulong fileReferenceNumber,
        ulong expectedParentFileReferenceNumber,
        string expectedFileName,
        string? expectedFullPath,
        long maxCaptureBytes,
        out NtfsDataStreamInfo stream,
        out byte[] capturedData,
        DateTime expectedDeletedAtUtc = default,
        bool allowBoundedDeleteTransition = true,
        long expectedFileSizeBytes = 0)
    {
        stream = NotFound("The deleted file's NTFS $DATA stream could not be read.");
        capturedData = [];

        if (string.IsNullOrWhiteSpace(rootPath) ||
            fileReferenceNumber == 0 ||
            expectedParentFileReferenceNumber == 0 ||
            string.IsNullOrWhiteSpace(expectedFileName) ||
            maxCaptureBytes <= 0)
        {
            return false;
        }

        var root = GetNtfsVolumeRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        try
        {
            WindowsPrivilege.EnableSeBackupPrivilege();

            var volumeInfo = new NtfsVolumeInspector().Inspect(root);
            using var volumeHandle = CreateVolumeHandle(
                volumeInfo.RootPath,
                overlapped: false);

            stream = ReadDefaultDataStream(
                volumeInfo,
                volumeHandle,
                fileReferenceNumber,
                expectedFileName,
                expectedParentFileReferenceNumber,
                expectedFullPath,
                expectedDeletedAtUtc,
                allowBoundedDeleteTransition,
                expectedFileSizeBytes);

            if (!stream.Found)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS deletion snapshot: $DATA unavailable for fileRef={fileReferenceNumber}. " +
                    $"evidence={stream.Evidence}");
                return false;
            }

            TraceDataStreamLayout("capture-layout", fileReferenceNumber, stream, volumeInfo.BytesPerCluster);

            if (stream.FileSizeBytes < 0)
            {
                return false;
            }

            if (stream.FileSizeBytes > maxCaptureBytes)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS deletion snapshot: metadata retained but content capture skipped because " +
                    $"size={stream.FileSizeBytes:N0} exceeds maxCaptureBytes={maxCaptureBytes:N0}.");
                return true;
            }

            if (stream.IsResident)
            {
                var resident = stream.ResidentData ?? [];
                if (resident.LongLength != stream.FileSizeBytes)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS deletion snapshot: resident size mismatch fileRef={fileReferenceNumber}, " +
                        $"streamSize={stream.FileSizeBytes:N0}, residentBytes={resident.LongLength:N0}.");
                    return false;
                }

                capturedData = resident.ToArray();
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS deletion snapshot: captured resident data fileRef={fileReferenceNumber}, " +
                    $"size={capturedData.LongLength:N0}.");
                return true;
            }

            var targetLength = checked((int)stream.FileSizeBytes);
            capturedData = new byte[targetLength];

            var initializedBytes = Math.Min(
                stream.ValidDataLengthBytes > 0
                    ? stream.ValidDataLengthBytes
                    : stream.FileSizeBytes,
                stream.FileSizeBytes);

            var remaining = stream.FileSizeBytes;
            var remainingInitialized = initializedBytes;
            var destinationOffset = 0;
            var expectedVcn = 0L;

            foreach (var extent in stream.Extents)
            {
                if (extent.ClusterCount <= 0 ||
                    extent.VirtualClusterNumber != expectedVcn)
                {
                    capturedData = [];
                    return false;
                }

                var extentBytes = checked(
                    extent.ClusterCount * (long)volumeInfo.BytesPerCluster);
                var bytesForExtent = Math.Min(extentBytes, remaining);

                if (bytesForExtent > 0 &&
                    remainingInitialized > 0)
                {
                    var initializedForExtent = Math.Min(
                        bytesForExtent,
                        remainingInitialized);

                    if (!extent.IsSparse)
                    {
                        ReadRawClusters(
                            volumeHandle,
                            extent.LogicalClusterNumber,
                            initializedForExtent,
                            volumeInfo.BytesPerCluster,
                            capturedData,
                            destinationOffset);
                    }

                    destinationOffset = checked(
                        destinationOffset + (int)bytesForExtent);
                    remainingInitialized -= initializedForExtent;
                }
                else if (bytesForExtent > 0)
                {
                    destinationOffset = checked(
                        destinationOffset + (int)bytesForExtent);
                }

                remaining -= bytesForExtent;
                expectedVcn = checked(
                    expectedVcn + extent.ClusterCount);

                if (remaining == 0)
                {
                    break;
                }
            }

            if (remaining != 0)
            {
                capturedData = [];
                return false;
            }

            TraceCapturedContent("capture-content", fileReferenceNumber, capturedData);

            System.Diagnostics.Debug.WriteLine(
                $"NTFS deletion snapshot: captured nonresident data fileRef={fileReferenceNumber}, " +
                $"size={capturedData.LongLength:N0}, extents={stream.Extents.Count:N0}.");

            return true;
        }
        catch (Exception ex)
        {
            capturedData = [];
            stream = NotFound(
                $"NTFS deletion snapshot capture failed: {ex.Message}");

            System.Diagnostics.Debug.WriteLine(
                $"NTFS deletion snapshot capture failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }    }

    public bool TryReadDataStreamForDeletedReference(
        string rootPath,
        ulong fileReferenceNumber,
        ulong expectedParentFileReferenceNumber,
        string expectedFileName,
        string? expectedFullPath,
        DateTime expectedDeletedAtUtc,
        out NtfsDataStreamInfo stream)
    {
        stream = NotFound("The deleted file's NTFS $DATA stream could not be read.");

        if (string.IsNullOrWhiteSpace(rootPath) ||
            fileReferenceNumber == 0 ||
            expectedParentFileReferenceNumber == 0 ||
            string.IsNullOrWhiteSpace(expectedFileName))
        {
            return false;
        }

        var root = GetNtfsVolumeRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        try
        {
            WindowsPrivilege.EnableSeBackupPrivilege();

            var volumeInfo = new NtfsVolumeInspector().Inspect(root);
            using var volumeHandle = CreateVolumeHandle(
                volumeInfo.RootPath,
                overlapped: false);

            // Recovery-time lookup is used for retained historical/pre-start
            // references. Never fall back to a later reused MFT generation here:
            // the current $DATA stream can belong to a different file incarnation.
            const bool allowBoundedDeleteTransition = false;

            stream = ReadDefaultDataStream(
                volumeInfo,
                volumeHandle,
                fileReferenceNumber,
                expectedFileName,
                expectedParentFileReferenceNumber,
                expectedFullPath,
                expectedDeletedAtUtc,
                allowBoundedDeleteTransition);

            System.Diagnostics.Debug.WriteLine(
                $"NTFS recovery-time $DATA lookup: fileRef={fileReferenceNumber}, " +
                $"path={expectedFullPath}, found={stream.Found}, resident={stream.IsResident}, " +
                $"allowBoundedDeleteTransition={allowBoundedDeleteTransition}, " +
                $"size={stream.FileSizeBytes:N0}, extents={stream.Extents.Count:N0}, " +
                $"evidence={stream.Evidence}");

            return stream.Found;
        }
        catch (Exception ex)
        {
            stream = NotFound(
                $"Recovery-time NTFS $DATA lookup failed: {ex.Message}");

            System.Diagnostics.Debug.WriteLine(
                $"NTFS recovery-time $DATA lookup failed: " +
                $"{ex.GetType().Name}: {ex.Message}");

            return false;
        }
    }

    public NtfsDataStreamInfo ReadDefaultDataStream(
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        ulong fileReferenceNumber,
        string? expectedFileName = null,
        ulong? expectedParentFileReferenceNumber = null,
        string? expectedFullPath = null,
        DateTime expectedDeletedAtUtc = default,
        bool allowBoundedDeleteTransition = true,
        long expectedFileSizeBytes = 0)
    {
        // A deletion-time size captured before the file disappeared can remain
        // authoritative even when the current/reused MFT $FILE_NAME size is gone.
        if (expectedFileSizeBytes < 0)
        {
            expectedFileSizeBytes = 0;
        }

        var segmentNumber = fileReferenceNumber & 0x0000FFFFFFFFFFFFUL;
        var sequenceNumber = (ushort)(fileReferenceNumber >> 48);

        if (volumeInfo.BytesPerFileRecordSegment == 0 ||
            volumeInfo.MftValidDataLength <= 0 ||
            string.IsNullOrWhiteSpace(volumeInfo.RootPath))
        {
            return NotFound("The NTFS volume did not report usable MFT geometry.");
        }

        var relativeMftOffset = checked(
            (long)segmentNumber * volumeInfo.BytesPerFileRecordSegment);

        if (relativeMftOffset < 0)
        {
            return NotFound("The deleted file's MFT segment offset is invalid.");
        }

        var recordEndOffset = checked(
            relativeMftOffset + volumeInfo.BytesPerFileRecordSegment);

        var outsideCurrentValidLength =
            recordEndOffset > volumeInfo.MftValidDataLength;

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $DATA lookup: fileRef={fileReferenceNumber}, " +
            $"segment={segmentNumber}, sequence={sequenceNumber}, " +
            $"recordSize={volumeInfo.BytesPerFileRecordSegment}, " +
            $"mftValidLength={volumeInfo.MftValidDataLength}, " +
            $"recordOffset={relativeMftOffset}, " +
            $"outsideCurrentValidLength={outsideCurrentValidLength}.");

        // A retained USN deletion can refer to a record just beyond the current
        // MFT valid-data length after the MFT has contracted. Do not discard an
        // exact historical file reference here. ReadMftRecordByExtentMap()
        // validates the physical/mapped extent availability and the exact
        // sequence/base reference before the record is accepted.
        if (outsideCurrentValidLength)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS $DATA lookup: attempting extent-map read beyond current " +
                $"MFT valid length for historical fileRef={fileReferenceNumber}, " +
                $"segment={segmentNumber}.");
        }

        // FSCTL_GET_NTFS_FILE_RECORD ignores the sequence-number portion of the
        // file reference and only returns an in-use record at or below the requested
        // MFT index. Deleted MFT records are therefore not recoverable through that
        // FSCTL. Read the physical $MFT data through the mapping stored in MFT record 0
        // and validate the exact sequence number instead.
        //
        // ReadRawExact/ReadMappedFileBytes issue overlapped I/O. Keep a dedicated
        // overlapped handle for all physical $MFT reads; the normal volume handle is
        // intentionally retained for synchronous metadata/bitmap reads.
        using var rawMftVolumeHandle = CreateVolumeHandle(
            volumeInfo.RootPath,
            overlapped: true);

        var record = ReadMftRecordByExtentMap(
            rawMftVolumeHandle,
            volumeInfo,
            segmentNumber,
            sequenceNumber,
            expectedBaseFileReference: fileReferenceNumber);

        if (record is not null)
        {
            var actualSequence = BinaryPrimitives.ReadUInt16LittleEndian(
                record.AsSpan(16, 2));
            var actualFlags = BinaryPrimitives.ReadUInt16LittleEndian(
                record.AsSpan(22, 2));
            var actualBaseReference = BinaryPrimitives.ReadUInt64LittleEndian(
                record.AsSpan(32, 8));

            System.Diagnostics.Trace.WriteLine(
                $"NTFS exact MFT record read: fileRef={fileReferenceNumber}, " +
                $"segment={segmentNumber}, expectedSequence={sequenceNumber}, " +
                $"actualSequence={actualSequence}, flags=0x{actualFlags:X4}, " +
                $"baseRef={actualBaseReference}, expectedBaseRef={fileReferenceNumber}, " +
                $"expectedName={expectedFileName ?? "(none)"}, " +
                $"expectedParent={expectedParentFileReferenceNumber?.ToString() ?? "(none)"}.");
        }
        else
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS exact MFT record read FAILED: fileRef={fileReferenceNumber}, " +
                $"segment={segmentNumber}, expectedSequence={sequenceNumber}, " +
                $"expectedName={expectedFileName ?? "(none)"}, " +
                $"expectedParent={expectedParentFileReferenceNumber?.ToString() ?? "(none)"}.");
        }

        if (record is null &&
            !allowBoundedDeleteTransition)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS $DATA lookup: bounded delete-transition fallback DISABLED for " +
                $"fileRef={fileReferenceNumber}, segment={segmentNumber}, expectedSequence={sequenceNumber}.");
        }

        if (record is null &&
            allowBoundedDeleteTransition &&
            !string.IsNullOrWhiteSpace(expectedFileName) &&
            expectedParentFileReferenceNumber.HasValue)
        {
            // NTFS can advance the MFT record sequence more than once after a
            // deletion has been journaled, especially when the segment is touched by
            // subsequent metadata operations before recovery runs. Retry the exact
            // segment without strict sequence/base checks, but accept it only when:
            //   1. the sequence advanced forward by a small bounded amount,
            //   2. the record is still a non-directory deleted FILE record,
            //   3. the retained $FILE_NAME identifies the expected filename/parent, and
            //   4. the retained FILE_NAME timestamp is close to the original USN delete.
            //
            // This is deliberately stronger than accepting an arbitrary sequence change
            // because an unrelated reused MFT generation could otherwise be mistaken for
            // the deleted file.
            const ushort maxDeleteSequenceAdvance = 8;

            var relaxedRecord = ReadMftRecordByExtentMap(
                rawMftVolumeHandle,
                volumeInfo,
                segmentNumber,
                expectedSequenceNumber: 0,
                expectedBaseFileReference: 0);

            if (relaxedRecord is not null)
            {
                var actualSequence = BinaryPrimitives.ReadUInt16LittleEndian(
                    relaxedRecord.AsSpan(16, 2));

                var sequenceAdvance = CalculateForwardSequenceAdvance(
                    sequenceNumber,
                    actualSequence);

                var currentFlags = BinaryPrimitives.ReadUInt16LittleEndian(
                    relaxedRecord.AsSpan(22, 2));
                var isInUse = (currentFlags & 0x0001) != 0;

                var fileNameMatch = !isInUse &&
                    sequenceNumber != 0 &&
                    sequenceAdvance > 0 &&
                    sequenceAdvance <= maxDeleteSequenceAdvance &&
                    HasMatchingFileNameEntry(
                        rawMftVolumeHandle,
                        relaxedRecord,
                        expectedFileName,
                        expectedParentFileReferenceNumber.Value,
                        expectedFullPath,
                        expectedSequenceNumber: sequenceNumber,
                        expectedDeletedAtUtc: expectedDeletedAtUtc);

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS $DATA lookup: bounded delete-transition check: " +
                    $"fileRef={fileReferenceNumber}, segment={segmentNumber}, " +
                    $"expectedSequence={sequenceNumber}, actualSequence={actualSequence}, " +
                    $"sequenceAdvance={sequenceAdvance}, flags=0x{currentFlags:X4}, " +
                    $"inUse={isInUse}, fileNameMatch={fileNameMatch}.");

                if (fileNameMatch)
                {
                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS $DATA lookup: accepted bounded delete-transition MFT record " +
                        $"for fileRef={fileReferenceNumber}, segment={segmentNumber}, " +
                        $"expectedSequence={sequenceNumber}, actualSequence={actualSequence}, " +
                        $"sequenceAdvance={sequenceAdvance}, maxAdvance={maxDeleteSequenceAdvance}.");
                    record = relaxedRecord;
                }
                else
                {
                    var historicalSlackStream = TryReadHistoricalNonResidentDataFromSlack(
                        volumeInfo,
                        relaxedRecord,
                        expectedFileName,
                        expectedParentFileReferenceNumber.Value,
                        expectedDeletedAtUtc);

                    if (historicalSlackStream is not null)
                    {
                        System.Diagnostics.Trace.WriteLine(
                            $"NTFS $DATA lookup: accepted historical MFT-slack $DATA evidence " +
                            $"for fileRef={fileReferenceNumber}, segment={segmentNumber}, " +
                            $"expectedSequence={sequenceNumber}, actualSequence={actualSequence}, " +
                            $"fileSize={historicalSlackStream.FileSizeBytes:N0}, " +
                            $"extents={historicalSlackStream.Extents.Count:N0}.");

                        return historicalSlackStream;
                    }

                    if (fileReferenceNumber == 1125899908285351UL)
                    {
                        TraceHistoricalLogFileEvidence(
                            volumeInfo,
                            volumeHandle,
                            fileReferenceNumber,
                            expectedFileName,
                            expectedParentFileReferenceNumber.Value);
                    }

                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS $DATA lookup: rejected relaxed MFT record for " +
                        $"fileRef={fileReferenceNumber}, segment={segmentNumber}, " +
                        $"expectedSequence={sequenceNumber}, actualSequence={actualSequence}, " +
                        $"sequenceAdvance={sequenceAdvance}, maxAdvance={maxDeleteSequenceAdvance}, " +
                        $"expectedName={expectedFileName}, expectedParent={expectedParentFileReferenceNumber}, " +
                        $"deletedAt={expectedDeletedAtUtc:O}.");
                }
            }
        }

        if (record is null)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS $DATA lookup: could not read the exact MFT record for fileRef={fileReferenceNumber}.");
            return NotFound("NTFS could not read and validate the exact deleted MFT record for this file reference.");
        }

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $DATA extraction starting: fileRef={fileReferenceNumber}, " +
            $"segment={segmentNumber}, expectedName={expectedFileName ?? "(none)"}, " +
            $"expectedParent={expectedParentFileReferenceNumber?.ToString() ?? "(none)"}.");

        return ReadDefaultDataStreamFromMftRecord(
            volumeInfo,
            volumeHandle,
            rawMftVolumeHandle,
            fileReferenceNumber,
            record,
            expectedFileName,
            expectedParentFileReferenceNumber,
            expectedFileSizeBytes);
    }

    internal NtfsDataStreamInfo ReadDefaultDataStreamFromScannedMftRecord(
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        ulong fileReferenceNumber,
        byte[] record,
        string? expectedFileName = null,
        ulong? expectedParentFileReferenceNumber = null,
        long expectedFileSizeBytes = 0,
        bool historicalSlackOnly = false)
    {
        ArgumentNullException.ThrowIfNull(record);

        if (record.Length < volumeInfo.BytesPerFileRecordSegment ||
            volumeInfo.BytesPerFileRecordSegment <= 0)
        {
            return NotFound("The scanned NTFS MFT record size is invalid.");
        }

        // The scanner already applied the update-sequence fixups while parsing
        // this exact MFT record. Keep that record as the source of truth instead
        // of attempting another lookup using an older USN file-reference sequence.
        System.Diagnostics.Trace.WriteLine(
            $"NTFS historical preflight reader ENTER: " +
            $"fileRef={fileReferenceNumber}, " +
            $"expectedSize={expectedFileSizeBytes:N0}, " +
            $"historicalSlackOnly={historicalSlackOnly}, " +
            $"recordLength={record.Length}.");

        using var rawMftVolumeHandle = CreateVolumeHandle(
            volumeInfo.RootPath,
            overlapped: true);

        System.Diagnostics.Trace.WriteLine(
            $"NTFS historical preflight reader HANDLE READY: " +
            $"fileRef={fileReferenceNumber}.");

        System.Diagnostics.Trace.WriteLine(
            $"NTFS historical preflight reader INNER START: " +
            $"fileRef={fileReferenceNumber}.");

        var result = ReadDefaultDataStreamFromMftRecord(
            volumeInfo,
            volumeHandle,
            rawMftVolumeHandle,
            fileReferenceNumber,
            record,
            expectedFileName,
            expectedParentFileReferenceNumber,
            expectedFileSizeBytes,
            historicalSlackOnly);

        System.Diagnostics.Trace.WriteLine(
            $"NTFS historical preflight reader INNER END: " +
            $"fileRef={fileReferenceNumber}, " +
            $"found={result.Found}, " +
            $"size={result.FileSizeBytes:N0}, " +
            $"extents={result.Extents.Count:N0}, " +
            $"evidence={result.Evidence}.");

        return result;
    }

    private NtfsDataStreamInfo ReadDefaultDataStreamFromMftRecord(
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        SafeFileHandle rawMftVolumeHandle,
        ulong fileReferenceNumber,
        byte[] record,
        string? expectedFileName = null,
        ulong? expectedParentFileReferenceNumber = null,
        long expectedFileSizeBytes = 0,
        bool historicalSlackOnly = false)
    {
        System.Diagnostics.Trace.WriteLine(
            $"NTFS historical reader CORE ENTER: " +
            $"fileRef={fileReferenceNumber}, " +
            $"expectedSize={expectedFileSizeBytes:N0}, " +
            $"historicalSlackOnly={historicalSlackOnly}, " +
            $"expectedName={expectedFileName ?? "(none)"}, " +
            $"expectedParent={expectedParentFileReferenceNumber?.ToString() ?? "(none)"}.");

        var flags = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(22, 2));
        var dataAttributes = FindUnnamedDataAttributes(record, volumeInfo);

        System.Diagnostics.Trace.WriteLine(
            $"NTFS historical reader CORE ATTRIBUTES DONE: " +
            $"fileRef={fileReferenceNumber}, " +
            $"flags=0x{flags:X4}, " +
            $"unnamedDataAttributes={dataAttributes.Count}.");

        foreach (var dataAttribute in dataAttributes)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS $DATA attribute: resident={dataAttribute.IsResident}, " +
                $"lowestVcn={dataAttribute.LowestVcn}, fileSize={dataAttribute.FileSizeBytes}, " +
                $"validLength={dataAttribute.ValidDataLengthBytes}, extents={dataAttribute.Extents.Count}.");
        }

        var historicalFileSize = TryReadFileNameSize(
            record,
            volumeInfo.TotalClusters * (long)volumeInfo.BytesPerCluster,
            expectedFileName,
            expectedParentFileReferenceNumber);

        System.Diagnostics.Trace.WriteLine(
            $"NTFS historical reader CORE FILENAME SIZE DONE: " +
            $"fileRef={fileReferenceNumber}, " +
            $"recordSize={historicalFileSize:N0}, " +
            $"expectedSize={expectedFileSizeBytes:N0}.");

        // The reused MFT segment may no longer retain the old $FILE_NAME
        // value, but the deletion-history record already captured the exact
        // historical size. Use that trusted size to continue the narrow slack
        // search instead of requiring the old $FILE_NAME size to survive.
        if (historicalFileSize <= 0 && expectedFileSizeBytes > 0)
        {
            historicalFileSize = expectedFileSizeBytes;

            System.Diagnostics.Trace.WriteLine(
                $"NTFS historical MFT slack search: using supplied historical file size " +
                $"fileRef={fileReferenceNumber}, expectedSize={historicalFileSize:N0}.");
        }

        if (historicalSlackOnly)
        {
            var slackStart = FindAttributeSlackStart(record);

            System.Diagnostics.Trace.WriteLine(
                $"NTFS historical-only MFT slack search: " +
                $"fileRef={fileReferenceNumber}, " +
                $"fileName={expectedFileName ?? "(none)"}, " +
                $"parentRef={expectedParentFileReferenceNumber?.ToString() ?? "(none)"}, " +
                $"fileNameSize={historicalFileSize:N0}, " +
                $"slackStart={slackStart}.");

            if (slackStart >= 0 &&
                !string.IsNullOrWhiteSpace(expectedFileName) &&
                expectedParentFileReferenceNumber.HasValue)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS historical reader CORE SLACK SEARCH START: " +
                    $"fileRef={fileReferenceNumber}, " +
                    $"slackStart={slackStart}, " +
                    $"expectedSize={historicalFileSize:N0}.");

                var historicalSlackData = FindHistoricalNonResidentDataAttributes(
                    record,
                    volumeInfo,
                    slackStart,
                    historicalFileNameOffset: -1,
                    historicalFileSize,
                    fileReferenceNumber);

                var rawSlack = record.AsSpan(slackStart);
                var dataTypeByteHits = 0;
                for (var i = 0; i + 4 <= rawSlack.Length; i++)
                {
                    if (BinaryPrimitives.ReadUInt32LittleEndian(rawSlack.Slice(i, 4)) == NtfsAttributeData)
                    {
                        dataTypeByteHits++;
                    }
                }

                var nonZeroSlackBytes = 0;
                for (var i = 0; i < rawSlack.Length; i++)
                {
                    if (rawSlack[i] != 0)
                    {
                        nonZeroSlackBytes++;
                    }
                }

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS historical reader CORE SLACK RAW: " +
                    $"fileRef={fileReferenceNumber}, " +
                    $"slackStart={slackStart}, " +
                    $"slackLength={rawSlack.Length}, " +
                    $"0x80TypeHits={dataTypeByteHits}, " +
                    $"nonZeroBytes={nonZeroSlackBytes}, " +
                    $"hex={Convert.ToHexString(rawSlack)}.");

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS historical reader CORE SLACK SEARCH END: " +
                    $"fileRef={fileReferenceNumber}, " +
                    $"matches={historicalSlackData.Count:N0}.");

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS historical-only MFT slack $DATA search: " +
                    $"fileRef={fileReferenceNumber}, " +
                    $"fileName={expectedFileName}, " +
                    $"expectedSize={historicalFileSize:N0}, " +
                    $"matches={historicalSlackData.Count:N0}.");

                if (historicalSlackData.Count > 0)
                {
                    return BuildDataStream(
                        historicalSlackData,
                        1);
                }
            }

            return BuildFileNameSizeOnlyResult(
                historicalFileSize,
                historicalFileSize > 0
                    ? "The historical MFT segment was inspected for the deleted file's nonresident $DATA in MFT slack, but no structurally valid size-matched mapping-pair attribute was found."
                    : "The historical MFT segment was inspected for a structurally valid unnamed nonresident $DATA mapping-pair attribute in MFT slack, but none was found.");
        }

        // When the current attribute list no longer exposes the deleted file's
        // nonresident $DATA stream, the old attribute record may still survive
        // in MFT slack after the end-of-attributes marker. This is a narrow
        // forensic fallback: require an exact historical $FILE_NAME match,
        // require the old $DATA file size to equal that historical size, and
        // require valid mapping pairs before treating the slack as recovery
        // evidence.
        if (dataAttributes.Count == 0 &&
            !string.IsNullOrWhiteSpace(expectedFileName) &&
            expectedParentFileReferenceNumber.HasValue)
        {
            var slackStart = FindAttributeSlackStart(record);

            System.Diagnostics.Trace.WriteLine(
                $"NTFS historical MFT slack search: " +
                $"fileRef={fileReferenceNumber}, " +
                $"fileName={expectedFileName}, " +
                $"parentRef={expectedParentFileReferenceNumber.Value}, " +
                $"fileNameSize={historicalFileSize:N0}, " +
                $"slackStart={slackStart}.");

            if (slackStart >= 0 &&
                historicalFileSize > 0)
            {
                // The retained $FILE_NAME above has already been validated
                // against the exact filename + parent supplied by the candidate.
                // Do not require a second $FILE_NAME structure to survive in slack:
                // the old nonresident $DATA attribute can remain independently in
                // the unused tail of the reused MFT record.
                var historicalSlackData = FindHistoricalNonResidentDataAttributes(
                    record,
                    volumeInfo,
                    slackStart,
                    historicalFileNameOffset: -1,
                    historicalFileSize,
                    fileReferenceNumber);

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS historical MFT slack $DATA search: " +
                    $"fileRef={fileReferenceNumber}, " +
                    $"fileName={expectedFileName}, " +
                    $"expectedSize={historicalFileSize:N0}, " +
                    $"matches={historicalSlackData.Count:N0}.");

                if (historicalSlackData.Count > 0)
                {
                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS historical MFT slack $DATA evidence: " +
                        $"fileRef={fileReferenceNumber}, " +
                        $"fileName={expectedFileName}, " +
                        $"fileSize={historicalFileSize:N0}, " +
                        $"extents={historicalSlackData.Sum(x => x.Extents.Count):N0}.");

                    return BuildDataStream(
                        historicalSlackData,
                        1);
                }
            }
        }

        var attributeList = FindAttributeList(record, volumeInfo, volumeHandle);
        if (!attributeList.Found)
        {
            return dataAttributes.Count > 0
                ? BuildDataStream(dataAttributes, 1)
                : BuildFileNameSizeOnlyResult(
                    historicalFileSize,
                    "No unnamed $DATA attribute was retained, but the deleted file's NTFS $FILE_NAME size was recovered.");
        }

        if (!attributeList.IsResident && attributeList.ResidentData is null)
        {
            // The base record may still contain a complete unnamed $DATA stream.
            // Preserve that evidence instead of failing the entire candidate just
            // because an unrelated/nonresident $ATTRIBUTE_LIST could not be read.
            return dataAttributes.Count > 0
                ? BuildDataStream(dataAttributes, 1)
                : BuildFileNameSizeOnlyResult(
                    historicalFileSize,
                    "The file retains a nonresident $ATTRIBUTE_LIST that could not be safely reconstructed, but the deleted file's NTFS $FILE_NAME size was recovered.");
        }

        IReadOnlyList<NtfsAttributeListEntry> entries;
        try
        {
            entries = NtfsAttributeListParser.Parse(attributeList.ResidentData!);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS $ATTRIBUTE_LIST parse failed for fileRef={fileReferenceNumber}: {ex.Message}");

            // Keep any complete unnamed $DATA attribute already retained in the
            // base MFT record. Extension records are an enhancement, not a reason
            // to throw away otherwise usable recovery evidence.
            return dataAttributes.Count > 0
                ? BuildDataStream(dataAttributes, 1)
                : BuildFileNameSizeOnlyResult(
                    historicalFileSize,
                    $"The NTFS $ATTRIBUTE_LIST could not be parsed safely, but the deleted file's NTFS $FILE_NAME size was recovered. Parser error: {ex.Message}");
        }

        var referencedSources = new HashSet<(ulong FileReference, long LowestVcn)>();
        foreach (var entry in entries.Where(x => x.AttributeType == NtfsAttributeData && x.IsUnnamed))
        {
            if (!referencedSources.Add((entry.SegmentReference, entry.LowestVcn)))
            {
                continue;
            }

            if ((entry.SegmentReference & 0x0000FFFFFFFFFFFFUL) ==
                (fileReferenceNumber & 0x0000FFFFFFFFFFFFUL) &&
                (ushort)(entry.SegmentReference >> 48) == (ushort)(fileReferenceNumber >> 48))
            {
                continue;
            }

            var extensionSegment = entry.SegmentReference & 0x0000FFFFFFFFFFFFUL;
            var extensionSequence = (ushort)(entry.SegmentReference >> 48);

            var extensionRecord = ReadMftRecordByExtentMap(
                rawMftVolumeHandle,
                volumeInfo,
                extensionSegment,
                extensionSequence,
                expectedBaseFileReference: fileReferenceNumber);

            if (extensionRecord is null)
            {
                continue;
            }

            var extensionData = FindUnnamedDataAttributes(extensionRecord, volumeInfo)
                .Where(x => x.LowestVcn == entry.LowestVcn)
                .ToList();

            dataAttributes.AddRange(extensionData);
        }

        return dataAttributes.Count > 0
            ? BuildDataStream(dataAttributes, Math.Max(1, dataAttributes.Count))
            : BuildFileNameSizeOnlyResult(
                historicalFileSize,
                "The deleted MFT record retained the historical NTFS $FILE_NAME size, but no usable unnamed $DATA attribute was found.");
    }

    private static NtfsDataStreamInfo BuildFileNameSizeOnlyResult(
        long fileSizeBytes,
        string evidence)
    {
        return new NtfsDataStreamInfo
        {
            Found = false,
            FileSizeBytes = fileSizeBytes,
            Evidence = fileSizeBytes > 0
                ? $"{evidence} File size={fileSizeBytes:N0} bytes."
                : evidence
        };
    }

    private static long TryReadFileNameSize(
        byte[] record,
        long volumeSizeBytes,
        string? expectedFileName,
        ulong? expectedParentFileReferenceNumber)
    {        const uint NtfsFileNameAttribute = 0x30;
        const int ParentReferenceOffset = 0;
        const int AllocatedSizeOffset = 40;
        const int RealSizeOffset = 48;
        const int NameLengthOffset = 64;
        const int NameNamespaceOffset = 65;
        const int NameOffset = 66;

        try
        {
            foreach (var attribute in EnumerateAttributes(record))
            {
                if (attribute.Type != NtfsFileNameAttribute ||
                    attribute.FormCode != 0 ||
                    attribute.NameLength != 0)
                {
                    continue;
                }

                if (attribute.Offset < 0 ||
                    attribute.Length < 24 ||
                    attribute.Offset + attribute.Length > record.Length)
                {
                    continue;
                }

                var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(attribute.Offset + 16, sizeof(uint)));
                var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                    record.AsSpan(attribute.Offset + 20, sizeof(ushort)));

                if (valueLength < 66 ||
                    valueOffset < 24 ||
                    valueOffset + valueLength > attribute.Length)
                {
                    continue;
                }

                var valueStart = attribute.Offset + valueOffset;

                var storedNameLength = record[valueStart + NameLengthOffset];
                var nameNamespace = record[valueStart + NameNamespaceOffset];

                if (storedNameLength == 0 || nameNamespace > 3)
                {
                    continue;
                }

                var nameByteLength = checked(storedNameLength * 2);
                if (NameOffset + nameByteLength > valueLength)
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(expectedFileName))
                {
                    var storedName = System.Text.Encoding.Unicode.GetString(
                        record,
                        valueStart + NameOffset,
                        nameByteLength);

                    if (!string.Equals(
                            storedName,
                            expectedFileName,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                }

                if (expectedParentFileReferenceNumber.HasValue)
                {
                    var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(
                        record.AsSpan(valueStart + ParentReferenceOffset, sizeof(ulong)));

                    if (parentReference != expectedParentFileReferenceNumber.Value)
                    {
                        continue;
                    }
                }

                var allocatedSize = BinaryPrimitives.ReadInt64LittleEndian(
                    record.AsSpan(valueStart + AllocatedSizeOffset, sizeof(long)));
                var realSize = BinaryPrimitives.ReadInt64LittleEndian(
                    record.AsSpan(valueStart + RealSizeOffset, sizeof(long)));

                if (realSize < 0 ||
                    allocatedSize < 0 ||
                    realSize > allocatedSize ||
                    (volumeSizeBytes > 0 && realSize > volumeSizeBytes))
                {
                    continue;
                }

                return realSize;
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS $FILE_NAME size extraction failed: " +
                $"{ex.GetType().Name}: {ex.Message}");
        }

        return 0;
    }

    private static List<DataAttributeDescriptor> FindHistoricalNonResidentDataAttributes(
        byte[] record,
        NtfsVolumeInfo volumeInfo,
        int slackStart,
        int historicalFileNameOffset,
        long historicalFileSize,
        ulong fileReferenceNumber = 0)
    {
        var result = new List<DataAttributeDescriptor>();

        if (slackStart < 0 ||
            slackStart >= record.Length ||
            historicalFileSize < 0)
        {
            return result;
        }

        const int nonResidentMinimumLength = 64;
        const int maxRelatedSlackDistance = 4096;

        var dataTypeHits = 0;
        var unnamedNonResidentHits = 0;
        var geometryMatches = 0;
        var sizeMatches = 0;
        var mappingParseSuccesses = 0;
        var coverageMatches = 0;
        var historicalSizeKnown = historicalFileSize > 0;

        var sizeMatchDetails = new List<string>();

        try
        {
            for (var attributeOffset = slackStart;
                 attributeOffset + nonResidentMinimumLength <= record.Length;
                 attributeOffset++)
            {
            if (historicalFileNameOffset >= 0 &&
                Math.Abs(attributeOffset - historicalFileNameOffset) > maxRelatedSlackDistance)
            {
                continue;
            }

            var type = BinaryPrimitives.ReadUInt32LittleEndian(
                record.AsSpan(attributeOffset, 4));

            if (type != NtfsAttributeData)
            {
                continue;
            }

            dataTypeHits++;

            var attributeLength = BinaryPrimitives.ReadUInt32LittleEndian(
                record.AsSpan(attributeOffset + 4, 4));

            if (attributeLength < nonResidentMinimumLength ||
                attributeOffset + attributeLength > record.Length)
            {
                continue;
            }

            var formCode = record[attributeOffset + 8];
            var nameLength = record[attributeOffset + 9];

            if (formCode != NonResidentForm ||
                nameLength != 0)
            {
                continue;
            }

            unnamedNonResidentHits++;

            var lowestVcn = BinaryPrimitives.ReadInt64LittleEndian(
                record.AsSpan(attributeOffset + 16, 8));

            var mappingPairsOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                record.AsSpan(attributeOffset + 32, 2));

            var allocatedSize = BinaryPrimitives.ReadInt64LittleEndian(
                record.AsSpan(attributeOffset + 40, 8));

            var fileSize = BinaryPrimitives.ReadInt64LittleEndian(
                record.AsSpan(attributeOffset + 48, 8));

            var validDataLength = BinaryPrimitives.ReadInt64LittleEndian(
                record.AsSpan(attributeOffset + 56, 8));

            if (lowestVcn < 0 ||
                lowestVcn != 0 ||
                mappingPairsOffset < nonResidentMinimumLength ||
                mappingPairsOffset >= attributeLength ||
                fileSize <= 0 ||
                validDataLength < 0 ||
                validDataLength > fileSize)
            {
                continue;
            }

            geometryMatches++;

            if (historicalSizeKnown && fileSize != historicalFileSize)
            {
                continue;
            }

            sizeMatches++;

            if (sizeMatchDetails.Count < 16)
            {
                sizeMatchDetails.Add(
                    $"offset={attributeOffset},attrLen={attributeLength},mappingOffset={mappingPairsOffset}," +
                    $"lowestVcn={lowestVcn},allocated={allocatedSize:N0},fileSize={fileSize:N0}," +
                    $"validLength={validDataLength:N0}");
            }

            if (volumeInfo.BytesPerCluster == 0)
            {
                continue;
            }

            var volumeSizeBytes = checked(
                volumeInfo.TotalClusters * (long)volumeInfo.BytesPerCluster);

            if (fileSize > volumeSizeBytes)
            {
                continue;
            }

            IReadOnlyList<NtfsDataExtent> extents;

            try
            {
                var mappingPairsStart = checked(
                    attributeOffset + (int)mappingPairsOffset);
                var mappingPairsLength = checked(
                    (int)attributeLength - (int)mappingPairsOffset);

                if (mappingPairsStart < attributeOffset ||
                    mappingPairsLength <= 0 ||
                    mappingPairsStart + mappingPairsLength > record.Length)
                {
                    continue;
                }

                extents = NtfsMappingPairsParser.Parse(
                    record.AsSpan(
                        mappingPairsStart,
                        mappingPairsLength),
                    lowestVcn);

                mappingParseSuccesses++;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS historical slack $DATA mapping-pair parse rejected: " +
                    $"attributeOffset={attributeOffset}, " +
                    $"fileSize={fileSize:N0}, error={ex.Message}.");
                continue;
            }

            if (extents.Count == 0)
            {
                continue;
            }

            var expectedClusters = checked(
                (validDataLength + volumeInfo.BytesPerCluster - 1) /
                volumeInfo.BytesPerCluster);

            long coveredClusters = 0;
            var expectedVcn = lowestVcn;
            var validExtentChain = true;

            foreach (var extent in extents)
            {
                if (extent.ClusterCount <= 0 ||
                    extent.VirtualClusterNumber != expectedVcn)
                {
                    validExtentChain = false;
                    break;
                }

                coveredClusters = checked(
                    coveredClusters + extent.ClusterCount);

                expectedVcn = checked(
                    expectedVcn + extent.ClusterCount);
            }

            if (!validExtentChain ||
                coveredClusters < expectedClusters)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS historical slack $DATA mapping coverage rejected: " +
                    $"attributeOffset={attributeOffset}, " +
                    $"fileSize={fileSize:N0}, validDataLength={validDataLength:N0}, " +
                    $"coveredClusters={coveredClusters:N0}, expectedClusters={expectedClusters:N0}.");
                continue;
            }

            coverageMatches++;

            result.Add(
                new DataAttributeDescriptor
                {
                    LowestVcn = lowestVcn,
                    IsResident = false,
                    FileSizeBytes = fileSize,
                    ValidDataLengthBytes = validDataLength,
                    Extents = extents
                });

            // When the historical size is known, return the first exact size match.
            // When the historical size is unknown, keep scanning so an ambiguous
            // slack tail does not result in an arbitrary first-match recovery.
            if (historicalSizeKnown)
            {
                break;
            }
        }
        }
        catch (Exception ex)
        {
            if (fileReferenceNumber != 0)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS historical targeted slack $DATA exception: " +
                    $"fileRef={fileReferenceNumber}, " +
                    $"exception={ex.GetType().Name}: {ex.Message}.");
            }

            throw;
        }
        finally
        {
            if (fileReferenceNumber != 0)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS historical reader SLACK COUNTERS: " +
                    $"fileRef={fileReferenceNumber}, " +
                    $"slackStart={slackStart}, " +
                    $"expectedSize={historicalFileSize:N0}, " +
                    $"dataTypeHits={dataTypeHits}, " +
                    $"unnamedNonResidentHits={unnamedNonResidentHits}, " +
                    $"geometryMatches={geometryMatches}, " +
                    $"sizeMatches={sizeMatches}, " +
                    $"mappingParseSuccesses={mappingParseSuccesses}, " +
                    $"coverageMatches={coverageMatches}, " +
                    $"accepted={result.Count}, " +
                    $"sizeMatchDetails={(sizeMatchDetails.Count == 0 ? "(none)" : string.Join(" | ", sizeMatchDetails))}.");
            }
        }

        if (!historicalSizeKnown && result.Count != 1)
        {
            if (fileReferenceNumber != 0)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS historical reader unknown-size slack probe rejected: " +
                    $"fileRef={fileReferenceNumber}, candidateCount={result.Count}.");
            }

            result.Clear();
        }

        return result;
    }
    private static List<DataAttributeDescriptor> FindUnnamedDataAttributes(
        byte[] record,
        NtfsVolumeInfo volumeInfo)
    {
        var result = new List<DataAttributeDescriptor>();
        foreach (var attribute in EnumerateAttributes(record))
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS attribute: type=0x{attribute.Type:X8}, form={attribute.FormCode}, " +
                $"nameLength={attribute.NameLength}, offset={attribute.Offset}, length={attribute.Length}.");
            if (attribute.Type != NtfsAttributeData || attribute.NameLength != 0)
            {
                continue;
            }

            var descriptor = attribute.FormCode == NonResidentForm
                ? ParseNonResidentDataDescriptor(
                    record,
                    attribute.Offset,
                    attribute.Length)
                : ParseResidentDataDescriptor(
                    record,
                    attribute.Offset,
                    attribute.Length);

            result.Add(descriptor);
        }

        return result;
    }

    private static AttributeListDescriptor FindAttributeList(
        byte[] record,
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle)
    {
        foreach (var attribute in EnumerateAttributes(record))
        {
            if (attribute.Type != NtfsAttributeList || attribute.NameLength != 0)
            {
                continue;
            }

            if (attribute.FormCode == NonResidentForm)
            {
                try
                {
                    if (attribute.Length < 64)
                    {
                        throw new InvalidDataException(
                            "The nonresident $ATTRIBUTE_LIST attribute is incomplete.");
                    }

                    var lowestVcn = BinaryPrimitives.ReadInt64LittleEndian(
                        record.AsSpan(attribute.Offset + 16, 8));
                    var mappingPairsOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                        record.AsSpan(attribute.Offset + 32, 2));
                    var fileSize = BinaryPrimitives.ReadInt64LittleEndian(
                        record.AsSpan(attribute.Offset + 48, 8));
                    var validDataLength = BinaryPrimitives.ReadInt64LittleEndian(
                        record.AsSpan(attribute.Offset + 56, 8));

                    if (lowestVcn != 0 ||
                        mappingPairsOffset >= attribute.Length ||
                        fileSize <= 0 ||
                        fileSize > MaxAttributeListBytes ||
                        validDataLength <= 0 ||
                        validDataLength > fileSize)
                    {
                        throw new InvalidDataException(
                            "The nonresident $ATTRIBUTE_LIST geometry is outside the supported safe range.");
                    }

                    IReadOnlyList<NtfsDataExtent> extents;
                    try
                    {
                        extents = NtfsMappingPairsParser.Parse(
                            record.AsSpan(
                                attribute.Offset + mappingPairsOffset,
                                attribute.Length - mappingPairsOffset),
                            lowestVcn);
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidDataException(
                            "The nonresident $ATTRIBUTE_LIST mapping pairs could not be parsed.",
                            ex);
                    }

                    var data = new byte[checked((int)validDataLength)];
                    var expectedVcn = 0L;
                    var remaining = data.LongLength;
                    var destinationOffset = 0;

                    foreach (var extent in extents)
                    {
                        if (extent.VirtualClusterNumber != expectedVcn)
                        {
                            throw new InvalidDataException(
                                "The nonresident $ATTRIBUTE_LIST contains a VCN gap or overlap.");
                        }

                        var extentBytes = checked(
                            extent.ClusterCount * volumeInfo.BytesPerCluster);
                        var bytesToRead = Math.Min(extentBytes, remaining);

                        if (bytesToRead <= 0)
                        {
                            break;
                        }

                        if (!extent.IsSparse)
                        {
                            ReadRawClusters(
                                volumeHandle,
                                extent.LogicalClusterNumber,
                                bytesToRead,
                                volumeInfo.BytesPerCluster,
                                data,
                                destinationOffset);
                        }

                        destinationOffset = checked(
                            destinationOffset + (int)bytesToRead);
                        remaining -= bytesToRead;
                        expectedVcn = checked(
                            expectedVcn + extent.ClusterCount);

                        if (remaining == 0)
                        {
                            break;
                        }
                    }

                    if (remaining != 0)
                    {
                        throw new InvalidDataException(
                            "The nonresident $ATTRIBUTE_LIST data runs do not cover its valid data length.");
                    }

                    return new AttributeListDescriptor
                    {
                        Found = true,
                        IsResident = false,
                        ResidentData = data
                    };
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS $ATTRIBUTE_LIST read skipped: {ex.GetType().Name}: {ex.Message}");

                    return new AttributeListDescriptor
                    {
                        Found = true,
                        IsResident = false,
                        ResidentData = null
                    };
                }
            }

            try
            {
                var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.AsSpan(attribute.Offset + 16, 4));
                var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                    record.AsSpan(attribute.Offset + 20, 2));

                if (valueOffset + valueLength > attribute.Length)
                {
                    throw new InvalidDataException(
                        "The resident $ATTRIBUTE_LIST value is outside its attribute record.");
                }

                var residentData = new byte[checked((int)valueLength)];
                record.AsSpan(
                    attribute.Offset + valueOffset,
                    checked((int)valueLength)).CopyTo(residentData);

                return new AttributeListDescriptor
                {
                    Found = true,
                    IsResident = true,
                    ResidentData = residentData
                };
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS resident $ATTRIBUTE_LIST read skipped: " +
                    $"{ex.GetType().Name}: {ex.Message}");

                return new AttributeListDescriptor
                {
                    Found = true,
                    IsResident = true,
                    ResidentData = null
                };
            }
        }

        return new AttributeListDescriptor();
    }

    private static IEnumerable<AttributeDescriptor> EnumerateAttributes(byte[] record)
    {
        var firstAttributeOffset = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(20, 2));
        if (firstAttributeOffset < 24 || firstAttributeOffset >= record.Length)
        {
            yield break;
        }

        var offset = (int)firstAttributeOffset;
        while (offset + 16 <= record.Length)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(record.AsSpan(offset, 4));
            if (type == NtfsAttributeEnd)
            {
                yield break;
            }

            var recordLength = BinaryPrimitives.ReadUInt32LittleEndian(record.AsSpan(offset + 4, 4));
            if (recordLength < 24 ||
                offset + recordLength > record.Length)
            {
                yield break;
            }

            var nameLength = record[offset + 9];
            var nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(offset + 10, 2));

            if (nameLength == 0 ||
                (nameOffset != 0 &&
                 offset + nameOffset + nameLength * 2 <= record.Length))
            {
                yield return new AttributeDescriptor
                {
                    Type = type,
                    Offset = offset,
                    Length = checked((int)recordLength),
                    FormCode = record[offset + 8],
                    NameLength = nameLength
                };
            }

            offset += checked((int)recordLength);
        }
    }

    private static DataAttributeDescriptor ParseResidentDataDescriptor(
        byte[] record,
        int attributeOffset,
        int attributeLength)
    {
        if (attributeLength < 24)
        {
            throw new InvalidDataException("The resident $DATA attribute is incomplete.");
        }

        var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(
            record.AsSpan(attributeOffset + 16, 4));
        var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            record.AsSpan(attributeOffset + 20, 2));

        if (valueOffset + valueLength > attributeLength)
        {
            throw new InvalidDataException("The resident $DATA value is outside its attribute record.");
        }

        var data = new byte[checked((int)valueLength)];
        record.AsSpan(
            attributeOffset + valueOffset,
            checked((int)valueLength)).CopyTo(data);

        return new DataAttributeDescriptor
        {
            LowestVcn = 0,
            IsResident = true,
            FileSizeBytes = valueLength,
            ValidDataLengthBytes = valueLength,
            ResidentData = data
        };
    }

    private static DataAttributeDescriptor ParseNonResidentDataDescriptor(
        byte[] record,
        int attributeOffset,
        int attributeLength)
    {
        if (attributeLength < 64)
        {
            throw new InvalidDataException("The nonresident $DATA attribute is incomplete.");
        }

        var lowestVcn = BinaryPrimitives.ReadInt64LittleEndian(
            record.AsSpan(attributeOffset + 16, 8));
        var mappingPairsOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            record.AsSpan(attributeOffset + 32, 2));
        var fileSize = BinaryPrimitives.ReadInt64LittleEndian(
            record.AsSpan(attributeOffset + 48, 8));
        var validDataLength = BinaryPrimitives.ReadInt64LittleEndian(
            record.AsSpan(attributeOffset + 56, 8));

        if (mappingPairsOffset >= attributeLength)
        {
            throw new InvalidDataException("The nonresident $DATA mapping pairs are outside the attribute record.");
        }

        var mappingPairs = record.AsSpan(
            attributeOffset + mappingPairsOffset,
            attributeLength - mappingPairsOffset);

        IReadOnlyList<NtfsDataExtent> extents;
        try
        {
            extents = NtfsMappingPairsParser.Parse(mappingPairs, lowestVcn);
        }
        catch (Exception ex)
        {
            throw new InvalidDataException(
                "The NTFS data-run list could not be parsed.",
                ex);
        }

        return new DataAttributeDescriptor
        {
            LowestVcn = lowestVcn,
            IsResident = false,
            FileSizeBytes = fileSize,
            ValidDataLengthBytes = validDataLength,
            Extents = extents
        };
    }

    private static NtfsDataStreamInfo BuildDataStream(
        List<DataAttributeDescriptor> descriptors,
        int mftSegmentCount)
    {
        if (descriptors.Count == 0)
        {
            System.Diagnostics.Debug.WriteLine(
                "NTFS $DATA lookup: BuildDataStream received zero unnamed $DATA descriptors.");
            return NotFound("No unnamed $DATA attribute was retained in the base or extension MFT records.");        }

        if (descriptors.Any(x => x.IsResident))
        {
            if (descriptors.Count != 1)
            {
                return NotFound("The NTFS default $DATA stream mixes resident and extension records, which this recovery stage does not safely combine.");
            }

            var resident = descriptors[0];
            return new NtfsDataStreamInfo
            {
                Found = true,
                IsResident = true,
                FileSizeBytes = resident.FileSizeBytes,
                ValidDataLengthBytes = resident.ValidDataLengthBytes,
                ResidentData = resident.ResidentData,
                Evidence = "The default $DATA stream is resident inside the retained MFT record."
            };
        }

        var ordered = descriptors
            .OrderBy(x => x.LowestVcn)
            .ToList();

        var fileSize = ordered[0].FileSizeBytes;
        var validDataLength = ordered[0].ValidDataLengthBytes;
        var extents = new List<NtfsDataExtent>();
        var expectedVcn = 0L;

        foreach (var descriptor in ordered)
        {
            if (descriptor.FileSizeBytes != fileSize ||
                descriptor.ValidDataLengthBytes != validDataLength)
            {
                return NotFound("The NTFS $DATA extension records disagree about the logical file size.");
            }

            foreach (var extent in descriptor.Extents)
            {
                if (extent.VirtualClusterNumber != expectedVcn)
                {
                    return NotFound("The retained NTFS $DATA extension records contain a VCN gap or overlap.");
                }

                extents.Add(extent);
                expectedVcn = checked(expectedVcn + extent.ClusterCount);
            }
        }

        return new NtfsDataStreamInfo
        {
            Found = true,
            IsResident = false,
            FileSizeBytes = fileSize,
            ValidDataLengthBytes = validDataLength,
            Extents = extents,
            Evidence = mftSegmentCount > 1
                ? $"The default $DATA stream spans {mftSegmentCount:N0} MFT record(s) through an NTFS $ATTRIBUTE_LIST and retained {extents.Count:N0} data extent(s)."
                : $"The default $DATA stream retained {extents.Count:N0} nonresident extent(s)."
        };
    }

    private sealed class AttributeDescriptor
    {
        public uint Type { get; init; }
        public int Offset { get; init; }
        public int Length { get; init; }
        public byte FormCode { get; init; }
        public byte NameLength { get; init; }
    }

    private sealed class DataAttributeDescriptor
    {
        public long LowestVcn { get; init; }
        public bool IsResident { get; init; }
        public long FileSizeBytes { get; init; }
        public long ValidDataLengthBytes { get; init; }
        public byte[]? ResidentData { get; init; }
        public IReadOnlyList<NtfsDataExtent> Extents { get; init; } = [];
    }

    private sealed class AttributeListDescriptor
    {
        public bool Found { get; init; }
        public bool IsResident { get; init; }
        public byte[]? ResidentData { get; init; }
    }

    // DIAGNOSTIC ONLY: no behavioral effect.
    private static void TraceDataStreamLayout(
        string tag,
        ulong fileReferenceNumber,
        NtfsDataStreamInfo stream,
        uint bytesPerCluster)
    {
        System.Diagnostics.Trace.WriteLine(
            $"NTFS {tag}: fileRef={fileReferenceNumber}, resident={stream.IsResident}, " +
            $"fileSize={stream.FileSizeBytes:N0}, validDataLength={stream.ValidDataLengthBytes:N0}, " +
            $"extents={stream.Extents.Count:N0}, bytesPerCluster={bytesPerCluster}.");

        long mappedClusters = 0;
        long sparseClusters = 0;
        foreach (var extent in stream.Extents)
        {
            mappedClusters += extent.ClusterCount;
            if (extent.IsSparse)
            {
                sparseClusters += extent.ClusterCount;
            }

            System.Diagnostics.Trace.WriteLine(
                $"NTFS {tag}: extent vcn={extent.VirtualClusterNumber}, " +
                $"clusters={extent.ClusterCount}, lcn={extent.LogicalClusterNumber}, " +
                $"sparse={extent.IsSparse}, byteOffset={(extent.IsSparse ? -1L : extent.LogicalClusterNumber * (long)bytesPerCluster)}.");
        }

        System.Diagnostics.Trace.WriteLine(
            $"NTFS {tag}: mappedClusters={mappedClusters}, sparseClusters={sparseClusters}, " +
            $"mappedBytes={mappedClusters * bytesPerCluster:N0}, " +
            $"vdlIsZeroButSizeIsNot={stream.ValidDataLengthBytes == 0 && stream.FileSizeBytes > 0}.");
    }

    // DIAGNOSTIC ONLY: no behavioral effect.
    private static void TraceCapturedContent(
        string tag,
        ulong fileReferenceNumber,
        byte[] data)
    {
        var nonZero = 0L;
        foreach (var b in data)
        {
            if (b != 0)
            {
                nonZero++;
            }
        }

        var head = Convert.ToHexString(data.AsSpan(0, Math.Min(32, data.Length)));
        var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data));

        System.Diagnostics.Trace.WriteLine(
            $"NTFS {tag}: fileRef={fileReferenceNumber}, bytes={data.LongLength:N0}, " +
            $"nonZeroBytes={nonZero:N0}, allZero={nonZero == 0}, head32={head}, sha256={sha}.");
    }

    private static void ReadRawClusters(
        SafeFileHandle volumeHandle,
        long logicalClusterNumber,
        long byteCount,
        uint bytesPerCluster,
        byte[] destination,
        int destinationOffset)
    {
        var offset = checked(logicalClusterNumber * (long)bytesPerCluster);
        var buffer = new byte[RawReadBufferSize];
        var remaining = byteCount;
        var targetOffset = destinationOffset;

        while (remaining > 0)
        {
            var chunk = (int)Math.Min(buffer.Length, remaining);

            if (!SetFilePointerEx(volumeHandle, offset, out _, 0))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not seek to a nonresident NTFS data extent.");
            }

            if (!ReadFile(
                    volumeHandle,
                    buffer,
                    (uint)chunk,
                    out var bytesRead,
                    IntPtr.Zero) ||
                bytesRead != (uint)chunk)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not read a nonresident NTFS data extent.");
            }

            Buffer.BlockCopy(buffer, 0, destination, targetOffset, chunk);

            offset = checked(offset + chunk);
            targetOffset = checked(targetOffset + chunk);
            remaining -= chunk;
        }
    }

    private byte[]? ReadMftRecordByExtentMap(
        SafeFileHandle volumeHandle,
        NtfsVolumeInfo volumeInfo,
        ulong segmentNumber,
        ushort expectedSequenceNumber,
        ulong expectedBaseFileReference)
    {
        _mftExtents ??= ReadMftDataExtents(
            volumeHandle,
            volumeInfo);

        if (_mftExtents.Count == 0)
        {
            System.Diagnostics.Debug.WriteLine(
                "NTFS MFT extent map: no $MFT $DATA extents were found.");
            return null;
        }

        var logicalByteOffset = checked(
            (long)segmentNumber * volumeInfo.BytesPerFileRecordSegment);

        var record = new byte[checked((int)volumeInfo.BytesPerFileRecordSegment)];
        var bytesRead = ReadMappedFileBytes(
            volumeHandle,
            volumeInfo.BytesPerCluster,
            _mftExtents,
            logicalByteOffset,
            record);

        if (bytesRead != record.Length)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS MFT extent map: segment={segmentNumber}, " +
                $"logicalOffset={logicalByteOffset}, read={bytesRead}, expected={record.Length}.");
            return null;
        }

        if (record.Length < 48 ||
            record[0] != (byte)'F' ||
            record[1] != (byte)'I' ||
            record[2] != (byte)'L' ||
            record[3] != (byte)'E')
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS MFT extent map: invalid FILE signature for segment={segmentNumber}, " +
                $"logicalOffset={logicalByteOffset}.");
            return null;
        }

        try
        {
            ApplyUpdateSequenceFixups(
                record,
                checked((int)volumeInfo.BytesPerSector));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS MFT extent map: update-sequence fixup failed for segment={segmentNumber}: {ex.Message}");
            return null;
        }

        var actualSequence = BinaryPrimitives.ReadUInt16LittleEndian(
            record.AsSpan(16, 2));

        if (expectedSequenceNumber != 0 &&
            actualSequence != expectedSequenceNumber)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS MFT extent map: sequence mismatch segment={segmentNumber}, " +
                $"expected={expectedSequenceNumber}, actual={actualSequence}.");
            return null;
        }

        var actualBaseReference = BinaryPrimitives.ReadUInt64LittleEndian(
            record.AsSpan(32, 8));

        if (expectedBaseFileReference != 0 &&
            actualBaseReference != 0 &&
            actualBaseReference != expectedBaseFileReference)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS MFT extent map: base-reference mismatch segment={segmentNumber}, " +
                $"expected={expectedBaseFileReference}, actual={actualBaseReference}.");
            return null;
        }

        return record;
    }

    private static IReadOnlyList<NtfsDataExtent> ReadMftDataExtents(
        SafeFileHandle volumeHandle,
        NtfsVolumeInfo volumeInfo)
    {
        var recordSize = checked((int)volumeInfo.BytesPerFileRecordSegment);
        var record0 = new byte[recordSize];

        // MFT record 0 is always at the beginning of $MFT, so the starting LCN
        // reported by FSCTL_GET_NTFS_VOLUME_DATA is sufficient to read this one
        // bootstrap record. After that, use record 0's own $DATA mapping pairs
        // for every other MFT segment.
        var mftStartOffset = checked(
            volumeInfo.MftStartLcn * (long)volumeInfo.BytesPerCluster);

        ReadRawExact(
            volumeHandle,
            mftStartOffset,
            record0);

        if (record0.Length < 48 ||
            record0[0] != (byte)'F' ||
            record0[1] != (byte)'I' ||
            record0[2] != (byte)'L' ||
            record0[3] != (byte)'E')
        {
            throw new InvalidDataException(
                "The NTFS $MFT bootstrap record does not contain a valid FILE signature.");
        }

        ApplyUpdateSequenceFixups(
            record0,
            checked((int)volumeInfo.BytesPerSector));

        var dataAttributes = FindUnnamedDataAttributes(
            record0,
            volumeInfo);

        var dataAttribute = dataAttributes
            .Where(attribute => !attribute.IsResident)
            .OrderBy(attribute => attribute.LowestVcn)
            .FirstOrDefault();

        if (dataAttribute is null ||
            dataAttribute.Extents.Count == 0)
        {
            throw new InvalidDataException(
                "The NTFS $MFT bootstrap record does not retain a nonresident $DATA mapping.");
        }

        System.Diagnostics.Debug.WriteLine(
            $"NTFS MFT extent map: record0 DATA extents={dataAttribute.Extents.Count}, " +
            $"fileSize={dataAttribute.FileSizeBytes}, validLength={dataAttribute.ValidDataLengthBytes}.");

        return dataAttribute.Extents;
    }

    internal byte[]? ReadHistoricalMftRecordForReference(
        SafeFileHandle volumeHandle,
        NtfsVolumeInfo volumeInfo,
        ulong fileReferenceNumber)
    {
        if (fileReferenceNumber == 0)
        {
            return null;
        }

        var segmentNumber = fileReferenceNumber & 0x0000FFFFFFFFFFFFUL;

        System.Diagnostics.Trace.WriteLine(
            $"NTFS historical MFT preflight: fileRef={fileReferenceNumber}, " +
            $"segment={segmentNumber}.");

        var record = ReadMftRecordByExtentMap(
            volumeHandle,
            volumeInfo,
            segmentNumber,
            expectedSequenceNumber: 0,
            expectedBaseFileReference: 0);

        if (record is null)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS historical MFT preflight: segment read failed. " +
                $"fileRef={fileReferenceNumber}, segment={segmentNumber}.");
            return null;
        }

        System.Diagnostics.Trace.WriteLine(
            $"NTFS historical MFT preflight: segment read succeeded. " +
            $"fileRef={fileReferenceNumber}, segment={segmentNumber}, " +
            $"currentSequence={BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(16, 2))}, " +
            $"currentFlags=0x{BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(22, 2)):X4}.");

        return record;
    }

    internal int ReadMftLogicalBytes(
        SafeFileHandle volumeHandle,
        NtfsVolumeInfo volumeInfo,
        long fileOffset,
        byte[] destination)
    {
        if (volumeInfo.MftValidDataLength <= 0 ||
            fileOffset < 0 ||
            destination.Length == 0)
        {
            return 0;
        }

        if (fileOffset >= volumeInfo.MftValidDataLength)
        {
            return 0;
        }

        var bytesToRead = (int)Math.Min(
            destination.Length,
            volumeInfo.MftValidDataLength - fileOffset);

        _mftExtents ??= ReadMftDataExtents(
            volumeHandle,
            volumeInfo);

        if (bytesToRead == destination.Length)
        {
            return ReadMappedFileBytes(
                volumeHandle,
                volumeInfo.BytesPerCluster,
                _mftExtents,
                fileOffset,
                destination);
        }

        var temp = new byte[bytesToRead];
        var bytesRead = ReadMappedFileBytes(
            volumeHandle,
            volumeInfo.BytesPerCluster,
            _mftExtents,
            fileOffset,
            temp);

        if (bytesRead > 0)
        {
            Buffer.BlockCopy(temp, 0, destination, 0, bytesRead);
        }

        return bytesRead;
    }

    private static int ReadMappedFileBytes(
        SafeFileHandle volumeHandle,
        uint bytesPerCluster,
        IReadOnlyList<NtfsDataExtent> extents,
        long fileOffset,
        byte[] destination)
    {
        if (fileOffset < 0 ||
            destination.Length == 0 ||
            bytesPerCluster == 0)
        {
            return 0;
        }

        var remaining = destination.Length;
        var destinationOffset = 0;
        var logicalOffset = fileOffset;

        foreach (var extent in extents.OrderBy(x => x.VirtualClusterNumber))
        {
            var extentStart = checked(
                extent.VirtualClusterNumber * (long)bytesPerCluster);
            var extentLength = checked(
                extent.ClusterCount * (long)bytesPerCluster);
            var extentEnd = checked(extentStart + extentLength);

            if (logicalOffset >= extentEnd ||
                logicalOffset < extentStart)
            {
                continue;
            }

            var withinExtent = logicalOffset - extentStart;
            var bytesAvailable = checked(extentEnd - logicalOffset);
            var bytesToRead = (int)Math.Min(
                (long)remaining,
                bytesAvailable);

            if (bytesToRead <= 0)
            {
                continue;
            }

            if (extent.IsSparse)
            {
                // A sparse MFT run represents zero-filled logical bytes. We still
                // need to advance the logical offset so a later physical extent can
                // be reached instead of terminating the sequential MFT scan.
                Array.Clear(
                    destination,
                    destinationOffset,
                    bytesToRead);
            }
            else
            {
                var physicalOffset = checked(
                    extent.LogicalClusterNumber * (long)bytesPerCluster +
                    withinExtent);

                var temp = new byte[bytesToRead];

                ReadRawExact(
                    volumeHandle,
                    physicalOffset,
                    temp);

                Buffer.BlockCopy(
                    temp,
                    0,
                    destination,
                    destinationOffset,
                    bytesToRead);
            }

            destinationOffset += bytesToRead;
            remaining -= bytesToRead;
            logicalOffset += bytesToRead;

            if (remaining == 0)
            {
                break;
            }
        }

        return destinationOffset;
    }

    private static byte[]? ReadRawRecord(
        SafeFileHandle volumeHandle,
        NtfsVolumeInfo volumeInfo,
        ulong segmentNumber)
    {
        var relativeOffset = checked(
            checked((long)segmentNumber) * volumeInfo.BytesPerFileRecordSegment);

        if (relativeOffset < 0 ||
            relativeOffset + volumeInfo.BytesPerFileRecordSegment > volumeInfo.MftValidDataLength)
        {
            return null;
        }

        var mftStartOffset = checked(
            volumeInfo.MftStartLcn * (long)volumeInfo.BytesPerCluster);

        var record = new byte[checked((int)volumeInfo.BytesPerFileRecordSegment)];
        ReadRawExact(
            volumeHandle,
            checked(mftStartOffset + relativeOffset),
            record);

        if (record.Length < 48 ||
            record[0] != (byte)'F' ||
            record[1] != (byte)'I' ||
            record[2] != (byte)'L' ||
            record[3] != (byte)'E')
        {
            return null;
        }
        ApplyUpdateSequenceFixups(
            record,
            checked((int)volumeInfo.BytesPerSector));

        return record;
    }

    private static bool HasMatchingFileNameEntry(
        SafeFileHandle volumeHandle,
        byte[] record,
        string expectedFileName,
        ulong expectedParentFileReferenceNumber,
        string? expectedFullPath,
        ushort expectedSequenceNumber = 0,
        DateTime expectedDeletedAtUtc = default)
    {
        var flags = BinaryPrimitives.ReadUInt16LittleEndian(
            record.AsSpan(22, 2));
        var actualSequenceNumber = BinaryPrimitives.ReadUInt16LittleEndian(
            record.AsSpan(16, 2));

        // If the current MFT sequence still equals the USN sequence, an IN_USE
        // flag can reflect a just-finished delete transaction. If the sequence
        // has changed, only a deleted record is safe to consider.
        if (expectedSequenceNumber != 0 &&
            actualSequenceNumber != expectedSequenceNumber &&
            (flags & 0x0001) != 0)
        {
            return false;
        }

        if ((flags & 0x0002) != 0)
        {
            return false;
        }

        var normalizedName = expectedFileName.Trim();

        foreach (var attribute in EnumerateAttributes(record))
        {
            if (attribute.Type != 0x30 ||
                attribute.NameLength != 0 ||
                attribute.FormCode != 0)
            {
                continue;
            }

            if (attribute.Length < 24)
            {
                continue;
            }

            var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(
                record.AsSpan(attribute.Offset + 16, 4));
            var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                record.AsSpan(attribute.Offset + 20, 2));

            if (valueLength < 66 ||
                valueOffset + valueLength > attribute.Length)
            {
                continue;
            }

            var valueStart = attribute.Offset + valueOffset;
            var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(
                record.AsSpan(valueStart, 8));

            var nameLength = record[valueStart + 64];
            var nameBytes = checked(nameLength * 2);

            if (nameLength == 0 ||
                valueStart + 66 + nameBytes > record.Length)
            {
                continue;
            }

            var name = System.Text.Encoding.Unicode.GetString(
                record.AsSpan(valueStart + 66, nameBytes));

            if (!string.Equals(
                    name,
                    normalizedName,
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // A retained FILE_NAME entry is only evidence for this deleted
            // instance when its timestamp is compatible with the deletion event.
            // This applies even when the old parent reference is stale but the
            // resolved historical/current path happens to match.
            var timestampMatches = expectedDeletedAtUtc == default;

            if (!timestampMatches)
            {
                var modificationTimeFileTime =
                    BinaryPrimitives.ReadInt64LittleEndian(
                        record.AsSpan(valueStart + 16, sizeof(long)));

                DateTime modificationTimeUtc;
                try
                {
                    modificationTimeUtc =
                        DateTime.FromFileTimeUtc(modificationTimeFileTime);
                }
                catch
                {
                    modificationTimeUtc = DateTime.MinValue;
                }

                var timestampDeltaMinutes =
                    modificationTimeUtc == DateTime.MinValue
                        ? double.MaxValue
                        : Math.Abs(
                            (modificationTimeUtc - expectedDeletedAtUtc).TotalMinutes);

                timestampMatches = timestampDeltaMinutes <= 5;

                if (timestampMatches)
                {
                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS FILE_NAME match: name={name}, parentRef={parentReference}, " +
                        $"modifiedAt={modificationTimeUtc:O}, " +
                        $"deleteAt={expectedDeletedAtUtc:O}, " +
                        $"deltaMinutes={timestampDeltaMinutes:0.###}.");
                }
                else
                {
                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS FILE_NAME rejected by timestamp: name={name}, " +
                        $"parentRef={parentReference}, modifiedAt={modificationTimeUtc:O}, " +
                        $"deleteAt={expectedDeletedAtUtc:O}, " +
                        $"deltaMinutes={timestampDeltaMinutes:0.###}.");
                }
            }

            if (parentReference == expectedParentFileReferenceNumber &&
                timestampMatches)
            {
                return true;
            }

            if (!timestampMatches)
            {
                continue;
            }

            // The USN parent reference can become stale after the parent
            // directory's own MFT sequence changes. When the historical full
            // path is available, validate the retained FILE_NAME against the
            // current parent path instead of requiring the old 64-bit parent
            // reference to match byte-for-byte.
            if (!string.IsNullOrWhiteSpace(expectedFullPath))
            {
                try
                {
                    var currentParentPath = NtfsParentPathResolver.Resolve(
                        volumeHandle,
                        parentReference);

                    var currentFullPath = string.IsNullOrWhiteSpace(currentParentPath)
                        ? name
                        : Path.Combine(currentParentPath, name);

                    if (string.Equals(
                            NormalizePath(currentFullPath),
                            NormalizePath(expectedFullPath),
                            StringComparison.OrdinalIgnoreCase))
                    {
                        System.Diagnostics.Debug.WriteLine(
                            $"NTFS $DATA lookup: accepted FILE_NAME path match despite stale parent reference. " +
                            $"expectedParent={expectedParentFileReferenceNumber}, actualParent={parentReference}, " +
                            $"path={currentFullPath}.");
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS $DATA lookup: FILE_NAME path validation failed for parentRef={parentReference}: {ex.Message}");
                }
            }
        }

        return false;
    }

    private static ushort CalculateForwardSequenceAdvance(
        ushort expectedSequence,
        ushort actualSequence)
    {
        if (expectedSequence == 0 ||
            actualSequence == 0)
        {
            return 0;
        }

        return actualSequence >= expectedSequence
            ? (ushort)(actualSequence - expectedSequence)
            : (ushort)(ushort.MaxValue - expectedSequence + actualSequence + 1);
    }

    private static string? GetNtfsVolumeRoot(string path)
    {
        var normalized = path.Trim();

        while (normalized.StartsWith(@"\\?\", StringComparison.Ordinal) ||
               normalized.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }

        var root = Path.GetPathRoot(normalized);
        if (string.IsNullOrWhiteSpace(root))
        {
            return null;
        }

        return root;
    }

    private static string NormalizePath(string path) =>
        path.Trim().Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

    private static byte[]? ReadMftRecordDirect(
        SafeFileHandle mftHandle,
        NtfsVolumeInfo volumeInfo,
        ulong segmentNumber,
        ushort expectedSequenceNumber,
        ulong expectedBaseFileReference)
    {
        var relativeOffset = checked(
            checked((long)segmentNumber) * volumeInfo.BytesPerFileRecordSegment);

        if (relativeOffset < 0 ||
            relativeOffset + volumeInfo.BytesPerFileRecordSegment > volumeInfo.MftValidDataLength)
        {
            return null;
        }

        var record = new byte[checked((int)volumeInfo.BytesPerFileRecordSegment)];
        ReadAt(
            mftHandle,
            relativeOffset,
            record);

        if (record.Length < 48 ||
            record[0] != (byte)'F' ||
            record[1] != (byte)'I' ||
            record[2] != (byte)'L' ||
            record[3] != (byte)'E')
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS MFT logical read: invalid FILE signature for segment={segmentNumber}.");
            return null;
        }

        try
        {
            ApplyUpdateSequenceFixups(
                record,
                checked((int)volumeInfo.BytesPerSector));
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS MFT logical read: update-sequence fixup failed for segment={segmentNumber}: {ex.Message}");
            return null;
        }

        var sequenceNumber = BinaryPrimitives.ReadUInt16LittleEndian(
            record.AsSpan(16, 2));

        if (expectedSequenceNumber != 0 &&
            sequenceNumber != expectedSequenceNumber)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS MFT logical read: sequence mismatch segment={segmentNumber}, " +
                $"expected={expectedSequenceNumber}, actual={sequenceNumber}.");
            return null;
        }

        var baseFileReference = BinaryPrimitives.ReadUInt64LittleEndian(
            record.AsSpan(32, 8));

        if (expectedBaseFileReference != 0 &&
            baseFileReference != 0 &&
            baseFileReference != expectedBaseFileReference)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS MFT logical read: base-reference mismatch segment={segmentNumber}, " +
                $"expected={expectedBaseFileReference}, actual={baseFileReference}.");
            return null;
        }

        return record;
    }

    private static byte[]? ReadRecord(
        SafeFileHandle volumeHandle,
        NtfsVolumeInfo volumeInfo,
        ulong segmentNumber,
        ushort expectedSequenceNumber,
        ulong expectedBaseFileReference)
    {
        var relativeOffset = checked(
            checked((long)segmentNumber) * volumeInfo.BytesPerFileRecordSegment);

        if (relativeOffset < 0 ||
            relativeOffset + volumeInfo.BytesPerFileRecordSegment > volumeInfo.MftValidDataLength)
        {
            return null;
        }

        var mftStartOffset = checked(
            volumeInfo.MftStartLcn * (long)volumeInfo.BytesPerCluster);

        var record = new byte[checked((int)volumeInfo.BytesPerFileRecordSegment)];
        ReadRawExact(
            volumeHandle,
            checked(mftStartOffset + relativeOffset),
            record);

        if (record.Length < 48 ||
            record[0] != (byte)'F' ||
            record[1] != (byte)'I' ||
            record[2] != (byte)'L' ||
            record[3] != (byte)'E')
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS ReadRecord: invalid FILE signature for segment={segmentNumber}.");
            return null;
        }

        ApplyUpdateSequenceFixups(record, checked((int)volumeInfo.BytesPerSector));

        var sequenceNumber = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(16, 2));
        var flags = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(22, 2));

        if (expectedSequenceNumber != 0 && sequenceNumber != expectedSequenceNumber)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS ReadRecord: sequence mismatch segment={segmentNumber}, " +
                $"expected={expectedSequenceNumber}, actual={sequenceNumber}.");
            return null;
        }

        if ((flags & 0x0001) != 0)
        {
            // A freshly deleted file can briefly remain marked IN_USE while the
            // final close/delete bookkeeping completes. The USN file reference
            // that reached this reader is already tied to the deletion event, so
            // keep the record and inspect its $DATA rather than rejecting it
            // before the attribute parser gets a chance to recover the stream.
            System.Diagnostics.Debug.WriteLine(
                $"NTFS ReadRecord: deleted reference is still marked IN_USE; " +
                $"continuing because the exact USN file reference was supplied. " +
                $"flags=0x{flags:X4}, segment={segmentNumber}.");
        }

        var baseFileReference = BinaryPrimitives.ReadUInt64LittleEndian(record.AsSpan(32, 8));
        if (baseFileReference != 0 && baseFileReference != expectedBaseFileReference)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS ReadRecord: base reference mismatch segment={segmentNumber}, " +
                $"baseRef={baseFileReference}, expected={expectedBaseFileReference}.");
            return null;
        }

        System.Diagnostics.Debug.WriteLine(
            $"NTFS ReadRecord: valid deleted record segment={segmentNumber}, " +
            $"sequence={sequenceNumber}, flags=0x{flags:X4}, baseRef={baseFileReference}.");

        return record;
    }

    private static NtfsDataStreamInfo NotFound(string evidence) =>
        new()
        {
            Found = false,
            Evidence = evidence
        };

    internal static void ApplyUpdateSequenceFixups(Span<byte> record, int bytesPerSector)
    {
        if (bytesPerSector <= 0 || record.Length < 48)
        {
            throw new InvalidDataException("Invalid NTFS sector geometry.");
        }

        var usaOffset = BinaryPrimitives.ReadUInt16LittleEndian(record.Slice(4, 2));
        var usaCount = BinaryPrimitives.ReadUInt16LittleEndian(record.Slice(6, 2));

        if (usaOffset == 0 ||
            usaCount < 2 ||
            usaOffset + usaCount * 2 > record.Length)
        {
            throw new InvalidDataException("The NTFS update-sequence array is invalid.");
        }

        var sequence = BinaryPrimitives.ReadUInt16LittleEndian(record.Slice(usaOffset, 2));

        for (var i = 1; i < usaCount; i++)
        {
            var endOffset = checked(i * bytesPerSector - 2);
            if (endOffset + 2 > record.Length)
            {
                throw new InvalidDataException("The NTFS update-sequence replacement is outside the record.");
            }

            var onDisk = BinaryPrimitives.ReadUInt16LittleEndian(record.Slice(endOffset, 2));
            if (onDisk != sequence)
            {
                throw new InvalidDataException("The NTFS update-sequence check failed.");
            }

            var replacement = BinaryPrimitives.ReadUInt16LittleEndian(
                record.Slice(usaOffset + i * 2, 2));

            BinaryPrimitives.WriteUInt16LittleEndian(record.Slice(endOffset, 2), replacement);
        }
    }

    private static void ReadRawExact(
        SafeFileHandle volumeHandle,
        long fileOffset,
        byte[] buffer)
    {
        using var completionEvent = new ManualResetEvent(initialState: false);

        var overlapped = new NativeOverlapped
        {
            OffsetLow = unchecked((int)(fileOffset & 0xFFFFFFFF)),
            OffsetHigh = unchecked((int)(fileOffset >> 32)),
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
                    volumeHandle,
                    bufferHandle.AddrOfPinnedObject(),
                    checked((uint)buffer.Length),
                    IntPtr.Zero,
                    overlappedPtr);

                if (!started)
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != ErrorIoPending)
                    {
                        throw new Win32Exception(
                            error,
                            $"Raw NTFS MFT read failed at offset {fileOffset:N0}.");
                    }
                }

                completionEvent.WaitOne();

                if (!GetOverlappedResult(
                        volumeHandle,
                        overlappedPtr,
                        out var bytesRead,
                        bWait: false))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        $"Raw NTFS MFT read completion failed at offset {fileOffset:N0}.");
                }

                if (bytesRead != (uint)buffer.Length)
                {
                    throw new IOException(
                        $"Raw NTFS MFT read returned {bytesRead:N0} bytes; expected {buffer.Length:N0}.");
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

    // FSCTL_GET_NTFS_FILE_RECORD is intentionally not used for deleted-file
    // recovery. It ignores the sequence-number portion of a file reference and
    // returns an in-use record at or below the requested MFT index. The physical
    // MFT mapping above is required when the target record itself is deleted.

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile,
        out ByHandleFileInformation lpFileInformation);

    private static SafeFileHandle CreateVolumeHandle(
        string root,
        bool overlapped)
    {
        var volumeName = root.TrimEnd(Path.DirectorySeparatorChar);
        var flags = FileFlagBackupSemantics |
                    (overlapped ? FileFlagOverlapped : 0);

        var handle = CreateFile(
            $@"\\.\{volumeName[..2]}",
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();

            throw new Win32Exception(
                error,
                $"Could not open NTFS volume {root} for raw MFT access.");
        }

        return handle;
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

    private static void ReadAt(SafeFileHandle handle, long offset, byte[] buffer)
    {
        if (!SetFilePointerEx(handle, offset, out _, 0))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not seek to the requested NTFS MFT record.");
        }

        if (!ReadFile(
                handle,
                buffer,
                (uint)buffer.Length,
                out var bytesRead,
                IntPtr.Zero) ||
            bytesRead != (uint)buffer.Length)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "Could not read the NTFS MFT record.");
        }
    }

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
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        IntPtr lpBuffer,
        uint nNumberOfBytesToRead,
        IntPtr lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetOverlappedResult(
        SafeFileHandle hFile,
        IntPtr lpOverlapped,
        out uint lpNumberOfBytesTransferred,
        [MarshalAs(UnmanagedType.Bool)] bool bWait);

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
    private static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);
}