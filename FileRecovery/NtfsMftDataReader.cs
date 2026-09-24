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

            var normalizedDirectory = Path.GetFullPath(scanDirectory)
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
                ReadAt(
                    volumeHandle,
                    physicalOffset,
                    slack,
                    cancellationToken);

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

                var fileNameMatches = HasMatchingFileNameEntry(
                    volumeHandle,
                    record,
                    expectedFileName,
                    expectedParentFileReferenceNumber,
                    expectedFullPath,
                    expectedSequenceNumber: sequenceNumber);

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS fresh resident $DATA: relaxed record inspected. " +
                    $"segment={segmentNumber}, currentSequence={currentSequence}, " +
                    $"expectedSequence={sequenceNumber}, flags=0x{currentFlags:X4}, " +
                    $"baseRef={currentBaseReference}, fileNameParentMatch={fileNameMatches}.");

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

    public NtfsDataStreamInfo ReadDefaultDataStream(
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        ulong fileReferenceNumber,
        string? expectedFileName = null,
        ulong? expectedParentFileReferenceNumber = null,
        string? expectedFullPath = null)
    {
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

        if (relativeMftOffset < 0 ||
            relativeMftOffset + volumeInfo.BytesPerFileRecordSegment > volumeInfo.MftValidDataLength)
        {
            return NotFound("The deleted file's MFT segment is outside the current valid MFT range.");
        }

        System.Diagnostics.Debug.WriteLine(
            $"NTFS $DATA lookup: fileRef={fileReferenceNumber}, " +
            $"segment={segmentNumber}, sequence={sequenceNumber}, " +
            $"recordSize={volumeInfo.BytesPerFileRecordSegment}, " +
            $"mftValidLength={volumeInfo.MftValidDataLength}.");

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

        if (record is null &&
            !string.IsNullOrWhiteSpace(expectedFileName) &&
            expectedParentFileReferenceNumber.HasValue)
        {
            // A very recent deletion can race the MFT sequence bookkeeping.
            // The USN record already supplied the exact segment; retry that segment
            // without strict sequence/base checks, but only accept it when the
            // retained $FILE_NAME still identifies the expected parent/name.
            var relaxedRecord = ReadMftRecordByExtentMap(
                rawMftVolumeHandle,
                volumeInfo,
                segmentNumber,
                expectedSequenceNumber: 0,
                expectedBaseFileReference: 0);

            if (relaxedRecord is not null &&
                HasMatchingFileNameEntry(
                    rawMftVolumeHandle,
                    relaxedRecord,
                    expectedFileName,
                    expectedParentFileReferenceNumber.Value,
                    expectedFullPath,
                    expectedSequenceNumber: sequenceNumber))
            {
                System.Diagnostics.Debug.WriteLine(
                    $"NTFS $DATA lookup: accepted raw MFT record for " +
                    $"fileRef={fileReferenceNumber}, segment={segmentNumber}.");
                record = relaxedRecord;
            }
        }

        if (record is null)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS $DATA lookup: could not read the exact MFT record for fileRef={fileReferenceNumber}.");
            return NotFound("NTFS could not read and validate the exact deleted MFT record for this file reference.");
        }

        return ReadDefaultDataStreamFromMftRecord(
            volumeInfo,
            volumeHandle,
            rawMftVolumeHandle,
            fileReferenceNumber,
            record);
    }

    internal NtfsDataStreamInfo ReadDefaultDataStreamFromScannedMftRecord(
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        ulong fileReferenceNumber,
        byte[] record)
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
        using var rawMftVolumeHandle = CreateVolumeHandle(
            volumeInfo.RootPath,
            overlapped: true);

        return ReadDefaultDataStreamFromMftRecord(
            volumeInfo,
            volumeHandle,
            rawMftVolumeHandle,
            fileReferenceNumber,
            record);
    }

    private NtfsDataStreamInfo ReadDefaultDataStreamFromMftRecord(
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        SafeFileHandle rawMftVolumeHandle,
        ulong fileReferenceNumber,
        byte[] record)
    {
        var flags = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(22, 2));
        var dataAttributes = FindUnnamedDataAttributes(record, volumeInfo);

        System.Diagnostics.Debug.WriteLine(
            $"NTFS $DATA lookup: MFT record flags=0x{flags:X4}, " +
            $"unnamedDataAttributes={dataAttributes.Count}.");

        foreach (var dataAttribute in dataAttributes)
        {
            System.Diagnostics.Debug.WriteLine(
                $"NTFS $DATA attribute: resident={dataAttribute.IsResident}, " +
                $"lowestVcn={dataAttribute.LowestVcn}, fileSize={dataAttribute.FileSizeBytes}, " +
                $"validLength={dataAttribute.ValidDataLengthBytes}, extents={dataAttribute.Extents.Count}.");
        }

        var attributeList = FindAttributeList(record, volumeInfo, volumeHandle);
        if (!attributeList.Found)
        {
            return BuildDataStream(dataAttributes, 1);
        }

        if (!attributeList.IsResident && attributeList.ResidentData is null)
        {
            // The base record may still contain a complete unnamed $DATA stream.
            // Preserve that evidence instead of failing the entire candidate just
            // because an unrelated/nonresident $ATTRIBUTE_LIST could not be read.
            return dataAttributes.Count > 0
                ? BuildDataStream(dataAttributes, 1)
                : NotFound(
                    "The file retains a nonresident $ATTRIBUTE_LIST that could not be safely reconstructed.");
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
                : NotFound($"The NTFS $ATTRIBUTE_LIST could not be parsed: {ex.Message}");
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

        return BuildDataStream(dataAttributes, Math.Max(1, dataAttributes.Count));
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
                if (attribute.Length < 64)
                {
                    throw new InvalidDataException("The nonresident $ATTRIBUTE_LIST attribute is incomplete.");
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

                    var extentBytes = checked(extent.ClusterCount * volumeInfo.BytesPerCluster);
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

                    destinationOffset = checked(destinationOffset + (int)bytesToRead);
                    remaining -= bytesToRead;
                    expectedVcn = checked(expectedVcn + extent.ClusterCount);

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

            var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(
                record.AsSpan(attribute.Offset + 16, 4));
            var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                record.AsSpan(attribute.Offset + 20, 2));

            if (valueOffset + valueLength > attribute.Length)
            {
                throw new InvalidDataException("The resident $ATTRIBUTE_LIST value is outside its attribute record.");
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
            return NotFound("No unnamed $DATA attribute was retained in the base or extension MFT records.");
        }

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
                    "Could not seek to a nonresident $ATTRIBUTE_LIST data extent.");
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
                    "Could not read a nonresident $ATTRIBUTE_LIST data extent.");
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
        ushort expectedSequenceNumber = 0)
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

            if (parentReference == expectedParentFileReferenceNumber)
            {
                return true;
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
