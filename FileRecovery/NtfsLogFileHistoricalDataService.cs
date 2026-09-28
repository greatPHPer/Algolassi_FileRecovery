using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class NtfsLogFileHistoricalDataService
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const int ErrorIoPending = 997;

    private const ushort OpenNonresidentAttribute = 0x001C;
    private const ushort UpdateResidentValue = 0x0007;
    private const ushort UpdateMappingPairs = 0x0009;
    private const uint NtfsAttributeTypeData = 0x00000080;
    private const uint LfsClientRecord = 0x0001;
    private const int RecordHeaderMinimumLength = 48;
    private const long MaxLogBytesToRead = 128L * 1024L * 1024L;

    public bool TryRecoverFileData(
        string rootPath,
        ulong fileReferenceNumber,
        string expectedFileName,
        long fileSizeBytes,
        long maxCaptureBytes,
        out byte[] data,
        out string evidence)
    {
        data = [];
        evidence = string.Empty;

        if (string.IsNullOrWhiteSpace(rootPath) ||
            fileReferenceNumber == 0 ||
            string.IsNullOrWhiteSpace(expectedFileName) ||
            fileSizeBytes <= 0 ||
            fileSizeBytes > maxCaptureBytes ||
            fileSizeBytes > int.MaxValue)
        {
            evidence = "The historical $LogFile recovery arguments are outside the supported range.";
            return false;
        }

        var normalizedRoot = GetNtfsVolumeRoot(rootPath);
        if (string.IsNullOrWhiteSpace(normalizedRoot))
        {
            evidence = "The source path is not on a valid NTFS volume.";
            return false;
        }

        try
        {
            WindowsPrivilege.EnableSeBackupPrivilege();

            var volumeInfo = new NtfsVolumeInspector().Inspect(normalizedRoot);

            using var metadataHandle = CreateVolumeHandle(
                normalizedRoot,
                overlapped: false);

            using var rawHandle = CreateVolumeHandle(
                normalizedRoot,
                overlapped: true);

            var reader = new NtfsMftDataReader();
            var logStream = reader.ReadMetadataFileDataStream(
                volumeInfo,
                metadataHandle,
                2);

            if (!logStream.Found ||
                logStream.IsResident ||
                logStream.Extents.Count == 0 ||
                logStream.FileSizeBytes <= 0)
            {
                evidence = "NTFS $LogFile did not expose a usable nonresident $DATA stream.";
                return false;
            }

            var logicalLength = Math.Min(
                logStream.FileSizeBytes,
                MaxLogBytesToRead);

            var logData = ReadMappedLogicalFile(
                rawHandle,
                volumeInfo.BytesPerCluster,
                logStream.Extents,
                logicalLength);

            if (!TryReadGeometry(
                    logData,
                    volumeInfo.BytesPerSector,
                    out var geometry,
                    out var geometryEvidence))
            {
                evidence = geometryEvidence;
                return false;
            }

            ApplyFastPages(
                logData,
                geometry,
                volumeInfo.BytesPerSector);

            var records = ParseRecords(
                logData,
                geometry,
                volumeInfo.BytesPerSector);

            // Small plain-text files normally keep their $DATA value resident
            // inside the MFT record. UpdateMappingPairs only covers nonresident
            // data, so try the exact historical UpdateResidentValue records first.
            if (TryRecoverResidentFileData(
                    records,
                    fileReferenceNumber,
                    fileSizeBytes,
                    volumeInfo.BytesPerCluster,
                    volumeInfo.BytesPerFileRecordSegment,
                    out data,
                    out var residentEvidence))
            {
                evidence = residentEvidence;
                return true;
            }

            var mappingCandidates =
                FindTargetMappingCandidates(
                    records,
                    fileReferenceNumber,
                    volumeInfo.BytesPerCluster,
                    volumeInfo.BytesPerFileRecordSegment);

            if (mappingCandidates.Count == 0)
            {
                evidence =
                    $"No $LogFile UpdateMappingPairs record could be tied to exact " +
                    $"file reference {fileReferenceNumber} for '{expectedFileName}'.";
                return false;
            }

            var requiredClusters = checked(
                (fileSizeBytes + volumeInfo.BytesPerCluster - 1) /
                volumeInfo.BytesPerCluster);

            foreach (var candidate in mappingCandidates.OrderByDescending(
                         item => item.Lsn))
            {
                if (!TryBuildCompleteChain(
                        candidate.Extents,
                        requiredClusters,
                        out var extents,
                        out var chainEvidence))
                {
                    continue;
                }

                var recovered = new byte[checked((int)fileSizeBytes)];
                var remaining = fileSizeBytes;
                var destinationOffset = 0;
                var expectedVcn = 0L;

                try
                {
                    foreach (var extent in extents)
                    {
                        if (extent.VirtualClusterNumber != expectedVcn)
                        {
                            throw new InvalidDataException(
                                $"Historical $LogFile extent chain has a VCN gap at {expectedVcn:N0}.");
                        }

                        var extentBytes = checked(
                            extent.ClusterCount *
                            (long)volumeInfo.BytesPerCluster);

                        var bytesToRead = Math.Min(
                            extentBytes,
                            remaining);

                        if (bytesToRead > 0)
                        {
                            if (extent.LogicalClusterNumber < 0)
                            {
                                Array.Clear(
                                    recovered,
                                    destinationOffset,
                                    checked((int)bytesToRead));
                            }
                            else
                            {
                                ReadRawExact(
                                    rawHandle,
                                    checked(
                                        extent.LogicalClusterNumber *
                                        (long)volumeInfo.BytesPerCluster),
                                    recovered,
                                    destinationOffset,
                                    checked((int)bytesToRead));
                            }

                            destinationOffset = checked(
                                destinationOffset + (int)bytesToRead);
                            remaining -= bytesToRead;
                        }

                        expectedVcn = checked(
                            expectedVcn + extent.ClusterCount);

                        if (remaining == 0)
                        {
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS $LogFile historical cluster read failed: " +
                        $"{ex.GetType().Name}: {ex.Message}");
                    continue;
                }

                if (remaining != 0)
                {
                    continue;
                }

                data = recovered;

                evidence =
                    $"Recovered {data.LongLength:N0} byte(s) from exact NTFS $LogFile " +
                    $"file-reference mapping. {chainEvidence}";

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS $LogFile historical data recovery succeeded: " +
                    $"fileRef={fileReferenceNumber}, name={expectedFileName}, " +
                    $"size={data.LongLength:N0}, lsn=0x{candidate.Lsn:X16}.");

                return true;
            }

            evidence =
                $"$LogFile mapping records existed for '{expectedFileName}', but none " +
                "formed a complete VCN-0 cluster chain for the historical file size.";
            return false;
        }
        catch (Exception ex)
        {
            evidence =
                $"NTFS $LogFile historical data recovery failed: " +
                $"{ex.GetType().Name}: {ex.Message}";

            System.Diagnostics.Debug.WriteLine(
                evidence);

            return false;
        }
    }

    private static bool TryRecoverResidentFileData(
        IReadOnlyList<ParsedLogRecord> records,
        ulong targetFileReference,
        long fileSizeBytes,
        uint bytesPerCluster,
        uint bytesPerFileRecordSegment,
        out byte[] data,
        out string evidence)
    {
        data = [];
        evidence = string.Empty;

        var targetSegment =
            targetFileReference &
            0x0000FFFFFFFFFFFFUL;

        var targetSequence =
            checked((ushort)(targetFileReference >> 48));

        var definitions =
            FindResidentDataDefinitions(
                records,
                targetSegment,
                targetSequence,
                fileSizeBytes,
                bytesPerCluster,
                bytesPerFileRecordSegment);

        var definitionSummary =
            definitions.Count == 0
                ? "none"
                : string.Join(
                    ", ",
                    definitions.Select(
                        item =>
                            $"offset=0x{item.DataOffset:X}, size={item.InitialValue.Length:N0}"));

        var residentUpdates =
            records
                .Where(record =>
                    CalculateTargetMftSegment(
                        record,
                        bytesPerCluster,
                        bytesPerFileRecordSegment) == targetSegment &&
                    (record.RedoOperation == UpdateResidentValue ||
                     record.UndoOperation == UpdateResidentValue))
                .OrderBy(record => record.Lsn)
                .ThenBy(record => record.PhysicalOrder)
                .ToList();

        System.Diagnostics.Debug.WriteLine(
            $"NTFS $LogFile resident data scan: " +
            $"targetSegment={targetSegment:N0}, " +
            $"targetSequence={targetSequence}, " +
            $"dataDefinitions={definitions.Count:N0} [{definitionSummary}], " +
            $"UpdateResidentValueRecords={residentUpdates.Count:N0}, " +
            $"targetSize={fileSizeBytes:N0}.");

        if (definitions.Count == 0)
        {
            evidence =
                $"Exact historical MFT segment {targetSegment:N0} / sequence " +
                $"{targetSequence} had {definitions.Count:N0} unnamed resident " +
                $"$DATA definition(s) and {residentUpdates.Count:N0} UpdateResidentValue record(s).";
            return false;
        }

        foreach (var definition in definitions
                     .OrderBy(item => item.DataOffset))
        {
            var updates =
                residentUpdates
                    .Where(record =>
                        record.Lsn > definition.GenerationStartLsn &&
                        (!definition.GenerationEndLsnExclusive.HasValue ||
                         record.Lsn < definition.GenerationEndLsnExclusive.Value))
                    .ToList();

            var recovered = new byte[checked((int)fileSizeBytes)];
            var covered = new bool[recovered.Length];

            var initialLength =
                Math.Min(
                    definition.InitialValue.Length,
                    recovered.Length);

            if (initialLength > 0)
            {
                Buffer.BlockCopy(
                    definition.InitialValue,
                    0,
                    recovered,
                    0,
                    initialLength);

                Array.Fill(
                    covered,
                    true,
                    0,
                    initialLength);
            }

            foreach (var record in updates)
            {
                var patch =
                    record.RedoOperation == UpdateResidentValue
                        ? record.RedoData
                        : record.UndoData;

                if (patch.Length == 0)
                {
                    continue;
                }

                var targetOffset =
                    checked(
                        record.RecordOffset +
                        record.AttributeOffset);

                var relativeOffset =
                    targetOffset -
                    definition.DataOffset;

                if (relativeOffset < 0 ||
                    relativeOffset >= recovered.Length)
                {
                    continue;
                }

                var bytesToCopy =
                    Math.Min(
                        (long)patch.Length,
                        recovered.Length -
                        relativeOffset);

                if (bytesToCopy <= 0)
                {
                    continue;
                }

                Buffer.BlockCopy(
                    patch,
                    0,
                    recovered,
                    checked((int)relativeOffset),
                    checked((int)bytesToCopy));

                Array.Fill(
                    covered,
                    true,
                    checked((int)relativeOffset),
                    checked((int)bytesToCopy));
            }

            if (!covered.All(value => value))
            {
                continue;
            }

            data = recovered;

            evidence =
                $"Recovered {data.LongLength:N0} byte(s) from exact NTFS " +
                $"$LogFile resident $DATA history at MFT segment " +
                $"{targetSegment:N0}, sequence {targetSequence}. " +
                $"The resident $DATA attribute was tied to the same exact " +
                $"deleted MFT generation and reconstructed from " +
                $"{updates.Count:N0} UpdateResidentValue record(s) " +
                $"within that exact generation.";

            System.Diagnostics.Debug.WriteLine(
                $"NTFS $LogFile resident historical data recovery succeeded: " +
                $"fileRef={targetFileReference}, " +
                $"segment={targetSegment:N0}, " +
                $"sequence={targetSequence}, " +
                $"size={data.LongLength:N0}, " +
                $"updates={updates.Count:N0}.");

            return true;
        }

        evidence =
            $"Exact NTFS $LogFile resident $DATA definition(s) were found for " +
            $"MFT segment {targetSegment:N0}, sequence {targetSequence}, but " +
            $"the retained resident updates did not cover all {fileSizeBytes:N0} byte(s).";
        return false;
    }

    private static List<ResidentDataDefinition> FindResidentDataDefinitions(
        IReadOnlyList<ParsedLogRecord> records,
        ulong targetSegment,
        ushort targetSequence,
        long expectedSize,
        uint bytesPerCluster,
        uint bytesPerFileRecordSegment)
    {
        var initializations =
            records
                .Where(record =>
                    record.RedoOperation == 0x0002 &&
                    CalculateTargetMftSegment(
                        record,
                        bytesPerCluster,
                        bytesPerFileRecordSegment) == targetSegment)
                .OrderBy(record => record.Lsn)
                .ThenBy(record => record.PhysicalOrder)
                .ToList();

        var definitions =
            new List<ResidentDataDefinition>();

        for (var i = 0; i < initializations.Count; i++)
        {
            var record = initializations[i];

            if (!TryFindUnnamedResidentDataAttributes(
                    record.RedoData,
                    targetSequence,
                    expectedSize,
                    out var initialized))
            {
                continue;
            }

            ulong? nextGenerationLsn = null;

            for (var j = i + 1; j < initializations.Count; j++)
            {
                if (initializations[j].Lsn > record.Lsn)
                {
                    nextGenerationLsn = initializations[j].Lsn;
                    break;
                }
            }

            foreach (var item in initialized)
            {
                definitions.Add(
                    item with
                    {
                        GenerationStartLsn = record.Lsn,
                        GenerationEndLsnExclusive = nextGenerationLsn
                    });
            }
        }

        return definitions;
    }

    private static bool TryFindUnnamedResidentDataAttributes(
        byte[] recordData,
        ushort expectedSequence,
        long expectedSize,
        out List<ResidentDataDefinition> definitions)
    {
        definitions = [];

        if (recordData.Length < 24 ||
            recordData[0] != (byte)'F' ||
            recordData[1] != (byte)'I' ||
            recordData[2] != (byte)'L' ||
            recordData[3] != (byte)'E' ||
            BinaryPrimitives.ReadUInt16LittleEndian(
                recordData.AsSpan(16, 2)) != expectedSequence)
        {
            return false;
        }

        var attributesOffset =
            BinaryPrimitives.ReadUInt16LittleEndian(
                recordData.AsSpan(20, 2));

        if (attributesOffset < 24 ||
            attributesOffset >= recordData.Length)
        {
            return false;
        }

        var cursor = checked((int)attributesOffset);

        while (cursor + 16 <= recordData.Length)
        {
            var type =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    recordData.AsSpan(cursor, 4));

            if (type == 0xFFFFFFFF)
            {
                break;
            }

            var length =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    recordData.AsSpan(cursor + 4, 4));

            if (length < 24 ||
                cursor + length > recordData.Length)
            {
                break;
            }

            var nonResident =
                recordData[cursor + 8] != 0;

            var nameLength =
                recordData[cursor + 9];

            if (type == NtfsAttributeTypeData &&
                !nonResident &&
                nameLength == 0)
            {
                var valueLength =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        recordData.AsSpan(cursor + 16, 4));

                var valueOffset =
                    BinaryPrimitives.ReadUInt16LittleEndian(
                        recordData.AsSpan(cursor + 18, 2));

                if (valueOffset >= 24 &&
                    valueOffset + valueLength <= length)
                {
                    var boundedLength =
                        Math.Min(
                            (long)valueLength,
                            Math.Max(
                                0,
                                Math.Min(
                                    (long)recordData.Length -
                                    cursor -
                                    valueOffset,
                                    expectedSize)));

                    definitions.Add(
                        new ResidentDataDefinition(
                            checked((long)cursor + valueOffset),
                            boundedLength == 0
                                ? []
                                : recordData
                                    .AsSpan(
                                        checked(cursor + valueOffset),
                                        checked((int)boundedLength))
                                    .ToArray()));
                }
            }

            cursor += checked((int)length);
        }

        return definitions.Count > 0;
    }

    private static List<MappingCandidate> FindTargetMappingCandidates(
        IReadOnlyList<ParsedLogRecord> records,
        ulong targetFileReference,
        uint bytesPerCluster,
        uint bytesPerFileRecordSegment)
    {
        var targetSegment =
            targetFileReference &
            0x0000FFFFFFFFFFFFUL;

        var openAttributes =
            new Dictionary<ushort, OpenAttributeState>();

        var candidates = new List<MappingCandidate>();

        foreach (var record in records
                     .OrderBy(item => item.Lsn)
                     .ThenBy(item => item.PhysicalOrder))
        {
            if (record.RedoOperation == OpenNonresidentAttribute)
            {
                if (TryReadOpenAttributeFileReference(
                        record.RedoData,
                        out var fileReference))
                {
                    openAttributes[record.TargetAttribute] =
                        new OpenAttributeState(
                            fileReference,
                            DecodeUnicodeString(record.UndoData));
                }

                continue;
            }

            if (record.RedoOperation != UpdateMappingPairs &&
                record.UndoOperation != UpdateMappingPairs)
            {
                continue;
            }

            var mappingBytes =
                record.RedoOperation == UpdateMappingPairs
                    ? record.RedoData
                    : record.UndoData;

            if (mappingBytes.Length == 0)
            {
                continue;
            }

            // UpdateMappingPairs can update the resident $MFT record containing
            // the nonresident attribute's runlist. In that form, the target VCN
            // and cluster-block offset identify the exact MFT segment being
            // modified. This is the strongest identity link for a reused deleted
            // file segment.
            var targetSegmentForRecord =
                CalculateTargetMftSegment(
                    record,
                    bytesPerCluster,
                    bytesPerFileRecordSegment);

            var exactMftTarget =
                targetSegmentForRecord.HasValue &&
                targetSegmentForRecord.Value == targetSegment;

            var exactOpenAttributeTarget =
                openAttributes.TryGetValue(
                    record.TargetAttribute,
                    out var openAttribute) &&
                openAttribute.FileReference == targetFileReference &&
                string.IsNullOrWhiteSpace(openAttribute.AttributeName);

            if (!exactMftTarget &&
                !exactOpenAttributeTarget)
            {
                continue;
            }

            try
            {
                var extents =
                    NtfsMappingPairsParser.Parse(
                        mappingBytes,
                        startingVcn: 0);

                if (extents.Count == 0)
                {
                    continue;
                }

                candidates.Add(
                    new MappingCandidate(
                        record.Lsn,
                        record.TargetAttribute,
                        exactMftTarget
                            ? "MFT-segment"
                            : "open-attribute",
                        extents));
            }
            catch
            {
                // Keep searching later exact-file mapping updates.
            }
        }

        return candidates;
    }

    private static ulong? CalculateTargetMftSegment(
        ParsedLogRecord record,
        uint bytesPerCluster,
        uint bytesPerFileRecordSegment)
    {
        if (record.TargetVcn < 0 ||
            bytesPerCluster == 0 ||
            bytesPerFileRecordSegment == 0)
        {
            return null;
        }

        var targetOffset =
            checked(
                record.TargetVcn *
                (long)bytesPerCluster +
                record.ClusterBlockOffset * 512L);

        var recordSize =
            record.TargetBlockSize > 0
                ? checked(record.TargetBlockSize * 512L)
                : bytesPerFileRecordSegment;

        if (recordSize <= 0)
        {
            return null;
        }

        return checked(
            (ulong)(targetOffset / recordSize));
    }

    private static bool TryBuildCompleteChain(
        IReadOnlyList<NtfsDataExtent> source,
        long requiredClusters,
        out List<NtfsDataExtent> result,
        out string evidence)
    {
        result = [];
        evidence = string.Empty;

        if (source.Count == 0 ||
            requiredClusters <= 0)
        {
            return false;
        }

        var expectedVcn = 0L;
        var coveredClusters = 0L;

        foreach (var extent in source.OrderBy(
                     item => item.VirtualClusterNumber))
        {
            if (extent.VirtualClusterNumber != expectedVcn ||
                extent.ClusterCount <= 0)
            {
                return false;
            }

            result.Add(extent);

            coveredClusters = checked(
                coveredClusters + extent.ClusterCount);

            expectedVcn = checked(
                expectedVcn + extent.ClusterCount);

            if (coveredClusters >= requiredClusters)
            {
                evidence =
                    $"Validated {result.Count:N0} historical $DATA extent(s) " +
                    $"covering {coveredClusters:N0} cluster(s).";
                return true;
            }
        }

        return false;
    }

    private static List<ParsedLogRecord> ParseRecords(
        byte[] logData,
        LogGeometry geometry,
        uint bytesPerSector)
    {
        var result = new List<ParsedLogRecord>();
        var pageCount = logData.Length / geometry.LogPageSize;
        var physicalOrder = 0L;

        for (var pageIndex = geometry.WrappedStartPage;
             pageIndex < pageCount;
             pageIndex++)
        {
            var pageStart = checked(
                pageIndex * geometry.LogPageSize);

            var page = logData
                .AsSpan(
                    pageStart,
                    geometry.LogPageSize)
                .ToArray();

            if (!TryApplyLogPageFixups(
                    page,
                    checked((int)bytesPerSector)) ||
                EncodingAscii(page, 0, 4) != "RCRD")
            {
                continue;
            }

            var nextRecordOffset =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    page.AsSpan(24, 2));

            if (nextRecordOffset <= geometry.LogPageDataOffset ||
                nextRecordOffset > page.Length)
            {
                nextRecordOffset =
                    checked((ushort)page.Length);
            }

            var recordOffset =
                geometry.LogPageDataOffset;

            while (recordOffset +
                       geometry.RecordHeaderLength <=
                   nextRecordOffset)
            {
                var clientDataLength =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        page.AsSpan(recordOffset + 24, 4));

                if (clientDataLength < 32 ||
                    clientDataLength >
                    (uint)(
                        nextRecordOffset -
                        recordOffset -
                        geometry.RecordHeaderLength))
                {
                    break;
                }

                var alignedLength =
                    Align8(
                        geometry.RecordHeaderLength +
                        checked((int)clientDataLength));

                if (alignedLength <= 0 ||
                    recordOffset + alignedLength >
                    nextRecordOffset)
                {
                    break;
                }

                var clientStart =
                    checked(
                        recordOffset +
                        geometry.RecordHeaderLength);

                var clientEnd =
                    checked(
                        clientStart +
                        (int)clientDataLength);

                if (clientEnd > page.Length)
                {
                    break;
                }

                var recordType =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        page.AsSpan(recordOffset + 32, 4));

                if (recordType == LfsClientRecord)
                {
                    var clientData =
                        page.AsSpan(
                                clientStart,
                                (int)clientDataLength)
                            .ToArray();

                    var thisLsn =
                        BinaryPrimitives.ReadUInt64LittleEndian(
                            page.AsSpan(recordOffset, 8));

                    var redoOperation =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            clientData.AsSpan(0, 2));

                    var undoOperation =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            clientData.AsSpan(2, 2));

                    var targetAttribute =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            clientData.AsSpan(12, 2));

                    var targetRecordOffset =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            clientData.AsSpan(16, 2));

                    var attributeOffset =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            clientData.AsSpan(18, 2));

                    var targetVcn =
                        BinaryPrimitives.ReadInt64LittleEndian(
                            clientData.AsSpan(24, 8));

                    var clusterBlockOffset =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            clientData.AsSpan(20, 2));

                    var targetBlockSize =
                        BinaryPrimitives.ReadUInt16LittleEndian(
                            clientData.AsSpan(22, 2));

                    result.Add(
                        new ParsedLogRecord(
                            thisLsn,
                            physicalOrder++,
                            redoOperation,
                            undoOperation,
                            targetAttribute,
                            targetRecordOffset,
                            attributeOffset,
                            targetVcn,
                            clusterBlockOffset,
                            targetBlockSize,
                            ReadLogData(
                                clientData,
                                4,
                                6),
                            ReadLogData(
                                clientData,
                                8,
                                10)));
                }

                recordOffset += alignedLength;
            }
        }

        return result;
    }

    private static byte[] ReadLogData(
        byte[] clientData,
        int offsetField,
        int lengthField)
    {
        var offset =
            BinaryPrimitives.ReadUInt16LittleEndian(
                clientData.AsSpan(offsetField, 2));

        var length =
            BinaryPrimitives.ReadUInt16LittleEndian(
                clientData.AsSpan(lengthField, 2));

        if (length == 0 ||
            offset < 32 ||
            offset + length > clientData.Length)
        {
            return [];
        }

        return clientData
            .AsSpan(offset, length)
            .ToArray();
    }

    private static bool TryReadOpenAttributeFileReference(
        byte[] redoData,
        out ulong fileReference)
    {
        fileReference = 0;

        if (redoData.Length >= 24)
        {
            var v1Reference =
                BinaryPrimitives.ReadUInt64LittleEndian(
                    redoData.AsSpan(16, 8));

            if (v1Reference != 0)
            {
                fileReference = v1Reference;
                return true;
            }
        }

        if (redoData.Length >= 16)
        {
            var v0Reference =
                BinaryPrimitives.ReadUInt64LittleEndian(
                    redoData.AsSpan(8, 8));

            if (v0Reference != 0)
            {
                fileReference = v0Reference;
                return true;
            }
        }

        return false;
    }

    private static string DecodeUnicodeString(
        byte[] bytes) =>
        bytes.Length == 0
            ? string.Empty
            : System.Text.Encoding.Unicode
                .GetString(bytes)
                .TrimEnd('\0');

    private static bool TryReadGeometry(
        byte[] logData,
        uint bytesPerSector,
        out LogGeometry geometry,
        out string evidence)
    {
        geometry = default;
        evidence = string.Empty;

        for (var pageIndex = 0; pageIndex < 2; pageIndex++)
        {
            var pageOffset =
                checked(pageIndex * 4096);

            if (pageOffset + 4096 > logData.Length)
            {
                break;
            }

            var page =
                logData.AsSpan(
                    pageOffset,
                    4096)
                .ToArray();

            if (!TryApplyLogPageFixups(
                    page,
                    checked((int)bytesPerSector)) ||
                EncodingAscii(page, 0, 4) != "RSTR")
            {
                continue;
            }

            var systemPageSize =
                checked(
                    (int)BinaryPrimitives.ReadUInt32LittleEndian(
                        page.AsSpan(16, 4)));

            var logPageSize =
                checked(
                    (int)BinaryPrimitives.ReadUInt32LittleEndian(
                        page.AsSpan(20, 4)));

            var restartOffset =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    page.AsSpan(24, 2));

            var majorVersion =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    page.AsSpan(28, 2));

            if (systemPageSize <= 0 ||
                logPageSize < 1024 ||
                logPageSize > 1024 * 1024 ||
                restartOffset + 0x28 > page.Length)
            {
                continue;
            }

            var sequenceBits =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    page.AsSpan(restartOffset + 0x10, 4));

            var recordHeaderLength =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    page.AsSpan(restartOffset + 0x24, 2));

            var logPageDataOffset =
                BinaryPrimitives.ReadUInt16LittleEndian(
                    page.AsSpan(restartOffset + 0x26, 2));

            if (sequenceBits < 3 ||
                sequenceBits >= 64 ||
                recordHeaderLength < RecordHeaderMinimumLength ||
                logPageDataOffset < recordHeaderLength ||
                logPageDataOffset >= logPageSize)
            {
                continue;
            }

            geometry = new LogGeometry(
                systemPageSize,
                logPageSize,
                majorVersion >= 2 ? 34 : 4,
                recordHeaderLength,
                logPageDataOffset);

            evidence =
                $"$LogFile geometry version={majorVersion}, " +
                $"pageSize={logPageSize}, " +
                $"recordHeaderLength={recordHeaderLength}, " +
                $"dataOffset={logPageDataOffset}.";
            return true;
        }

        evidence = "Could not determine valid NTFS $LogFile geometry.";
        return false;
    }

    private static void ApplyFastPages(
        byte[] logData,
        LogGeometry geometry,
        uint bytesPerSector)
    {
        if (geometry.WrappedStartPage != 34)
        {
            return;
        }

        for (var pageIndex = 2; pageIndex < 34; pageIndex++)
        {
            var sourceOffset =
                checked(pageIndex * geometry.LogPageSize);

            if (sourceOffset + geometry.LogPageSize >
                logData.Length)
            {
                break;
            }

            var page =
                logData.AsSpan(
                        sourceOffset,
                        geometry.LogPageSize)
                    .ToArray();

            if (!TryApplyLogPageFixups(
                    page,
                    checked((int)bytesPerSector)) ||
                EncodingAscii(page, 0, 4) != "RCRD" ||
                page.Length < 64)
            {
                continue;
            }

            var targetOffset =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    page.AsSpan(60, 4));

            if (targetOffset <
                    (uint)(geometry.WrappedStartPage *
                        geometry.LogPageSize) ||
                targetOffset +
                    (uint)geometry.LogPageSize >
                    (uint)logData.Length ||
                targetOffset %
                    (uint)geometry.LogPageSize != 0)
            {
                continue;
            }

            Buffer.BlockCopy(
                page,
                0,
                logData,
                checked((int)targetOffset),
                geometry.LogPageSize);
        }
    }

    private static bool TryApplyLogPageFixups(
        byte[] page,
        int bytesPerSector)
    {
        if (page.Length == 0 ||
            bytesPerSector <= 0 ||
            page.Length % bytesPerSector != 0)
        {
            return false;
        }

        var usaOffset =
            BinaryPrimitives.ReadUInt16LittleEndian(
                page.AsSpan(4, 2));

        var usaSize =
            BinaryPrimitives.ReadUInt16LittleEndian(
                page.AsSpan(6, 2));

        if (usaOffset < 8 ||
            usaSize < 2 ||
            usaOffset + usaSize * 2 >
            page.Length ||
            (usaSize - 1) *
            bytesPerSector !=
            page.Length)
        {
            return false;
        }

        var sequence =
            page.AsSpan(
                    usaOffset,
                    2)
                .ToArray();

        for (var i = 1; i < usaSize; i++)
        {
            var trailer =
                checked(
                    i * bytesPerSector - 2);

            if (!page.AsSpan(
                    trailer,
                    2)
                .SequenceEqual(sequence))
            {
                return false;
            }

            page[trailer] =
                page[usaOffset + i * 2];

            page[trailer + 1] =
                page[usaOffset + i * 2 + 1];
        }

        return true;
    }

    private static byte[] ReadMappedLogicalFile(
        SafeFileHandle volumeHandle,
        uint bytesPerCluster,
        IReadOnlyList<NtfsDataExtent> extents,
        long logicalLength)
    {
        if (logicalLength <= 0 ||
            logicalLength > int.MaxValue)
        {
            return [];
        }

        var result =
            new byte[checked((int)logicalLength)];

        var destinationOffset = 0;
        var remaining = logicalLength;

        foreach (var extent in extents.OrderBy(
                     item => item.VirtualClusterNumber))
        {
            var extentBytes =
                checked(
                    extent.ClusterCount *
                    (long)bytesPerCluster);

            var bytesToRead =
                Math.Min(
                    extentBytes,
                    remaining);

            if (bytesToRead <= 0)
            {
                break;
            }

            if (!extent.IsSparse)
            {
                ReadRawExact(
                    volumeHandle,
                    checked(
                        extent.LogicalClusterNumber *
                        (long)bytesPerCluster),
                    result,
                    destinationOffset,
                    checked((int)bytesToRead));
            }

            destinationOffset =
                checked(
                    destinationOffset +
                    (int)bytesToRead);

            remaining -= bytesToRead;

            if (remaining == 0)
            {
                break;
            }
        }

        if (remaining != 0)
        {
            throw new EndOfStreamException(
                "The retained $LogFile extents did not cover its logical size.");
        }

        return result;
    }

    private static void ReadRawExact(
        SafeFileHandle volumeHandle,
        long fileOffset,
        byte[] destination,
        int destinationOffset,
        int length)
    {
        using var completionEvent =
            new ManualResetEvent(false);

        var nativeOverlapped =
            new NativeOverlapped
            {
                OffsetLow =
                    unchecked(
                        (int)(fileOffset &
                              0xFFFFFFFF)),
                OffsetHigh =
                    unchecked(
                        (int)(fileOffset >> 32)),
                HEvent =
                    completionEvent.SafeWaitHandle
                        .DangerousGetHandle()
            };

        var overlappedPtr =
            Marshal.AllocHGlobal(
                Marshal.SizeOf<NativeOverlapped>());

        try
        {
            Marshal.StructureToPtr(
                nativeOverlapped,
                overlappedPtr,
                false);

            var handle =
                GCHandle.Alloc(
                    destination,
                    GCHandleType.Pinned);

            try
            {
                var started =
                    ReadFile(
                        volumeHandle,
                        handle.AddrOfPinnedObject() +
                        destinationOffset,
                        checked((uint)length),
                        IntPtr.Zero,
                        overlappedPtr);

                if (!started)
                {
                    var error =
                        Marshal.GetLastWin32Error();

                    if (error !=
                        ErrorIoPending)
                    {
                        throw new Win32Exception(
                            error,
                            $"Could not read NTFS volume data at byte offset {fileOffset:N0}.");
                    }
                }

                completionEvent.WaitOne();

                if (!GetOverlappedResult(
                        volumeHandle,
                        overlappedPtr,
                        out var bytesRead,
                        false) ||
                    bytesRead != (uint)length)
                {
                    throw new EndOfStreamException(
                        $"NTFS raw read returned {bytesRead:N0} byte(s) instead of {length:N0}.");
                }
            }
            finally
            {
                handle.Free();
            }
        }
        finally
        {
            Marshal.FreeHGlobal(overlappedPtr);
        }
    }

    private static SafeFileHandle CreateVolumeHandle(
        string root,
        bool overlapped)
    {
        var normalizedRoot =
            GetNtfsVolumeRoot(root)
            ?? throw new ArgumentException(
                "A valid NTFS volume root is required.",
                nameof(root));

        var volumeName =
            normalizedRoot.TrimEnd(
                Path.DirectorySeparatorChar);

        var flags =
            FileFlagBackupSemantics |
            (overlapped
                ? FileFlagOverlapped
                : 0);

        var handle =
            CreateFile(
                $@"\.{volumeName[..2]}",
                GenericRead,
                FileShareRead |
                FileShareWrite |
                FileShareDelete,
                IntPtr.Zero,
                OpenExisting,
                flags,
                IntPtr.Zero);

        if (handle.IsInvalid)
        {
            var error =
                Marshal.GetLastWin32Error();

            handle.Dispose();

            throw new Win32Exception(
                error,
                $"Could not open NTFS source volume {normalizedRoot} for historical $LogFile recovery.");
        }

        return handle;
    }

    private static string? GetNtfsVolumeRoot(
        string path)
    {
        var normalized = path.Trim();

        while (normalized.StartsWith(
                   @"\?",
                   StringComparison.Ordinal) ||
               normalized.StartsWith(
                   @"\.",
                   StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }

        return Path.GetPathRoot(normalized);
    }

    private static int Align8(int value) =>
        checked((value + 7) & ~7);

    private static string EncodingAscii(
        byte[] buffer,
        int offset,
        int length) =>
        System.Text.Encoding.ASCII.GetString(
            buffer,
            offset,
            length);

    private sealed record OpenAttributeState(
        ulong FileReference,
        string AttributeName);

    private sealed record ResidentDataDefinition(
        long DataOffset,
        byte[] InitialValue,
        ulong GenerationStartLsn = 0,
        ulong? GenerationEndLsnExclusive = null);

    private sealed record MappingCandidate(
        ulong Lsn,
        ushort TargetAttribute,
        string IdentitySource,
        IReadOnlyList<NtfsDataExtent> Extents);

    private sealed record ParsedLogRecord(
        ulong Lsn,
        long PhysicalOrder,
        ushort RedoOperation,
        ushort UndoOperation,
        ushort TargetAttribute,
        ushort RecordOffset,
        ushort AttributeOffset,
        long TargetVcn,
        ushort ClusterBlockOffset,
        ushort TargetBlockSize,
        byte[] RedoData,
        byte[] UndoData);

    private readonly record struct LogGeometry(
        int SystemPageSize,
        int LogPageSize,
        int WrappedStartPage,
        int RecordHeaderLength,
        int LogPageDataOffset);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOverlapped
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public int OffsetLow;
        public int OffsetHigh;
        public IntPtr HEvent;
    }

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool GetOverlappedResult(
        SafeFileHandle hFile,
        IntPtr lpOverlapped,
        out uint lpNumberOfBytesTransferred,
        [MarshalAs(UnmanagedType.Bool)]
        bool bWait);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        IntPtr lpBuffer,
        uint nNumberOfBytesToRead,
        IntPtr lpNumberOfBytesRead,
        IntPtr lpOverlapped);
}
