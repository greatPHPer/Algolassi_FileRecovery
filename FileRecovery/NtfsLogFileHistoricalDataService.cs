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
    private const ushort UpdateNonresidentValue = 0x0008;
    private const ushort UpdateMappingPairs = 0x0009;
    private const ushort SetNewAttributeSizes = 0x000B;
    private const ushort DeallocateFileRecordSegment = 0x0003;
    private const ushort SetBitsInNonresidentBitmap = 0x0015;
    private const ushort ClearBitsInNonresidentBitmap = 0x0016;
    private const ushort PrepareTransaction = 0x0019;
    private const ushort CommitTransaction = 0x001A;
    private const ushort ForgetTransaction = 0x001B;
    private const uint NtfsAttributeTypeData = 0x00000080;
    private const uint LfsClientRecord = 0x0001;
    private const int RecordHeaderMinimumLength = 48;
    // Marker searches intentionally stay bounded. Targeted historical recovery
    // must read the complete retained $LogFile because the deletion transaction
    // may be anywhere in the circular journal. The known-good V10 run required
    // the full 671,088,640-byte logical $LogFile.
    private const long MaxLogBytesToRead = 128L * 1024L * 1024L;
    private const long MaxHistoricalRecoveryLogBytes = 1L * 1024L * 1024L * 1024L;

    // Only retain operations that can contribute to targeted historical recovery.
    // The marker diagnostic intentionally uses the unfiltered parser because it is
    // a generic content search. Targeted recovery must not materialize unrelated
    // transaction payloads into memory.
    // Serialize historical $LogFile recovery so the targeted diagnostic cannot
    // overlap a background journal capture in the same process.
    private static readonly SemaphoreSlim HistoricalLogFileRecoveryGate = new(1, 1);

    private static readonly HashSet<ushort> RecoveryRelevantOperations =
    [
        0x0002, // InitializeFileRecordSegment
        DeallocateFileRecordSegment,
        UpdateResidentValue,
        UpdateNonresidentValue,
        UpdateMappingPairs,
        SetNewAttributeSizes,
        SetBitsInNonresidentBitmap,
        ClearBitsInNonresidentBitmap,
        PrepareTransaction,
        CommitTransaction,
        ForgetTransaction,
        OpenNonresidentAttribute,
        0x001D // Open-attribute table dump
    ];

    public bool TryFindMarkerInHistoricalLogFile(
        string rootPath,
        string marker,
        out string evidence)
    {
        evidence = string.Empty;

        if (string.IsNullOrWhiteSpace(rootPath) ||
            string.IsNullOrWhiteSpace(marker))
        {
            evidence = "A source volume and marker are required.";
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

            var markerVariants = new[]
            {
                (
                    Encoding: "UTF-8",
                    Bytes: System.Text.Encoding.UTF8.GetBytes(marker)),
                (
                    Encoding: "UTF-16LE",
                    Bytes: System.Text.Encoding.Unicode.GetBytes(marker)),
                (
                    Encoding: "UTF-16BE",
                    Bytes: System.Text.Encoding.BigEndianUnicode.GetBytes(marker))
            };

            var rawMatches = new List<string>();
            foreach (var variant in markerVariants)
            {
                var offset = logData.AsSpan().IndexOf(variant.Bytes);
                if (offset >= 0)
                {
                    rawMatches.Add(
                        $"{variant.Encoding}@{offset:N0}");
                }
            }

            var geometryOk = TryReadGeometry(
                logData,
                volumeInfo.BytesPerSector,
                out var geometry,
                out _);

            var redoMatches = new List<string>();
            var undoMatches = new List<string>();

            if (geometryOk)
            {
                ApplyFastPages(
                    logData,
                    geometry,
                    volumeInfo.BytesPerSector);

                var records = ParseRecords(
                    logData,
                    geometry,
                    volumeInfo.BytesPerSector);

                foreach (var record in records)
                {
                    foreach (var variant in markerVariants)
                    {
                        var redoOffset = record.RedoData.AsSpan().IndexOf(variant.Bytes);
                        if (redoOffset >= 0)
                        {
                            redoMatches.Add(
                                $"encoding={variant.Encoding}, " +
                                $"lsn=0x{record.Lsn:X16}, " +
                                $"targetAttribute=0x{record.TargetAttribute:X4}, " +
                                $"targetVcn={record.TargetVcn:N0}, " +
                                $"clusterBlockOffset={record.ClusterBlockOffset}, " +
                                $"recordOffset={record.RecordOffset}, " +
                                $"redoOffset={redoOffset:N0}, " +
                                $"bytes={record.RedoData.Length:N0}");
                        }

                        var undoOffset = record.UndoData.AsSpan().IndexOf(variant.Bytes);
                        if (undoOffset >= 0)
                        {
                            undoMatches.Add(
                                $"encoding={variant.Encoding}, " +
                                $"lsn=0x{record.Lsn:X16}, " +
                                $"targetAttribute=0x{record.TargetAttribute:X4}, " +
                                $"targetVcn={record.TargetVcn:N0}, " +
                                $"clusterBlockOffset={record.ClusterBlockOffset}, " +
                                $"recordOffset={record.RecordOffset}, " +
                                $"undoOffset={undoOffset:N0}, " +
                                $"bytes={record.UndoData.Length:N0}");
                        }
                    }
                }
            }

            var found =
                rawMatches.Count > 0 ||
                redoMatches.Count > 0 ||
                undoMatches.Count > 0;

            evidence =
                $"$LogFile bytes={logData.LongLength:N0}; " +
                $"rawMarkerMatches={rawMatches.Count:N0}" +
                (rawMatches.Count > 0
                    ? $" [{string.Join("; ", rawMatches.Take(6))}]"
                    : string.Empty) +
                $"; redoMarkerMatches={redoMatches.Count:N0}" +
                (redoMatches.Count > 0
                    ? $" [{string.Join("; ", redoMatches.Take(6))}]"
                    : string.Empty) +
                $"; undoMarkerMatches={undoMatches.Count:N0}" +
                (undoMatches.Count > 0
                    ? $" [{string.Join("; ", undoMatches.Take(6))}]"
                    : string.Empty);

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile marker diagnostic: markerLength={marker.Length:N0}, " +
                $"found={found}, {evidence}");

            return found;
        }
        catch (Exception ex)
        {
            evidence =
                $"$LogFile marker diagnostic failed: " +
                $"{ex.GetType().Name}: {ex.Message}";

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile marker diagnostic exception: {evidence}");

            return false;
        }
    }

    public bool TryRecoverFileData(
        string rootPath,
        ulong fileReferenceNumber,
        string expectedFileName,
        long fileSizeBytes,
        long maxCaptureBytes,
        out byte[] data,
        out string evidence,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        data = [];
        evidence = string.Empty;

        if (string.IsNullOrWhiteSpace(rootPath) ||
            fileReferenceNumber == 0 ||
            string.IsNullOrWhiteSpace(expectedFileName) ||
            fileSizeBytes < 0 ||
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

        HistoricalLogFileRecoveryGate.Wait(cancellationToken);
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
                MaxHistoricalRecoveryLogBytes);

            progress?.Report(
                $"Reading historical NTFS $LogFile for {expectedFileName}... " +
                $"{logicalLength / (1024d * 1024d):0} MB journal data");

            var logData = ReadMappedLogicalFile(
                rawHandle,
                volumeInfo.BytesPerCluster,
                logStream.Extents,
                logicalLength,
                progress,
                cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();

            progress?.Report(
                $"Parsing historical NTFS $LogFile for {expectedFileName}...");

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
                volumeInfo.BytesPerSector,
                RecoveryRelevantOperations,
                progress,
                cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();

            // Emit a compact target-file evidence inventory before any recovery
            // decision is made. This is diagnostic only: it deliberately does not
            // relax MFT sequence validation or infer bytes from an ambiguous record.
            TraceTargetHistoricalEvidence(
                records,
                fileReferenceNumber,
                volumeInfo.BytesPerCluster,
                volumeInfo.BytesPerFileRecordSegment);

            progress?.Report(
                $"Searching historical NTFS transactions for {expectedFileName}...");

            // When the retained $FILE_NAME size is unavailable, recover the size
            // from the exact historical MFT generation in $LogFile. A retained
            // InitializeFileRecordSegment gives us the original unnamed nonresident
            // $DATA definition, while SetNewAttributeSizes records can carry the
            // later data_size after the file grew.
            if (fileSizeBytes <= 0)
            {
                if (!TryInferHistoricalFileSize(
                        records,
                        fileReferenceNumber,
                        volumeInfo.BytesPerCluster,
                        volumeInfo.BytesPerFileRecordSegment,
                        maxCaptureBytes,
                        out var inferredSize,
                        out var sizeInferenceEvidence))
                {
                    evidence =
                        $"The retained $LogFile did not expose a trusted historical " +
                        $"size for exact file reference {fileReferenceNumber} " +
                        $"('{expectedFileName}'). {sizeInferenceEvidence}";
                    return false;
                }

                fileSizeBytes = inferredSize;

                progress?.Report(
                    $"Historical size recovered for {expectedFileName}: {fileSizeBytes:N0} bytes.");

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS $LogFile historical size inferred from MFT generation: " +
                    $"fileRef={fileReferenceNumber}, " +
                    $"name={expectedFileName}, " +
                    $"size={fileSizeBytes:N0}, " +
                    $"evidence={sizeInferenceEvidence}");
            }

            if (fileSizeBytes <= 0 ||
                fileSizeBytes > maxCaptureBytes ||
                fileSizeBytes > int.MaxValue)
            {
                evidence =
                    $"The inferred historical file size {fileSizeBytes:N0} bytes " +
                    "is outside the supported $LogFile recovery range.";
                return false;
            }

            // Small plain-text files normally keep their $DATA value resident
            // inside the MFT record. UpdateMappingPairs only covers nonresident
            // data, so try the exact historical UpdateResidentValue records first.
            progress?.Report(
                $"Checking historical resident $DATA for {expectedFileName}...");

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

            // The open-attribute table can identify nonresident data updates
            // even when the file-record initialization and mapping-pair records have
            // already wrapped out of $LogFile. Reconstruct the file only when the
            // logged write ranges are tied to this exact historical file reference
            // and together cover the complete historical file size.
            progress?.Report(
                $"Checking historical nonresident data updates for {expectedFileName}...");

            if (TryRecoverFromHistoricalNonresidentValueUpdates(
                    records,
                    fileReferenceNumber,
                    fileSizeBytes,
                    volumeInfo.BytesPerCluster,
                    out data,
                    out var nonresidentValueEvidence))
            {
                evidence = nonresidentValueEvidence;
                return true;
            }

            // A nonresident file's runlist can be preserved in the
            // historical InitializeFileRecordSegment record even when the
            // $LogFile journal window contains no later UpdateMappingPairs record.
            // For reused deleted MFT segments this is still an exact identity link:
            // the FILE record sequence must match the original USN file reference.
            progress?.Report(
                $"Checking historical MFT initialization for {expectedFileName}...");

            if (TryRecoverNonresidentDataFromHistoricalMftInitialization(
                    records,
                    fileReferenceNumber,
                    fileSizeBytes,
                    volumeInfo.BytesPerCluster,
                    volumeInfo.BytesPerFileRecordSegment,
                    rawHandle,
                    out data,
                    out var historicalMftEvidence))
            {
                evidence = historicalMftEvidence;
                return true;
            }

            // Transaction-correlated bitmap clears preserve the LCN range(s)
            // released by a deletion even when the historical MFT $DATA runlist
            // is no longer present. Accept only an exact single-range match tied
            // to the same MFT deallocation transaction and still free now.
            progress?.Report(
                $"Checking historical bitmap deallocation for {expectedFileName}...");

            if (TryRecoverFromHistoricalBitmapClear(
                    records,
                    fileReferenceNumber,
                    expectedFileName,
                    fileSizeBytes,
                    volumeInfo.BytesPerCluster,
                    rawHandle,
                    metadataHandle,
                    volumeInfo,
                    out data,
                    out var bitmapEvidence))
            {
                evidence = bitmapEvidence;
                return true;
            }

            progress?.Report(
                $"Checking historical mapping pairs for {expectedFileName}...");

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
                    System.Diagnostics.Trace.WriteLine(
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

                System.Diagnostics.Trace.WriteLine(
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

            System.Diagnostics.Trace.WriteLine(
                evidence);

            return false;
        }
        finally
        {
            HistoricalLogFileRecoveryGate.Release();
        }
    }

    private static bool TryInferHistoricalFileSize(
        IReadOnlyList<ParsedLogRecord> records,
        ulong targetFileReference,
        uint bytesPerCluster,
        uint bytesPerFileRecordSegment,
        long maxCaptureBytes,
        out long fileSizeBytes,
        out string evidence)
    {
        fileSizeBytes = 0;
        evidence = string.Empty;

        if (bytesPerCluster == 0 ||
            bytesPerFileRecordSegment == 0)
        {
            evidence = "NTFS cluster/record geometry was unavailable.";
            return false;
        }

        var targetSegment =
            targetFileReference &
            0x0000FFFFFFFFFFFFUL;

        var targetSequence =
            checked((ushort)(targetFileReference >> 48));

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

        if (initializations.Count == 0)
        {
            evidence =
                $"No retained InitializeFileRecordSegment record matched " +
                $"MFT segment {targetSegment:N0}.";
            return false;
        }

        var candidates = new List<(ulong Lsn, long Size, string Source)>();

        for (var i = 0; i < initializations.Count; i++)
        {
            var initialization = initializations[i];

            if (!TryFindUnnamedNonresidentDataAttributes(
                    initialization.RedoData,
                    targetSequence,
                    expectedSize: 0,
                    out var definitions))
            {
                continue;
            }

            ulong? nextGenerationLsn = null;

            for (var j = i + 1; j < initializations.Count; j++)
            {
                if (initializations[j].Lsn > initialization.Lsn)
                {
                    nextGenerationLsn = initializations[j].Lsn;
                    break;
                }
            }

            foreach (var definition in definitions
                         .Where(item =>
                             item.StartingVcn == 0 &&
                             item.FileSizeBytes > 0 &&
                             item.FileSizeBytes <= maxCaptureBytes &&
                             item.FileSizeBytes <= int.MaxValue))
            {
                candidates.Add(
                    (
                        initialization.Lsn,
                        definition.FileSizeBytes,
                        "InitializeFileRecordSegment"));

                var sizeUpdates =
                    records
                        .Where(record =>
                            record.Lsn > initialization.Lsn &&
                            (!nextGenerationLsn.HasValue ||
                             record.Lsn < nextGenerationLsn.Value) &&
                            (record.RedoOperation == SetNewAttributeSizes ||
                             record.UndoOperation == SetNewAttributeSizes) &&
                            CalculateTargetMftSegment(
                                record,
                                bytesPerCluster,
                                bytesPerFileRecordSegment) == targetSegment &&
                            record.AttributeOffset == definition.AttributeOffset)
                        .OrderBy(record => record.Lsn)
                        .ThenBy(record => record.PhysicalOrder)
                        .ToList();

                foreach (var sizeUpdate in sizeUpdates)
                {
                    var sizePayload =
                        sizeUpdate.RedoOperation == SetNewAttributeSizes
                            ? sizeUpdate.RedoData
                            : sizeUpdate.UndoData;

                    if (sizePayload.Length < 24)
                    {
                        continue;
                    }

                    var allocatedSize =
                        BinaryPrimitives.ReadInt64LittleEndian(
                            sizePayload.AsSpan(0, 8));

                    var dataSize =
                        BinaryPrimitives.ReadInt64LittleEndian(
                            sizePayload.AsSpan(8, 8));

                    var validSize =
                        BinaryPrimitives.ReadInt64LittleEndian(
                            sizePayload.AsSpan(16, 8));

                    if (allocatedSize < 0 ||
                        dataSize <= 0 ||
                        validSize < 0 ||
                        dataSize > allocatedSize ||
                        validSize > dataSize ||
                        dataSize > maxCaptureBytes ||
                        dataSize > int.MaxValue)
                    {
                        continue;
                    }

                    candidates.Add(
                        (
                            sizeUpdate.Lsn,
                            dataSize,
                            "SetNewAttributeSizes"));

                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS $LogFile historical size candidate: " +
                        $"fileRef={targetFileReference}, " +
                        $"segment={targetSegment:N0}, " +
                        $"sequence={targetSequence}, " +
                        $"lsn=0x{sizeUpdate.Lsn:X16}, " +
                        $"attributeOffset=0x{definition.AttributeOffset:X}, " +
                        $"allocatedSize={allocatedSize:N0}, " +
                        $"dataSize={dataSize:N0}, " +
                        $"validSize={validSize:N0}.");
                }
            }
        }

        if (candidates.Count == 0)
        {
            evidence =
                $"Retained MFT initialization records existed for segment " +
                $"{targetSegment:N0}, but no exact-sequence unnamed nonresident " +
                "$DATA definition carried a safe historical size.";
            return false;
        }

        var selected = candidates
            .OrderByDescending(candidate => candidate.Lsn)
            .ThenByDescending(candidate => candidate.Size)
            .First();

        fileSizeBytes = selected.Size;

        var distinctSizes =
            candidates
                .Select(candidate => candidate.Size)
                .Distinct()
                .OrderByDescending(size => size)
                .ToArray();

        var sizeSummary =
            string.Join(
                ", ",
                distinctSizes.Select(size => size.ToString("N0")));

        evidence =
            $"Selected the latest exact-generation historical size from " +
            $"{selected.Source} at LSN 0x{selected.Lsn:X16}. " +
            $"Retained size candidates: {sizeSummary} byte(s).";

        return true;
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

        var targetSegmentRecords =
            records
                .Where(record =>
                    CalculateTargetMftSegment(
                        record,
                        bytesPerCluster,
                        bytesPerFileRecordSegment) == targetSegment)
                .OrderBy(record => record.Lsn)
                .ThenBy(record => record.PhysicalOrder)
                .ToList();

        var operationCounts =
            targetSegmentRecords
                .GroupBy(record =>
                {
                    var operation =
                        record.RedoOperation != 0
                            ? record.RedoOperation
                            : record.UndoOperation;
                    return operation;
                })
                .OrderBy(group => group.Key)
                .Select(group => $"0x{group.Key:X4}={group.Count():N0}")
                .ToArray();

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $LogFile target MFT diagnostics: " +
            $"fileRef={targetFileReference}, " +
            $"segment={targetSegment:N0}, " +
            $"sequence={targetSequence}, " +
            $"records={targetSegmentRecords.Count:N0}, " +
            $"ops={(operationCounts.Length == 0 ? "(none)" : string.Join(", ", operationCounts))}.");

        foreach (var targetRecord in targetSegmentRecords.Take(32))
        {
            var redoLength = targetRecord.RedoData.Length;
            var undoLength = targetRecord.UndoData.Length;

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile target MFT record: " +
                $"lsn=0x{targetRecord.Lsn:X16}, " +
                $"previousLsn=0x{targetRecord.ClientPreviousLsn:X16}, " +
                $"undoNextLsn=0x{targetRecord.ClientUndoNextLsn:X16}, " +
                $"transaction=0x{targetRecord.TransactionId:X8}, " +
                $"redo=0x{targetRecord.RedoOperation:X4}/{redoLength:N0}, " +
                $"undo=0x{targetRecord.UndoOperation:X4}/{undoLength:N0}, " +
                $"recordOffset={targetRecord.RecordOffset}, " +
                $"attributeOffset={targetRecord.AttributeOffset}, " +
                $"targetVcn={targetRecord.TargetVcn}, " +
                $"clusterBlock={targetRecord.ClusterBlockOffset}, " +
                $"targetBlockSize={targetRecord.TargetBlockSize}." );
        }

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

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $LogFile resident data scan: " +
            $"targetSegment={targetSegment:N0}, " +
            $"targetSequence={targetSequence}, " +
            $"dataDefinitions={definitions.Count:N0} [{definitionSummary}], " +
            $"UpdateResidentValueRecords={residentUpdates.Count:N0}, " +
            $"targetSize={fileSizeBytes:N0}.");

        if (definitions.Count == 0)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile resident data scan: " +
                $"NO resident $DATA definition survived for segment={targetSegment:N0}, " +
                $"sequence={targetSequence}. " +
                $"InitializeFileRecordSegment records with an exact sequence were not enough " +
                $"to reconstruct a resident unnamed $DATA attribute.");

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

            System.Diagnostics.Trace.WriteLine(
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

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile resident definition candidate: " +
                $"lsn=0x{record.Lsn:X16}, " +
                $"segment={targetSegment:N0}, " +
                $"sequence={targetSequence}, " +
                $"attributes={initialized.Count:N0}, " +
                $"redoBytes={record.RedoData.Length:N0}.");

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

    private static void TraceTargetHistoricalEvidence(
        IReadOnlyList<ParsedLogRecord> records,
        ulong targetFileReference,
        uint bytesPerCluster,
        uint bytesPerFileRecordSegment)
    {
        var targetSegment =
            targetFileReference &
            0x0000FFFFFFFFFFFFUL;

        var targetSequence =
            checked((ushort)(targetFileReference >> 48));

        var segmentRecords =
            records
                .Where(record =>
                    CalculateTargetMftSegment(
                        record,
                        bytesPerCluster,
                        bytesPerFileRecordSegment) == targetSegment)
                .OrderBy(record => record.Lsn)
                .ThenBy(record => record.PhysicalOrder)
                .ToList();

        // Diagnostic inventory of every retained $MFT-resident operation for the
        // exact historical segment. This is diagnostic only and does not relax
        // identity validation or accept heuristic data.
        foreach (var record in segmentRecords)
        {
            var selectedOperation =
                record.RedoOperation != 0
                    ? record.RedoOperation
                    : record.UndoOperation;

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile target segment operation: " +
                $"fileRef={targetFileReference}, " +
                $"segment={targetSegment:N0}, " +
                $"lsn=0x{record.Lsn:X16}, " +
                $"transaction=0x{record.TransactionId:X8}, " +
                $"redo=0x{record.RedoOperation:X4}, " +
                $"undo=0x{record.UndoOperation:X4}, " +
                $"targetAttribute=0x{record.TargetAttribute:X4}, " +
                $"recordOffset=0x{record.RecordOffset:X}, " +
                $"attributeOffset=0x{record.AttributeOffset:X}, " +
                $"targetVcn={record.TargetVcn:N0}, " +
                $"clusterBlockOffset={record.ClusterBlockOffset}, " +
                $"targetBlockSize={record.TargetBlockSize}, " +
                $"redoBytes={record.RedoData.Length:N0}, " +
                $"undoBytes={record.UndoData.Length:N0}, " +
                $"selectedOperation=0x{selectedOperation:X4}.");
        }

        var initializationRecords =
            segmentRecords
                .Where(record =>
                    record.RedoOperation == 0x0002 ||
                    record.UndoOperation == 0x0002)
                .ToList();

        var deallocationRecords =
            segmentRecords
                .Where(record =>
                    record.RedoOperation == DeallocateFileRecordSegment ||
                    record.UndoOperation == DeallocateFileRecordSegment)
                .ToList();

        var sizeRecords =
            segmentRecords
                .Where(record =>
                    record.RedoOperation == SetNewAttributeSizes ||
                    record.UndoOperation == SetNewAttributeSizes)
                .ToList();

        var bitmapRecords =
            records
                .Where(record =>
                    record.RedoOperation == ClearBitsInNonresidentBitmap ||
                    record.UndoOperation == ClearBitsInNonresidentBitmap ||
                    record.RedoOperation == SetBitsInNonresidentBitmap ||
                    record.UndoOperation == SetBitsInNonresidentBitmap)
                .OrderBy(record => record.Lsn)
                .ThenBy(record => record.PhysicalOrder)
                .ToList();

        var targetOpenAttributes =
            records
                .Where(record =>
                    record.RedoOperation == OpenNonresidentAttribute &&
                    record.RedoData.Length > 0)
                .SelectMany(record =>
                    ReadPossibleOpenAttributeFileReferences(record.RedoData)
                        .Where(reference => reference == targetFileReference)
                        .Select(_ => record))
                .ToList();

        var targetOpenAttributeDumpMatches =
            FindOpenAttributeTableDumpMatches(
                records,
                targetFileReference);

        var exactInitializationSequences =
            initializationRecords
                .Select(record => record.RedoData)
                .Where(data => data.Length >= 24 &&
                               EncodingAscii(data, 0, Math.Min(4, data.Length)) == "FILE")
                .Select(data =>
                    BinaryPrimitives.ReadUInt16LittleEndian(
                        data.AsSpan(16, 2)))
                .Distinct()
                .OrderBy(sequence => sequence)
                .ToArray();

        var exactSequenceInitializations =
            exactInitializationSequences.Contains(targetSequence);

        var targetTransactionIds =
            deallocationRecords
                .Select(record => record.TransactionId)
                .Where(transaction => transaction != 0)
                .Distinct()
                .OrderBy(transaction => transaction)
                .ToArray();

        var bitmapTransactionSummary =
            bitmapRecords
                .Where(record =>
                    targetTransactionIds.Contains(record.TransactionId))
                .GroupBy(record => record.TransactionId)
                .Select(group =>
                    $"0x{group.Key:X8}:{group.Count():N0}")
                .ToArray();

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $LogFile target evidence inventory: " +
            $"fileRef={targetFileReference}, " +
            $"segment={targetSegment:N0}, " +
            $"expectedSequence={targetSequence}, " +
            $"segmentRecords={segmentRecords.Count:N0}, " +
            $"initializations={initializationRecords.Count:N0}, " +
            $"initializationSequences=[{string.Join(",", exactInitializationSequences)}], " +
            $"exactSequenceInitializationPresent={exactSequenceInitializations}, " +
            $"deallocations={deallocationRecords.Count:N0}, " +
            $"sizeUpdates={sizeRecords.Count:N0}, " +
            $"exactOpenNonresidentAttributes={targetOpenAttributes.Count:N0}, " +
            $"openAttributeDumpTargetMatches={targetOpenAttributeDumpMatches.Count:N0}, " +
            $"bitmapRecords={bitmapRecords.Count:N0}, " +
            $"bitmapRecordsInDeletionTransactions=[{string.Join(",", bitmapTransactionSummary)}].");

        foreach (var record in initializationRecords)
        {
            var actualSequence =
                record.RedoData.Length >= 24
                    ? BinaryPrimitives.ReadUInt16LittleEndian(
                        record.RedoData.AsSpan(16, 2))
                    : (ushort)0;

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile target initialization evidence: " +
                $"fileRef={targetFileReference}, " +
                $"segment={targetSegment:N0}, " +
                $"expectedSequence={targetSequence}, " +
                $"actualSequence={actualSequence}, " +
                $"lsn=0x{record.Lsn:X16}, " +
                $"transaction=0x{record.TransactionId:X8}, " +
                $"redoOperation=0x{record.RedoOperation:X4}, " +
                $"undoOperation=0x{record.UndoOperation:X4}, " +
                $"redoBytes={record.RedoData.Length:N0}, " +
                $"undoBytes={record.UndoData.Length:N0}.");
        }

        foreach (var record in sizeRecords)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile target size-update evidence: " +
                $"fileRef={targetFileReference}, " +
                $"segment={targetSegment:N0}, " +
                $"lsn=0x{record.Lsn:X16}, " +
                $"transaction=0x{record.TransactionId:X8}, " +
                $"attributeOffset=0x{record.AttributeOffset:X}, " +
                $"redoOperation=0x{record.RedoOperation:X4}, " +
                $"undoOperation=0x{record.UndoOperation:X4}, " +
                $"redoBytes={record.RedoData.Length:N0}, " +
                $"undoBytes={record.UndoData.Length:N0}.");
        }

        foreach (var record in deallocationRecords)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile target deallocation evidence: " +
                $"fileRef={targetFileReference}, " +
                $"segment={targetSegment:N0}, " +
                $"lsn=0x{record.Lsn:X16}, " +
                $"transaction=0x{record.TransactionId:X8}, " +
                $"redoOperation=0x{record.RedoOperation:X4}, " +
                $"undoOperation=0x{record.UndoOperation:X4}.");
        }
    }

    private static bool TryRecoverFromHistoricalNonresidentValueUpdates(
        IReadOnlyList<ParsedLogRecord> records,
        ulong targetFileReference,
        long fileSizeBytes,
        uint bytesPerCluster,
        out byte[] data,
        out string evidence)
    {
        data = [];
        evidence = string.Empty;

        if (fileSizeBytes <= 0 ||
            fileSizeBytes > int.MaxValue ||
            bytesPerCluster == 0)
        {
            return false;
        }

        // The previous implementation resolved the latest OpenNonresidentAttribute
        // by scanning and sorting the entire open-attribute collection for EVERY
        // UpdateNonresidentValue record. On a large retained $LogFile this can become
        // effectively O(updates * opens), which is needlessly expensive and can make
        // targeted recovery appear hung for hours.
        //
        // Index both operation types by attribute slot, sort each small history once,
        // then walk each attribute's opens and updates together. The resulting lookup
        // is O(N log N) for sorting plus O(N) for the merge, instead of O(N^2).
        var opensByAttribute =
            new Dictionary<ushort, List<OpenAttributeHistory>>();

        var updatesByAttribute =
            new Dictionary<ushort, List<ParsedLogRecord>>();

        var allOpenAttributeCount = 0;
        var allUpdateNonresidentValueCount = 0;

        foreach (var record in records)
        {
            if (record.RedoOperation == OpenNonresidentAttribute &&
                record.RedoData.Length > 0)
            {
                var references = ReadPossibleOpenAttributeFileReferences(
                    record.RedoData);

                if (references.Count == 0)
                {
                    continue;
                }

                if (!opensByAttribute.TryGetValue(
                        record.TargetAttribute,
                        out var opens))
                {
                    opens = [];
                    opensByAttribute[record.TargetAttribute] = opens;
                }

                foreach (var fileReference in references)
                {
                    var attributeName = DecodeUnicodeString(record.UndoData);

                    opens.Add(
                        new OpenAttributeHistory(
                            record.Lsn,
                            fileReference,
                            attributeName));

                    allOpenAttributeCount++;

                }

                continue;
            }

            if (record.RedoOperation == UpdateNonresidentValue &&
                record.RedoData.Length > 0)
            {
                if (!updatesByAttribute.TryGetValue(
                        record.TargetAttribute,
                        out var updates))
                {
                    updates = [];
                    updatesByAttribute[record.TargetAttribute] = updates;
                }

                updates.Add(record);
                allUpdateNonresidentValueCount++;
            }
        }

        var candidateUpdates = new List<ParsedLogRecord>();

        foreach (var attributePair in updatesByAttribute)
        {
            if (!opensByAttribute.TryGetValue(
                    attributePair.Key,
                    out var opens) ||
                opens.Count == 0)
            {
                continue;
            }

            opens.Sort(
                static (left, right) => left.Lsn.CompareTo(right.Lsn));

            var updates = attributePair.Value;
            updates.Sort(
                static (left, right) =>
                {
                    var comparison = left.Lsn.CompareTo(right.Lsn);
                    return comparison != 0
                        ? comparison
                        : left.PhysicalOrder.CompareTo(right.PhysicalOrder);
                });

            var openIndex = 0;
            OpenAttributeHistory? latestOpen = null;

            foreach (var record in updates)
            {
                while (openIndex < opens.Count &&
                       opens[openIndex].Lsn <= record.Lsn)
                {
                    latestOpen = opens[openIndex];
                    openIndex++;
                }

                if (latestOpen is not null &&
                    latestOpen.FileReference == targetFileReference &&
                    string.IsNullOrWhiteSpace(latestOpen.AttributeName))
                {
                    candidateUpdates.Add(record);
                }
            }
        }

        var exactOpens =
            opensByAttribute.Values
                .SelectMany(list => list)
                .Where(item =>
                    item.FileReference == targetFileReference &&
                    string.IsNullOrWhiteSpace(item.AttributeName))
                .OrderBy(item => item.Lsn)
                .ToList();

        var openAttributeDumpMatches =
            FindOpenAttributeTableDumpMatches(
                records,
                targetFileReference);

        var targetSegment =
            targetFileReference &
            0x0000FFFFFFFFFFFFUL;

        var sameSegmentOpenReferences =
            opensByAttribute.Values
                .SelectMany(list => list)
                .Where(item =>
                    (item.FileReference & 0x0000FFFFFFFFFFFFUL) ==
                    targetSegment)
                .Select(item => item.FileReference)
                .Distinct()
                .Take(20)
                .ToList();

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $LogFile historical nonresident value scan: " +
            $"fileRef={targetFileReference}, " +
            $"segment={targetSegment:N0}, " +
            $"size={fileSizeBytes:N0}, " +
            $"allOpenAttributes={allOpenAttributeCount:N0}, " +
            $"exactOpenAttributes={exactOpens.Count:N0}, " +
            $"allUpdateNonresidentValue={allUpdateNonresidentValueCount:N0}, " +
            $"candidateUpdates={candidateUpdates.Count:N0}, " +
            $"sameSegmentOpenRefs={string.Join(",", sameSegmentOpenReferences)}, " +
            $"openAttributeDumpMatches={openAttributeDumpMatches.Count:N0}, " +
            $"lookup=attribute-indexed-ordered-merge.");

        if (candidateUpdates.Count == 0)
        {
            evidence =
                $"No exact-file OpenNonresidentAttribute mapping was retained for " +
                $"file reference {targetFileReference}, or no UpdateNonresidentValue " +
                "records were retained for that attribute.";
            return false;
        }

        var recovered = new byte[checked((int)fileSizeBytes)];
        var covered = new bool[recovered.Length];
        var appliedUpdates = 0;

        foreach (var record in candidateUpdates
                     .OrderBy(item => item.Lsn)
                     .ThenBy(item => item.PhysicalOrder))
        {
            var fileOffset =
                checked(
                    record.TargetVcn *
                    (long)bytesPerCluster +
                    record.ClusterBlockOffset * 512L);

            if (fileOffset < 0 ||
                fileOffset >= fileSizeBytes)
            {
                continue;
            }

            var bytesToCopy =
                Math.Min(
                    (long)record.RedoData.Length,
                    fileSizeBytes - fileOffset);

            if (bytesToCopy <= 0)
            {
                continue;
            }

            Buffer.BlockCopy(
                record.RedoData,
                0,
                recovered,
                checked((int)fileOffset),
                checked((int)bytesToCopy));

            Array.Fill(
                covered,
                true,
                checked((int)fileOffset),
                checked((int)bytesToCopy));

            appliedUpdates++;

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile historical nonresident value candidate: " +
                $"fileRef={targetFileReference}, " +
                $"lsn=0x{record.Lsn:X16}, " +
                $"targetAttribute=0x{record.TargetAttribute:X4}, " +
                $"targetVcn={record.TargetVcn:N0}, " +
                $"clusterBlockOffset={record.ClusterBlockOffset}, " +
                $"fileOffset={fileOffset:N0}, " +
                $"bytes={bytesToCopy:N0}.");
        }

        var uncovered = 0;
        foreach (var value in covered)
        {
            if (!value)
            {
                uncovered++;
                break;
            }
        }

        if (uncovered != 0)
        {
            evidence =
                $"Found {candidateUpdates.Count:N0} exact-file UpdateNonresidentValue " +
                $"record(s) and applied {appliedUpdates:N0}, but they did not cover " +
                $"the complete {fileSizeBytes:N0}-byte historical file.";
            return false;
        }

        data = recovered;
        evidence =
            $"Recovered {data.LongLength:N0} byte(s) entirely from exact-file NTFS " +
            $"$LogFile UpdateNonresidentValue records. " +
            $"Applied {appliedUpdates:N0} logged write range(s) with complete byte coverage.";

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $LogFile historical nonresident value recovery succeeded: " +
            $"fileRef={targetFileReference}, " +
            $"size={data.LongLength:N0}, " +
            $"updates={appliedUpdates:N0}.");

        return true;
    }

    private sealed record OpenAttributeHistory(
        ulong Lsn,
        ulong FileReference,
        string AttributeName);

    private static IReadOnlyList<ulong> ReadPossibleOpenAttributeFileReferences(
        byte[] redoData)
    {
        var references = new HashSet<ulong>();

        if (redoData.Length >= 24)
        {
            var x64Reference =
                BinaryPrimitives.ReadUInt64LittleEndian(
                    redoData.AsSpan(16, 8));

            if (x64Reference != 0)
            {
                references.Add(x64Reference);
            }
        }

        if (redoData.Length >= 16)
        {
            var x86Reference =
                BinaryPrimitives.ReadUInt64LittleEndian(
                    redoData.AsSpan(8, 8));

            if (x86Reference != 0)
            {
                references.Add(x86Reference);
            }
        }

        return references.ToArray();
    }

    private static List<string> FindOpenAttributeTableDumpMatches(
        IReadOnlyList<ParsedLogRecord> records,
        ulong targetFileReference)
    {
        var matches = new List<string>();

        foreach (var record in records
                     .Where(item =>
                         item.RedoOperation == 0x001D &&
                         item.RedoData.Length >= 24)
                     .OrderBy(item => item.Lsn)
                     .ThenBy(item => item.PhysicalOrder))
        {
            try
            {
                var entrySize =
                    BinaryPrimitives.ReadUInt16LittleEndian(
                        record.RedoData.AsSpan(0, 2));

                var entryCount =
                    BinaryPrimitives.ReadUInt16LittleEndian(
                        record.RedoData.AsSpan(2, 2));

                const int tableHeaderLength = 24;

                if (entrySize < 24 ||
                    entryCount == 0 ||
                    entrySize > 4096)
                {
                    continue;
                }

                var tableBytes =
                    checked((long)entrySize * entryCount);

                if (tableHeaderLength + tableBytes > record.RedoData.Length)
                {
                    continue;
                }

                for (var index = 0; index < entryCount; index++)
                {
                    var entryOffset =
                        checked(tableHeaderLength + index * entrySize);

                    var entry =
                        record.RedoData.AsSpan(
                            entryOffset,
                            entrySize);

                    var candidateReferences = new List<(int Offset, ulong FileReference)>();

                    if (entry.Length >= 16)
                    {
                        var v0Reference =
                            BinaryPrimitives.ReadUInt64LittleEndian(
                                entry.Slice(8, 8));

                        if (v0Reference != 0)
                        {
                            candidateReferences.Add((8, v0Reference));
                        }
                    }

                    if (entry.Length >= 24)
                    {
                        var v1Reference =
                            BinaryPrimitives.ReadUInt64LittleEndian(
                                entry.Slice(16, 8));

                        if (v1Reference != 0)
                        {
                            candidateReferences.Add((16, v1Reference));
                        }
                    }

                    foreach (var candidate in candidateReferences)
                    {
                        if (candidate.FileReference != targetFileReference)
                        {
                            continue;
                        }

                        var tableAttributeOffset = entryOffset;

                        matches.Add(
                            $"lsn=0x{record.Lsn:X16}, " +
                            $"entryIndex={index:N0}, " +
                            $"entrySize={entrySize:N0}, " +
                            $"referenceOffset=0x{candidate.Offset:X}, " +
                            $"targetAttributeOffset=0x{tableAttributeOffset:X}.");

                        System.Diagnostics.Trace.WriteLine(
                            $"NTFS $LogFile open-attribute table dump TARGET MATCH: " +
                            $"fileRef={targetFileReference}, " +
                            matches[^1]);
                    }
                }
            }
            catch
            {
                // A malformed or incompatible historical dump must never
                // interfere with ordinary recovery diagnostics.
            }
        }

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $LogFile open-attribute table dump scan: " +
            $"fileRef={targetFileReference}, " +
            $"dumpRecords={records.Count(item => item.RedoOperation == 0x001D):N0}, " +
            $"targetMatches={matches.Count:N0}.");

        return matches;
    }

    private static bool TryRecoverNonresidentDataFromHistoricalMftInitialization(
        IReadOnlyList<ParsedLogRecord> records,
        ulong targetFileReference,
        long fileSizeBytes,
        uint bytesPerCluster,
        uint bytesPerFileRecordSegment,
        SafeFileHandle rawVolumeHandle,
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

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $LogFile historical nonresident MFT initialization scan: " +
            $"fileRef={targetFileReference}, " +
            $"segment={targetSegment:N0}, " +
            $"sequence={targetSequence}, " +
            $"initializationRecords={initializations.Count:N0}, " +
            $"targetSize={fileSizeBytes:N0}.");

        foreach (var initialization in initializations)
        {
            if (!TryFindUnnamedNonresidentDataAttributes(
                    initialization.RedoData,
                    targetSequence,
                    fileSizeBytes,
                    out var definitions))
            {
                continue;
            }

            foreach (var definition in definitions)
            {
                var summary =
                    definition.Extents.Count == 0
                        ? "none"
                        : string.Join(
                            "; ",
                            definition.Extents.Select(
                                extent =>
                                    $"vcn={extent.VirtualClusterNumber:N0}, " +
                                    $"clusters={extent.ClusterCount:N0}, " +
                                    $"lcn={(extent.IsSparse ? "sparse" : extent.LogicalClusterNumber.ToString("N0"))}"));

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS $LogFile historical nonresident $DATA candidate: " +
                    $"fileRef={targetFileReference}, " +
                    $"lsn=0x{initialization.Lsn:X16}, " +
                    $"attributeOffset=0x{definition.AttributeOffset:X}, " +
                    $"startVcn={definition.StartingVcn:N0}, " +
                    $"endVcn={definition.EndingVcn:N0}, " +
                    $"declaredFileSize={definition.FileSizeBytes:N0}, " +
                    $"mappingBytes={definition.MappingPairsLength:N0}, " +
                    $"extents={definition.Extents.Count:N0} [{summary}].");

                if (definition.StartingVcn != 0)
                {
                    continue;
                }

                var requiredClusters = checked(
                    (fileSizeBytes + bytesPerCluster - 1) /
                    bytesPerCluster);

                if (!TryBuildCompleteChain(
                        definition.Extents,
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
                                $"Historical MFT initialization extent chain has a VCN gap at {expectedVcn:N0}.");
                        }

                        var extentBytes = checked(
                            extent.ClusterCount * (long)bytesPerCluster);

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
                                    rawVolumeHandle,
                                    checked(
                                        extent.LogicalClusterNumber *
                                        (long)bytesPerCluster),
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
                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS $LogFile historical nonresident MFT initialization read failed: " +
                        $"fileRef={targetFileReference}, lsn=0x{initialization.Lsn:X16}, " +
                        $"{ex.GetType().Name}: {ex.Message}");
                    continue;
                }

                if (remaining != 0)
                {
                    continue;
                }

                data = recovered;

                evidence =
                    $"Recovered {data.LongLength:N0} byte(s) from the exact historical " +
                    $"MFT InitializeFileRecordSegment $DATA runlist. {chainEvidence}";

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS $LogFile historical nonresident MFT initialization recovery succeeded: " +
                    $"fileRef={targetFileReference}, " +
                    $"segment={targetSegment:N0}, " +
                    $"sequence={targetSequence}, " +
                    $"size={data.LongLength:N0}, " +
                    $"lsn=0x{initialization.Lsn:X16}.");

                return true;
            }
        }

        return false;
    }

    private static bool TryFindUnnamedNonresidentDataAttributes(
        byte[] recordData,
        ushort expectedSequence,
        long expectedSize,
        out List<NonresidentDataDefinition> definitions)
    {
        definitions = [];

        if (recordData.Length < 40)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile historical MFT initialization rejected: " +
                $"redoDataLength={recordData.Length}, expectedSequence={expectedSequence}.");
            return false;
        }

        var signature =
            System.Text.Encoding.ASCII.GetString(
                recordData,
                0,
                Math.Min(4, recordData.Length));

        var actualSequence =
            BinaryPrimitives.ReadUInt16LittleEndian(
                recordData.AsSpan(16, 2));

        var attributesOffset =
            BinaryPrimitives.ReadUInt16LittleEndian(
                recordData.AsSpan(20, 2));

        var flags =
            BinaryPrimitives.ReadUInt16LittleEndian(
                recordData.AsSpan(22, 2));

        var usedLength =
            BinaryPrimitives.ReadUInt32LittleEndian(
                recordData.AsSpan(24, 4));

        var totalLength =
            BinaryPrimitives.ReadUInt32LittleEndian(
                recordData.AsSpan(28, 4));

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $LogFile historical MFT initialization header: " +
            $"redoDataLength={recordData.Length}, " +
            $"signature='{signature}', " +
            $"expectedSequence={expectedSequence}, " +
            $"actualSequence={actualSequence}, " +
            $"attributesOffset={attributesOffset}, " +
            $"flags=0x{flags:X4}, " +
            $"usedLength={usedLength}, " +
            $"totalLength={totalLength}.");

        if (!string.Equals(
                signature,
                "FILE",
                StringComparison.Ordinal) ||
            actualSequence != expectedSequence)
        {
            return false;
        }

        if (attributesOffset < 24 ||
            attributesOffset >= recordData.Length)
        {
            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile historical MFT initialization rejected: " +
                $"invalid attributesOffset={attributesOffset}, " +
                $"redoDataLength={recordData.Length}.");
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

            var declaredLength =
                BinaryPrimitives.ReadUInt32LittleEndian(
                    recordData.AsSpan(cursor + 4, 4));

            if (declaredLength < 24)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"NTFS $LogFile historical MFT attribute scan: " +
                    $"invalid attribute length={declaredLength} at offset=0x{cursor:X}.");
                break;
            }

            // InitializeFileRecordSegment redo data can be shorter than the full
            // declared MFT attribute while still containing the complete useful
            // $DATA header/runlist prefix. Never reject the final attribute merely
            // because its declared end extends beyond the retained redo payload.
            var availableLength =
                Math.Min(
                    checked((int)declaredLength),
                    recordData.Length - cursor);

            var nonResident =
                recordData[cursor + 8] != 0;

            var nameLength =
                recordData[cursor + 9];

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile historical MFT attribute: " +
                $"offset=0x{cursor:X}, type=0x{type:X8}, " +
                $"declaredLength={declaredLength:N0}, " +
                $"availableLength={availableLength:N0}, " +
                $"nonResident={nonResident}, nameLength={nameLength}.");

            if (type == NtfsAttributeTypeData &&
                nonResident &&
                nameLength == 0 &&
                availableLength >= 64)
            {
                var startingVcn =
                    BinaryPrimitives.ReadInt64LittleEndian(
                        recordData.AsSpan(cursor + 16, 8));

                var endingVcn =
                    BinaryPrimitives.ReadInt64LittleEndian(
                        recordData.AsSpan(cursor + 24, 8));

                var mappingPairsOffset =
                    BinaryPrimitives.ReadUInt16LittleEndian(
                        recordData.AsSpan(cursor + 32, 2));

                var declaredFileSize =
                    BinaryPrimitives.ReadInt64LittleEndian(
                        recordData.AsSpan(cursor + 48, 8));

                if (mappingPairsOffset >= 64 &&
                    mappingPairsOffset < availableLength &&
                    declaredFileSize >= 0)
                {
                    var mappingStart =
                        checked(cursor + mappingPairsOffset);

                    var mappingLength =
                        availableLength - mappingPairsOffset;

                    var mappingBytes =
                        recordData.AsSpan(
                            mappingStart,
                            mappingLength);

                    var terminator =
                        mappingBytes.IndexOf((byte)0);

                    if (terminator >= 0)
                    {
                        var mappingSpan =
                            mappingBytes[..terminator];

                        try
                        {
                            var extents =
                                NtfsMappingPairsParser.Parse(
                                    mappingSpan,
                                    startingVcn);

                            var expectedEndingVcn =
                                extents.Count == 0
                                    ? startingVcn - 1
                                    : checked(
                                        extents[^1].VirtualClusterNumber +
                                        extents[^1].ClusterCount -
                                        1);

                            if (extents.Count > 0 &&
                                expectedEndingVcn == endingVcn &&
                                (expectedSize <= 0 ||
                                 declaredFileSize == expectedSize ||
                                 declaredFileSize == 0))
                            {
                                definitions.Add(
                                    new NonresidentDataDefinition(
                                        checked((long)cursor),
                                        startingVcn,
                                        endingVcn,
                                        declaredFileSize,
                                        terminator,
                                        extents));
                            }
                            else
                            {
                                System.Diagnostics.Trace.WriteLine(
                                    $"NTFS $LogFile historical MFT nonresident $DATA rejected: " +
                                    $"offset=0x{cursor:X}, startVcn={startingVcn:N0}, " +
                                    $"endVcn={endingVcn:N0}, parsedEndVcn={expectedEndingVcn:N0}, " +
                                    $"declaredFileSize={declaredFileSize:N0}, " +
                                    $"expectedSize={expectedSize:N0}, extents={extents.Count:N0}.");
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Trace.WriteLine(
                                $"NTFS $LogFile historical MFT nonresident $DATA mapping parse failed: " +
                                $"offset=0x{cursor:X}, " +
                                $"{ex.GetType().Name}: {ex.Message}");
                        }
                    }
                    else
                    {
                        System.Diagnostics.Trace.WriteLine(
                            $"NTFS $LogFile historical MFT nonresident $DATA rejected: " +
                            $"mapping-pairs terminator not present in available redo payload. " +
                            $"offset=0x{cursor:X}, mappingOffset={mappingPairsOffset}, " +
                            $"availableLength={availableLength}.");
                    }
                }
                else
                {
                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS $LogFile historical MFT nonresident $DATA rejected: " +
                        $"mappingOffset={mappingPairsOffset}, " +
                        $"availableLength={availableLength}, " +
                        $"declaredFileSize={declaredFileSize:N0}.");
                }
            }

            // We cannot safely advance into a record past a truncated final
            // attribute because the next attribute header is not available.
            if (availableLength < declaredLength)
            {
                break;
            }

            cursor += checked((int)declaredLength);
        }

        return definitions.Count > 0;
    }

    private static bool TryRecoverFromHistoricalBitmapClear(
        IReadOnlyList<ParsedLogRecord> records,
        ulong targetFileReference,
        string expectedFileName,
        long fileSizeBytes,
        uint bytesPerCluster,
        SafeFileHandle rawVolumeHandle,
        SafeFileHandle metadataHandle,
        NtfsVolumeInfo volumeInfo,
        out byte[] data,
        out string evidence)
    {
        data = [];
        evidence = string.Empty;

        if (fileSizeBytes <= 0 ||
            bytesPerCluster == 0)
        {
            return false;
        }

        var targetSegment =
            targetFileReference &
            0x0000FFFFFFFFFFFFUL;

        var requiredClusters =
            checked(
                (fileSizeBytes + bytesPerCluster - 1) /
                bytesPerCluster);

        var deletionRecords =
            records
                .Where(record =>
                    record.TransactionId != 0 &&
                    (record.RedoOperation == DeallocateFileRecordSegment ||
                     record.UndoOperation == DeallocateFileRecordSegment) &&
                    CalculateTargetMftSegment(
                        record,
                        bytesPerCluster,
                        volumeInfo.BytesPerFileRecordSegment) == targetSegment)
                .OrderBy(record => record.Lsn)
                .ThenBy(record => record.PhysicalOrder)
                .ToList();

        if (deletionRecords.Count == 0)
        {
            evidence =
                $"No retained DeallocateFileRecordSegment record could be tied " +
                $"to MFT segment {targetSegment:N0}.";
            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile historical bitmap scan: fileRef={targetFileReference}, " +
                $"name={expectedFileName}, segment={targetSegment:N0}, " +
                $"requiredClusters={requiredClusters:N0}, deletionRecords=0.");
            return false;
        }

        var candidateWindows =
            new List<(ulong StartLsn, ulong EndLsn, uint TransactionId, ulong DeallocateLsn)>();

        foreach (var deletion in deletionRecords)
        {
            var transactionId = deletion.TransactionId;

            var previousPrepare =
                records
                    .Where(record =>
                        record.TransactionId == transactionId &&
                        record.Lsn <= deletion.Lsn &&
                        (record.RedoOperation == PrepareTransaction ||
                         record.UndoOperation == PrepareTransaction))
                    .OrderByDescending(record => record.Lsn)
                    .ThenByDescending(record => record.PhysicalOrder)
                    .FirstOrDefault();

            var nextTransactionEnd =
                records
                    .Where(record =>
                        record.TransactionId == transactionId &&
                        record.Lsn > deletion.Lsn &&
                        (record.RedoOperation == CommitTransaction ||
                         record.UndoOperation == CommitTransaction ||
                         record.RedoOperation == ForgetTransaction ||
                         record.UndoOperation == ForgetTransaction))
                    .OrderBy(record => record.Lsn)
                    .ThenBy(record => record.PhysicalOrder)
                    .FirstOrDefault();

            var startLsn =
                previousPrepare?.Lsn ?? deletion.Lsn;

            var endLsn =
                nextTransactionEnd?.Lsn ?? ulong.MaxValue;

            candidateWindows.Add(
                (startLsn, endLsn, transactionId, deletion.Lsn));

            System.Diagnostics.Trace.WriteLine(
                $"NTFS $LogFile historical bitmap transaction window: " +
                $"fileRef={targetFileReference}, " +
                $"transaction=0x{transactionId:X8}, " +
                $"startLsn=0x{startLsn:X16}, " +
                $"deallocateLsn=0x{deletion.Lsn:X16}, " +
                $"endLsn={(endLsn == ulong.MaxValue ? "MAX" : $"0x{endLsn:X16}")}.");
        }

        var ranges = new List<HistoricalBitmapRange>();

        foreach (var window in candidateWindows)
        {
            foreach (var record in records
                         .Where(record =>
                             record.TransactionId == window.TransactionId &&
                             record.Lsn >= window.StartLsn &&
                             record.Lsn <= window.EndLsn &&
                             record.RedoOperation == ClearBitsInNonresidentBitmap &&
                             record.UndoOperation == SetBitsInNonresidentBitmap)
                         .OrderBy(record => record.Lsn)
                         .ThenBy(record => record.PhysicalOrder))
            {
                if (!TryParseBitmapRange(
                        record.RedoData,
                        out var startingLcn,
                        out var bitCount))
                {
                    continue;
                }

                ranges.Add(
                    new HistoricalBitmapRange(
                        record.Lsn,
                        record.TransactionId,
                        startingLcn,
                        bitCount,
                        window.DeallocateLsn));

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS $LogFile historical bitmap clear candidate: " +
                    $"fileRef={targetFileReference}, " +
                    $"transaction=0x{record.TransactionId:X8}, " +
                    $"lsn=0x{record.Lsn:X16}, " +
                    $"deallocateLsn=0x{window.DeallocateLsn:X16}, " +
                    $"startingLcn={startingLcn:N0}, " +
                    $"bitCount={bitCount:N0}, " +
                    $"bytes={bitCount * (long)bytesPerCluster:N0}.");
            }
        }

        var exactRanges =
            ranges
                .Where(range =>
                    range.BitCount == requiredClusters)
                .ToList();

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $LogFile historical bitmap scan: " +
            $"fileRef={targetFileReference}, " +
            $"name={expectedFileName}, " +
            $"segment={targetSegment:N0}, " +
            $"requiredClusters={requiredClusters:N0}, " +
            $"deletionRecords={deletionRecords.Count:N0}, " +
            $"transactionWindows={candidateWindows.Count:N0}, " +
            $"clearCandidates={ranges.Count:N0}, " +
            $"exactSizeCandidates={exactRanges.Count:N0}.");

        if (exactRanges.Count != 1)
        {
            evidence =
                $"Found {ranges.Count:N0} bitmap clear range(s) inside the retained " +
                $"deletion transaction window(s), but exactly one matching " +
                $"{requiredClusters:N0}-cluster range was not available. " +
                "Ambiguous historical allocation evidence is not accepted.";
            return false;
        }

        var selected = exactRanges[0];

        if (!TryReadCurrentBitmapRange(
                rawVolumeHandle,
                metadataHandle,
                volumeInfo,
                selected.StartingLcn,
                selected.BitCount,
                out var bitmapIsFree,
                out var bitmapEvidence))
        {
            evidence =
                $"Current $Bitmap validation failed for the historical range. " +
                $"{bitmapEvidence}";
            return false;
        }

        if (!bitmapIsFree)
        {
            evidence =
                $"Historical bitmap range at LCN {selected.StartingLcn:N0} is no longer " +
                "entirely free; current contents are not accepted.";
            return false;
        }

        data =
            new byte[checked((int)fileSizeBytes)];

        try
        {
            ReadRawExact(
                rawVolumeHandle,
                checked(
                    selected.StartingLcn *
                    (long)bytesPerCluster),
                data,
                0,
                data.Length);
        }
        catch (Exception ex)
        {
            data = [];
            evidence =
                $"Historical bitmap range is free, but reading its contents failed: " +
                $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }

        evidence =
            $"Recovered {data.LongLength:N0} byte(s) from an exact NTFS deletion " +
            $"transaction bitmap-clear range. Transaction 0x{selected.TransactionId:X8} " +
            $"cleared exactly {selected.BitCount:N0} clusters beginning at LCN " +
            $"{selected.StartingLcn:N0} within the retained transaction lifetime; " +
            "the same range remains entirely free in the current $Bitmap.";

        System.Diagnostics.Trace.WriteLine(
            $"NTFS $LogFile historical bitmap-clear recovery succeeded: " +
            $"fileRef={targetFileReference}, " +
            $"name={expectedFileName}, " +
            $"transaction=0x{selected.TransactionId:X8}, " +
            $"lsn=0x{selected.Lsn:X16}, " +
            $"deallocateLsn=0x{selected.DeallocateLsn:X16}, " +
            $"startingLcn={selected.StartingLcn:N0}, " +
            $"clusters={selected.BitCount:N0}, " +
            $"size={data.LongLength:N0}.");

        return true;
    }

    private static bool TryParseBitmapRange(
        byte[] data,
        out long startingLcn,
        out long bitCount)
    {
        startingLcn = 0;
        bitCount = 0;

        if (data.Length < 8)
            return false;

        startingLcn = BinaryPrimitives.ReadUInt32LittleEndian(
            data.AsSpan(0, 4));
        bitCount = BinaryPrimitives.ReadUInt32LittleEndian(
            data.AsSpan(4, 4));

        return bitCount > 0;
    }

    private static bool TryReadCurrentBitmapRange(
        SafeFileHandle rawVolumeHandle,
        SafeFileHandle metadataHandle,
        NtfsVolumeInfo volumeInfo,
        long startingLcn,
        long bitCount,
        out bool allFree,
        out string evidence)
    {
        allFree = false;
        evidence = string.Empty;

        var bitmapStream = new NtfsMftDataReader().ReadMetadataFileDataStream(
            volumeInfo,
            metadataHandle,
            6);

        if (!bitmapStream.Found ||
            bitmapStream.IsResident ||
            bitmapStream.Extents.Count == 0)
        {
            evidence = "NTFS $Bitmap did not expose a usable nonresident $DATA stream.";
            return false;
        }

        var endingBitExclusive = checked(startingLcn + bitCount);
        var logicalByteStart = startingLcn / 8;
        var logicalByteEndExclusive = checked((endingBitExclusive + 7) / 8);
        var logicalByteLength = checked(logicalByteEndExclusive - logicalByteStart);

        if (logicalByteStart < 0 ||
            logicalByteLength <= 0 ||
            logicalByteLength > int.MaxValue)
        {
            evidence = "The historical bitmap range is outside supported bounds.";
            return false;
        }

        var bitmapBytes = ReadMappedLogicalRange(
            rawVolumeHandle,
            volumeInfo.BytesPerCluster,
            bitmapStream.Extents,
            logicalByteStart,
            logicalByteLength);

        for (var bit = 0L; bit < bitCount; bit++)
        {
            var absoluteBit = checked(startingLcn + bit);
            var byteIndex = checked(
                (int)((absoluteBit / 8) - logicalByteStart));
            var bitMask = (byte)(1 << (int)(absoluteBit & 7));

            if ((bitmapBytes[byteIndex] & bitMask) != 0)
            {
                evidence = $"Current $Bitmap reports LCN {absoluteBit:N0} as allocated.";
                return true;
            }
        }

        allFree = true;
        evidence =
            $"Current $Bitmap reports all {bitCount:N0} historical cluster bit(s) as free.";
        return true;
    }

    private static byte[] ReadMappedLogicalRange(
        SafeFileHandle volumeHandle,
        uint bytesPerCluster,
        IReadOnlyList<NtfsDataExtent> extents,
        long logicalOffset,
        long length)
    {
        if (logicalOffset < 0 ||
            length <= 0 ||
            length > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        var result = new byte[checked((int)length)];
        var logicalEnd = checked(logicalOffset + length);
        var destinationOffset = 0;

        foreach (var extent in extents.OrderBy(
                     item => item.VirtualClusterNumber))
        {
            var extentLogicalStart =
                checked(
                    extent.VirtualClusterNumber *
                    (long)bytesPerCluster);

            var extentLogicalEnd =
                checked(
                    extentLogicalStart +
                    extent.ClusterCount *
                    (long)bytesPerCluster);

            var overlapStart =
                Math.Max(
                    logicalOffset,
                    extentLogicalStart);

            var overlapEnd =
                Math.Min(
                    logicalEnd,
                    extentLogicalEnd);

            if (overlapStart >= overlapEnd)
                continue;

            var bytesToCopy =
                checked((int)(overlapEnd - overlapStart));

            var extentOffset =
                checked(overlapStart - extentLogicalStart);

            if (extent.IsSparse)
            {
                Array.Clear(
                    result,
                    destinationOffset,
                    bytesToCopy);
            }
            else
            {
                ReadRawExact(
                    volumeHandle,
                    checked(
                        extent.LogicalClusterNumber *
                        (long)bytesPerCluster +
                        extentOffset),
                    result,
                    destinationOffset,
                    bytesToCopy);
            }

            destinationOffset += bytesToCopy;

            if (destinationOffset == result.Length)
                break;
        }

        if (destinationOffset != result.Length)
        {
            throw new EndOfStreamException(
                $"NTFS mapped range did not cover logical offset " +
                $"{logicalOffset:N0} for {length:N0} byte(s).");
        }

        return result;
    }

    private sealed record HistoricalBitmapRange(
        ulong Lsn,
        uint TransactionId,
        long StartingLcn,
        long BitCount,
        ulong DeallocateLsn);

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

                var coveredEndVcn =
                    extents
                        .Select(extent =>
                            extent.VirtualClusterNumber +
                            extent.ClusterCount)
                        .DefaultIfEmpty(0)
                        .Max();

                var extentSummary =
                    string.Join(
                        "; ",
                        extents
                            .Take(32)
                            .Select(extent =>
                                $"VCN={extent.VirtualClusterNumber:N0}+" +
                                $"{extent.ClusterCount:N0}->" +
                                $"{(extent.IsSparse ? "SPARSE" : extent.LogicalClusterNumber.ToString("N0"))}"));

                if (extents.Count > 32)
                {
                    extentSummary += "; ...";
                }

                System.Diagnostics.Trace.WriteLine(
                    $"NTFS $LogFile historical mapping candidate: " +
                    $"fileRef={targetFileReference}, " +
                    $"targetSegment={targetSegment:N0}, " +
                    $"lsn=0x{record.Lsn:X16}, " +
                    $"transaction=0x{record.TransactionId:X8}, " +
                    $"targetAttribute=0x{record.TargetAttribute:X4}, " +
                    $"identity={(exactMftTarget ? "MFT-segment" : "open-attribute")}, " +
                    $"recordTargetOffset=0x{record.RecordOffset:X}, " +
                    $"attributeTargetOffset=0x{record.AttributeOffset:X}, " +
                    $"targetVcn={record.TargetVcn:N0}, " +
                    $"clusterBlockOffset={record.ClusterBlockOffset}, " +
                    $"targetBlockSize={record.TargetBlockSize}, " +
                    $"mappingBytes={mappingBytes.Length:N0}, " +
                    $"extentCount={extents.Count:N0}, " +
                    $"coveredEndVcn={coveredEndVcn:N0}, " +
                    $"extents=[{extentSummary}].");

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
        uint bytesPerSector,
        IReadOnlySet<ushort>? operationFilter = null,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var result = new List<ParsedLogRecord>();
        var pageCount = logData.Length / geometry.LogPageSize;
        var physicalOrder = 0L;

        for (var pageIndex = geometry.WrappedStartPage;
             pageIndex < pageCount;
             pageIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (progress is not null &&
                (pageIndex == geometry.WrappedStartPage ||
                 (pageIndex - geometry.WrappedStartPage) % 128 == 0))
            {
                progress.Report(
                    $"Parsing historical NTFS $LogFile... page " +
                    $"{pageIndex - geometry.WrappedStartPage + 1:N0} / " +
                    $"{pageCount - geometry.WrappedStartPage:N0}");
            }

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

                var transactionId =
                    BinaryPrimitives.ReadUInt32LittleEndian(
                        page.AsSpan(recordOffset + 36, 4));

                if (recordType == LfsClientRecord)
                {
                    var clientDataSpan = page.AsSpan(
                        clientStart,
                        (int)clientDataLength);

                    if (operationFilter is not null &&
                        !operationFilter.Contains(
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                clientDataSpan.Slice(0, 2))) &&
                        !operationFilter.Contains(
                            BinaryPrimitives.ReadUInt16LittleEndian(
                                clientDataSpan.Slice(2, 2))))
                    {
                        recordOffset += alignedLength;
                        continue;
                    }

                    var clientData = clientDataSpan.ToArray();

                    var thisLsn =
                        BinaryPrimitives.ReadUInt64LittleEndian(
                            page.AsSpan(recordOffset, 8));

                    var clientPreviousLsn =
                        BinaryPrimitives.ReadUInt64LittleEndian(
                            page.AsSpan(recordOffset + 8, 8));

                    var clientUndoNextLsn =
                        BinaryPrimitives.ReadUInt64LittleEndian(
                            page.AsSpan(recordOffset + 16, 8));

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
                            clientPreviousLsn,
                            clientUndoNextLsn,
                            transactionId,
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

        progress?.Report(
            $"Parsed historical NTFS $LogFile: {result.Count:N0} retained recovery record(s).");

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
        long logicalLength,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
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

        const int ioChunkBytes = 8 * 1024 * 1024;
        long totalRead = 0;

        foreach (var extent in extents.OrderBy(
                     item => item.VirtualClusterNumber))
        {
            var extentBytes =
                checked(
                    extent.ClusterCount *
                    (long)bytesPerCluster);

            var extentRemaining =
                Math.Min(
                    extentBytes,
                    remaining);

            if (extentRemaining <= 0)
            {
                break;
            }

            var extentOffset = 0L;

            while (extentRemaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var chunkBytes = checked(
                    (int)Math.Min(
                        extentRemaining,
                        ioChunkBytes));

                if (!extent.IsSparse)
                {
                    ReadRawExact(
                        volumeHandle,
                        checked(
                            extent.LogicalClusterNumber *
                            (long)bytesPerCluster +
                            extentOffset),
                        result,
                        destinationOffset,
                        chunkBytes);
                }

                destinationOffset = checked(
                    destinationOffset + chunkBytes);

                extentOffset = checked(
                    extentOffset + chunkBytes);

                extentRemaining -= chunkBytes;
                remaining -= chunkBytes;
                totalRead += chunkBytes;

                progress?.Report(
                    $"Reading historical NTFS $LogFile... " +
                    $"{totalRead / (1024d * 1024d):0} / " +
                    $"{logicalLength / (1024d * 1024d):0} MB");

                if (remaining == 0)
                {
                    break;
                }
            }

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
                $@"\\.\{volumeName[..2]}",
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

    private sealed record NonresidentDataDefinition(
        long AttributeOffset,
        long StartingVcn,
        long EndingVcn,
        long FileSizeBytes,
        int MappingPairsLength,
        IReadOnlyList<NtfsDataExtent> Extents);

    private sealed record MappingCandidate(
        ulong Lsn,
        ushort TargetAttribute,
        string IdentitySource,
        IReadOnlyList<NtfsDataExtent> Extents);

    private sealed record ParsedLogRecord(
        ulong Lsn,
        ulong ClientPreviousLsn,
        ulong ClientUndoNextLsn,
        uint TransactionId,
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