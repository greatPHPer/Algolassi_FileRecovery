using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class MftCandidateScanner
{
    private const uint FsctlEnumUsnData = 0x000900B3;
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const int ErrorIoPending = 997;
    private const int ErrorOperationAborted = 995;

    private const uint UsnReasonFileDelete = 0x00000200;
    private const uint FileAttributeDirectory = 0x00000010;
    private const int UsnRecordV2MinimumLength = 60;

    public IReadOnlyList<RecoveryCandidate> Scan(
        string rootPath,
        CancellationToken cancellationToken = default)
    {
        WindowsPrivilege.EnableSeBackupPrivilege();
        return ScanInternal(
            rootPath,
            targetPaths: null,
            targetDirectory: null,
            includeSubdirectories: false,
            cancellationToken: cancellationToken,
            maxPages: int.MaxValue);
    }

    public IReadOnlyList<RecoveryCandidate> ScanForPaths(
        string rootPath,
        IReadOnlyCollection<string> targetPaths,
        CancellationToken cancellationToken = default,
        int maxPages = 128)
    {
        ArgumentNullException.ThrowIfNull(targetPaths);

        WindowsPrivilege.EnableSeBackupPrivilege();

        if (maxPages <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxPages));
        }

        var normalizedTargets = targetPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(NormalizePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return ScanInternal(
            rootPath,
            targetPaths: normalizedTargets,
            targetDirectory: null,
            includeSubdirectories: false,
            cancellationToken: cancellationToken,
            maxPages: maxPages);
    }

    public async Task<IReadOnlyList<RecoveryCandidate>> ScanRawMftForPathsAsync(
        string rootPath,
        IReadOnlyCollection<string> targetPaths,
        CancellationToken cancellationToken = default,
        long maxBytesToScan = 512L * 1024L * 1024L,
        IProgress<long>? progress = null,
        IReadOnlyCollection<(string FullPath, ulong FileReferenceNumber, ulong ParentFileReferenceNumber, DateTime DeletedAtUtc)>? targetReferences = null)
    {
        ArgumentNullException.ThrowIfNull(targetPaths);

        WindowsPrivilege.EnableSeBackupPrivilege();

        if (maxBytesToScan <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytesToScan));
        }

        var normalizedTargets = targetPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(NormalizePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (normalizedTargets.Count == 0)
        {
            return [];
        }

        var root = GetNtfsVolumeRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException("A valid Windows volume path is required.", nameof(rootPath));
        }

        if (!string.Equals(
                new DriveInfo(root).DriveFormat,
                "NTFS",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Permanent deleted-file scanning currently supports NTFS volumes only.");
        }

        var fullRoot = Path.GetFullPath(root);
        var volumeInfo = new NtfsVolumeInspector().Inspect(fullRoot);
        using var volumeHandle = CreateVolumeHandle(fullRoot);
        using var mftScanVolumeHandle = CreateVolumeHandle(
            fullRoot,
            overlapped: true);

        const int bufferSize = 4 * 1024 * 1024;

        var dataReader = new NtfsMftDataReader();

        var targetsByName = normalizedTargets
            .Select(target => new
            {
                Target = target,
                Name = Path.GetFileName(target)
            })
            .Where(item => !string.IsNullOrWhiteSpace(item.Name))
            .GroupBy(item => item.Name!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                group => group.Key,
                group => group.Select(item => item.Target).ToList(),
                StringComparer.OrdinalIgnoreCase);

        var targetNames = targetsByName.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);

        var historicalTargetsBySegment = (targetReferences ?? [])
            .Where(target =>
                !string.IsNullOrWhiteSpace(target.FullPath) &&
                target.FileReferenceNumber != 0)
            .Select(target => (
                FullPath: NormalizePath(target.FullPath),
                FileReferenceNumber: target.FileReferenceNumber,
                ParentFileReferenceNumber: target.ParentFileReferenceNumber,
                DeletedAtUtc: target.DeletedAtUtc,
                SegmentNumber: target.FileReferenceNumber & 0x0000FFFFFFFFFFFFUL))
            .GroupBy(target => target.SegmentNumber)
            .ToDictionary(
                group => group.Key,
                group => group.ToList());

        var results = new List<RecoveryCandidate>();
        var seenReferences = new HashSet<ulong>();
        var recordSize = checked((int)volumeInfo.BytesPerFileRecordSegment);
        var fileSignatureCount = 0L;
        var deletedRecordCount = 0L;
        var fileNameEntryCount = 0L;
        var targetNameMatchCount = 0L;
        var staleSegmentMatchCount = 0L;
        var staleTimestampMatchCount = 0L;
        var historicalSegmentSeenCount = 0L;
        var historicalDeletedSegmentSeenCount = 0L;
        var historicalInUseSegmentSeenCount = 0L;

        if (recordSize <= 0 ||
            volumeInfo.MftValidDataLength <= 0)
        {
            return [];
        }

        var bytesToScan = Math.Min(
            volumeInfo.MftValidDataLength,
            maxBytesToScan);

        // Prefer the newest portion of the MFT for the bounded fallback,
        // but always start on an exact MFT record boundary.
        var scanStartRelative = checked(
            volumeInfo.MftValidDataLength - bytesToScan);

        scanStartRelative -= scanStartRelative % recordSize;
        bytesToScan = Math.Min(
            maxBytesToScan,
            checked(volumeInfo.MftValidDataLength - scanStartRelative));
        bytesToScan -= bytesToScan % recordSize;

        var scanBufferSize = bufferSize - bufferSize % recordSize;
        scanBufferSize = Math.Max(recordSize, scanBufferSize);
        var buffer = new byte[scanBufferSize];

        // The $MFT can be fragmented. scanStartRelative is a logical
        // offset inside $MFT and must be translated through record 0's
        // $DATA mapping pairs rather than added to MftStartLcn.
        long scanned = 0;

        while (scanned < bytesToScan)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var remaining = bytesToScan - scanned;
            var requestBytes = (int)Math.Min(
                Math.Min(buffer.Length, 1024 * 1024),
                remaining);
            requestBytes -= requestBytes % recordSize;

            if (requestBytes < recordSize)
            {
                break;
            }

            cancellationToken.ThrowIfCancellationRequested();

            var readOffset = checked(scanStartRelative + scanned);

            // Read logical $MFT bytes through the extent map. The dedicated
            // overlapped handle is retained because the extent-aware reader
            // performs raw asynchronous volume reads.
            var bytesRead = dataReader.ReadMftLogicalBytes(
                mftScanVolumeHandle,
                volumeInfo,
                readOffset,
                buffer);

            if (bytesRead <= 0)
            {
                break;
            }

            var usableBytes = bytesRead - bytesRead % recordSize;

            for (var offset = 0; offset < usableBytes; offset += recordSize)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Parse the FILE record directly from the read buffer. Avoid
                // copying every MFT record into a second array.
                var recordSpan = buffer.AsSpan(offset, recordSize);
                var segmentNumber = checked(
                    (ulong)((scanStartRelative + scanned + offset) / recordSize));

                if (historicalTargetsBySegment.ContainsKey(segmentNumber))
                {
                    historicalSegmentSeenCount++;

                    if (recordSpan.Length >= 23)
                    {
                        var currentSequence = BinaryPrimitives.ReadUInt16LittleEndian(
                            recordSpan.Slice(16, 2));
                        var currentFlags = BinaryPrimitives.ReadUInt16LittleEndian(
                            recordSpan.Slice(22, 2));

                        if ((currentFlags & 0x0001) == 0)
                        {
                            historicalDeletedSegmentSeenCount++;
                        }
                        else
                        {
                            historicalInUseSegmentSeenCount++;
                        }

                        System.Diagnostics.Debug.WriteLine(
                            $"Historical target MFT segment observed: segment={segmentNumber}, " +
                            $"currentSequence={currentSequence}, flags=0x{currentFlags:X4}.");
                    }
                }

                if (recordSpan.Length >= 4 &&
                    recordSpan[0] == (byte)'F' &&
                    recordSpan[1] == (byte)'I' &&
                    recordSpan[2] == (byte)'L' &&
                    recordSpan[3] == (byte)'E')
                {
                    fileSignatureCount++;
                }

                if (!TryParseDeletedFileNameEntries(
                        recordSpan,
                        volumeInfo.BytesPerSector,
                        segmentNumber,
                        out var fileReferenceNumber,
                        out var fileEntries))
                {
                    continue;
                }

                deletedRecordCount++;
                fileNameEntryCount += fileEntries.Count;

                // Keep the exact MFT record that was just scanned. This is
                // important for deletions that happened before the application
                // started: the USN journal can contain an older file-reference
                // sequence than the currently retained deleted MFT record.
                var scannedRecord = recordSpan.ToArray();

                foreach (var entry in fileEntries)
                {
                    targetsByName.TryGetValue(entry.Name, out var sameNameTargets);

                    var currentDirectoryPath = string.Empty;
                    string directoryPath = string.Empty;
                    string? matchingTarget = null;
                    string? matchingEvidence = null;

                    if (sameNameTargets is not null)
                    {
                        targetNameMatchCount++;

                        // Prefer validating the actual FILE_NAME parent against the
                        // historical target path. This prevents a same-named deleted
                        // file in another directory from being promoted accidentally.
                        currentDirectoryPath = NtfsParentPathResolver.Resolve(
                            volumeHandle,
                            entry.ParentFileReferenceNumber) ?? string.Empty;

                        if (!string.IsNullOrWhiteSpace(currentDirectoryPath))
                        {
                            directoryPath = currentDirectoryPath;
                            matchingTarget = sameNameTargets.FirstOrDefault(target =>
                                string.Equals(
                                    NormalizePath(Path.Combine(directoryPath, entry.Name)),
                                    target,
                                    StringComparison.OrdinalIgnoreCase));
                        }
                        else if (sameNameTargets.Count == 1)
                        {
                            // The parent itself may also have been deleted. For a
                            // unique target filename, retain the historical directory
                            // as the conservative fallback when the current parent
                            // cannot be resolved.
                            matchingTarget = sameNameTargets[0];
                            directoryPath = Path.GetDirectoryName(matchingTarget) ?? string.Empty;
                        }
                    }

                    // Historical USN file-reference sequences can be stale after
                    // the same MFT segment is reused. When the current deleted
                    // record's sequence or direct path no longer matches, allow a
                    // much narrower forensic fallback: the segment and FILE_NAME must
                    // be the same, the parent must still identify the historical
                    // directory, and the current $FILE_NAME modification timestamp
                    // must be very close to the historical delete timestamp. This
                    // avoids treating an unrelated reused deleted record as the target.
                    if (matchingTarget is null &&
                        historicalTargetsBySegment.TryGetValue(
                            fileReferenceNumber & 0x0000FFFFFFFFFFFFUL,
                            out var segmentTargets))
                    {
                        if (string.IsNullOrWhiteSpace(currentDirectoryPath))
                        {
                            currentDirectoryPath = NtfsParentPathResolver.Resolve(
                                volumeHandle,
                                entry.ParentFileReferenceNumber) ?? string.Empty;
                        }

                        var entryParentSegment =
                            entry.ParentFileReferenceNumber & 0x0000FFFFFFFFFFFFUL;

                        staleSegmentMatchCount += segmentTargets.Count;

                        var timeMatched = segmentTargets
                            .Where(target =>
                                string.Equals(
                                    Path.GetFileName(target.FullPath),
                                    entry.Name,
                                    StringComparison.OrdinalIgnoreCase) &&
                                (target.ParentFileReferenceNumber == 0 ||
                                 (target.ParentFileReferenceNumber & 0x0000FFFFFFFFFFFFUL) ==
                                 entryParentSegment))
                            .OrderBy(target =>
                                Math.Abs((entry.TimestampUtc - target.DeletedAtUtc).TotalSeconds))
                            .FirstOrDefault(target =>
                                target.DeletedAtUtc != default &&
                                entry.TimestampUtc != default &&
                                Math.Abs((entry.TimestampUtc - target.DeletedAtUtc).TotalMinutes) <= 5 &&
                                (string.IsNullOrWhiteSpace(currentDirectoryPath) ||
                                 string.Equals(
                                     NormalizePath(currentDirectoryPath),
                                     NormalizePath(Path.GetDirectoryName(target.FullPath) ?? string.Empty),
                                     StringComparison.OrdinalIgnoreCase)));

                        if (timeMatched.FullPath is not null)
                        {
                            staleTimestampMatchCount++;
                            matchingTarget = timeMatched.FullPath;
                            directoryPath = Path.GetDirectoryName(matchingTarget) ?? currentDirectoryPath;
                            matchingEvidence =
                                "Retained deleted MFT record matched the historical USN MFT segment, parent context, and a 5-minute FILE_NAME modification-time window around the USN deletion despite a stale file-reference sequence.";
                        }
                    }

                    if (string.IsNullOrWhiteSpace(matchingTarget) ||
                        !seenReferences.Add(fileReferenceNumber))
                    {
                        continue;
                    }

                    // Use the exact MFT record already found by the raw scan.
                    // Never re-read it through the older USN file reference.
                    var data = dataReader.ReadDefaultDataStreamFromScannedMftRecord(
                        volumeInfo,
                        volumeHandle,
                        fileReferenceNumber,
                        scannedRecord);

                    if (!data.Found)
                    {
                        continue;
                    }

                    IReadOnlyList<NtfsExtentAllocation> allocations = [];
                    const string allocationEvidence =
                        "Current NTFS cluster allocation will be verified immediately before recovery.";

                    results.Add(BuildCandidate(
                        fileReferenceNumber,
                        entry.ParentFileReferenceNumber,
                        Path.GetFileName(matchingTarget),
                        directoryPath,
                        entry.TimestampUtc,
                        data,
                        allocations,
                        string.Join(
                            " ",
                            new[]
                            {
                                allocationEvidence,
                                matchingEvidence
                            }.Where(x => !string.IsNullOrWhiteSpace(x)))));

                    if (results.Count >= normalizedTargets.Count)
                    {
                        return results;
                    }
                }
            }

            scanned += usableBytes;
            progress?.Report(scanned);

            if (bytesRead < requestBytes)
            {
                break;
            }
        }

        progress?.Report(scanned);

        System.Diagnostics.Debug.WriteLine(
            $"Raw MFT fallback: scanned={scanned:N0} bytes, " +
            $"recordSize={recordSize:N0}, FILE signatures={fileSignatureCount:N0}, " +
            $"deletedRecords={deletedRecordCount:N0}, FILE_NAME entries={fileNameEntryCount:N0}, " +
            $"targetNameMatches={targetNameMatchCount:N0}, staleSegmentMatches={staleSegmentMatchCount:N0}, " +
            $"staleTimestampMatches={staleTimestampMatchCount:N0}, " +
            $"historicalSegmentsSeen={historicalSegmentSeenCount:N0}, " +
            $"historicalDeletedSegmentsSeen={historicalDeletedSegmentSeenCount:N0}, " +
            $"historicalInUseSegmentsSeen={historicalInUseSegmentSeenCount:N0}, " +
            $"results={results.Count:N0}.");

        if (targetReferences is not null &&
            targetReferences.Count > 0 &&
            results.Count < normalizedTargets.Count)
        {
            // Restore the bounded FSCTL_ENUM_USN_DATA fallback for target paths
            // that the raw logical $MFT scan did not recover. This can surface
            // fresh delete evidence when the raw parser misses the just-freed record.
            //
            // Trust only an EXACT historical MFT file-reference match. Because the
            // sequence number is part of the file reference, an MFT segment that has
            // been reused cannot pass this check.
            try
            {
                var coveredPaths = results
                    .Select(candidate => NormalizePath(candidate.FullPath))
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                var fallbackTargets = normalizedTargets
                    .Where(path => !coveredPaths.Contains(path))
                    .ToList();

                if (fallbackTargets.Count > 0)
                {
                    var fallbackCandidates = ScanForPaths(
                        root,
                        fallbackTargets,
                        cancellationToken,
                        maxPages: 128);

                    var historicalReferencesByPath = targetReferences
                        .Where(target =>
                            !string.IsNullOrWhiteSpace(target.FullPath) &&
                            target.FileReferenceNumber != 0)
                        .GroupBy(
                            target => NormalizePath(target.FullPath),
                            StringComparer.OrdinalIgnoreCase)
                        .ToDictionary(
                            group => group.Key,
                            group => group
                                .Select(target => target.FileReferenceNumber)
                                .ToHashSet(),
                            StringComparer.OrdinalIgnoreCase);

                    var trustedFallbackCandidates = fallbackCandidates
                        .Where(candidate =>
                            historicalReferencesByPath.TryGetValue(
                                NormalizePath(candidate.FullPath),
                                out var historicalReferences) &&
                            historicalReferences.Contains(candidate.FileReferenceNumber))
                        .ToList();

                    System.Diagnostics.Debug.WriteLine(
                        $"Bounded MFT/USN fallback: missingTargets={fallbackTargets.Count:N0}, " +
                        $"scannedCandidates={fallbackCandidates.Count:N0}, " +
                        $"trustedExactReferenceMatches={trustedFallbackCandidates.Count:N0}.");

                    foreach (var fallback in trustedFallbackCandidates)
                    {
                        if (!coveredPaths.Add(NormalizePath(fallback.FullPath)))
                        {
                            continue;
                        }

                        results.Add(fallback);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"Bounded MFT/USN fallback failed: {ex.GetType().Name}: {ex.Message}");
            }
        }

        return results;
    }

    public IReadOnlyList<RecoveryCandidate> ScanForFileReferences(
        string rootPath,
        IReadOnlyCollection<(string FullPath, ulong FileReferenceNumber, ulong ParentFileReferenceNumber, DateTime DeletedAtUtc)> targets,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targets);

        WindowsPrivilege.EnableSeBackupPrivilege();

        var normalizedTargets = targets
            .Where(target =>
                !string.IsNullOrWhiteSpace(target.FullPath) &&
                target.FileReferenceNumber != 0)
            .Select(target => (
                FullPath: NormalizePath(target.FullPath),
                target.FileReferenceNumber,
                target.ParentFileReferenceNumber,
                target.DeletedAtUtc))
            .ToList();

        if (normalizedTargets.Count == 0)
        {
            return [];
        }

        var root = Path.GetPathRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException("A valid Windows volume path is required.", nameof(rootPath));
        }

        if (!string.Equals(new DriveInfo(root).DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Permanent deleted-file scanning currently supports NTFS volumes only.");
        }

        var fullRoot = Path.GetFullPath(root);
        var volumeInfo = new NtfsVolumeInspector().Inspect(fullRoot);
        using var volumeHandle = CreateVolumeHandle(fullRoot);
        var dataReader = new NtfsMftDataReader();
        var bitmapReader = new NtfsVolumeBitmapReader();
        var results = new List<RecoveryCandidate>();

        foreach (var target in normalizedTargets)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var directoryPath = target.ParentFileReferenceNumber == 0
                ? string.Empty
                : NtfsParentPathResolver.Resolve(
                    volumeHandle,
                    target.ParentFileReferenceNumber) ?? string.Empty;

            var name = Path.GetFileName(target.FullPath);
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            // The NTFS file reference is authoritative. Parent-path reconstruction
            // can fail for a deleted file even when its MFT record is still intact.
            // Do not discard the candidate merely because the reconstructed path
            // differs from the historical path.
            if (string.IsNullOrWhiteSpace(directoryPath) ||
                directoryPath.StartsWith("(Parent directory unavailable)", StringComparison.OrdinalIgnoreCase))
            {
                var historicalDirectory = Path.GetDirectoryName(target.FullPath);
                directoryPath = string.IsNullOrWhiteSpace(historicalDirectory)
                    ? string.Empty
                    : historicalDirectory;
            }

            var data = dataReader.ReadDefaultDataStream(
                volumeInfo,
                volumeHandle,
                target.FileReferenceNumber,
                name,
                target.ParentFileReferenceNumber,
                target.FullPath);

            IReadOnlyList<NtfsExtentAllocation> allocations = [];
            string allocationEvidence = string.Empty;

            if (data.Found && !data.IsResident && data.Extents.Count > 0)
            {
                try
                {
                    allocations = bitmapReader.CheckExtents(
                        volumeHandle,
                        data.Extents,
                        cancellationToken);

                    allocationEvidence = BuildAllocationEvidence(allocations);
                }
                catch (Exception ex)
                {
                    allocationEvidence = $"Cluster allocation could not be verified: {ex.Message}";
                }
            }

            results.Add(BuildCandidate(
                target.FileReferenceNumber,
                target.ParentFileReferenceNumber,
                name,
                directoryPath,
                target.DeletedAtUtc,
                data,
                allocations,
                allocationEvidence));
        }

        return results;
    }

    private IReadOnlyList<RecoveryCandidate> ScanInternal(
        string rootPath,
        IReadOnlySet<string>? targetPaths,
        string? targetDirectory,
        bool includeSubdirectories,
        CancellationToken cancellationToken,
        int maxPages)
    {
        var root = Path.GetPathRoot(rootPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException("A valid Windows volume path is required.", nameof(rootPath));
        }

        if (!string.Equals(new DriveInfo(root).DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Permanent deleted-file scanning currently supports NTFS volumes only.");
        }

        var fullRoot = Path.GetFullPath(root);
        var volumeInfo = new NtfsVolumeInspector().Inspect(fullRoot);
        using var volumeHandle = CreateVolumeHandle(fullRoot);
        var dataReader = new NtfsMftDataReader();
        var bitmapReader = new NtfsVolumeBitmapReader();

        var results = new List<RecoveryCandidate>();
        var normalizedTargetDirectory = string.IsNullOrWhiteSpace(targetDirectory)
            ? null
            : NormalizePath(targetDirectory);

        var targetFileNames = targetPaths is null
            ? null
            : targetPaths
                .Select(Path.GetFileName)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

        ulong startFileReferenceNumber = 0;
        var pagesRead = 0;

        while (!cancellationToken.IsCancellationRequested &&
               pagesRead < maxPages)
        {
            pagesRead++;

            var request = new MftEnumDataV0
            {
                StartFileReferenceNumber = startFileReferenceNumber,
                LowUsn = 0,
                HighUsn = long.MaxValue
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
                throw new Win32Exception(error,
                    $"NTFS MFT enumeration failed for {fullRoot}.");
            }

            if (bytesReturned < sizeof(ulong))
            {
                break;
            }

            var nextStart = BinaryPrimitives.ReadUInt64LittleEndian(output.AsSpan(0, 8));
            var offset = 8;
            var foundRecords = 0;

            while (offset + 4 <= bytesReturned)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var recordLength = BinaryPrimitives.ReadUInt32LittleEndian(output.AsSpan(offset, 4));
                if (recordLength < UsnRecordV2MinimumLength ||
                    recordLength > bytesReturned - offset)
                {
                    break;
                }

                var recordSpan = output.AsSpan(offset, checked((int)recordLength));
                var majorVersion = BinaryPrimitives.ReadUInt16LittleEndian(recordSpan.Slice(4, 2));
                if (majorVersion == 2)
                {
                    var fileReference = BinaryPrimitives.ReadUInt64LittleEndian(recordSpan.Slice(8, 8));
                    var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(recordSpan.Slice(16, 8));
                    var timestampFileTime = BinaryPrimitives.ReadInt64LittleEndian(recordSpan.Slice(32, 8));
                    var reason = BinaryPrimitives.ReadUInt32LittleEndian(recordSpan.Slice(40, 4));
                    var attributes = BinaryPrimitives.ReadUInt32LittleEndian(recordSpan.Slice(52, 4));
                    var nameLength = BinaryPrimitives.ReadUInt16LittleEndian(recordSpan.Slice(56, 2));
                    var nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(recordSpan.Slice(58, 2));

                    if ((reason & UsnReasonFileDelete) != 0 &&
                        (attributes & FileAttributeDirectory) == 0 &&
                        nameOffset + nameLength <= recordSpan.Length)
                    {
                        var name = System.Text.Encoding.Unicode.GetString(
                            recordSpan.Slice(nameOffset, nameLength));

                        if (targetFileNames is not null &&
                            !targetFileNames.Contains(name))
                        {
                            offset += checked((int)recordLength);
                            continue;
                        }

                        var timestampUtc = DateTime.UtcNow;
                        try
                        {
                            timestampUtc = DateTime.FromFileTimeUtc(timestampFileTime);
                        }
                        catch
                        {
                        }

                        var directoryPath = NtfsParentPathResolver.Resolve(
                            volumeHandle,
                            parentReference) ?? string.Empty;

                        if (normalizedTargetDirectory is not null &&
                            !IsDirectoryMatch(
                                directoryPath,
                                normalizedTargetDirectory,
                                includeSubdirectories))
                        {
                            offset += checked((int)recordLength);
                            continue;
                        }

                        var fullPath = string.IsNullOrWhiteSpace(directoryPath)
                            ? name
                            : Path.Combine(directoryPath, name);

                        if (targetPaths is not null &&
                            !targetPaths.Contains(NormalizePath(fullPath)))
                        {
                            offset += checked((int)recordLength);
                            continue;
                        }

                        var data = dataReader.ReadDefaultDataStream(
                            volumeInfo,
                            volumeHandle,
                            fileReference,
                            name,
                            parentReference,
                            fullPath);

                        IReadOnlyList<NtfsExtentAllocation> allocations = [];
                        string allocationEvidence = string.Empty;

                        if (data.Found && !data.IsResident && data.Extents.Count > 0)
                        {
                            try
                            {
                                allocations = bitmapReader.CheckExtents(
                                    volumeHandle,
                                    data.Extents,
                                    cancellationToken);

                                allocationEvidence = BuildAllocationEvidence(allocations);
                            }
                            catch (Exception ex)
                            {
                                allocationEvidence = $"Cluster allocation could not be verified: {ex.Message}";
                            }
                        }

                        results.Add(BuildCandidate(
                            fileReference,
                            parentReference,
                            name,
                            directoryPath,
                            timestampUtc,
                            data,
                            allocations,
                            allocationEvidence));

                        foundRecords++;

                        if (targetPaths is not null &&
                            results.Count >= targetPaths.Count)
                        {
                            return results;
                        }
                    }
                }

                offset += checked((int)recordLength);
            }

            if (nextStart <= startFileReferenceNumber || foundRecords == 0 && bytesReturned <= sizeof(ulong))
            {
                break;
            }

            startFileReferenceNumber = nextStart;
        }

        return results;
    }

    private static bool TryParseDeletedFileNameEntries(
        Span<byte> record,
        uint bytesPerSector,
        ulong segmentNumber,
        out ulong fileReferenceNumber,
        out IReadOnlyList<DeletedFileNameEntry> entries)
    {
        fileReferenceNumber = 0;
        entries = [];

        if (record.Length < 48 ||
            record[0] != (byte)'F' ||
            record[1] != (byte)'I' ||
            record[2] != (byte)'L' ||
            record[3] != (byte)'E')
        {
            return false;
        }

        try
        {
            NtfsMftDataReader.ApplyUpdateSequenceFixups(
                record,
                checked((int)bytesPerSector));
        }
        catch
        {
            return false;
        }

        var flags = BinaryPrimitives.ReadUInt16LittleEndian(record.Slice(22, 2));

        // Only deleted file records: bit 0 (IN_USE) is clear and bit 1
        // (DIRECTORY) is clear.
        if ((flags & 0x0001) != 0 || (flags & 0x0002) != 0)
        {
            return false;
        }

        var sequenceNumber = BinaryPrimitives.ReadUInt16LittleEndian(
            record.Slice(16, 2));

        fileReferenceNumber =
            (segmentNumber & 0x0000FFFFFFFFFFFFUL) |
            ((ulong)sequenceNumber << 48);

        var firstAttributeOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            record.Slice(20, 2));

        if (firstAttributeOffset < 24 ||
            firstAttributeOffset >= record.Length)
        {
            return false;
        }

        var found = new List<DeletedFileNameEntry>();
        var offset = (int)firstAttributeOffset;

        while (offset + 16 <= record.Length)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(
                record.Slice(offset, 4));

            if (type == 0xFFFFFFFF)
            {
                break;
            }

            var attributeLength = BinaryPrimitives.ReadUInt32LittleEndian(
                record.Slice(offset + 4, 4));

            if (attributeLength < 24 ||
                offset + attributeLength > record.Length)
            {
                break;
            }

            var nonResident = record[offset + 8];
            var attributeNameLength = record[offset + 9];

            if (type == 0x30 && nonResident == 0 && attributeNameLength == 0)
            {
                var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(
                    record.Slice(offset + 16, 4));
                var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                    record.Slice(offset + 20, 2));

                if (valueOffset + valueLength <= attributeLength &&
                    valueLength >= 66)
                {
                    var valueStart = offset + valueOffset;
                    var parentReference = BinaryPrimitives.ReadUInt64LittleEndian(
                        record.Slice(valueStart, 8));

                    var timestampFileTime = BinaryPrimitives.ReadInt64LittleEndian(
                        record.Slice(valueStart + 16, 8));

                    var nameLength = record[valueStart + 64];
                    var nameByteLength = checked(nameLength * 2);

                    if (valueStart + 66 + nameByteLength <= record.Length &&
                        nameLength > 0)
                    {
                        var name = System.Text.Encoding.Unicode.GetString(
                            record.Slice(valueStart + 66, nameByteLength));

                        DateTime timestampUtc;
                        try
                        {
                            timestampUtc = DateTime.FromFileTimeUtc(timestampFileTime);
                        }
                        catch
                        {
                            timestampUtc = DateTime.UtcNow;
                        }

                        found.Add(new DeletedFileNameEntry(
                            parentReference,
                            name,
                            timestampUtc));
                    }
                }
            }

            offset += checked((int)attributeLength);
        }

        entries = found;
        return found.Count > 0;
    }

    private readonly record struct DeletedFileNameEntry(
        ulong ParentFileReferenceNumber,
        string Name,
        DateTime TimestampUtc);

    private static string NormalizePath(string path) =>
        path.Trim().Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);

    private static bool IsDirectoryMatch(
        string candidate,
        string directory,
        bool includeSubdirectories)
    {
        var left = NormalizePath(candidate).TrimEnd(Path.DirectorySeparatorChar);
        var right = NormalizePath(directory).TrimEnd(Path.DirectorySeparatorChar);

        if (string.Equals(left, right, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return includeSubdirectories &&
               left.StartsWith(
                   right + Path.DirectorySeparatorChar,
                   StringComparison.OrdinalIgnoreCase);
    }

    private static RecoveryCandidate BuildCandidate(
        ulong fileReferenceNumber,
        ulong parentFileReferenceNumber,
        string name,
        string directoryPath,
        DateTime timestampUtc,
        NtfsDataStreamInfo data,
        IReadOnlyList<NtfsExtentAllocation> allocations,
        string allocationEvidence)
    {
        var freeClusters = allocations.Sum(x => x.FreeClusterCount);
        var allocatedClusters = allocations.Sum(x => x.AllocatedClusterCount);

        var strength =
            data.Found && data.IsResident ? RecoveryStrength.Medium :
            data.Found && allocations.Count > 0 && allocatedClusters == 0
                ? RecoveryStrength.Medium :
            data.Found && allocatedClusters > 0
                ? RecoveryStrength.Weak :
            string.IsNullOrWhiteSpace(directoryPath)
                ? RecoveryStrength.Weak
                : RecoveryStrength.Medium;

        return new RecoveryCandidate
        {
            FileReferenceNumber = fileReferenceNumber,
            ParentFileReferenceNumber = parentFileReferenceNumber,
            Name = name,
            DirectoryPath = directoryPath,
            LastUsnTimestampUtc = timestampUtc,
            Strength = strength,
            Evidence = string.IsNullOrWhiteSpace(directoryPath)
                ? "NTFS metadata shows a file-delete record, but the parent directory could not be resolved."
                : "NTFS metadata shows a file-delete record and the parent directory was resolved.",
            DataStreamFound = data.Found,
            DataStreamResident = data.IsResident,
            ResidentData = data.ResidentData,
            FileSizeBytes = data.FileSizeBytes,
            ValidDataLengthBytes = data.ValidDataLengthBytes,
            DataExtents = data.Extents,
            ExtentAllocations = allocations,
            FreeDataClusterCount = freeClusters,
            AllocatedDataClusterCount = allocatedClusters,
            DataEvidence = string.Join(
                " ",
                new[] { data.Evidence, allocationEvidence }
                    .Where(x => !string.IsNullOrWhiteSpace(x)))
        };
    }

    private static string BuildAllocationEvidence(IReadOnlyList<NtfsExtentAllocation> allocations)
    {
        var free = allocations.Sum(x => x.FreeClusterCount);
        var allocated = allocations.Sum(x => x.AllocatedClusterCount);

        if (allocated == 0 && free > 0)
        {
            return $"Current NTFS bitmap: {free:N0} data cluster(s) are free.";
        }

        if (allocated > 0 && free > 0)
        {
            return $"Current NTFS bitmap: {free:N0} data cluster(s) are free and {allocated:N0} are allocated.";
        }

        if (allocated > 0)
        {
            return $"Current NTFS bitmap: {allocated:N0} data cluster(s) are currently allocated.";
        }

        return "Current NTFS bitmap did not return usable allocation evidence.";
    }

    private static int ReadRawVolumeChunk(
        SafeFileHandle volumeHandle,
        byte[] buffer,
        int bytesToRead,
        long fileOffset,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

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
                using var cancellationRegistration =
                    cancellationToken.Register(
                        static state =>
                        {
                            var request = (CancelReadState)state!;
                            _ = CancelIoEx(
                                request.Handle,
                                request.Overlapped);
                        },
                        new CancelReadState(volumeHandle, overlappedPtr));

                var started = ReadFile(
                    volumeHandle,
                    bufferHandle.AddrOfPinnedObject(),
                    checked((uint)bytesToRead),
                    IntPtr.Zero,
                    overlappedPtr);

                if (!started)
                {
                    var startError = Marshal.GetLastWin32Error();

                    if (startError != ErrorIoPending)
                    {
                        throw new Win32Exception(
                            startError,
                            $"Raw NTFS volume read failed at offset {fileOffset:N0}.");
                    }
                }

                completionEvent.WaitOne();

                if (!GetOverlappedResult(
                        volumeHandle,
                        overlappedPtr,
                        out var bytesRead,
                        bWait: false))
                {
                    var completionError = Marshal.GetLastWin32Error();

                    if (completionError == ErrorOperationAborted &&
                        cancellationToken.IsCancellationRequested)
                    {
                        throw new OperationCanceledException(cancellationToken);
                    }

                    throw new Win32Exception(
                        completionError,
                        $"Raw NTFS volume read completion failed at offset {fileOffset:N0}.");
                }

                return checked((int)bytesRead);
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

    private readonly record struct CancelReadState(
        SafeFileHandle Handle,
        IntPtr Overlapped);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeOverlapped
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public int OffsetLow;
        public int OffsetHigh;
        public IntPtr HEvent;
    }

    private static string? GetNtfsVolumeRoot(string path)
    {
        var normalized = path.Trim();

        while (normalized.StartsWith(@"\\?\", StringComparison.Ordinal) ||
               normalized.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }

        return Path.GetPathRoot(normalized);
    }

    private static SafeFileHandle CreateVolumeHandle(
        string root,
        bool overlapped = false)
    {
        var volumeName = root.TrimEnd(Path.DirectorySeparatorChar);
        var flags =
            FileFlagBackupSemantics |
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
                $"Could not open NTFS volume {root}. Device={volumeName}.");
        }

        return handle;
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

    [StructLayout(LayoutKind.Sequential)]
    private struct MftEnumDataV0
    {
        public ulong StartFileReferenceNumber;
        public long LowUsn;
        public long HighUsn;
    }

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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CancelIoEx(
        SafeFileHandle hFile,
        IntPtr lpOverlapped);

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
}
