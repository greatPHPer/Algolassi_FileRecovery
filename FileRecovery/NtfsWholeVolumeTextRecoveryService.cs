using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class NtfsWholeVolumeTextRecoveryService
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    private const int IoBufferSize = 8 * 1024 * 1024;
    private const int ProgressIntervalBytes = 128 * 1024 * 1024;
    private const int MaxMarkerBytes = 4096;
    private const int MaxRecoveredTextBytes = 64 * 1024 * 1024;
    // Large known-size text recovery is streamed to disk and is marker-anchored.
    // Keep an explicit bound so an incorrect metadata size cannot trigger unbounded I/O.
    private const long MaxStreamedKnownLengthTextBytes = 2L * 1024L * 1024L * 1024L;

    public RecoveryResult Recover(
        RecoveryCandidate candidate,
        string destinationDirectory,
        string marker,
        CancellationToken cancellationToken = default,
        IProgress<long>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        if (string.IsNullOrWhiteSpace(marker))
        {
            throw new ArgumentException(
                "A known text marker is required for the whole-volume forensic scan.",
                nameof(marker));
        }

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

        if (markerVariants.Any(item => item.Bytes.Length < 4))
        {
            throw new ArgumentException(
                "The text marker must contain at least 4 bytes in the supported encodings.",
                nameof(marker));
        }

        if (markerVariants.Any(item => item.Bytes.Length > MaxMarkerBytes))
        {
            throw new ArgumentException(
                $"The text marker cannot exceed {MaxMarkerBytes:N0} bytes in the supported encodings.",
                nameof(marker));
        }

        if (candidate.DataStreamFound)
        {
            throw new InvalidOperationException(
                "Whole-volume forensic text scanning is only required for candidates without retained NTFS $DATA evidence.");
        }

        if (!Path.GetExtension(candidate.Name).Equals(
                ".txt",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "The whole-volume target-content scan currently supports deleted .txt files only.");
        }

        RecoveryDestinationPolicy.Validate(candidate.FullPath, destinationDirectory);
        WindowsPrivilege.EnableSeBackupPrivilege();

        var sourceRoot = GetNtfsVolumeRoot(candidate.FullPath);
        if (string.IsNullOrWhiteSpace(sourceRoot))
        {
            throw new InvalidOperationException(
                "The deleted file's source volume could not be determined.");
        }

        var volumeInfo = new NtfsVolumeInspector().Inspect(sourceRoot);
        var totalVolumeBytes = checked(
            volumeInfo.TotalClusters * (long)volumeInfo.BytesPerCluster);

        if (totalVolumeBytes <= 0)
        {
            throw new InvalidOperationException(
                "The NTFS volume reported an invalid total byte length.");
        }

        using var volumeHandle = CreateVolumeHandle(sourceRoot);

        if (candidate.FileSizeBytes > MaxRecoveredTextBytes)
        {
            if (candidate.FileSizeBytes > MaxStreamedKnownLengthTextBytes)
            {
                throw new InvalidOperationException(
                    $"Streaming exact-size text recovery is limited to {MaxStreamedKnownLengthTextBytes:N0} bytes; " +
                    $"this candidate reports {candidate.FileSizeBytes:N0} bytes.");
            }

            return RecoverLargeKnownLengthTextFromStartMarker(
                candidate,
                destinationDirectory,
                markerVariants,
                volumeInfo,
                volumeHandle,
                cancellationToken,
                progress);
        }

        var overlapLength = markerVariants.Max(item => item.Bytes.Length) - 1;
        var previousTail = Array.Empty<byte>();
        long scannedBytes = 0;
        long lastReportedBytes = 0;

        progress?.Report(0);

        System.Diagnostics.Debug.WriteLine(
            $"NTFS whole-volume target scan started: candidate={candidate.FullPath}, " +
            $"markerEncodings=UTF-8/UTF-16LE/UTF-16BE, volumeBytes={totalVolumeBytes:N0}.");

        while (scannedBytes < totalVolumeBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var remaining = totalVolumeBytes - scannedBytes;
            var bytesToRead = (int)Math.Min(IoBufferSize, remaining);
            bytesToRead -= bytesToRead % checked((int)volumeInfo.BytesPerCluster);

            if (bytesToRead < volumeInfo.BytesPerCluster)
            {
                break;
            }

            var physicalOffset = scannedBytes;
            byte[]? buffer = null;
            var attemptedBytes = bytesToRead;

            // Raw volume reads can occasionally fail on a small protected or
            // otherwise unreadable region near filesystem metadata. Do not abort
            // a forensic scan of the entire volume because one large read failed.
            // Reduce the request geometrically until the problematic range can be
            // isolated to a single cluster.
            while (attemptedBytes >= volumeInfo.BytesPerCluster)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    buffer = new byte[attemptedBytes];
                    ReadAt(
                        volumeHandle,
                        physicalOffset,
                        buffer,
                        cancellationToken);
                    break;
                }
                catch (Win32Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS whole-volume target scan read retry: " +
                        $"offset={physicalOffset:N0}, requested={attemptedBytes:N0}, " +
                        $"error={ex.NativeErrorCode}, message={ex.Message}.");

                    attemptedBytes /= 2;
                    attemptedBytes -=
                        attemptedBytes % checked((int)volumeInfo.BytesPerCluster);
                }
            }

            if (buffer is null)
            {
                var skippedBytes = Math.Min(
                    checked((long)volumeInfo.BytesPerCluster),
                    remaining);

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS whole-volume target scan skipped unreadable cluster: " +
                    $"offset={physicalOffset:N0}, bytes={skippedBytes:N0}.");

                scannedBytes = checked(scannedBytes + skippedBytes);
                previousTail = [];

                if (scannedBytes - lastReportedBytes >= ProgressIntervalBytes ||
                    scannedBytes == totalVolumeBytes)
                {
                    lastReportedBytes = scannedBytes;
                    progress?.Report(scannedBytes);
                }

                continue;
            }

            var bytesRead = buffer.Length;
            var window = new byte[checked(previousTail.Length + bytesRead)];

            if (previousTail.Length > 0)
            {
                Buffer.BlockCopy(
                    previousTail,
                    0,
                    window,
                    0,
                    previousTail.Length);
            }

            Buffer.BlockCopy(
                buffer,
                0,
                window,
                previousTail.Length,
                bytesRead);

            scannedBytes = checked(scannedBytes + buffer.Length);

            if (scannedBytes - lastReportedBytes >= ProgressIntervalBytes ||
                scannedBytes == totalVolumeBytes)
            {
                lastReportedBytes = scannedBytes;
                progress?.Report(scannedBytes);
            }

            var searchStartOffset = 0;

            while (searchStartOffset < window.Length)
            {
                (string Encoding, byte[] Bytes)? matchedMarker = null;
                var markerOffsetInWindow = -1;

                foreach (var markerVariant in markerVariants)
                {
                    var variantSearchOffset = searchStartOffset;

                    while (variantSearchOffset < window.Length)
                    {
                        var relativeOffset = window
                            .AsSpan(variantSearchOffset)
                            .IndexOf(markerVariant.Bytes);

                        if (relativeOffset < 0)
                        {
                            break;
                        }

                        var candidateOffset = checked(
                            variantSearchOffset + relativeOffset);

                        var absoluteCandidateOffset = checked(
                            physicalOffset -
                            previousTail.Length +
                            candidateOffset);

                        if (IsUtf16Encoding(markerVariant.Encoding) &&
                            (absoluteCandidateOffset & 1L) != 0)
                        {
                            variantSearchOffset = checked(candidateOffset + 1);
                            continue;
                        }

                        if (markerOffsetInWindow < 0 ||
                            candidateOffset < markerOffsetInWindow)
                        {
                            markerOffsetInWindow = candidateOffset;
                            matchedMarker = markerVariant;
                        }

                        break;
                    }
                }

                if (!matchedMarker.HasValue ||
                    markerOffsetInWindow < 0)
                {
                    break;
                }

                try
                {
                    var recovery = RecoverTextRegionFromScannedBuffer(
                        candidate,
                        destinationDirectory,
                        volumeInfo,
                        volumeHandle,
                        matchedMarker.Value.Bytes,
                        matchedMarker.Value.Encoding,
                        window,
                        checked(physicalOffset - previousTail.Length),
                        markerOffsetInWindow,
                        cancellationToken);

                    var absoluteMarkerOffset = checked(
                        physicalOffset -
                        previousTail.Length +
                        markerOffsetInWindow);

                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS whole-volume target scan hit: " +
                        $"candidate={candidate.FullPath}, " +
                        $"encoding={matchedMarker.Value.Encoding}, " +
                        $"markerOffset={absoluteMarkerOffset:N0}, " +
                        $"scanned={scannedBytes:N0}.");

                    return recovery;
                }
                catch (MarkerRecoverySizeMismatchException ex)
                {
                    var absoluteMarkerOffset = checked(
                        physicalOffset -
                        previousTail.Length +
                        markerOffsetInWindow);

                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS whole-volume target scan rejected marker region: " +
                        $"candidate={candidate.FullPath}, " +
                        $"encoding={matchedMarker.Value.Encoding}, " +
                        $"markerOffset={absoluteMarkerOffset:N0}, " +
                        $"recoveredBytes={ex.RecoveredBytes:N0}, " +
                        $"expectedBytes={candidate.FileSizeBytes:N0}.");

                    searchStartOffset = checked(markerOffsetInWindow + 1);
                }
            }

            previousTail = buffer.Length <= overlapLength
                ? buffer
                : buffer.AsSpan(buffer.Length - overlapLength).ToArray();
        }

        progress?.Report(scannedBytes);

        System.Diagnostics.Debug.WriteLine(
            $"NTFS whole-volume target scan complete: " +
            $"candidate={candidate.FullPath}, scanned={scannedBytes:N0}, " +
            $"volumeBytes={totalVolumeBytes:N0}, markerFound=false.");

        throw new InvalidOperationException(
            $"The supplied text marker was not found anywhere in the NTFS volume. " +
            $"The forensic scan examined {scannedBytes:N0} byte(s) of the " +
            $"{totalVolumeBytes:N0}-byte volume.");
    }

    private RecoveryResult RecoverLargeKnownLengthTextFromStartMarker(
        RecoveryCandidate candidate,
        string destinationDirectory,
        (string Encoding, byte[] Bytes)[] markerVariants,
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        CancellationToken cancellationToken,
        IProgress<long>? progress)
    {
        var expectedLength = candidate.FileSizeBytes;
        if (expectedLength <= MaxRecoveredTextBytes ||
            expectedLength > MaxStreamedKnownLengthTextBytes)
        {
            throw new InvalidOperationException(
                "The candidate size is outside the supported large-text recovery range.");
        }

        var bytesPerCluster = checked((long)volumeInfo.BytesPerCluster);
        if (bytesPerCluster <= 0)
        {
            throw new InvalidOperationException("The source volume reported an invalid cluster size.");
        }

        // When a validated deletion-time NTFS runlist survived in the history record,
        // prefer reconstructing through those original extents. This handles fragmented
        // files without guessing boundaries from arbitrary free-space regions. If a map
        // exists but fails validation, stop with a precise reason rather than repeating
        // a potentially expensive whole-volume free-space scan.
        var retainedSnapshot = candidate.NtfsDataSnapshot;
        var retainedExtentCount = retainedSnapshot?.DataExtents.Count ?? 0;

        System.Diagnostics.Trace.WriteLine(
            $"NTFS large text runlist decision: path={candidate.FullPath}, " +
            $"snapshotPresent={retainedSnapshot is not null}, " +
            $"snapshotCaptured={retainedSnapshot?.IsComplete == true}, " +
            $"snapshotSize={retainedSnapshot?.FileSizeBytes ?? 0:N0}, " +
            $"snapshotValidDataLength={retainedSnapshot?.ValidDataLengthBytes ?? 0:N0}, " +
            $"retainedExtents={retainedExtentCount:N0}.");

        if (retainedExtentCount > 0)
        {
            return RecoverLargeKnownLengthTextFromRetainedExtentMap(
                candidate,
                destinationDirectory,
                markerVariants,
                volumeInfo,
                volumeHandle,
                expectedLength,
                cancellationToken,
                progress);
        }

        if (retainedExtentCount == 0)
        {
            throw new InvalidOperationException(
                "No retained NTFS data runlist reached the large-text recovery candidate " +
                $"(snapshotPresent={retainedSnapshot is not null}, " +
                $"snapshotCaptured={retainedSnapshot?.IsComplete == true}, " +
                $"snapshotSize={retainedSnapshot?.FileSizeBytes ?? 0:N0}, " +
                $"snapshotExtents={retainedExtentCount:N0}). " +
                "The repeated whole-volume scan was skipped to avoid another lengthy scan. " +
                "Inspect the NTFS deletion-history/runlist handoff before retrying.");
        }

        var volumeBitmap = new NtfsVolumeBitmapReader();
        var totalVolumeBytes = checked(volumeInfo.TotalClusters * bytesPerCluster);
        var overlapLength = markerVariants.Max(item => item.Bytes.Length) + 3;
        long freeBytesVisited = 0;

        System.Diagnostics.Trace.WriteLine(
            $"NTFS large exact-size text carve started: candidate={candidate.FullPath}, " +
            $"expectedBytes={expectedLength:N0}, markerMustStartFile=true, " +
            $"maximumBytes={MaxStreamedKnownLengthTextBytes:N0}.");

        progress?.Report(0);

        foreach (var freeExtent in volumeBitmap.EnumerateFreeExtents(
                     volumeHandle,
                     volumeInfo,
                     cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var extentStart = checked(freeExtent.LogicalClusterNumber * bytesPerCluster);
            var extentLength = checked(freeExtent.ClusterCount * bytesPerCluster);
            var extentEnd = checked(extentStart + extentLength);
            freeBytesVisited = checked(freeBytesVisited + extentLength);

            // The full candidate must fit inside one contiguous free extent. A fragmented
            // file needs an NTFS runlist/history source; arbitrary free regions cannot safely
            // be concatenated into a plausible-looking text file.
            if (extentLength < expectedLength)
            {
                progress?.Report(Math.Min(totalVolumeBytes, extentEnd));
                continue;
            }

            byte[] previousTail = [];
            long extentBytesRead = 0;

            while (extentBytesRead < extentLength)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var remainingInExtent = extentLength - extentBytesRead;
                var bytesToRead = checked((int)Math.Min(IoBufferSize, remainingInExtent));
                bytesToRead -= checked((int)(bytesToRead % bytesPerCluster));

                if (bytesToRead <= 0)
                {
                    break;
                }

                var readOffset = checked(extentStart + extentBytesRead);
                var buffer = new byte[bytesToRead];
                ReadAt(volumeHandle, readOffset, buffer, cancellationToken);

                var window = new byte[checked(previousTail.Length + buffer.Length)];
                if (previousTail.Length > 0)
                {
                    Buffer.BlockCopy(previousTail, 0, window, 0, previousTail.Length);
                }

                Buffer.BlockCopy(buffer, 0, window, previousTail.Length, buffer.Length);
                var windowAbsoluteOffset = checked(readOffset - previousTail.Length);
                var earliestMarkerOffset = -1;
                (string Encoding, byte[] Bytes)? earliestMarker = null;

                foreach (var variant in markerVariants)
                {
                    var searchFrom = 0;

                    while (searchFrom < window.Length)
                    {
                        var relative = window.AsSpan(searchFrom).IndexOf(variant.Bytes);
                        if (relative < 0)
                        {
                            break;
                        }

                        var foundAt = checked(searchFrom + relative);
                        var absoluteFoundAt = checked(windowAbsoluteOffset + foundAt);

                        if ((!variant.Encoding.StartsWith("UTF-16", StringComparison.Ordinal) ||
                             (absoluteFoundAt & 1L) == 0) &&
                            (earliestMarkerOffset < 0 || foundAt < earliestMarkerOffset))
                        {
                            earliestMarkerOffset = foundAt;
                            earliestMarker = variant;
                        }

                        searchFrom = checked(foundAt + 1);
                        if (earliestMarkerOffset >= 0 && searchFrom >= earliestMarkerOffset)
                        {
                            break;
                        }
                    }
                }

                if (earliestMarker.HasValue && earliestMarkerOffset >= 0)
                {
                    var absoluteMarkerOffset = checked(windowAbsoluteOffset + earliestMarkerOffset);
                    var candidateStart = absoluteMarkerOffset;
                    var markerEncoding = earliestMarker.Value.Encoding;

                    // Permit a BOM directly before the marker, so the marker can still
                    // identify byte zero of a UTF-8 or UTF-16 text file.
                    if (markerEncoding.Equals("UTF-8", StringComparison.OrdinalIgnoreCase) &&
                        earliestMarkerOffset >= 3 &&
                        window.AsSpan(earliestMarkerOffset - 3, 3).SequenceEqual(new byte[] { 0xEF, 0xBB, 0xBF }))
                    {
                        candidateStart -= 3;
                    }
                    else if (markerEncoding.Equals("UTF-16LE", StringComparison.OrdinalIgnoreCase) &&
                             earliestMarkerOffset >= 2 &&
                             window.AsSpan(earliestMarkerOffset - 2, 2).SequenceEqual(new byte[] { 0xFF, 0xFE }))
                    {
                        candidateStart -= 2;
                    }
                    else if (markerEncoding.Equals("UTF-16BE", StringComparison.OrdinalIgnoreCase) &&
                             earliestMarkerOffset >= 2 &&
                             window.AsSpan(earliestMarkerOffset - 2, 2).SequenceEqual(new byte[] { 0xFE, 0xFF }))
                    {
                        candidateStart -= 2;
                    }

                    // The large-file marker is deliberately required at the beginning.
                    // An arbitrary marker somewhere inside a 1 GiB text file does not
                    // reveal where its first byte belongs.
                    var markerDisplacement = absoluteMarkerOffset - candidateStart;
                    if (candidateStart < extentStart ||
                        candidateStart % bytesPerCluster != 0 ||
                        markerDisplacement > 3 ||
                        candidateStart > extentEnd - expectedLength)
                    {
                        throw new InvalidOperationException(
                            "The first matching text marker in free NTFS space did not identify a cluster-aligned " +
                            "file start with enough contiguous free space for the known file size. For files over 64 MiB, " +
                            "enter a distinctive marker from the very beginning of the deleted file.");
                    }

                    var firstCluster = candidateStart / bytesPerCluster;
                    var lastClusterExclusive = checked(
                        (candidateStart + expectedLength + bytesPerCluster - 1) / bytesPerCluster);
                    var clusterCount = checked(lastClusterExclusive - firstCluster);
                    var allocation = volumeBitmap.CheckExtents(
                        volumeHandle,
                        [
                            new NtfsDataExtent
                            {
                                VirtualClusterNumber = 0,
                                LogicalClusterNumber = firstCluster,
                                ClusterCount = clusterCount
                            }
                        ],
                        cancellationToken);

                    if (allocation.Count != 1 ||
                        allocation[0].AllocatedClusterCount != 0 ||
                        allocation[0].FreeClusterCount != clusterCount)
                    {
                        throw new InvalidOperationException(
                            "The marker was found, but the full known-size text range is not currently free in one contiguous NTFS extent.");
                    }

                    if (!TryStreamValidatedTextToDestination(
                            candidate,
                            destinationDirectory,
                            volumeHandle,
                            candidateStart,
                            expectedLength,
                            markerEncoding,
                            cancellationToken,
                            out var destinationPath))
                    {
                        throw new InvalidOperationException(
                            "The marker was found at a possible file start, but the entire known-size range did not validate as text. " +
                            "No recovered output was retained.");
                    }

                    System.Diagnostics.Trace.WriteLine(
                        $"NTFS large exact-size text carve succeeded: candidate={candidate.FullPath}, " +
                        $"startOffset={candidateStart:N0}, expectedBytes={expectedLength:N0}, " +
                        $"destination={destinationPath}; content identity remains heuristic.");

                    return new RecoveryResult
                    {
                        Success = true,
                        SourcePath = candidate.FullPath,
                        DestinationPath = destinationPath,
                        BytesRecovered = expectedLength,
                        Evidence =
                            $"Recovered exactly {expectedLength:N0} bytes by streaming a marker-anchored text candidate " +
                            "from one contiguous, currently-free NTFS extent. Every byte validated as strict UTF-8/ASCII " +
                            "or the marker's UTF-16 encoding. Large plain-text files have no intrinsic end marker, so " +
                            "this remains heuristic file-identity evidence; verify the recovered SHA-256 when possible."
                    };
                }

                extentBytesRead = checked(extentBytesRead + buffer.Length);
                progress?.Report(Math.Min(totalVolumeBytes, checked(readOffset + buffer.Length)));

                previousTail = buffer.Length <= overlapLength
                    ? buffer
                    : buffer.AsSpan(buffer.Length - overlapLength).ToArray();
            }
        }

        progress?.Report(totalVolumeBytes);
        System.Diagnostics.Trace.WriteLine(
            $"NTFS large exact-size text carve complete: candidate={candidate.FullPath}, " +
            $"freeBytesVisited={freeBytesVisited:N0}, markerFound=false.");

        throw new InvalidOperationException(
            $"The start marker was not found in a currently-free NTFS extent large enough to hold the known " +
            $"{expectedLength:N0}-byte file. The large-file text carver requires a distinctive marker from the " +
            "very beginning of the file and one contiguous, currently-free extent.");
    }

    private RecoveryResult RecoverLargeKnownLengthTextFromRetainedExtentMap(
        RecoveryCandidate candidate,
        string destinationDirectory,
        (string Encoding, byte[] Bytes)[] markerVariants,
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        long expectedLength,
        CancellationToken cancellationToken,
        IProgress<long>? progress)
    {
        var snapshot = candidate.NtfsDataSnapshot
            ?? throw new InvalidOperationException("The retained NTFS deletion metadata is unavailable.");

        if (snapshot.FileSizeBytes != expectedLength)
        {
            throw new InvalidOperationException(
                $"The retained NTFS runlist size ({snapshot.FileSizeBytes:N0} bytes) does not match " +
                $"the supplied original size ({expectedLength:N0} bytes). The mapping was not used.");
        }

        if (snapshot.ValidDataLengthBytes < expectedLength)
        {
            throw new InvalidOperationException(
                $"The retained NTFS runlist reports only {snapshot.ValidDataLengthBytes:N0} valid data bytes " +
                $"for a {expectedLength:N0}-byte file. The mapping was not used.");
        }

        var bytesPerCluster = checked((long)volumeInfo.BytesPerCluster);
        if (bytesPerCluster <= 0 || volumeInfo.TotalClusters <= 0)
        {
            throw new InvalidOperationException("The source volume reported invalid cluster geometry.");
        }

        var requiredClusters = checked((expectedLength + bytesPerCluster - 1) / bytesPerCluster);
        var sourceExtents = snapshot.DataExtents
            .OrderBy(extent => extent.VirtualClusterNumber)
            .ToList();

        var mappedExtents = new List<NtfsDataExtent>();
        long nextVirtualCluster = 0;

        foreach (var sourceExtent in sourceExtents)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (nextVirtualCluster >= requiredClusters)
            {
                break;
            }

            if (sourceExtent.VirtualClusterNumber != nextVirtualCluster ||
                sourceExtent.ClusterCount <= 0 ||
                sourceExtent.IsSparse ||
                sourceExtent.LogicalClusterNumber < 0)
            {
                throw new InvalidOperationException(
                    "The retained NTFS runlist has a virtual-cluster gap, sparse run, invalid starting cluster, " +
                    "or non-positive extent length. Fragment reconstruction was refused.");
            }

            var clustersNeeded = checked(requiredClusters - nextVirtualCluster);
            var clustersToUse = Math.Min(sourceExtent.ClusterCount, clustersNeeded);

            if (sourceExtent.LogicalClusterNumber > volumeInfo.TotalClusters - clustersToUse)
            {
                throw new InvalidOperationException(
                    "The retained NTFS runlist points beyond the end of the source volume.");
            }

            mappedExtents.Add(new NtfsDataExtent
            {
                VirtualClusterNumber = sourceExtent.VirtualClusterNumber,
                LogicalClusterNumber = sourceExtent.LogicalClusterNumber,
                ClusterCount = clustersToUse
            });

            nextVirtualCluster = checked(nextVirtualCluster + clustersToUse);
        }

        if (nextVirtualCluster != requiredClusters || mappedExtents.Count == 0)
        {
            throw new InvalidOperationException(
                $"The retained NTFS runlist maps {nextVirtualCluster:N0} of the " +
                $"{requiredClusters:N0} required clusters. Fragment reconstruction was refused.");
        }

        var physicalExtents = mappedExtents
            .OrderBy(extent => extent.LogicalClusterNumber)
            .ToList();

        for (var index = 1; index < physicalExtents.Count; index++)
        {
            var previous = physicalExtents[index - 1];
            var current = physicalExtents[index];
            var previousEnd = checked(previous.LogicalClusterNumber + previous.ClusterCount);

            if (previousEnd > current.LogicalClusterNumber)
            {
                throw new InvalidOperationException(
                    "The retained NTFS runlist maps overlapping physical clusters. Fragment reconstruction was refused.");
            }
        }

        // Reading arbitrary clusters that have been reallocated can produce plausible but
        // unrelated text. Only reconstruct when every mapped cluster remains free according
        // to the current NTFS volume bitmap.
        var allocations = new NtfsVolumeBitmapReader().CheckExtents(
            volumeHandle,
            mappedExtents,
            cancellationToken);

        if (allocations.Count != mappedExtents.Count ||
            allocations.Where((allocation, index) =>
                    allocation.LogicalClusterNumber != mappedExtents[index].LogicalClusterNumber ||
                    allocation.ClusterCount != mappedExtents[index].ClusterCount ||
                    allocation.FreeClusterCount != allocation.ClusterCount ||
                    allocation.AllocatedClusterCount != 0 ||
                    allocation.Allocation == NtfsClusterAllocation.Unknown)
                .Any())
        {
            var freeClusters = allocations.Sum(allocation => allocation.FreeClusterCount);
            var allocatedClusters = allocations.Sum(allocation => allocation.AllocatedClusterCount);
            throw new InvalidOperationException(
                "The retained NTFS extent map exists, but not all original clusters are currently free " +
                $"(free={freeClusters:N0}, allocated={allocatedClusters:N0}, " +
                $"required={requiredClusters:N0}). To avoid reconstructing from potentially overwritten data, " +
                "the mapped recovery was stopped without repeating the whole-volume scan.");
        }

        var prefixLength = checked((int)Math.Min(
            (long)(MaxMarkerBytes + 3),
            expectedLength));
        var prefix = new byte[prefixLength];
        ReadMappedBytesAt(
            volumeHandle,
            mappedExtents,
            bytesPerCluster,
            0,
            prefix,
            cancellationToken);

        var markerEncoding = FindMarkerEncodingAtStart(prefix, markerVariants);
        if (markerEncoding is null)
        {
            throw new InvalidOperationException(
                "The retained NTFS runlist points to currently-free clusters, but the supplied marker does not " +
                "appear at byte zero (or immediately after a supported text BOM). The mapping was not used, " +
                "and the whole-volume scan was skipped to avoid another lengthy scan.");
        }

        System.Diagnostics.Trace.WriteLine(
            $"NTFS retained-runlist large text recovery started: path={candidate.FullPath}, " +
            $"expectedBytes={expectedLength:N0}, requiredClusters={requiredClusters:N0}, " +
            $"mappedExtents={mappedExtents.Count:N0}, currentlyFree=true, markerEncoding={markerEncoding}, " +
            "markerAtStart=true.");

        progress?.Report(0);

        if (!TryStreamValidatedMappedTextToDestination(
                candidate,
                destinationDirectory,
                volumeHandle,
                mappedExtents,
                bytesPerCluster,
                expectedLength,
                markerEncoding,
                cancellationToken,
                progress,
                out var destinationPath))
        {
            throw new InvalidOperationException(
                "The retained NTFS runlist contained the start marker, but the complete reconstructed file " +
                "did not pass strict text validation. The incomplete output was removed; the whole-volume " +
                "scan was skipped.");
        }

        // Recheck the volume bitmap after the full read. A concurrent allocation during
        // streaming means the original extents may have changed while they were being read.
        var finalAllocations = new NtfsVolumeBitmapReader().CheckExtents(
            volumeHandle,
            mappedExtents,
            cancellationToken);

        if (finalAllocations.Count != mappedExtents.Count ||
            finalAllocations.Where((allocation, index) =>
                    allocation.LogicalClusterNumber != mappedExtents[index].LogicalClusterNumber ||
                    allocation.ClusterCount != mappedExtents[index].ClusterCount ||
                    allocation.FreeClusterCount != allocation.ClusterCount ||
                    allocation.AllocatedClusterCount != 0 ||
                    allocation.Allocation != NtfsClusterAllocation.Free)
                .Any())
        {
            TryDelete(destinationPath);
            throw new InvalidOperationException(
                "The NTFS volume bitmap changed while the retained extents were being read. " +
                "The recovered output was removed because some original clusters may have been reused.");
        }

        progress?.Report(expectedLength);

        System.Diagnostics.Trace.WriteLine(
            $"NTFS retained-runlist large text recovery succeeded: path={candidate.FullPath}, " +
            $"bytes={expectedLength:N0}, mappedExtents={mappedExtents.Count:N0}, " +
            $"destination={destinationPath}; original content hash not independently known.");

        return new RecoveryResult
        {
            Success = true,
            SourcePath = candidate.FullPath,
            DestinationPath = destinationPath,
            BytesRecovered = expectedLength,
            Evidence =
                $"Reconstructed exactly {expectedLength:N0} bytes from {mappedExtents.Count:N0} retained deletion-time " +
                "NTFS data extents in original virtual-cluster order. All mapped clusters were currently free, " +
                "the supplied marker matched at logical byte zero, and the complete output passed strict text " +
                "validation. Verify the recovered SHA-256 against a known original hash where available; this " +
                "does not independently prove that every free cluster retained its original contents."
        };
    }

    private static string? FindMarkerEncodingAtStart(
        byte[] prefix,
        (string Encoding, byte[] Bytes)[] markerVariants)
    {
        foreach (var variant in markerVariants)
        {
            if (prefix.AsSpan().StartsWith(variant.Bytes))
            {
                return variant.Encoding;
            }

            byte[] bom = variant.Encoding switch
            {
                "UTF-8" => [0xEF, 0xBB, 0xBF],
                "UTF-16LE" => [0xFF, 0xFE],
                "UTF-16BE" => [0xFE, 0xFF],
                _ => []
            };

            if (bom.Length > 0 &&
                prefix.Length >= bom.Length + variant.Bytes.Length &&
                prefix.AsSpan(0, bom.Length).SequenceEqual(bom) &&
                prefix.AsSpan(bom.Length).StartsWith(variant.Bytes))
            {
                return variant.Encoding;
            }
        }

        return null;
    }

    private static void ReadMappedBytesAt(
        SafeFileHandle volumeHandle,
        IReadOnlyList<NtfsDataExtent> extents,
        long bytesPerCluster,
        long logicalOffset,
        byte[] destination,
        CancellationToken cancellationToken)
    {
        if (logicalOffset < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(logicalOffset));
        }

        var copied = 0;
        var currentLogicalOffset = logicalOffset;

        foreach (var extent in extents)
        {
            var extentVirtualStart = checked(extent.VirtualClusterNumber * bytesPerCluster);
            var extentLength = checked(extent.ClusterCount * bytesPerCluster);
            var extentVirtualEnd = checked(extentVirtualStart + extentLength);

            if (currentLogicalOffset >= extentVirtualEnd)
            {
                continue;
            }

            if (currentLogicalOffset < extentVirtualStart)
            {
                throw new InvalidOperationException(
                    "The retained NTFS runlist contains a gap while reading its logical file data.");
            }

            var offsetWithinExtent = checked(currentLogicalOffset - extentVirtualStart);
            var count = checked((int)Math.Min(
                (long)(destination.Length - copied),
                extentLength - offsetWithinExtent));

            if (count <= 0)
            {
                continue;
            }

            var chunk = new byte[count];
            var physicalOffset = checked(
                extent.LogicalClusterNumber * bytesPerCluster + offsetWithinExtent);

            ReadAt(volumeHandle, physicalOffset, chunk, cancellationToken);
            Buffer.BlockCopy(chunk, 0, destination, copied, count);
            copied += count;
            currentLogicalOffset = checked(currentLogicalOffset + count);

            if (copied == destination.Length)
            {
                return;
            }
        }

        throw new IOException(
            $"The retained NTFS runlist supplied only {copied:N0} byte(s) for a {destination.Length:N0}-byte prefix read.");
    }

    private static bool TryStreamValidatedMappedTextToDestination(
        RecoveryCandidate candidate,
        string destinationDirectory,
        SafeFileHandle volumeHandle,
        IReadOnlyList<NtfsDataExtent> extents,
        long bytesPerCluster,
        long expectedLength,
        string markerEncoding,
        CancellationToken cancellationToken,
        IProgress<long>? progress,
        out string destinationPath)
    {
        destinationPath = string.Empty;

        System.Text.Encoding strictEncoding = markerEncoding switch
        {
            "UTF-16LE" => new System.Text.UnicodeEncoding(false, false, true),
            "UTF-16BE" => new System.Text.UnicodeEncoding(true, false, true),
            _ => new System.Text.UTF8Encoding(false, true)
        };

        var decoder = strictEncoding.GetDecoder();
        var byteBuffer = new byte[IoBufferSize];
        var charBuffer = new char[IoBufferSize];

        destinationPath = RecoveryDestinationPolicy.CreateSafeFilePath(
            destinationDirectory,
            candidate.Name);

        var completedSuccessfully = false;
        var destinationCreated = false;

        try
        {
            using var output = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                IoBufferSize,
                FileOptions.SequentialScan);
            destinationCreated = true;

            long consumed = 0;
            var nextProgressReport = (long)ProgressIntervalBytes;

            foreach (var extent in extents)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var extentBytes = checked(extent.ClusterCount * bytesPerCluster);
                var bytesInThisExtent = Math.Min(extentBytes, expectedLength - consumed);
                long consumedInExtent = 0;

                while (consumedInExtent < bytesInThisExtent)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var count = checked((int)Math.Min(
                        (long)byteBuffer.Length,
                        bytesInThisExtent - consumedInExtent));

                    if (markerEncoding.StartsWith("UTF-16", StringComparison.Ordinal))
                    {
                        count -= count % 2;
                    }

                    if (count <= 0)
                    {
                        return false;
                    }

                    var chunkBytes = count == byteBuffer.Length
                        ? byteBuffer
                        : new byte[count];

                    var physicalOffset = checked(
                        extent.LogicalClusterNumber * bytesPerCluster + consumedInExtent);

                    ReadAt(volumeHandle, physicalOffset, chunkBytes, cancellationToken);

                    var flush = consumed + count == expectedLength;

                    try
                    {
                        decoder.Convert(
                            chunkBytes,
                            0,
                            count,
                            charBuffer,
                            0,
                            charBuffer.Length,
                            flush,
                            out var bytesUsed,
                            out var charsUsed,
                            out var completed);

                        if (bytesUsed != count || !completed)
                        {
                            return false;
                        }

                        for (var index = 0; index < charsUsed; index++)
                        {
                            var character = charBuffer[index];
                            if (character is not ('\t' or '\r' or '\n') &&
                                (char.IsControl(character) || character == '\uFFFD'))
                            {
                                return false;
                            }
                        }
                    }
                    catch (System.Text.DecoderFallbackException)
                    {
                        return false;
                    }

                    output.Write(chunkBytes, 0, count);
                    consumed = checked(consumed + count);
                    consumedInExtent = checked(consumedInExtent + count);

                    if (consumed >= nextProgressReport || consumed == expectedLength)
                    {
                        progress?.Report(consumed);
                        nextProgressReport = checked(consumed + ProgressIntervalBytes);
                    }
                }

                if (consumed >= expectedLength)
                {
                    break;
                }

                if (consumedInExtent != bytesInThisExtent)
                {
                    return false;
                }
            }

            if (consumed != expectedLength)
            {
                return false;
            }

            output.Flush();
            completedSuccessfully = true;
        }
        finally
        {
            if (!completedSuccessfully && destinationCreated)
            {
                TryDelete(destinationPath);
            }
        }

        return completedSuccessfully;
    }

    private static bool TryStreamValidatedTextToDestination(
        RecoveryCandidate candidate,
        string destinationDirectory,
        SafeFileHandle volumeHandle,
        long sourceOffset,
        long expectedLength,
        string markerEncoding,
        CancellationToken cancellationToken,
        out string destinationPath)
    {
        destinationPath = string.Empty;
        System.Text.Encoding strictEncoding = markerEncoding switch
        {
            "UTF-16LE" => new System.Text.UnicodeEncoding(false, false, true),
            "UTF-16BE" => new System.Text.UnicodeEncoding(true, false, true),
            _ => new System.Text.UTF8Encoding(false, true)
        };
        var decoder = strictEncoding.GetDecoder();
        var byteBuffer = new byte[IoBufferSize];
        var charBuffer = new char[IoBufferSize];

        destinationPath = RecoveryDestinationPolicy.CreateSafeFilePath(
            destinationDirectory,
            candidate.Name);

        var completedSuccessfully = false;
        var destinationCreated = false;
        try
        {
            using var output = new FileStream(
                destinationPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                IoBufferSize,
                FileOptions.SequentialScan);
            destinationCreated = true;

            long consumed = 0;
            while (consumed < expectedLength)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var count = checked((int)Math.Min(byteBuffer.Length, expectedLength - consumed));
                if (markerEncoding.StartsWith("UTF-16", StringComparison.Ordinal))
                {
                    count -= count % 2;
                }

                if (count <= 0)
                {
                    return false;
                }

                var chunkBytes = count == byteBuffer.Length
                    ? byteBuffer
                    : new byte[count];

                ReadAt(
                    volumeHandle,
                    checked(sourceOffset + consumed),
                    chunkBytes,
                    cancellationToken);

                var flush = consumed + count == expectedLength;
                try
                {
                    decoder.Convert(
                        chunkBytes,
                        0,
                        count,
                        charBuffer,
                        0,
                        charBuffer.Length,
                        flush,
                        out var bytesUsed,
                        out var charsUsed,
                        out var completed);

                    if (bytesUsed != count || !completed)
                    {
                        return false;
                    }

                    for (var i = 0; i < charsUsed; i++)
                    {
                        var character = charBuffer[i];
                        if (character is not ('\t' or '\r' or '\n') &&
                            (char.IsControl(character) || character == '\uFFFD'))
                        {
                            return false;
                        }
                    }
                }
                catch (System.Text.DecoderFallbackException)
                {
                    return false;
                }

                output.Write(chunkBytes, 0, count);
                consumed = checked(consumed + count);
            }

            output.Flush();
            completedSuccessfully = true;
        }
        finally
        {
            if (!completedSuccessfully && destinationCreated)
            {
                TryDelete(destinationPath);
            }
        }

        return completedSuccessfully;
    }

    private static bool LooksLikeStrictTextSample(
        byte[] sample,
        System.Text.Encoding encoding)
    {
        try
        {
            var text = encoding.GetString(sample);
            foreach (var character in text)
            {
                if (character is not ('\t' or '\r' or '\n') &&
                    (char.IsControl(character) || character == '\uFFFD'))
                {
                    return false;
                }
            }

            return true;
        }
        catch (System.Text.DecoderFallbackException)
        {
            return false;
        }
    }

    public (bool Found, long Offset, string? Encoding, long ScannedBytes) FindMarkerOnVolume(
        string sourcePath,
        string marker,
        CancellationToken cancellationToken = default,
        IProgress<long>? progress = null)
    {
        if (string.IsNullOrWhiteSpace(sourcePath))
        {
            throw new ArgumentException("A source path is required.", nameof(sourcePath));
        }

        if (string.IsNullOrWhiteSpace(marker))
        {
            throw new ArgumentException("A marker is required.", nameof(marker));
        }

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

        var sourceRoot = GetNtfsVolumeRoot(sourcePath);
        if (string.IsNullOrWhiteSpace(sourceRoot))
        {
            throw new InvalidOperationException(
                "The source path is not on a valid Windows volume.");
        }

        WindowsPrivilege.EnableSeBackupPrivilege();

        var volumeInfo = new NtfsVolumeInspector().Inspect(sourceRoot);
        var totalVolumeBytes = checked(
            volumeInfo.TotalClusters * (long)volumeInfo.BytesPerCluster);

        using var volumeHandle = CreateVolumeHandle(sourceRoot);

        var overlapLength = markerVariants.Max(item => item.Bytes.Length) - 1;
        var previousTail = Array.Empty<byte>();
        long scannedBytes = 0;
        long lastReportedBytes = 0;

        progress?.Report(0);

        while (scannedBytes < totalVolumeBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var remaining = totalVolumeBytes - scannedBytes;
            var bytesToRead = (int)Math.Min(IoBufferSize, remaining);
            bytesToRead -= bytesToRead % checked((int)volumeInfo.BytesPerCluster);

            if (bytesToRead < volumeInfo.BytesPerCluster)
            {
                break;
            }

            var physicalOffset = scannedBytes;
            byte[]? buffer = null;
            var attemptedBytes = bytesToRead;

            while (attemptedBytes >= volumeInfo.BytesPerCluster)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    buffer = new byte[attemptedBytes];
                    ReadAt(
                        volumeHandle,
                        physicalOffset,
                        buffer,
                        cancellationToken);
                    break;
                }
                catch (Win32Exception)
                {
                    attemptedBytes /= 2;
                    attemptedBytes -=
                        attemptedBytes % checked((int)volumeInfo.BytesPerCluster);
                }
            }

            if (buffer is null)
            {
                scannedBytes = checked(
                    scannedBytes + volumeInfo.BytesPerCluster);
                previousTail = [];
                continue;
            }

            var window = new byte[checked(previousTail.Length + buffer.Length)];

            if (previousTail.Length > 0)
            {
                Buffer.BlockCopy(
                    previousTail,
                    0,
                    window,
                    0,
                    previousTail.Length);
            }

            Buffer.BlockCopy(
                buffer,
                0,
                window,
                previousTail.Length,
                buffer.Length);

            foreach (var markerVariant in markerVariants)
            {
                var markerOffset = window.AsSpan().IndexOf(markerVariant.Bytes);
                if (markerOffset < 0)
                {
                    continue;
                }

                var absoluteOffset = checked(
                    physicalOffset -
                    previousTail.Length +
                    markerOffset);

                if (IsUtf16Encoding(markerVariant.Encoding) &&
                    (absoluteOffset & 1L) != 0)
                {
                    continue;
                }

                scannedBytes = checked(scannedBytes + buffer.Length);
                progress?.Report(scannedBytes);

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS raw live marker diagnostic: " +
                    $"source={sourcePath}, encoding={markerVariant.Encoding}, " +
                    $"offset={absoluteOffset:N0}.");

                return (
                    true,
                    absoluteOffset,
                    markerVariant.Encoding,
                    scannedBytes);
            }

            scannedBytes = checked(scannedBytes + buffer.Length);

            if (scannedBytes - lastReportedBytes >= ProgressIntervalBytes ||
                scannedBytes == totalVolumeBytes)
            {
                lastReportedBytes = scannedBytes;
                progress?.Report(scannedBytes);
            }

            previousTail = buffer.Length <= overlapLength
                ? buffer
                : buffer.AsSpan(buffer.Length - overlapLength).ToArray();
        }

        progress?.Report(scannedBytes);

        System.Diagnostics.Debug.WriteLine(
            $"NTFS raw live marker diagnostic complete: " +
            $"source={sourcePath}, scanned={scannedBytes:N0}, found=false.");

        return (false, -1, null, scannedBytes);
    }

    private static RecoveryResult RecoverTextRegionFromScannedBuffer(
        RecoveryCandidate candidate,
        string destinationDirectory,
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle volumeHandle,
        byte[] markerBytes,
        string markerEncoding,
        byte[] scanWindow,
        long scanWindowAbsoluteOffset,
        int markerOffsetInWindow,
        CancellationToken cancellationToken)
    {
        if (markerOffsetInWindow < 0 ||
            markerOffsetInWindow + markerBytes.Length > scanWindow.Length)
        {
            throw new InvalidOperationException(
                "The matched marker fell outside the scanned NTFS buffer.");
        }

        if (!scanWindow.AsSpan(
                markerOffsetInWindow,
                markerBytes.Length)
            .SequenceEqual(markerBytes))
        {
            throw new InvalidOperationException(
                "The matched marker could not be validated in the scanned NTFS buffer.");
        }

        var (start, end) = FindTextRegionBounds(
            scanWindow,
            markerOffsetInWindow,
            markerBytes.Length,
            markerEncoding);

        var recoveredLength = end - start;
        if (recoveredLength < markerBytes.Length)
        {
            start = markerOffsetInWindow;
            end = markerOffsetInWindow + markerBytes.Length;
            recoveredLength = markerBytes.Length;
        }

        if (recoveredLength > MaxRecoveredTextBytes)
        {
            throw new InvalidOperationException(
                $"The text region containing the marker exceeds the {MaxRecoveredTextBytes:N0}-byte forensic recovery limit.");
        }

        if (candidate.FileSizeBytes > 0 &&
            recoveredLength != candidate.FileSizeBytes)
        {
            throw new MarkerRecoverySizeMismatchException(
                recoveredLength,
                candidate.FileSizeBytes);
        }

        var absoluteStart = checked(scanWindowAbsoluteOffset + start);
        var absoluteEnd = checked(scanWindowAbsoluteOffset + end);

        var firstCluster = absoluteStart / volumeInfo.BytesPerCluster;
        var lastClusterExclusive = checked(
            (absoluteEnd + volumeInfo.BytesPerCluster - 1) /
            volumeInfo.BytesPerCluster);
        var clusterCount = checked(lastClusterExclusive - firstCluster);

        if (clusterCount <= 0)
        {
            throw new InvalidOperationException(
                "The matched NTFS text region did not map to a valid cluster range.");
        }

        var allocation = new NtfsVolumeBitmapReader().CheckExtents(
            volumeHandle,
            [
                new NtfsDataExtent
                {
                    VirtualClusterNumber = 0,
                    LogicalClusterNumber = firstCluster,
                    ClusterCount = clusterCount
                }
            ],
            cancellationToken);

        if (allocation.Count != 1)
        {
            throw new InvalidOperationException(
                "The matched NTFS text region could not be classified by the volume bitmap.");
        }

        var allocatedClusters = allocation[0].AllocatedClusterCount;
        var freeClusters = allocation[0].FreeClusterCount;

        var data = scanWindow.AsSpan(start, recoveredLength).ToArray();
        var destinationPath = RecoveryDestinationPolicy.CreateSafeFilePath(
            destinationDirectory,
            candidate.Name);

        try
        {
            File.WriteAllBytes(destinationPath, data);
        }
        catch
        {
            TryDelete(destinationPath);
            throw;
        }

        var allocationDescription =
            allocatedClusters > 0 && freeClusters > 0
                ? $"The recovered text spans both allocated and free clusters ({allocatedClusters:N0} allocated, {freeClusters:N0} free)."
                : allocatedClusters > 0
                    ? $"The matched text currently resides in allocated NTFS clusters ({allocatedClusters:N0} cluster(s)). It may be retained inside another live file and is therefore marker-confirmed but not historical file-identity proof."
                    : $"The matched text currently resides in free NTFS clusters ({freeClusters:N0} cluster(s)).";

        return new RecoveryResult
        {
            Success = true,
            SourcePath = candidate.FullPath,
            DestinationPath = destinationPath,
            BytesRecovered = data.Length,
            Evidence =
                $"Whole-volume forensic text scan found the supplied marker at byte " +
                $"{scanWindowAbsoluteOffset + markerOffsetInWindow:N0} using {markerEncoding} " +
                $"and recovered {data.Length:N0} contiguous text byte(s) directly from " +
                $"the verified raw scan buffer. " +
                allocationDescription
        };
    }


    private static (int Start, int End) FindTextRegionBounds(
        byte[] buffer,
        int markerOffset,
        int markerLength,
        string encoding)
    {
        if (string.Equals(
                encoding,
                "UTF-16LE",
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(
                encoding,
                "UTF-16BE",
                StringComparison.OrdinalIgnoreCase))
        {
            var littleEndian = string.Equals(
                encoding,
                "UTF-16LE",
                StringComparison.OrdinalIgnoreCase);

            var start = markerOffset;

            // Walk backwards in UTF-16 code units rather than individual bytes.
            while (start >= 2 &&
                   IsUtf16TextCodeUnit(
                       buffer,
                       start - 2,
                       littleEndian))
            {
                start -= 2;
            }

            // Include a UTF-16 BOM when it is immediately before the text.
            if (start >= 2)
            {
                var bom1 = buffer[start - 2];
                var bom2 = buffer[start - 1];

                var hasBom = littleEndian
                    ? bom1 == 0xFF && bom2 == 0xFE
                    : bom1 == 0xFE && bom2 == 0xFF;

                if (hasBom)
                {
                    start -= 2;
                }
            }

            var end = checked(markerOffset + markerLength);

            // Walk forwards in UTF-16 code units.
            while (end + 2 <= buffer.Length &&
                   IsUtf16TextCodeUnit(
                       buffer,
                       end,
                       littleEndian))
            {
                end += 2;
            }

            return (start, end);
        }

        var plainStart = markerOffset;

        while (plainStart > 0 &&
               IsPlainTextByte(buffer[plainStart - 1]))
        {
            plainStart--;
        }

        var plainEnd = checked(markerOffset + markerLength);

        while (plainEnd < buffer.Length &&
               IsPlainTextByte(buffer[plainEnd]))
        {
            plainEnd++;
        }

        return (plainStart, plainEnd);
    }

    private static bool IsUtf16Encoding(string encoding) =>
        string.Equals(encoding, "UTF-16LE", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(encoding, "UTF-16BE", StringComparison.OrdinalIgnoreCase);

    private sealed class MarkerRecoverySizeMismatchException : Exception
    {
        public MarkerRecoverySizeMismatchException(
            int recoveredBytes,
            long expectedBytes)
            : base(
                $"Marker region size mismatch: recovered={recoveredBytes:N0}, expected={expectedBytes:N0}.")
        {
            RecoveredBytes = recoveredBytes;
        }

        public int RecoveredBytes { get; }
    }

    private static bool IsUtf16TextCodeUnit(
        byte[] buffer,
        int offset,
        bool littleEndian)
    {
        if (offset < 0 || offset + 1 >= buffer.Length)
        {
            return false;
        }

        ushort value = littleEndian
            ? (ushort)(buffer[offset] |
                       (buffer[offset + 1] << 8))
            : (ushort)((buffer[offset] << 8) |
                       buffer[offset + 1]);

        return value is 0x0009 or 0x000A or 0x000D ||
               value is >= 0x0020 and <= 0x007E;
    }

    private static bool IsPlainTextByte(byte value) =>
        value is 0x09 or 0x0A or 0x0D ||
        value is >= 0x20 and <= 0x7E;

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

    private static SafeFileHandle CreateVolumeHandle(string root)
    {
        var volumeName = root.TrimEnd(Path.DirectorySeparatorChar);

        var handle = CreateFile(
            $@"\\.\{volumeName[..2]}",
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);

        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();

            throw new Win32Exception(
                error,
                $"Could not open NTFS source volume {root} for whole-volume forensic scanning.");
        }

        return handle;
    }

    private static void ReadAt(
        SafeFileHandle volumeHandle,
        long offset,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        var remaining = buffer.Length;
        var currentOffset = offset;
        var bufferOffset = 0;

        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var chunk = Math.Min(IoBufferSize, remaining);

            if (!SetFilePointerEx(
                    volumeHandle,
                    currentOffset,
                    out _,
                    0))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not seek to NTFS volume byte offset {currentOffset:N0}.");
            }

            var chunkBuffer = bufferOffset == 0 && chunk == buffer.Length
                ? buffer
                : new byte[chunk];

            if (!ReadFile(
                    volumeHandle,
                    chunkBuffer,
                    (uint)chunk,
                    out var bytesRead,
                    IntPtr.Zero) ||
                bytesRead != (uint)chunk)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"Could not read NTFS volume data at byte offset {currentOffset:N0}.");
            }

            if (!ReferenceEquals(chunkBuffer, buffer))
            {
                Buffer.BlockCopy(
                    chunkBuffer,
                    0,
                    buffer,
                    bufferOffset,
                    chunk);
            }

            currentOffset = checked(currentOffset + chunk);
            bufferOffset += chunk;
            remaining -= chunk;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
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
    private static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);
}
