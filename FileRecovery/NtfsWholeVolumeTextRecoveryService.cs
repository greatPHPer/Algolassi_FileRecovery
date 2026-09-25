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
            return RecoverTextRegionWithoutMarker(
                candidate,
                destinationDirectory,
                cancellationToken,
                progress);
        }

        if (string.IsNullOrWhiteSpace(marker))
        {
            return RecoverTextRegionWithoutMarker(
                candidate,
                destinationDirectory,
                cancellationToken,
                progress);
        }

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

            (string Encoding, byte[] Bytes)? matchedMarker = null;
            var markerOffsetInWindow = -1;

            foreach (var markerVariant in markerVariants)
            {
                var candidateOffset = window.AsSpan().IndexOf(markerVariant.Bytes);
                if (candidateOffset < 0)
                {
                    continue;
                }

                if (markerOffsetInWindow < 0 || candidateOffset < markerOffsetInWindow)
                {
                    markerOffsetInWindow = candidateOffset;
                    matchedMarker = markerVariant;
                }
            }

            scannedBytes = checked(scannedBytes + bytesRead);

            if (scannedBytes - lastReportedBytes >= ProgressIntervalBytes ||
                scannedBytes == totalVolumeBytes)
            {
                lastReportedBytes = scannedBytes;
                progress?.Report(scannedBytes);
            }

            if (matchedMarker.HasValue && markerOffsetInWindow >= 0)
            {
                var absoluteMarkerOffset = checked(
                    physicalOffset -
                    previousTail.Length +
                    markerOffsetInWindow);

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

                System.Diagnostics.Debug.WriteLine(
                    $"NTFS whole-volume target scan hit: " +
                    $"candidate={candidate.FullPath}, " +
                    $"encoding={matchedMarker.Value.Encoding}, " +
                    $"markerOffset={absoluteMarkerOffset:N0}, " +
                    $"scanned={scannedBytes:N0}.");

                return recovery;
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
            $"The supplied text marker was not found in the first " +
            $"{scannedBytes:N0} byte(s) of the NTFS volume.");
    }

    private RecoveryResult RecoverTextRegionWithoutMarker(
        RecoveryCandidate candidate,
        string destinationDirectory,
        CancellationToken cancellationToken,
        IProgress<long>? progress)
    {
        const int minimumCandidateBytes = 4096;

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

        long scannedBytes = 0;
        long lastReportedBytes = 0;
        var best = new TextRegionCandidate(-1, 0, string.Empty);

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
                    ReadAt(volumeHandle, physicalOffset, buffer, cancellationToken);
                    break;
                }
                catch (Win32Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine(
                        $"NTFS whole-volume text-region scan read retry: " +
                        $"offset={physicalOffset:N0}, requested={attemptedBytes:N0}, " +
                        $"error={ex.NativeErrorCode}, message={ex.Message}.");

                    attemptedBytes /= 2;
                    attemptedBytes -=
                        attemptedBytes % checked((int)volumeInfo.BytesPerCluster);
                }
            }

            if (buffer is null)
            {
                scannedBytes = checked(
                    scannedBytes + volumeInfo.BytesPerCluster);

                if (scannedBytes - lastReportedBytes >= ProgressIntervalBytes ||
                    scannedBytes == totalVolumeBytes)
                {
                    lastReportedBytes = scannedBytes;
                    progress?.Report(scannedBytes);
                }

                continue;
            }

            var regions = FindTextRegions(
                buffer,
                physicalOffset,
                minimumCandidateBytes);

            foreach (var region in regions)
            {
                if (region.Length > best.Length)
                {
                    best = region;
                }
            }

            scannedBytes = checked(scannedBytes + buffer.Length);

            if (scannedBytes - lastReportedBytes >= ProgressIntervalBytes ||
                scannedBytes == totalVolumeBytes)
            {
                lastReportedBytes = scannedBytes;
                progress?.Report(scannedBytes);
            }
        }

        progress?.Report(scannedBytes);

        if (best.Offset < 0 || best.Length < minimumCandidateBytes)
        {
            throw new InvalidOperationException(
                $"No text-like region of at least {minimumCandidateBytes:N0} byte(s) was found in the first " +
                $"{scannedBytes:N0} byte(s) of the NTFS volume.");
        }

        var recoveredData = new byte[best.Length];
        ReadAt(volumeHandle, best.Offset, recoveredData, cancellationToken);

        var destinationPath = RecoveryDestinationPolicy.CreateSafeFilePath(
            destinationDirectory,
            candidate.Name);

        try
        {
            File.WriteAllBytes(destinationPath, recoveredData);
        }
        catch
        {
            TryDelete(destinationPath);
            throw;
        }

        var firstCluster = best.Offset / volumeInfo.BytesPerCluster;
        var lastClusterExclusive = checked(
            (best.Offset + best.Length + volumeInfo.BytesPerCluster - 1) /
            volumeInfo.BytesPerCluster);
        var clusterCount = checked(lastClusterExclusive - firstCluster);

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

        var allocationDescription = allocation.Count == 1
            ? $"Bitmap classification: {allocation[0].AllocatedClusterCount:N0} allocated cluster(s), {allocation[0].FreeClusterCount:N0} free cluster(s)."
            : "Bitmap classification was unavailable for the selected region.";

        return new RecoveryResult
        {
            Success = true,
            SourcePath = candidate.FullPath,
            DestinationPath = destinationPath,
            BytesRecovered = recoveredData.Length,
            Evidence =
                $"Whole-volume forensic text-region scan found the longest qualifying " +
                $"{best.Encoding} text-like region at raw byte offset {best.Offset:N0} and " +
                $"recovered {recoveredData.Length:N0} contiguous byte(s). No content marker " +
                $"was supplied, so this is heuristic evidence and cannot prove that the " +
                $"region belongs to the deleted '{candidate.Name}'. {allocationDescription}"
        };
    }

    private static IReadOnlyList<TextRegionCandidate> FindTextRegions(
        byte[] buffer,
        long absoluteOffset,
        int minimumLength)
    {
        var regions = new List<TextRegionCandidate>();

        AddBestUtf8Region(buffer, absoluteOffset, minimumLength, regions);
        AddBestUtf16Region(buffer, absoluteOffset, minimumLength, true, regions);
        AddBestUtf16Region(buffer, absoluteOffset, minimumLength, false, regions);

        return regions;
    }

    private static void AddBestUtf8Region(
        byte[] buffer,
        long absoluteOffset,
        int minimumLength,
        List<TextRegionCandidate> regions)
    {
        var runStart = -1;
        var position = 0;

        while (position < buffer.Length)
        {
            var sequenceLength = GetUtf8SequenceLength(buffer, position);

            if (sequenceLength <= 0)
            {
                if (runStart >= 0)
                {
                    AddRegion(
                        regions,
                        absoluteOffset + runStart,
                        position - runStart,
                        "UTF-8",
                        minimumLength);
                }

                runStart = -1;
                position++;
                continue;
            }

            if (runStart < 0)
            {
                runStart = position;
            }

            position += sequenceLength;
        }

        if (runStart >= 0)
        {
            AddRegion(
                regions,
                absoluteOffset + runStart,
                position - runStart,
                "UTF-8",
                minimumLength);
        }
    }

    private static void AddBestUtf16Region(
        byte[] buffer,
        long absoluteOffset,
        int minimumLength,
        bool littleEndian,
        List<TextRegionCandidate> regions)
    {
        var bestStart = -1;
        var bestLength = 0;

        for (var alignment = 0; alignment < 2; alignment++)
        {
            var runStart = -1;
            var position = alignment;

            while (position + 1 < buffer.Length)
            {
                if (IsUtf16TextUnit(buffer, position, littleEndian))
                {
                    if (runStart < 0)
                    {
                        runStart = position;
                    }

                    position += 2;
                    continue;
                }

                if (runStart >= 0)
                {
                    var runLength = position - runStart;
                    if (runLength > bestLength)
                    {
                        bestStart = runStart;
                        bestLength = runLength;
                    }
                }

                runStart = -1;
                position += 2;
            }

            if (runStart >= 0)
            {
                var runLength = position - runStart;
                if (runLength > bestLength)
                {
                    bestStart = runStart;
                    bestLength = runLength;
                }
            }
        }

        if (bestStart >= 0)
        {
            AddRegion(
                regions,
                absoluteOffset + bestStart,
                bestLength,
                littleEndian ? "UTF-16LE" : "UTF-16BE",
                minimumLength);
        }
    }

    private static void AddRegion(
        List<TextRegionCandidate> regions,
        long offset,
        int length,
        string encoding,
        int minimumLength)
    {
        if (length >= minimumLength)
        {
            regions.Add(new TextRegionCandidate(offset, length, encoding));
        }
    }

    private static int GetUtf8SequenceLength(
        byte[] buffer,
        int position)
    {
        var value = buffer[position];

        if (value is 0x09 or 0x0A or 0x0D ||
            value is >= 0x20 and <= 0x7E)
        {
            return 1;
        }

        if (value is < 0xC2 or > 0xF4)
        {
            return 0;
        }

        var length =
            value <= 0xDF ? 2 :
            value <= 0xEF ? 3 : 4;

        if (position + length > buffer.Length)
        {
            return 0;
        }

        for (var i = 1; i < length; i++)
        {
            if (buffer[position + i] < 0x80 ||
                buffer[position + i] > 0xBF)
            {
                return 0;
            }
        }

        return length;
    }

    private readonly record struct TextRegionCandidate(
        long Offset,
        int Length,
        string Encoding);

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

        var start = markerOffsetInWindow;
        var end = markerOffsetInWindow + markerBytes.Length;

        if (markerEncoding.Equals("UTF-16LE", StringComparison.OrdinalIgnoreCase) ||
            markerEncoding.Equals("UTF-16BE", StringComparison.OrdinalIgnoreCase))
        {
            // UTF-16 stores ASCII-range text as two-byte code units, so every other
            // byte can legitimately be 0x00. The old byte-by-byte text test stopped
            // immediately at those zeros and therefore recovered only the marker itself.
            // Expand in whole UTF-16 code units around the matched marker.
            var littleEndian =
                markerEncoding.Equals("UTF-16LE", StringComparison.OrdinalIgnoreCase);

            while (start >= 2 &&
                   IsUtf16TextUnit(
                       scanWindow,
                       start - 2,
                       littleEndian))
            {
                start -= 2;
            }

            while (end + 1 < scanWindow.Length &&
                   IsUtf16TextUnit(
                       scanWindow,
                       end,
                       littleEndian))
            {
                end += 2;
            }
        }
        else
        {
            while (start > 0 && IsPlainTextByte(scanWindow[start - 1]))
            {
                start--;
            }

            while (end < scanWindow.Length && IsPlainTextByte(scanWindow[end]))
            {
                end++;
            }
        }

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

    private static bool IsPlainTextByte(byte value) =>
        value is 0x09 or 0x0A or 0x0D ||
        value is >= 0x20 and <= 0x7E;

    private static bool IsUtf16TextUnit(
        byte[] buffer,
        int offset,
        bool littleEndian)
    {
        if (offset < 0 || offset + 1 >= buffer.Length)
        {
            return false;
        }

        var codeUnit = littleEndian
            ? (ushort)(buffer[offset] | (buffer[offset + 1] << 8))
            : (ushort)((buffer[offset] << 8) | buffer[offset + 1]);

        return codeUnit is 0x0009 or 0x000A or 0x000D ||
               codeUnit is >= 0x0020 and <= 0x007E ||
               codeUnit is >= 0x00A0 and <= 0xD7FF ||
               codeUnit is >= 0xE000 and <= 0xFFFD;

    private static string? GetNtfsVolumeRoot(string path)
    {
        var normalized = path.Trim();

        while (normalized.StartsWith(@"\\?\", StringComparison.Ordinal) ||
               normalized.StartsWith(@"\\.\", StringComparison.Ordinal))
        {
            normalized = normalized[4..];
        }

        var root = Path.GetPathRoot(normalized);

        if (root is { Length: 2 } &&
            root[1] == ':')
        {
            root += Path.DirectorySeparatorChar;
        }

        return root;
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
