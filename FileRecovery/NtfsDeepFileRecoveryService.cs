using System.Runtime.InteropServices;
using System.Buffers.Binary;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;

namespace FileRecovery;

public sealed class NtfsDeepFileRecoveryService
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    private const int IoBufferSize = 4 * 1024 * 1024;
    public const long DefaultMaxBytesToScan = long.MaxValue;
    private const long MaxCarvedFileBytes = 64L * 1024L * 1024L;

    public RecoveryResult Recover(
        RecoveryCandidate candidate,
        string destinationDirectory,
        CancellationToken cancellationToken = default,
        long maxBytesToScan = DefaultMaxBytesToScan,
        IProgress<long>? progress = null,
        long knownFileSizeBytes = 0)
    {
        ArgumentNullException.ThrowIfNull(candidate);

        if (candidate.DataStreamFound)
        {
            throw new InvalidOperationException(
                "Deep NTFS carving is only required for candidates without retained NTFS $DATA evidence.");
        }

        if (maxBytesToScan <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytesToScan));
        }

        RecoveryDestinationPolicy.Validate(candidate.FullPath, destinationDirectory);

        var extension = Path.GetExtension(candidate.Name);

        // Do not reject an unfamiliar suffix here. TryCarve validates known
        // formats from their byte signatures, then permits a conservative,
        // exact-length text fallback for small files with a known original size.
        // Unsupported binary formats (including RAR) still need a dedicated parser.

        WindowsPrivilege.EnableSeBackupPrivilege();

        var sourceRoot = GetNtfsVolumeRoot(candidate.FullPath);
        if (string.IsNullOrWhiteSpace(sourceRoot))
        {
            throw new InvalidOperationException(
                "The deleted file's source volume could not be determined.");
        }

        if (!string.Equals(
                new DriveInfo(sourceRoot).DriveFormat,
                "NTFS",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Deep file carving currently supports NTFS volumes only.");
        }

        var volumeInfo = new NtfsVolumeInspector().Inspect(sourceRoot);
        using var volumeHandle = CreateVolumeHandle(sourceRoot);
        var bitmapReader = new NtfsVolumeBitmapReader();

        long scannedBytes = 0;
        var extentIndex = 0;
        byte[] previousChunk = [];

        System.Diagnostics.Debug.WriteLine(
            $"Deep NTFS carve started: candidate={candidate.FullPath}, " +
            $"extension={extension}, maxBytes={maxBytesToScan:N0}.");

        progress?.Report(0);

        foreach (var freeExtent in bitmapReader.EnumerateFreeExtents(
                     volumeHandle,
                     volumeInfo,
                     cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();

            extentIndex++;

            var extentBytes = checked(
                freeExtent.ClusterCount * (long)volumeInfo.BytesPerCluster);

            if (extentBytes <= 0)
            {
                continue;
            }

            var extentOffset = checked(
                freeExtent.LogicalClusterNumber * (long)volumeInfo.BytesPerCluster);
            var extentBytesScanned = 0L;

            // A single free extent can be much larger than the 64 MB carve buffer.
            // Walk the entire extent in bounded chunks instead of scanning only its
            // first chunk and then skipping the remainder.
            while (extentBytesScanned < extentBytes &&
                   scannedBytes < maxBytesToScan)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var bytesRemainingInExtent = extentBytes - extentBytesScanned;
                var bytesRemainingOverall = maxBytesToScan - scannedBytes;
                var bytesToRead = Math.Min(
                    bytesRemainingInExtent,
                    Math.Min(bytesRemainingOverall, MaxCarvedFileBytes));

                bytesToRead -= bytesToRead % volumeInfo.BytesPerCluster;

                if (bytesToRead < volumeInfo.BytesPerCluster)
                {
                    break;
                }

                var physicalOffset = checked(extentOffset + extentBytesScanned);
                var buffer = new byte[checked((int)bytesToRead)];

                ReadAt(
                    volumeHandle,
                    physicalOffset,
                    buffer,
                    cancellationToken);

                scannedBytes = checked(scannedBytes + bytesToRead);
                extentBytesScanned = checked(extentBytesScanned + bytesToRead);
                progress?.Report(scannedBytes);

                // Keep the previous 64 MB chunk as overlap. This lets a valid file
                // whose header starts near the end of one chunk and whose trailer
                // reaches into the next chunk be evaluated as one contiguous buffer.
                var overlapLength = previousChunk.Length;
                var scanWindow = new byte[checked(overlapLength + buffer.Length)];

                if (overlapLength > 0)
                {
                    Buffer.BlockCopy(
                        previousChunk,
                        0,
                        scanWindow,
                        0,
                        overlapLength);
                }

                Buffer.BlockCopy(
                    buffer,
                    0,
                    scanWindow,
                    overlapLength,
                    buffer.Length);

                var scanWindowOffset = checked(
                    physicalOffset - overlapLength);

                System.Diagnostics.Debug.WriteLine(
                    $"Deep NTFS carve chunk: candidate={candidate.Name}, " +
                    $"extent={extentIndex:N0}, offset={physicalOffset:N0}, " +
                    $"bytes={bytesToRead:N0}, overlap={overlapLength:N0}, " +
                    $"scanned={scannedBytes:N0}.");

                // RAR archives can be far larger than the bounded in-memory
                // signature-carving window. Validate the RAR header chain directly
                // from the volume and stream a complete contiguous archive to disk.
                // This also lets a RAR archive be recognized when its filename suffix
                // is unfamiliar, without buffering the entire archive in memory.
                if (TryRecoverRarFromScanWindow(
                        scanWindow,
                        scanWindowOffset,
                        physicalOffset,
                        extentOffset,
                        extentBytes,
                        volumeInfo.BytesPerCluster,
                        knownFileSizeBytes,
                        volumeHandle,
                        bitmapReader,
                        candidate,
                        destinationDirectory,
                        cancellationToken,
                        out var rarRecovery))
                {
                    return rarRecovery;
                }

                if (!TryCarve(
                        extension,
                        scanWindow,
                        knownFileSizeBytes,
                        volumeInfo.BytesPerCluster,
                        out var startOffset,
                        out var carvedLength,
                        out var format))
                {
                    previousChunk = buffer;
                    continue;
                }

                if (carvedLength <= 0 ||
                    carvedLength > MaxCarvedFileBytes ||
                    startOffset < 0 ||
                    startOffset > scanWindow.Length ||
                    carvedLength > scanWindow.Length - startOffset)
                {
                    previousChunk = buffer;
                    continue;
                }

                var absoluteByteOffset = checked(scanWindowOffset + startOffset);

                // A hit must overlap the newly-read chunk. Otherwise it would be a
                // duplicate match wholly contained in the previous overlap buffer.
                if (absoluteByteOffset + carvedLength <= physicalOffset)
                {
                    previousChunk = buffer;
                    continue;
                }

                var firstCluster = absoluteByteOffset / volumeInfo.BytesPerCluster;
                var lastByteExclusive = checked(
                    absoluteByteOffset + carvedLength);
                var lastClusterExclusive = checked(
                    (lastByteExclusive + volumeInfo.BytesPerCluster - 1) /
                    volumeInfo.BytesPerCluster);
                var clusterCount = checked(lastClusterExclusive - firstCluster);

                if (clusterCount <= 0)
                {
                    previousChunk = buffer;
                    continue;
                }

                var allocation = bitmapReader.CheckExtents(
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
                    // The source changed while scanning. Do not trust or write this hit.
                    previousChunk = buffer;
                    continue;
                }

                System.Diagnostics.Debug.WriteLine(
                    $"Deep NTFS carve hit: candidate={candidate.FullPath}, " +
                    $"format={format}, offset={absoluteByteOffset:N0}, " +
                    $"length={carvedLength:N0}, clusters={clusterCount:N0}.");

                var destinationPath = RecoveryDestinationPolicy.CreateSafeFilePath(
                    destinationDirectory,
                    candidate.Name);

                try
                {
                    using var output = new FileStream(
                        destinationPath,
                        FileMode.CreateNew,
                        FileAccess.Write,
                        FileShare.None,
                        IoBufferSize,
                        FileOptions.SequentialScan);

                    var writeOffset = checked((int)(absoluteByteOffset - scanWindowOffset));

                    output.Write(
                        scanWindow,
                        writeOffset,
                        carvedLength);
                }
                catch
                {
                    TryDelete(destinationPath);
                    throw;
                }

                return new RecoveryResult
                {
                    Success = true,
                    SourcePath = candidate.FullPath,
                    DestinationPath = destinationPath,
                    BytesRecovered = carvedLength,
                    Evidence =
                        format.StartsWith("Plain text", StringComparison.OrdinalIgnoreCase)
                            ? format.Contains("heuristic", StringComparison.OrdinalIgnoreCase)
                                ? $"Deep NTFS heuristic text carving recovered a {carvedLength:N0}-byte text-like region from currently free clusters without a known original file length. Plain-text files do not carry a self-delimiting file boundary, so the recovered extent is heuristic."
                                : $"Deep NTFS heuristic text carving recovered exactly {carvedLength:N0} byte(s) from currently free clusters using the known original file length. The content match is heuristic because plain-text files do not carry a self-delimiting file boundary."
                            : $"Deep NTFS file carving recovered {carvedLength:N0} byte(s) as a structurally valid {format} file from currently free clusters."
                };
            }

            previousChunk = [];
        }

        progress?.Report(scannedBytes);

        System.Diagnostics.Debug.WriteLine(
            $"Deep NTFS carve complete: candidate={candidate.FullPath}, " +
            $"scanned={scannedBytes:N0}, extents={extentIndex:N0}, noValidHit=true.");

        throw new InvalidOperationException(
            $"No structurally valid {extension} file was found in the first " +
            $"{scannedBytes:N0} free-space byte(s) scanned.");
    }

    public static bool SupportsDeepCarving(
        string fileName,
        long knownFileSizeBytes = 0)
    {
        var extension = Path.GetExtension(fileName);

        if (extension.Equals(".txt", StringComparison.OrdinalIgnoreCase))
        {
            // Plain text has no intrinsic end marker. Only attempt automatic
            // free-space recovery when the original file size is known so the
            // scanner can validate an exact-length text candidate. Without the
            // original size, returning the first printable block can silently
            // recover unrelated files (for example a Git DIRC/index block).
            return knownFileSizeBytes > 0;
        }

        // Unknown extensions are eligible for signature-based carving. The
        // actual bytes, not the filename suffix, determine whether a known format
        // can be reconstructed. Small, known-length text files may use the
        // conservative fallback below; unknown binary formats still need parsers.
        return true;
    }

    private const long MaxRarArchiveBytes = 16L * 1024L * 1024L * 1024L;
    private const int MaxRarHeaderBytes = 2 * 1024 * 1024;

    private static bool TryRecoverRarFromScanWindow(
        byte[] scanWindow,
        long scanWindowOffset,
        long currentChunkPhysicalOffset,
        long freeExtentStart,
        long freeExtentLength,
        long bytesPerCluster,
        long knownFileSizeBytes,
        SafeFileHandle volumeHandle,
        NtfsVolumeBitmapReader bitmapReader,
        RecoveryCandidate candidate,
        string destinationDirectory,
        CancellationToken cancellationToken,
        out RecoveryResult recovery)
    {
        recovery = null!;
        if (bytesPerCluster <= 0 || freeExtentLength <= 0)
        {
            return false;
        }

        var freeExtentEnd = checked(freeExtentStart + freeExtentLength);
        var searchFrom = 0;

        while (TryFindRarSignature(
                   scanWindow,
                   searchFrom,
                   out var signatureOffset,
                   out var signatureLength,
                   out _))
        {
            cancellationToken.ThrowIfCancellationRequested();
            searchFrom = signatureOffset + 1;

            var absoluteStart = checked(scanWindowOffset + signatureOffset);
            if (absoluteStart < freeExtentStart ||
                absoluteStart > freeExtentEnd - signatureLength)
            {
                continue;
            }

            var availableInExtent = freeExtentEnd - absoluteStart;
            var maximumArchiveLength = Math.Min(
                availableInExtent,
                MaxRarArchiveBytes);

            if (maximumArchiveLength < signatureLength)
            {
                continue;
            }

            long parsedArchiveLength;
            string parsedFormat;

            try
            {
                if (!TryMeasureRarArchive(
                        volumeHandle,
                        absoluteStart,
                        maximumArchiveLength,
                        cancellationToken,
                        out parsedArchiveLength,
                        out parsedFormat))
                {
                    continue;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine(
                    $"RAR structural scan rejected candidate at offset {absoluteStart:N0}: " +
                    $"{ex.GetType().Name}: {ex.Message}");
                continue;
            }

            if (parsedArchiveLength <= 0 ||
                parsedArchiveLength > maximumArchiveLength)
            {
                continue;
            }

            // Prefer the structurally measured RAR length. If NTFS supplied the
            // original length, accept it only when the end marker is at that
            // boundary or has at most 1 MiB of appended auxiliary data (for
            // example a third-party signature).
            var outputLength = parsedArchiveLength;
            if (knownFileSizeBytes > 0)
            {
                if (knownFileSizeBytes < parsedArchiveLength ||
                    knownFileSizeBytes > MaxRarArchiveBytes ||
                    knownFileSizeBytes - parsedArchiveLength > 1024L * 1024L)
                {
                    continue;
                }

                outputLength = knownFileSizeBytes;
            }

            if (outputLength > availableInExtent ||
                absoluteStart > long.MaxValue - outputLength)
            {
                continue;
            }

            // A signature found in the retained overlap may already have been
            // wholly passed by an earlier chunk. Do not recover it twice.
            if (absoluteStart + outputLength <= currentChunkPhysicalOffset)
            {
                continue;
            }

            var firstCluster = absoluteStart / bytesPerCluster;
            var lastByteExclusive = checked(absoluteStart + outputLength);
            var lastClusterExclusive = checked(
                (lastByteExclusive + bytesPerCluster - 1) / bytesPerCluster);
            var clusterCount = checked(lastClusterExclusive - firstCluster);

            if (clusterCount <= 0)
            {
                continue;
            }

            var allocation = bitmapReader.CheckExtents(
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
                System.Diagnostics.Trace.WriteLine(
                    $"RAR recovery rejected because its full span is no longer free: " +
                    $"path={candidate.FullPath}, offset={absoluteStart:N0}, " +
                    $"bytes={outputLength:N0}.");
                continue;
            }

            System.Diagnostics.Debug.WriteLine(
                $"Deep NTFS RAR carve hit: candidate={candidate.FullPath}, " +
                $"format={parsedFormat}, offset={absoluteStart:N0}, " +
                $"bytes={outputLength:N0}, clusters={clusterCount:N0}; " +
                "RAR headers validated, compressed payload checksums not independently verified.");

            var destinationPath = RecoveryDestinationPolicy.CreateSafeFilePath(
                destinationDirectory,
                candidate.Name);

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
                var remaining = outputLength;
                var sourceOffset = absoluteStart;

                while (remaining > 0)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var count = checked((int)Math.Min(IoBufferSize, remaining));
                    var copyBuffer = new byte[count];

                    ReadAt(
                        volumeHandle,
                        sourceOffset,
                        copyBuffer,
                        cancellationToken);

                    output.Write(copyBuffer, 0, copyBuffer.Length);
                    sourceOffset = checked(sourceOffset + count);
                    remaining -= count;
                }

                output.Flush();
            }
            catch
            {
                if (destinationCreated)
                {
                    TryDelete(destinationPath);
                }

                throw;
            }

            recovery = new RecoveryResult
            {
                Success = true,
                SourcePath = candidate.FullPath,
                DestinationPath = destinationPath,
                BytesRecovered = outputLength,
                Evidence =
                    $"Deep NTFS carving recovered a {outputLength:N0}-byte {parsedFormat} archive " +
                    "from a single currently-free contiguous cluster extent. The archive's header " +
                    "chain and header checksums were validated; the carver does not decompress archive " +
                    "members or independently verify their payload checksums. Open/test the recovered " +
                    "archive with a trusted archive utility to confirm payload integrity."
            };

            System.Diagnostics.Trace.WriteLine(
                $"Deep NTFS RAR carve succeeded: source={candidate.FullPath}, " +
                $"format={parsedFormat}, offset={absoluteStart:N0}, bytes={outputLength:N0}, " +
                $"destination={destinationPath}.");

            return true;
        }

        return false;
    }

    private static bool TryFindRarSignature(
        byte[] buffer,
        int searchFrom,
        out int start,
        out int signatureLength,
        out string format)
    {
        start = -1;
        signatureLength = 0;
        format = string.Empty;

        ReadOnlySpan<byte> rar5 = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
        ReadOnlySpan<byte> rar4 = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];

        if (searchFrom < 0)
        {
            searchFrom = 0;
        }

        for (var i = searchFrom; i < buffer.Length; i++)
        {
            if (i + rar5.Length <= buffer.Length &&
                buffer.AsSpan(i, rar5.Length).SequenceEqual(rar5))
            {
                start = i;
                signatureLength = rar5.Length;
                format = "RAR 5.x";
                return true;
            }

            if (i + rar4.Length <= buffer.Length &&
                buffer.AsSpan(i, rar4.Length).SequenceEqual(rar4))
            {
                start = i;
                signatureLength = rar4.Length;
                format = "RAR 4.x";
                return true;
            }
        }

        return false;
    }

    private static bool TryMeasureRarArchive(
        SafeFileHandle volumeHandle,
        long startOffset,
        long maximumArchiveLength,
        CancellationToken cancellationToken,
        out long archiveLength,
        out string format)
    {
        archiveLength = 0;
        format = string.Empty;

        if (maximumArchiveLength < 7)
        {
            return false;
        }

        var signatureBufferLength = checked((int)Math.Min(8L, maximumArchiveLength));
        var signatureBuffer = new byte[signatureBufferLength];
        ReadAt(volumeHandle, startOffset, signatureBuffer, cancellationToken);

        ReadOnlySpan<byte> rar5Signature = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
        ReadOnlySpan<byte> rar4Signature = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];

        if (signatureBuffer.Length >= rar5Signature.Length &&
            signatureBuffer.AsSpan(0, rar5Signature.Length).SequenceEqual(rar5Signature))
        {
            format = "RAR 5.x";
            return TryMeasureRar5Archive(
                volumeHandle,
                startOffset,
                maximumArchiveLength,
                cancellationToken,
                out archiveLength);
        }

        if (signatureBuffer.Length >= rar4Signature.Length &&
            signatureBuffer.AsSpan(0, rar4Signature.Length).SequenceEqual(rar4Signature))
        {
            format = "RAR 4.x";
            return TryMeasureRar4Archive(
                volumeHandle,
                startOffset,
                maximumArchiveLength,
                cancellationToken,
                out archiveLength);
        }

        return false;
    }

    private static bool TryMeasureRar5Archive(
        SafeFileHandle volumeHandle,
        long startOffset,
        long maximumArchiveLength,
        CancellationToken cancellationToken,
        out long archiveLength)
    {
        archiveLength = 0;
        long relativeOffset = 8;
        var sawMainHeader = false;

        // A header-only walk is enough to find the exact archive boundary:
        // each RAR5 block reports the size of its optional packed-data area.
        // Payload data is skipped, not buffered in memory.
        for (var blockIndex = 0; blockIndex < 1_000_000; blockIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (relativeOffset < 8 ||
                relativeOffset > maximumArchiveLength - 5)
            {
                return false;
            }

            var prefixLength = checked((int)Math.Min(
                14L,
                maximumArchiveLength - relativeOffset));
            if (prefixLength < 5)
            {
                return false;
            }

            var prefix = new byte[prefixLength];
            ReadAt(
                volumeHandle,
                checked(startOffset + relativeOffset),
                prefix,
                cancellationToken);

            var storedHeaderCrc = BinaryPrimitives.ReadUInt32LittleEndian(
                prefix.AsSpan(0, 4));

            var sizePosition = 4;
            if (!TryReadRarVint(prefix, ref sizePosition, out var headerSizeValue) ||
                headerSizeValue < 2 ||
                headerSizeValue > MaxRarHeaderBytes)
            {
                return false;
            }

            var sizeVintLength = sizePosition - 4;
            var headerSize = checked((int)headerSizeValue);
            var headerEnd = checked(
                relativeOffset + 4L + sizeVintLength + headerSize);

            if (headerEnd > maximumArchiveLength)
            {
                return false;
            }

            var headerBody = new byte[headerSize];
            ReadAt(
                volumeHandle,
                checked(startOffset + relativeOffset + 4L + sizeVintLength),
                headerBody,
                cancellationToken);

            var crcInput = new byte[checked(sizeVintLength + headerBody.Length)];
            Buffer.BlockCopy(prefix, 4, crcInput, 0, sizeVintLength);
            Buffer.BlockCopy(
                headerBody,
                0,
                crcInput,
                sizeVintLength,
                headerBody.Length);

            if (ComputeCrc32(crcInput) != storedHeaderCrc)
            {
                return false;
            }

            var headerPosition = 0;
            if (!TryReadRarVint(headerBody, ref headerPosition, out var headerType) ||
                !TryReadRarVint(headerBody, ref headerPosition, out var headerFlags))
            {
                return false;
            }

            ulong extraAreaSize = 0;
            ulong dataAreaSize = 0;
            var hasDataArea = (headerFlags & 0x0002) != 0;

            if ((headerFlags & 0x0001) != 0 &&
                !TryReadRarVint(headerBody, ref headerPosition, out extraAreaSize))
            {
                return false;
            }

            if (hasDataArea &&
                !TryReadRarVint(headerBody, ref headerPosition, out dataAreaSize))
            {
                return false;
            }

            if (extraAreaSize > headerSize ||
                dataAreaSize > (ulong)MaxRarArchiveBytes)
            {
                return false;
            }

            // Encrypted-header RAR5 archives require decrypting subsequent headers;
            // do not claim a structurally validated recovery for those archives.
            if (headerType == 4)
            {
                return false;
            }

            if (!sawMainHeader)
            {
                if (headerType != 1)
                {
                    return false;
                }

                sawMainHeader = true;
            }
            else if (headerType == 1)
            {
                return false;
            }

            var extraAreaLength = checked((int)extraAreaSize);
            var typeSpecificEnd = headerBody.Length - extraAreaLength;
            if (typeSpecificEnd < headerPosition)
            {
                return false;
            }

            // Validate the minimum type-specific fields as well as the common
            // block header. This greatly reduces the chance that bytes inside a
            // compressed payload accidentally mimic an end-of-archive header.
            var typeSpecificSpan = headerBody.AsSpan(0, typeSpecificEnd);
            switch (headerType)
            {
                case 1:
                    if (!TryReadRarVint(
                            typeSpecificSpan,
                            ref headerPosition,
                            out var archiveFlags))
                    {
                        return false;
                    }

                    if ((archiveFlags & 0x0002) != 0 &&
                        !TryReadRarVint(
                            typeSpecificSpan,
                            ref headerPosition,
                            out _))
                    {
                        return false;
                    }

                    break;

                case 2:
                case 3:
                    if (!TryReadRarVint(
                            typeSpecificSpan,
                            ref headerPosition,
                            out var fileFlags) ||
                        !TryReadRarVint(
                            typeSpecificSpan,
                            ref headerPosition,
                            out _) ||
                        !TryReadRarVint(
                            typeSpecificSpan,
                            ref headerPosition,
                            out _))
                    {
                        return false;
                    }

                    if ((fileFlags & 0x0002) != 0)
                    {
                        if (headerPosition > typeSpecificSpan.Length - 4)
                        {
                            return false;
                        }

                        headerPosition += 4;
                    }

                    if ((fileFlags & 0x0004) != 0)
                    {
                        if (headerPosition > typeSpecificSpan.Length - 4)
                        {
                            return false;
                        }

                        headerPosition += 4;
                    }

                    if (!TryReadRarVint(
                            typeSpecificSpan,
                            ref headerPosition,
                            out _) ||
                        !TryReadRarVint(
                            typeSpecificSpan,
                            ref headerPosition,
                            out _) ||
                        !TryReadRarVint(
                            typeSpecificSpan,
                            ref headerPosition,
                            out var nameLength) ||
                        nameLength > (ulong)(typeSpecificSpan.Length - headerPosition))
                    {
                        return false;
                    }

                    headerPosition += checked((int)nameLength);
                    break;

                case 5:
                    if (!TryReadRarVint(
                            typeSpecificSpan,
                            ref headerPosition,
                            out _))
                    {
                        return false;
                    }

                    break;
            }

            if (headerType == 5)
            {
                if (!sawMainHeader || hasDataArea || dataAreaSize != 0)
                {
                    return false;
                }

                archiveLength = headerEnd;
                return archiveLength <= maximumArchiveLength;
            }

            var remaining = maximumArchiveLength - headerEnd;
            if (dataAreaSize > (ulong)remaining)
            {
                return false;
            }

            var nextOffset = checked(headerEnd + (long)dataAreaSize);
            if (nextOffset <= relativeOffset ||
                nextOffset > MaxRarArchiveBytes)
            {
                return false;
            }

            relativeOffset = nextOffset;
        }

        return false;
    }

    private static bool TryMeasureRar4Archive(
        SafeFileHandle volumeHandle,
        long startOffset,
        long maximumArchiveLength,
        CancellationToken cancellationToken,
        out long archiveLength)
    {
        archiveLength = 0;
        long relativeOffset = 7;
        var sawMainHeader = false;

        for (var blockIndex = 0; blockIndex < 1_000_000; blockIndex++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (relativeOffset < 7 ||
                relativeOffset > maximumArchiveLength - 7)
            {
                return false;
            }

            var fixedHeader = new byte[7];
            ReadAt(
                volumeHandle,
                checked(startOffset + relativeOffset),
                fixedHeader,
                cancellationToken);

            var storedHeaderCrc = BinaryPrimitives.ReadUInt16LittleEndian(
                fixedHeader.AsSpan(0, 2));
            var headerType = fixedHeader[2];
            var headerFlags = BinaryPrimitives.ReadUInt16LittleEndian(
                fixedHeader.AsSpan(3, 2));
            var headerSize = BinaryPrimitives.ReadUInt16LittleEndian(
                fixedHeader.AsSpan(5, 2));

            if (headerSize < 7 ||
                headerSize > maximumArchiveLength - relativeOffset)
            {
                return false;
            }

            var header = new byte[headerSize];
            ReadAt(
                volumeHandle,
                checked(startOffset + relativeOffset),
                header,
                cancellationToken);

            var computedHeaderCrc = (ushort)(
                ComputeCrc32(header.AsSpan(2)) & 0xFFFF);

            if (computedHeaderCrc != storedHeaderCrc)
            {
                return false;
            }

            ulong dataAreaSize = 0;
            if ((headerFlags & 0x8000) != 0)
            {
                if (headerSize < 11)
                {
                    return false;
                }

                dataAreaSize = BinaryPrimitives.ReadUInt32LittleEndian(
                    header.AsSpan(7, 4));
            }

            if (!sawMainHeader)
            {
                if (headerType != 0x73)
                {
                    return false;
                }

                // RAR4's MHD_PASSWORD bit means subsequent block headers are
                // encrypted. Header-chain validation cannot safely continue.
                if ((headerFlags & 0x0080) != 0)
                {
                    return false;
                }

                sawMainHeader = true;
            }
            else if (headerType == 0x73)
            {
                return false;
            }

            if (headerType == 0x7B)
            {
                archiveLength = checked(relativeOffset + headerSize);
                return sawMainHeader &&
                       archiveLength <= maximumArchiveLength;
            }

            if (headerType < 0x73 || headerType > 0x7A)
            {
                return false;
            }

            var headerEnd = checked(relativeOffset + headerSize);
            var remaining = maximumArchiveLength - headerEnd;
            if (dataAreaSize > (ulong)remaining)
            {
                return false;
            }

            var nextOffset = checked(headerEnd + (long)dataAreaSize);
            if (nextOffset <= relativeOffset ||
                nextOffset > MaxRarArchiveBytes)
            {
                return false;
            }

            relativeOffset = nextOffset;
        }

        return false;
    }

    private static bool TryReadRarVint(
        ReadOnlySpan<byte> input,
        ref int position,
        out ulong value)
    {
        value = 0;

        for (var index = 0; index < 10; index++)
        {
            if (position >= input.Length)
            {
                return false;
            }

            var next = input[position++];
            if (index == 9 && (next & 0xFE) != 0)
            {
                return false;
            }

            value |= (ulong)(next & 0x7F) << (index * 7);
            if ((next & 0x80) == 0)
            {
                return true;
            }
        }

        return false;
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;

        foreach (var value in data)
        {
            crc ^= value;

            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0
                    ? (crc >> 1) ^ 0xEDB88320u
                    : crc >> 1;
            }
        }

        return ~crc;
    }

    private static bool SupportsExtension(string extension) =>
        extension.Equals(".jpg", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".jpeg", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".png", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".gif", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".bmp", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".wav", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".webp", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".zip", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".docx", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".xlsx", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".pptx", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".txt", StringComparison.OrdinalIgnoreCase);

    private static bool TryCarve(
        string extension,
        byte[] buffer,
        long knownFileSizeBytes,
        long bytesPerCluster,
        out int startOffset,
        out int length,
        out string format)
    {
        startOffset = 0;
        length = 0;
        format = string.Empty;

        // For an unfamiliar extension, use content signatures instead of trusting
        // the suffix. The output keeps the original filename, while evidence records
        // the format detected from its bytes.
        if (!SupportsExtension(extension))
        {
            if (TryFindJpeg(buffer, out startOffset, out length))
            {
                format = "JPEG (extension-independent)";
                return true;
            }
            if (TryFindPng(buffer, out startOffset, out length))
            {
                format = "PNG (extension-independent)";
                return true;
            }
            if (TryFindGif(buffer, out startOffset, out length))
            {
                format = "GIF (extension-independent)";
                return true;
            }
            if (TryFindBmp(buffer, out startOffset, out length))
            {
                format = "BMP (extension-independent)";
                return true;
            }
            if (TryFindWav(buffer, out startOffset, out length))
            {
                format = "WAV (extension-independent)";
                return true;
            }
            if (TryFindWebp(buffer, out startOffset, out length))
            {
                format = "WebP (extension-independent)";
                return true;
            }
            if (TryFindPdf(buffer, out startOffset, out length))
            {
                format = "PDF (extension-independent)";
                return true;
            }
            if (TryFindZip(buffer, out startOffset, out length))
            {
                format = "ZIP (extension-independent; may include Office formats)";
                return true;
            }

            // Plain text has no reliable end marker. Only attempt an exact-length
            // match when the original size is known and <= 1 MiB. This is heuristic,
            // not proof that the matching bytes belong to this deleted file.
            if (knownFileSizeBytes > 0 &&
                knownFileSizeBytes <= 1024L * 1024L &&
                bytesPerCluster > 0 &&
                bytesPerCluster <= int.MaxValue &&
                knownFileSizeBytes <= int.MaxValue &&
                TryFindText(
                    buffer,
                    checked((int)knownFileSizeBytes),
                    checked((int)bytesPerCluster),
                    out startOffset))
            {
                length = checked((int)knownFileSizeBytes);
                format = "Plain text (unknown-extension heuristic)";
                return true;
            }

            startOffset = 0;
            length = 0;
            format = string.Empty;
            return false;
        }

        if (extension.Equals(".txt", StringComparison.OrdinalIgnoreCase))
        {
            if (bytesPerCluster <= 0)
            {
                return false;
            }

            if (knownFileSizeBytes > 0)
            {
                if (knownFileSizeBytes > MaxCarvedFileBytes ||
                    !TryFindText(
                        buffer,
                        checked((int)knownFileSizeBytes),
                        checked((int)bytesPerCluster),
                        out startOffset))
                {
                    return false;
                }

                length = checked((int)knownFileSizeBytes);
                format = "Plain text";
                return true;
            }

            if (!TryFindUnknownSizeText(
                    buffer,
                    checked((int)bytesPerCluster),
                    out startOffset,
                    out length))
            {
                return false;
            }

            format = "Plain text (heuristic)";
            return true;
        }

        if (extension.Equals(".jpg", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".jpeg", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindJpeg(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "JPEG";
            return true;
        }

        if (extension.Equals(".png", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindPng(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "PNG";
            return true;
        }

        if (extension.Equals(".gif", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindGif(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "GIF";
            return true;
        }

        if (extension.Equals(".bmp", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindBmp(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "BMP";
            return true;
        }

        if (extension.Equals(".wav", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindWav(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "WAV";
            return true;
        }

        if (extension.Equals(".webp", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindWebp(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "WebP";
            return true;
        }

        if (extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindPdf(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "PDF";
            return true;
        }

        if (extension.Equals(".zip", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".docx", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".xlsx", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".pptx", StringComparison.OrdinalIgnoreCase))
        {
            if (!TryFindZip(buffer, out startOffset, out length))
            {
                return false;
            }

            format = "ZIP";
            return true;
        }

        return false;
    }

    private static bool TryFindText(
        byte[] buffer,
        int expectedLength,
        int bytesPerCluster,
        out int start)
    {
        start = -1;

        if (expectedLength <= 0 ||
            expectedLength > MaxCarvedFileBytes ||
            expectedLength > buffer.Length)
        {
            return false;
        }

        // Plain text has no intrinsic end marker. Restrict this fallback to the
        // exact known byte length and require every byte to be valid printable
        // UTF-8/ASCII text (plus common whitespace). This deliberately remains
        // heuristic and should never be presented as exact file identity.
        var lastStart = buffer.Length - expectedLength;
        for (var i = 0; i <= lastStart; i += bytesPerCluster)
        {
            var span = buffer.AsSpan(i, expectedLength);

            if (span.IndexOf((byte)0) >= 0 ||
                !LooksLikeText(span))
            {
                continue;
            }

            start = i;
            return true;
        }

        return false;
    }

    private static bool TryFindUnknownSizeText(
        byte[] buffer,
        int bytesPerCluster,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        if (buffer.Length == 0 || bytesPerCluster <= 0)
        {
            return false;
        }

        // Without an original size, plain text has no trustworthy boundary.
        // Restrict the search to cluster-aligned starts and return only a
        // contiguous text-like prefix. A minimum length avoids treating isolated
        // printable bytes as a recovered file.
        const int minimumLength = 4;
        var maxStart = buffer.Length - minimumLength;

        for (var i = 0; i <= maxStart; i += bytesPerCluster)
        {
            if (buffer[i] == 0)
            {
                continue;
            }

            var candidateLength = 0;
            var position = i;

            while (position < buffer.Length &&
                   candidateLength < MaxCarvedFileBytes)
            {
                var value = buffer[position];

                if (value == 0)
                {
                    break;
                }

                if (value is >= 0x20 and <= 0x7E || value is 0x09 or 0x0A or 0x0D)
                {
                    candidateLength++;
                    position++;
                    continue;
                }

                // Accept a complete UTF-8 sequence when present.
                if (value is >= 0xC2 and <= 0xF4)
                {
                    var sequenceLength =
                        value <= 0xDF ? 2 :
                        value <= 0xEF ? 3 : 4;

                    if (position + sequenceLength > buffer.Length)
                    {
                        break;
                    }

                    var valid = true;
                    for (var j = 1; j < sequenceLength; j++)
                    {
                        if (buffer[position + j] < 0x80 ||
                            buffer[position + j] > 0xBF)
                        {
                            valid = false;
                            break;
                        }
                    }

                    if (!valid)
                    {
                        break;
                    }

                    candidateLength += sequenceLength;
                    position += sequenceLength;
                    continue;
                }

                break;
            }

            if (candidateLength >= minimumLength)
            {
                start = i;
                length = candidateLength;
                return true;
            }
        }

        return false;
    }

    private static bool LooksLikeText(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return false;
        }

        var printable = 0;
        for (var i = 0; i < data.Length; i++)
        {
            var value = data[i];

            if (value is 0x09 or 0x0A or 0x0D)
            {
                printable++;
                continue;
            }

            if (value is >= 0x20 and <= 0x7E)
            {
                printable++;
                continue;
            }

            // Basic validation for UTF-8 multibyte sequences.
            if (value is >= 0xC2 and <= 0xF4)
            {
                var sequenceLength =
                    value <= 0xDF ? 2 :
                    value <= 0xEF ? 3 : 4;

                if (i + sequenceLength > data.Length)
                {
                    return false;
                }

                for (var j = 1; j < sequenceLength; j++)
                {
                    if (data[i + j] < 0x80 || data[i + j] > 0xBF)
                    {
                        return false;
                    }
                }

                printable += sequenceLength;
                i += sequenceLength - 1;
                continue;
            }

            return false;
        }

        return printable == data.Length;
    }

    private static bool TryFindJpeg(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        for (var i = 0; i + 2 < buffer.Length; i++)
        {
            if (buffer[i] != 0xFF ||
                buffer[i + 1] != 0xD8 ||
                buffer[i + 2] != 0xFF)
            {
                continue;
            }

            for (var j = i + 3; j + 1 < buffer.Length; j++)
            {
                if (buffer[j] == 0xFF && buffer[j + 1] == 0xD9)
                {
                    start = i;
                    length = checked(j + 2 - i);
                    return length <= MaxCarvedFileBytes;
                }
            }
        }

        return false;
    }

    private static bool TryFindPng(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        ReadOnlySpan<byte> signature =
        [
            0x89, 0x50, 0x4E, 0x47,
            0x0D, 0x0A, 0x1A, 0x0A
        ];

        for (var candidate = buffer.AsSpan().IndexOf(signature);
             candidate >= 0;)
        {
            var absolute = candidate;
            var position = absolute + signature.Length;

            while (position + 12 <= buffer.Length)
            {
                var chunkLength =
                    BinaryPrimitives.ReadUInt32BigEndian(
                        buffer.AsSpan(position, 4));

                var next = checked((long)position + 12 + chunkLength);
                if (next > buffer.Length || next - absolute > MaxCarvedFileBytes)
                {
                    break;
                }

                var type = buffer.AsSpan(position + 4, 4);
                position = checked((int)next);

                if (type.SequenceEqual("IEND"u8))
                {
                    start = absolute;
                    length = position - absolute;
                    return true;
                }
            }

            var nextSearch = absolute + 1;
            if (nextSearch >= buffer.Length - signature.Length + 1)
            {
                break;
            }

            var found = buffer.AsSpan(nextSearch).IndexOf(signature);
            candidate = found < 0 ? -1 : nextSearch + found;
        }

        return false;
    }

    private static bool TryFindGif(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        for (var i = 0; i + 13 <= buffer.Length; i++)
        {
            if (!(
                buffer.AsSpan(i, 6).SequenceEqual("GIF87a"u8) ||
                buffer.AsSpan(i, 6).SequenceEqual("GIF89a"u8)))
            {
                continue;
            }

            for (var j = i + 13; j < buffer.Length; j++)
            {
                if (buffer[j] == 0x3B)
                {
                    start = i;
                    length = j + 1 - i;
                    return length <= MaxCarvedFileBytes;
                }
            }
        }

        return false;
    }

    private static bool TryFindBmp(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        for (var i = 0; i + 6 <= buffer.Length; i++)
        {
            if (buffer[i] != 0x42 || buffer[i + 1] != 0x4D)
            {
                continue;
            }

            var fileSize = BinaryPrimitives.ReadUInt32LittleEndian(
                buffer.AsSpan(i + 2, 4));

            if (fileSize < 14 ||
                fileSize > MaxCarvedFileBytes ||
                i + fileSize > buffer.Length)
            {
                continue;
            }

            start = i;
            length = checked((int)fileSize);
            return true;
        }

        return false;
    }

    private static bool TryFindWav(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        for (var i = 0; i + 12 <= buffer.Length; i++)
        {
            if (!buffer.AsSpan(i, 4).SequenceEqual("RIFF"u8) ||
                !buffer.AsSpan(i + 8, 4).SequenceEqual("WAVE"u8))
            {
                continue;
            }

            var riffSize = BinaryPrimitives.ReadUInt32LittleEndian(
                buffer.AsSpan(i + 4, 4));

            var totalSize = checked((long)riffSize + 8);
            if (totalSize < 12 ||
                totalSize > MaxCarvedFileBytes ||
                i + totalSize > buffer.Length)
            {
                continue;
            }

            start = i;
            length = checked((int)totalSize);
            return true;
        }

        return false;
    }

    private static bool TryFindWebp(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        for (var i = 0; i + 12 <= buffer.Length; i++)
        {
            if (!buffer.AsSpan(i, 4).SequenceEqual("RIFF"u8) ||
                !buffer.AsSpan(i + 8, 4).SequenceEqual("WEBP"u8))
            {
                continue;
            }

            var riffSize = BinaryPrimitives.ReadUInt32LittleEndian(
                buffer.AsSpan(i + 4, 4));
            var totalSize = checked((long)riffSize + 8);

            if (totalSize < 12 ||
                totalSize > MaxCarvedFileBytes ||
                i + totalSize > buffer.Length)
            {
                continue;
            }

            start = i;
            length = checked((int)totalSize);
            return true;
        }

        return false;
    }

    private static bool TryFindPdf(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        var signature = "%PDF-"u8;
        var eof = "%%EOF"u8;

        var searchFrom = 0;
        while (searchFrom < buffer.Length)
        {
            var relativeStart = buffer.AsSpan(searchFrom).IndexOf(signature);
            if (relativeStart < 0)
            {
                return false;
            }

            start = searchFrom + relativeStart;
            if (start >= buffer.Length)
            {
                return false;
            }

            var eofRelative = buffer.AsSpan(start + signature.Length).IndexOf(eof);
            if (eofRelative < 0)
            {
                searchFrom = start + 1;
                continue;
            }

            var eofStart = start + signature.Length + eofRelative;
            length = eofStart + eof.Length - start;
            if (length <= MaxCarvedFileBytes)
            {
                return true;
            }

            searchFrom = start + 1;
        }

        return false;
    }

    private static bool TryFindZip(
        byte[] buffer,
        out int start,
        out int length)
    {
        start = -1;
        length = 0;

        var localHeader = new byte[] { 0x50, 0x4B, 0x03, 0x04 };
        var emptyHeader = new byte[] { 0x50, 0x4B, 0x05, 0x06 };

        var searchFrom = 0;
        while (searchFrom < buffer.Length)
        {
            var relativeStart = buffer.AsSpan(searchFrom).IndexOf(localHeader);
            if (relativeStart < 0)
            {
                return false;
            }

            start = searchFrom + relativeStart;
            for (var i = buffer.Length - 22; i >= start; i--)
            {
                if (!buffer.AsSpan(i, 4).SequenceEqual(emptyHeader))
                {
                    continue;
                }

                var commentLength = BinaryPrimitives.ReadUInt16LittleEndian(
                    buffer.AsSpan(i + 20, 2));
                var end = checked((long)i + 22 + commentLength);

                if (end <= buffer.Length &&
                    end - start <= MaxCarvedFileBytes)
                {
                    length = checked((int)(end - start));
                    return true;
                }
            }

            searchFrom = start + 1;
        }

        return false;
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
                    $"Could not seek to free cluster offset {currentOffset:N0}.");
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
                    $"Could not read free cluster data at byte offset {currentOffset:N0}.");
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
            handle.Dispose();
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"Could not open NTFS source volume {root} for deep file carving.");
        }

        return handle;
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

    [System.Runtime.InteropServices.DllImport(
        "kernel32.dll",
        CharSet = System.Runtime.InteropServices.CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [System.Runtime.InteropServices.DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool SetFilePointerEx(
        SafeFileHandle hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [System.Runtime.InteropServices.DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool ReadFile(
        SafeFileHandle hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);
}
