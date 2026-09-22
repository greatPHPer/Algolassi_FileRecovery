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

    private const uint NtfsAttributeList = 0x20;
    private const uint NtfsAttributeData = 0x80;
    private const uint NtfsAttributeEnd = 0xFFFFFFFF;
    private const byte NonResidentForm = 1;

    public NtfsDataStreamInfo ReadDefaultDataStream(
        NtfsVolumeInfo volumeInfo,
        SafeFileHandle mftHandle,
        ulong fileReferenceNumber)
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

        var record = ReadRecord(
            mftHandle,
            volumeInfo,
            segmentNumber,
            sequenceNumber,
            expectedBaseFileReference: fileReferenceNumber);

        if (record is null)
        {
            return NotFound("The referenced MFT segment no longer contains a valid deleted-file record.");
        }

        var dataAttributes = FindUnnamedDataAttributes(record, volumeInfo);

        var attributeList = FindAttributeList(record, volumeInfo);
        if (!attributeList.Found)
        {
            return BuildDataStream(dataAttributes, 1);
        }

        if (!attributeList.IsResident)
        {
            return NotFound(
                "The file retains a nonresident $ATTRIBUTE_LIST; this recovery stage requires the attribute list itself to be resident.");
        }

        IReadOnlyList<AttributeListEntry> entries;
        try
        {
            entries = ParseAttributeList(attributeList.ResidentData!);
        }
        catch (Exception ex)
        {
            return NotFound($"The NTFS $ATTRIBUTE_LIST could not be parsed: {ex.Message}");
        }

        var referencedSources = new HashSet<(ulong FileReference, long LowestVcn)>();
        foreach (var entry in entries.Where(x => x.AttributeType == NtfsAttributeData && x.IsUnnamed))
        {
            if (!referencedSources.Add((entry.SegmentReference, entry.LowestVcn)))
            {
                continue;
            }

            if (entry.SegmentReference == fileReferenceNumber)
            {
                continue;
            }

            var extensionSegment = entry.SegmentReference & 0x0000FFFFFFFFFFFFUL;
            var extensionSequence = (ushort)(entry.SegmentReference >> 48);

            var extensionRecord = ReadRecord(
                mftHandle,
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

        return BuildDataStream(
            dataAttributes,
            dataAttributes.Select(x => x.SourceSegmentCount).DefaultIfEmpty(1).Max());
    }

    private static List<DataAttributeDescriptor> FindUnnamedDataAttributes(
        byte[] record,
        NtfsVolumeInfo volumeInfo)
    {
        var result = new List<DataAttributeDescriptor>();
        foreach (var attribute in EnumerateAttributes(record))
        {
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
        NtfsVolumeInfo volumeInfo)
    {
        foreach (var attribute in EnumerateAttributes(record))
        {
            if (attribute.Type != NtfsAttributeList || attribute.NameLength != 0)
            {
                continue;
            }

            if (attribute.FormCode == NonResidentForm)
            {
                return new AttributeListDescriptor { Found = true, IsResident = false };
            }

            var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(
                record.AsSpan(attribute.Offset + 16, 4));
            var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(
                record.AsSpan(attribute.Offset + 20, 2));

            if (valueOffset + valueLength > attribute.Length)
            {
                throw new InvalidDataException("The resident $ATTRIBUTE_LIST value is outside its attribute record.");
            }

            var data = new byte[checked((int)valueLength)];
            record.AsSpan(
                attribute.Offset + valueOffset,
                checked((int)valueLength)).CopyTo(data);

            return new AttributeListDescriptor
            {
                Found = true,
                IsResident = true,
                ResidentData = data
            };
        }

        return new AttributeListDescriptor();
    }

    private static IReadOnlyList<AttributeListEntry> ParseAttributeList(byte[] data)
    {
        var result = new List<AttributeListEntry>();
        var offset = 0;

        while (offset + 26 <= data.Length)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
            if (type == NtfsAttributeEnd)
            {
                break;
            }

            var recordLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + 4, 2));
            var nameLength = data[offset + 6];
            var nameOffset = data[offset + 7];

            if (recordLength < 26 ||
                offset + recordLength > data.Length)
            {
                throw new InvalidDataException("An NTFS $ATTRIBUTE_LIST entry has an invalid record length.");
            }

            var lowestVcn = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(offset + 8, 8));
            var segmentReference = BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset + 16, 8));

            if (nameLength != 0 &&
                (nameOffset == 0 ||
                 nameOffset + nameLength * 2 > recordLength))
            {
                throw new InvalidDataException("An NTFS $ATTRIBUTE_LIST entry has an invalid attribute name.");
            }

            result.Add(new AttributeListEntry
            {
                AttributeType = type,
                LowestVcn = lowestVcn,
                SegmentReference = segmentReference,
                IsUnnamed = nameLength == 0
            });

            offset += recordLength;
        }

        return result;
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
                ? $"The default $DATA stream spans {mftSegmentCount:N0} MFT record(s) through a resident $ATTRIBUTE_LIST and retained {extents.Count:N0} data extent(s)."
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
        public int SourceSegmentCount { get; init; } = 1;
    }

    private sealed class AttributeListDescriptor
    {
        public bool Found { get; init; }
        public bool IsResident { get; init; }
        public byte[]? ResidentData { get; init; }
    }

    private sealed class AttributeListEntry
    {
        public uint AttributeType { get; init; }
        public long LowestVcn { get; init; }
        public ulong SegmentReference { get; init; }
        public bool IsUnnamed { get; init; }
    }

    private static byte[]? ReadRecord(
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
        ReadAt(mftHandle, relativeOffset, record);

        if (record.Length < 48 ||
            record[0] != (byte)'F' ||
            record[1] != (byte)'I' ||
            record[2] != (byte)'L' ||
            record[3] != (byte)'E')
        {
            return null;
        }

        ApplyUpdateSequenceFixups(record, checked((int)volumeInfo.BytesPerSector));

        var sequenceNumber = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(16, 2));
        var flags = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(22, 2));

        if (expectedSequenceNumber != 0 && sequenceNumber != expectedSequenceNumber)
        {
            return null;
        }

        if ((flags & 0x0001) != 0)
        {
            return null;
        }

        var baseFileReference = BinaryPrimitives.ReadUInt64LittleEndian(record.AsSpan(32, 8));
        if (baseFileReference != 0 && baseFileReference != expectedBaseFileReference)
        {
            return null;
        }

        return record;
    }

    internal static SafeFileHandle OpenMftHandle(string rootPath)
    {
        return CreateMftHandle(rootPath);
    }

    private static NtfsDataStreamInfo NotFound(string evidence) =>
        new()
        {
            Found = false,
            Evidence = evidence
        };

    private static void ApplyUpdateSequenceFixups(byte[] record, int bytesPerSector)
    {
        if (bytesPerSector <= 0 || record.Length < 48)
        {
            throw new InvalidDataException("Invalid NTFS sector geometry.");
        }

        var usaOffset = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(4, 2));
        var usaCount = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(6, 2));

        if (usaOffset == 0 ||
            usaCount < 2 ||
            usaOffset + usaCount * 2 > record.Length)
        {
            throw new InvalidDataException("The NTFS update-sequence array is invalid.");
        }

        var sequence = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(usaOffset, 2));

        for (var i = 1; i < usaCount; i++)
        {
            var endOffset = checked(i * bytesPerSector - 2);
            if (endOffset + 2 > record.Length)
            {
                throw new InvalidDataException("The NTFS update-sequence replacement is outside the record.");
            }

            var onDisk = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(endOffset, 2));
            if (onDisk != sequence)
            {
                throw new InvalidDataException("The NTFS update-sequence check failed.");
            }

            var replacement = BinaryPrimitives.ReadUInt16LittleEndian(
                record.AsSpan(usaOffset + i * 2, 2));

            BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(endOffset, 2), replacement);
        }
    }

    private static SafeFileHandle CreateMftHandle(string rootPath)
    {
        var normalizedRoot = Path.GetPathRoot(rootPath);
        if (string.IsNullOrWhiteSpace(normalizedRoot))
        {
            throw new InvalidOperationException("The NTFS source volume root could not be determined.");
        }

        var mftPath = Path.Combine(normalizedRoot, "$MFT");
        var handle = CreateFile(
            mftPath,
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
                $"Could not open the NTFS MFT at {mftPath}.");
        }

        return handle;
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
