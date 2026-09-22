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

    private const uint NtfsAttributeData = 0x80;
    private const uint NtfsAttributeEnd = 0xFFFFFFFF;
    private const byte NonResidentForm = 1;

    public NtfsDataStreamInfo ReadDefaultDataStream(
        NtfsVolumeInfo volumeInfo,
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

        using var mftHandle = CreateMftHandle(volumeInfo.RootPath);

        var record = new byte[checked((int)volumeInfo.BytesPerFileRecordSegment)];
        ReadAt(mftHandle, relativeMftOffset, record);

        if (record.Length < 48 ||
            record[0] != (byte)'F' ||
            record[1] != (byte)'I' ||
            record[2] != (byte)'L' ||
            record[3] != (byte)'E')
        {
            return NotFound("The referenced MFT segment no longer contains a valid FILE record.");
        }

        ApplyUpdateSequenceFixups(record, checked((int)volumeInfo.BytesPerSector));

        var recordSequence = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(16, 2));
        var recordFlags = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(22, 2));

        if (sequenceNumber != 0 && recordSequence != sequenceNumber)
        {
            return NotFound("The MFT segment sequence number no longer matches the deleted file reference.");
        }

        if ((recordFlags & 0x0001) != 0)
        {
            return NotFound("The MFT segment is currently marked in use, so the historical deletion reference may have been reused.");
        }

        var firstAttributeOffset = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(20, 2));
        if (firstAttributeOffset < 24 ||
            firstAttributeOffset >= record.Length)
        {
            return NotFound("The MFT record does not contain a valid attribute area.");
        }

        var offset = (int)firstAttributeOffset;
        while (offset + 16 <= record.Length)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(record.AsSpan(offset, 4));
            if (type == NtfsAttributeEnd)
            {
                break;
            }

            var recordLength = BinaryPrimitives.ReadUInt32LittleEndian(record.AsSpan(offset + 4, 4));
            if (recordLength < 24 ||
                offset + recordLength > record.Length)
            {
                break;
            }

            var formCode = record[offset + 8];
            var nameLength = record[offset + 9];
            var nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(offset + 10, 2));

            var isUnnamed = nameLength == 0;

            if (nameLength > 0 &&
                (nameOffset == 0 ||
                 offset + nameOffset + (nameLength * 2) > record.Length))
            {
                offset += checked((int)recordLength);
                continue;
            }

            if (type == NtfsAttributeData && isUnnamed)
            {
                if (formCode == NonResidentForm)
                {
                    return ParseNonResidentData(record, offset, checked((int)recordLength));
                }

                return ParseResidentData(record, offset, checked((int)recordLength));
            }

            offset += checked((int)recordLength);
        }

        return NotFound("No unnamed $DATA attribute was retained in the MFT segment.");
    }

    private static NtfsDataStreamInfo ParseResidentData(byte[] record, int attributeOffset, int attributeLength)
    {
        if (attributeLength < 24)
        {
            return NotFound("The resident $DATA attribute is incomplete.");
        }

        var valueLength = BinaryPrimitives.ReadUInt32LittleEndian(
            record.AsSpan(attributeOffset + 16, 4));
        var valueOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            record.AsSpan(attributeOffset + 20, 2));

        if (valueOffset + valueLength > attributeLength)
        {
            return NotFound("The resident $DATA value is outside its attribute record.");
        }

        var data = new byte[checked((int)valueLength)];
        record.AsSpan(attributeOffset + valueOffset, checked((int)valueLength)).CopyTo(data);

        return new NtfsDataStreamInfo
        {
            Found = true,
            IsResident = true,
            FileSizeBytes = valueLength,
            ValidDataLengthBytes = valueLength,
            ResidentData = data,
            Evidence = "The default $DATA stream is resident inside the retained MFT record."
        };
    }

    private static NtfsDataStreamInfo ParseNonResidentData(byte[] record, int attributeOffset, int attributeLength)
    {
        if (attributeLength < 64)
        {
            return NotFound("The nonresident $DATA attribute is incomplete.");
        }

        var lowestVcn = BinaryPrimitives.ReadInt64LittleEndian(
            record.AsSpan(attributeOffset + 16, 8));
        var mappingPairsOffset = BinaryPrimitives.ReadUInt16LittleEndian(
            record.AsSpan(attributeOffset + 32, 2));
        var allocatedLength = BinaryPrimitives.ReadInt64LittleEndian(
            record.AsSpan(attributeOffset + 40, 8));
        var fileSize = BinaryPrimitives.ReadInt64LittleEndian(
            record.AsSpan(attributeOffset + 48, 8));
        var validDataLength = BinaryPrimitives.ReadInt64LittleEndian(
            record.AsSpan(attributeOffset + 56, 8));

        if (mappingPairsOffset >= attributeLength)
        {
            return NotFound("The nonresident $DATA mapping pairs are outside the attribute record.");
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
            return NotFound($"The NTFS data-run list could not be parsed: {ex.Message}");
        }

        return new NtfsDataStreamInfo
        {
            Found = true,
            IsResident = false,
            FileSizeBytes = fileSize,
            ValidDataLengthBytes = validDataLength,
            Extents = extents,
            Evidence = $"The default $DATA stream retained {extents.Count:N0} nonresident extent(s); allocated length {allocatedLength:N0} bytes."
        };
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
