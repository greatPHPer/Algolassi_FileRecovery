using System.Buffers.Binary;
using System.Text;
using Xunit;

namespace FileRecovery.Tests;

public sealed class NtfsRarArchiveCarvingTests
{
    [Fact]
    public void TryMeasureRarArchive_ValidMinimalRar5_ReturnsExactLength()
    {
        var archive = BuildMinimalRar5();

        var result = Measure(archive);

        Assert.True(result.Success);
        Assert.Equal(archive.LongLength, result.Length);
        Assert.Equal("RAR 5.x", result.Format);
    }

    [Fact]
    public void TryMeasureRarArchive_ValidMinimalRar4_ReturnsExactLength()
    {
        var archive = BuildMinimalRar4();

        var result = Measure(archive);

        Assert.True(result.Success);
        Assert.Equal(archive.LongLength, result.Length);
        Assert.Equal("RAR 4.x", result.Format);
    }

    [Fact]
    public void TryMeasureRarArchive_BadHeaderCrc_RejectsRar5()
    {
        var archive = BuildMinimalRar5();
        archive[8] ^= 0x01;

        var result = Measure(archive);

        Assert.False(result.Success);
    }

    private static (bool Success, long Length, string Format) Measure(byte[] archive)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            "AlgoLassi.FileRecovery.Tests",
            $"rar-{Guid.NewGuid():N}.bin");

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, archive);

        try
        {
            using var input = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite);

            var success = NtfsDeepFileRecoveryService.TryMeasureRarArchive(
                input.SafeFileHandle,
                startOffset: 0,
                maximumArchiveLength: archive.LongLength,
                CancellationToken.None,
                out var length,
                out var format);

            return (success, length, format);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildMinimalRar5()
    {
        byte[] signature = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
        byte[] mainHeaderBody = [0x01, 0x00, 0x00];
        byte[] endHeaderBody = [0x05, 0x00, 0x00];

        return signature
            .Concat(BuildRar5Block(mainHeaderBody))
            .Concat(BuildRar5Block(endHeaderBody))
            .ToArray();
    }

    private static byte[] BuildRar5Block(byte[] headerBody)
    {
        if (headerBody.Length >= 128)
        {
            throw new ArgumentOutOfRangeException(nameof(headerBody));
        }

        var crcInput = new byte[headerBody.Length + 1];
        crcInput[0] = (byte)headerBody.Length;
        Buffer.BlockCopy(headerBody, 0, crcInput, 1, headerBody.Length);

        var block = new byte[4 + crcInput.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(
            block.AsSpan(0, 4),
            ComputeCrc32(crcInput));
        Buffer.BlockCopy(crcInput, 0, block, 4, crcInput.Length);
        return block;
    }

    private static byte[] BuildMinimalRar4()
    {
        byte[] signature = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];
        return signature
            .Concat(BuildRar4Header(0x73))
            .Concat(BuildRar4Header(0x7B))
            .ToArray();
    }

    private static byte[] BuildRar4Header(byte type)
    {
        var header = new byte[7];
        header[2] = type;
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(3, 2), 0);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(5, 2), 7);
        var crc = (ushort)(ComputeCrc32(header.AsSpan(2)) & 0xFFFF);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(0, 2), crc);
        return header;
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
}
