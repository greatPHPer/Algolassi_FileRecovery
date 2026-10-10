using System.Text;
using Xunit;

namespace FileRecovery.Tests;

public sealed class NtfsUnknownExtensionCarvingTests
{
    [Theory]
    [InlineData("report.unknown")]
    [InlineData("report.custombin")]
    public void SupportsDeepCarving_UnknownExtension_AllowsSignatureBasedSearch(string fileName)
    {
        Assert.True(NtfsDeepFileRecoveryService.SupportsDeepCarving(fileName));
    }

    [Fact]
    public void TryCarve_UnknownExtension_DetectsJpegFromContentSignature()
    {
        byte[] buffer =
        [
            0x00,
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x01, 0x02, 0xFF, 0xD9,
            0x00
        ];

        var found = NtfsDeepFileRecoveryService.TryCarve(
            ".unknown",
            buffer,
            knownFileSizeBytes: 0,
            bytesPerCluster: 4096,
            out var startOffset,
            out var length,
            out var format);

        Assert.True(found);
        Assert.Equal(1, startOffset);
        Assert.Equal(10, length);
        Assert.Equal("JPEG (extension-independent)", format);
    }

    [Fact]
    public void TryCarve_UnknownExtension_DetectsWavFromRiffWaveSignature()
    {
        var buffer = new byte[52];
        Encoding.ASCII.GetBytes("RIFF").CopyTo(buffer, 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            buffer.AsSpan(4, 4),
            44);
        Encoding.ASCII.GetBytes("WAVE").CopyTo(buffer, 8);
        Encoding.ASCII.GetBytes("fmt ").CopyTo(buffer, 12);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            buffer.AsSpan(16, 4),
            16);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(
            buffer.AsSpan(20, 2),
            1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(
            buffer.AsSpan(22, 2),
            1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            buffer.AsSpan(24, 4),
            8000);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            buffer.AsSpan(28, 4),
            8000);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(
            buffer.AsSpan(32, 2),
            1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(
            buffer.AsSpan(34, 2),
            8);
        Encoding.ASCII.GetBytes("data").CopyTo(buffer, 36);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            buffer.AsSpan(40, 4),
            8);
        for (var i = 44; i < buffer.Length; i++)
        {
            buffer[i] = (byte)(i - 44);
        }

        var found = NtfsDeepFileRecoveryService.TryCarve(
            ".blob",
            buffer,
            knownFileSizeBytes: 0,
            bytesPerCluster: 4096,
            out var startOffset,
            out var length,
            out var format);

        Assert.True(found);
        Assert.Equal(0, startOffset);
        Assert.Equal(buffer.Length, length);
        Assert.Equal("WAV (extension-independent)", format);
    }

    [Fact]
    public void TryCarve_UnknownExtension_UsesExactKnownLengthForSmallText()
    {
        var buffer = Encoding.UTF8.GetBytes("Known text file");

        var found = NtfsDeepFileRecoveryService.TryCarve(
            ".unknown",
            buffer,
            knownFileSizeBytes: buffer.LongLength,
            bytesPerCluster: 4096,
            out var startOffset,
            out var length,
            out var format);

        Assert.True(found);
        Assert.Equal(0, startOffset);
        Assert.Equal(buffer.Length, length);
        Assert.Equal("Plain text (unknown-extension heuristic)", format);
    }

    [Fact]
    public void TryCarve_UnknownExtension_DoesNotGuessTextWhenOriginalLengthIsUnknown()
    {
        var buffer = Encoding.UTF8.GetBytes("Known text file");

        var found = NtfsDeepFileRecoveryService.TryCarve(
            ".unknown",
            buffer,
            knownFileSizeBytes: 0,
            bytesPerCluster: 4096,
            out var startOffset,
            out var length,
            out var format);

        Assert.False(found);
        Assert.Equal(0, startOffset);
        Assert.Equal(0, length);
        Assert.Equal(string.Empty, format);
    }

    [Fact]
    public void SupportsDeepCarving_TextWithoutKnownOriginalLength_RemainsDisabled()
    {
        Assert.False(NtfsDeepFileRecoveryService.SupportsDeepCarving("report.txt"));
        Assert.True(NtfsDeepFileRecoveryService.SupportsDeepCarving("report.txt", 128));
    }
}
