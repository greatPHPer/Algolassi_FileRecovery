using System.Buffers.Binary;
using System.Text;
using Xunit;

namespace FileRecovery.Tests;

public sealed class NtfsMp4ArchiveCarvingTests
{
    [Fact]
    public void TryMeasureMp4Archive_ValidContainer_FindsBoundaryBeforeFollowingFreeSpace()
    {
        var archive = BuildMp4();
        var backingData = archive.Concat(new byte[512]).ToArray();

        var result = Measure(
            backingData,
            maximumArchiveLength: backingData.LongLength,
            knownFileSizeBytes: 0);

        Assert.True(result.Success);
        Assert.Equal(archive.LongLength, result.Length);
    }

    [Fact]
    public void TryMeasureMp4Archive_KnownLength_ValidatesWholeBoxSequence()
    {
        var archive = BuildMp4();
        var backingData = archive.Concat(new byte[512]).ToArray();

        var result = Measure(
            backingData,
            maximumArchiveLength: archive.LongLength,
            knownFileSizeBytes: archive.LongLength);

        Assert.True(result.Success);
        Assert.Equal(archive.LongLength, result.Length);
    }

    [Fact]
    public void TryMeasureMp4Archive_ExtendedSizeMdat_ReturnsExactLength()
    {
        var archive = BuildMp4(extendedMdat: true);

        var result = Measure(
            archive,
            maximumArchiveLength: archive.LongLength,
            knownFileSizeBytes: archive.LongLength);

        Assert.True(result.Success);
        Assert.Equal(archive.LongLength, result.Length);
    }

    [Fact]
    public void TryMeasureMp4Archive_ZeroSizeMdat_RequiresKnownOriginalLength()
    {
        var archive = BuildMp4(zeroSizeMdat: true);

        var withKnownSize = Measure(
            archive,
            maximumArchiveLength: archive.LongLength,
            knownFileSizeBytes: archive.LongLength);
        var withoutKnownSize = Measure(
            archive.Concat(new byte[512]).ToArray(),
            maximumArchiveLength: archive.LongLength + 512,
            knownFileSizeBytes: 0);

        Assert.True(withKnownSize.Success);
        Assert.Equal(archive.LongLength, withKnownSize.Length);
        Assert.False(withoutKnownSize.Success);
    }

    [Fact]
    public void TryMeasureMp4Archive_MissingMovieBox_IsRejected()
    {
        var ftyp = BuildFileTypeBox();
        var mdat = BuildBox("mdat", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        var backingData = ftyp.Concat(mdat).Concat(new byte[512]).ToArray();

        var result = Measure(
            backingData,
            maximumArchiveLength: backingData.LongLength,
            knownFileSizeBytes: 0);

        Assert.False(result.Success);
    }

    [Fact]
    public void TryMeasureMp4Archive_TrackWithoutMediaBox_IsRejected()
    {
        var ftyp = BuildFileTypeBox();
        var brokenTrack = BuildBox(
            "trak",
            BuildBox("tkhd", new byte[4]));
        var moov = BuildBox(
            "moov",
            BuildBox("mvhd", new byte[4]).Concat(brokenTrack).ToArray());
        var mdat = BuildBox("mdat", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        var backingData = ftyp.Concat(moov).Concat(mdat).Concat(new byte[512]).ToArray();

        var result = Measure(
            backingData,
            maximumArchiveLength: backingData.LongLength,
            knownFileSizeBytes: 0);

        Assert.False(result.Success);
    }

    private static (bool Success, long Length) Measure(
        byte[] backingData,
        long maximumArchiveLength,
        long knownFileSizeBytes)
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            "AlgoLassi.FileRecovery.Tests");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"mp4-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, backingData);

        try
        {
            using var input = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite);

            var success = NtfsDeepFileRecoveryService.TryMeasureMp4Archive(
                input.SafeFileHandle,
                startOffset: 0,
                maximumArchiveLength,
                knownFileSizeBytes,
                CancellationToken.None,
                out var length);

            return (success, length);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static byte[] BuildMp4(
        bool extendedMdat = false,
        bool zeroSizeMdat = false)
    {
        var ftyp = BuildFileTypeBox();

        var movieHeader = BuildBox("mvhd", new byte[4]);
        var trackHeader = BuildBox("tkhd", new byte[4]);
        var mediaHeader = BuildBox("mdhd", new byte[4]);
        var handler = BuildBox("hdlr", new byte[4]);
        var media = BuildBox("mdia", mediaHeader.Concat(handler).ToArray());
        var track = BuildBox("trak", trackHeader.Concat(media).ToArray());
        var moov = BuildBox("moov", movieHeader.Concat(track).ToArray());

        // Include bytes resembling an MP4 ftyp signature inside mdat to ensure
        // the parser follows box lengths rather than searching compressed payload.
        byte[] mediaPayload =
        [
            0x00, 0x00, 0x00, 0x10, 0x66, 0x74, 0x79, 0x70,
            0x6D, 0x70, 0x34, 0x32, 0x01, 0x02, 0x03, 0x04
        ];

        byte[] mdat;
        if (zeroSizeMdat)
        {
            mdat = new byte[8 + mediaPayload.Length];
            BinaryPrimitives.WriteUInt32BigEndian(mdat.AsSpan(0, 4), 0);
            Encoding.ASCII.GetBytes("mdat").CopyTo(mdat, 4);
            mediaPayload.CopyTo(mdat, 8);
        }
        else if (extendedMdat)
        {
            mdat = new byte[16 + mediaPayload.Length];
            BinaryPrimitives.WriteUInt32BigEndian(mdat.AsSpan(0, 4), 1);
            Encoding.ASCII.GetBytes("mdat").CopyTo(mdat, 4);
            BinaryPrimitives.WriteUInt64BigEndian(
                mdat.AsSpan(8, 8),
                checked((ulong)mdat.Length));
            mediaPayload.CopyTo(mdat, 16);
        }
        else
        {
            mdat = BuildBox("mdat", mediaPayload);
        }

        return ftyp.Concat(moov).Concat(mdat).ToArray();
    }

    private static byte[] BuildFileTypeBox()
    {
        var payload = Encoding.ASCII.GetBytes("isom")
            .Concat(new byte[4]) // minor_version
            .Concat(Encoding.ASCII.GetBytes("isom"))
            .Concat(Encoding.ASCII.GetBytes("mp42"))
            .ToArray();

        return BuildBox("ftyp", payload);
    }

    private static byte[] BuildBox(string type, byte[] payload)
    {
        if (type.Length != 4)
        {
            throw new ArgumentOutOfRangeException(nameof(type));
        }

        var box = new byte[checked(8 + payload.Length)];
        BinaryPrimitives.WriteUInt32BigEndian(
            box.AsSpan(0, 4),
            checked((uint)box.Length));
        Encoding.ASCII.GetBytes(type).CopyTo(box, 4);
        payload.CopyTo(box, 8);
        return box;
    }
}
