using System.IO.Compression;
using System.Text;

namespace Netcheck.Core.Updates;

/// <summary>
/// Reads a .NET one-file app (P14) without running it: the installer and updater use it to read the version and the
/// protected-deployment marker of Netcheck.dll inside Netcheck.exe, and a running copy uses it to list its own
/// assemblies. Format: the apphost holds the bundle header offset right before a fixed 32-byte signature; the header
/// lists every embedded file (offset, size, compressed size, type, path); compressed entries are raw deflate.
/// </summary>
public static class OneFileBundle
{
    private static readonly byte[] Signature =
    [
        0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32,
        0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
    ];

    /// <summary>The paths of every file inside the one-file exe (empty when it isn't one).</summary>
    public static IReadOnlyList<string> ListFiles(string exe)
    {
        var names = new List<string>();
        Walk(exe, (path, _, _, _, _) => { names.Add(path); return false; });
        return names;
    }

    /// <summary>The bytes of <paramref name="name"/> inside the one-file exe, or null when it isn't one or lacks it.</summary>
    public static byte[]? ReadFile(string exe, string name, long maxBytes = 512L * 1024 * 1024)
    {
        byte[]? found = null;
        Walk(exe, (path, image, offset, size, compressed) =>
        {
            if (!string.Equals(path, name, StringComparison.OrdinalIgnoreCase))
                return false;
            found = Extract(image, offset, size, compressed, maxBytes);
            return true;
        });
        return found;
    }

    private static byte[]? Extract(byte[] image, long offset, long size, long compressed, long maxBytes)
    {
        if (size < 0 || size > maxBytes || offset < 0 || offset + Math.Max(size, compressed) > image.Length)
            return null;
        if (compressed == 0)
            return image.AsSpan((int)offset, (int)size).ToArray();
        using var inflate = new DeflateStream(new MemoryStream(image, (int)offset, (int)compressed, writable: false),
            CompressionMode.Decompress);
        var output = new byte[size];
        inflate.ReadExactly(output);
        return output;
    }

    /// <summary>Visits each manifest entry (path, image, offset, size, compressed size) until the visitor returns true.</summary>
    private static void Walk(string exe, Func<string, byte[], long, long, long, bool> visit)
    {
        try
        {
            var image = File.ReadAllBytes(exe);
            var at = image.AsSpan().IndexOf(Signature);
            if (at < 8)
                return;
            var header = BitConverter.ToInt64(image, at - 8);
            if (header <= 0 || header >= image.Length)
                return;
            using var reader = new BinaryReader(new MemoryStream(image, writable: false), Encoding.UTF8);
            reader.BaseStream.Position = header;
            var major = reader.ReadUInt32();
            reader.ReadUInt32();
            var count = reader.ReadInt32();
            if (major < 2 || count is < 0 or > 100_000)
                return;
            reader.ReadString();                               // bundle id
            reader.BaseStream.Position += 8 * 4 + 8;           // deps.json and runtimeconfig.json locations, flags
            for (var i = 0; i < count; i++)
            {
                var offset = reader.ReadInt64();
                var size = reader.ReadInt64();
                var compressed = major >= 6 ? reader.ReadInt64() : 0;
                reader.ReadByte();                             // file type
                var path = reader.ReadString();
                if (visit(path, image, offset, size, compressed))
                    return;
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or EndOfStreamException or
            InvalidDataException or ArgumentException)
        {
        }
    }
}
