using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Netcheck.Measurements.Resolvers;

/// <summary>Minimal DNS wire format (RFC 1035): one A-record question out, header + A answers back.</summary>
public static class DnsWire
{
    public const ushort TypeA = 1;
    public const int RcodeNoError = 0, RcodeNameError = 3;

    public static byte[] Query(ushort id, string name)
    {
        var buffer = new List<byte>(32 + name.Length);
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, id);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], 0x0100);   // standard query, recursion desired
        BinaryPrimitives.WriteUInt16BigEndian(header[4..], 1);        // one question
        buffer.AddRange(header.ToArray());
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63)
                throw new ArgumentException("Invalid DNS name.", nameof(name));
            buffer.Add((byte)bytes.Length);
            buffer.AddRange(bytes);
        }
        buffer.Add(0);
        buffer.AddRange([0, (byte)TypeA, 0, 1]);                       // QTYPE A, QCLASS IN
        return buffer.ToArray();
    }

    public sealed record Response(ushort Id, bool IsResponse, bool Truncated, int Rcode, IReadOnlyList<IPAddress> Addresses);

    /// <summary>Parses the header and any A answers. Returns null for malformed packets.</summary>
    public static Response? Parse(ReadOnlySpan<byte> packet)
    {
        try
        {
            if (packet.Length < 12)
                return null;
            var id = BinaryPrimitives.ReadUInt16BigEndian(packet);
            var flags = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
            var questions = BinaryPrimitives.ReadUInt16BigEndian(packet[4..]);
            var answers = BinaryPrimitives.ReadUInt16BigEndian(packet[6..]);
            var offset = 12;
            for (var q = 0; q < questions; q++)
            {
                offset = SkipName(packet, offset);
                offset += 4;
            }
            var addresses = new List<IPAddress>();
            for (var a = 0; a < answers && offset < packet.Length; a++)
            {
                offset = SkipName(packet, offset);
                var type = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..]);
                var length = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 8)..]);
                offset += 10;
                if (type == TypeA && length == 4)
                    addresses.Add(new IPAddress(packet.Slice(offset, 4)));
                offset += length;
            }
            return new Response(id, (flags & 0x8000) != 0, (flags & 0x0200) != 0, flags & 0x000F, addresses);
        }
        catch (Exception error) when (error is ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            return null;
        }
    }

    private static int SkipName(ReadOnlySpan<byte> packet, int offset)
    {
        while (true)
        {
            var length = packet[offset];
            if ((length & 0xC0) == 0xC0)
                return offset + 2;          // compression pointer ends the name
            if (length == 0)
                return offset + 1;
            offset += length + 1;
        }
    }
}
