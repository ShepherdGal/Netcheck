using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Netcheck.TestServer;

/// <summary>
/// Loopback UDP DNS server with known behaviour for the benchmark checks: fixed delays for popular ("cached") and
/// fresh names (labels starting "nc"), optional dropped replies, and optional redirecting of non-existent names.
/// </summary>
public sealed class FakeDnsServer : IAsyncDisposable
{
    private readonly UdpClient socket;
    private readonly CancellationTokenSource stop = new();
    private readonly Task loop;
    private int received;

    public FakeDnsServer(TimeSpan cachedDelay, TimeSpan freshDelay, int dropEvery = 0, bool redirectMissing = false)
    {
        socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        Port = ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
        loop = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                UdpReceiveResult packet;
                try { packet = await socket.ReceiveAsync(stop.Token); }
                catch (Exception) when (stop.IsCancellationRequested) { return; }
                catch (SocketException) { continue; }
                var n = Interlocked.Increment(ref received);
                if (dropEvery > 0 && n % dropEvery == 0)
                    continue;
                var query = packet.Buffer;
                var name = QuestionName(query);
                var fresh = name.StartsWith("nc", StringComparison.Ordinal);
                _ = Task.Run(async () =>
                {
                    await Task.Delay(fresh ? freshDelay : cachedDelay);
                    var reply = Reply(query, answer: !fresh || redirectMissing, rcode: fresh && !redirectMissing ? 3 : 0);
                    try { await socket.SendAsync(reply, packet.RemoteEndPoint); } catch (Exception) { }
                });
            }
        });
    }

    public int Port { get; }
    public int Received => Volatile.Read(ref received);

    private static string QuestionName(byte[] query)
    {
        var labels = new List<string>();
        for (var i = 12; i < query.Length && query[i] != 0; i += query[i] + 1)
            labels.Add(Encoding.ASCII.GetString(query, i + 1, query[i]));
        return string.Join('.', labels);
    }

    private static byte[] Reply(byte[] query, bool answer, int rcode)
    {
        var questionEnd = 12;
        while (query[questionEnd] != 0) questionEnd += query[questionEnd] + 1;
        questionEnd += 5;
        var reply = new List<byte>(query[..questionEnd]);
        var flags = (ushort)(0x8180 | rcode);                 // response, recursion desired + available
        reply[2] = (byte)(flags >> 8); reply[3] = (byte)flags;
        reply[6] = 0; reply[7] = (byte)(answer ? 1 : 0);      // answer count
        reply[8] = reply[9] = reply[10] = reply[11] = 0;
        if (answer)
        {
            Span<byte> a = stackalloc byte[16];
            BinaryPrimitives.WriteUInt16BigEndian(a, 0xC00C);   // pointer to the question name
            BinaryPrimitives.WriteUInt16BigEndian(a[2..], 1);   // A
            BinaryPrimitives.WriteUInt16BigEndian(a[4..], 1);   // IN
            BinaryPrimitives.WriteUInt32BigEndian(a[6..], 60);  // TTL
            BinaryPrimitives.WriteUInt16BigEndian(a[10..], 4);
            a[12] = 203; a[13] = 0; a[14] = 113; a[15] = 7;      // 203.0.113.7 (documentation range)
            reply.AddRange(a.ToArray());
        }
        return reply.ToArray();
    }

    public async ValueTask DisposeAsync()
    {
        stop.Cancel();
        socket.Dispose();
        try { await loop; } catch (Exception) { }
        stop.Dispose();
    }
}
