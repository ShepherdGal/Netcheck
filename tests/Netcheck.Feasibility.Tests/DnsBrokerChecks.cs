using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using Netcheck.Elevation;
using Netcheck.Windows;

[SupportedOSPlatform("windows")]
internal static class DnsBrokerChecks
{
    internal static async Task<int> RunAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = deadline.Token;
        var writable = Directory.CreateTempSubdirectory("netcheck-unprotected-");
        try { Require(!WindowsDnsBroker.ProtectedPath(writable) && !WindowsDnsBroker.IsEnabled); }
        finally { writable.Delete(); }
        var id = Guid.NewGuid();
        var before = new DnsChange(id, DnsTargetFamily.Ipv4, DnsTargetAssignment.Automatic, [], false);
        var proposed = new DnsChange(id, DnsTargetFamily.Ipv4, DnsTargetAssignment.Manual,
            [new("192.0.2.2", DnsEncryption.Plaintext)], false);
        var review = new ReviewedDnsChange(new(before, null, "native evidence"), proposed);
        var apply = new WindowsDnsBroker.Request(1, review, Recover: false);
        var fixture = new Fixture(review.Before);

        await Exchange(async pipe =>
        {
            await DnsBrokerPipe.SendAsync(pipe, apply, token);
            var check = await DnsBrokerPipe.ReceiveAsync<WindowsDnsBroker.Reply>(pipe, token);
            Require(check is { NeedsVerification: true, Outcome: null } && fixture.Writes == 1 && fixture.Record is not null);
            await DnsBrokerPipe.SendAsync(pipe, false, token);
            var result = await DnsBrokerPipe.ReceiveAsync<WindowsDnsBroker.Reply>(pipe, token);
            Require(result.Outcome == DnsTransactionOutcome.Restored && fixture.Writes == 2 && fixture.Record is null);
        });

        await Exchange(async pipe =>
        {
            await DnsBrokerPipe.SendAsync(pipe, apply, token);
            Require((await DnsBrokerPipe.ReceiveAsync<WindowsDnsBroker.Reply>(pipe, token)).NeedsVerification);
            await pipe.DisposeAsync();
        }, brokenPipeExpected: true);
        Require(fixture.Writes == 4 && fixture.Record is null &&
            DnsTransaction.Matches(fixture.Snapshot, before, review.Before));

        fixture.Snapshot = fixture.Snapshot with { NativeEvidence = "external change" };
        await Exchange(async pipe =>
        {
            await DnsBrokerPipe.SendAsync(pipe, apply, token);
            var result = await DnsBrokerPipe.ReceiveAsync<WindowsDnsBroker.Reply>(pipe, token);
            Require(result.Outcome == DnsTransactionOutcome.Rejected && fixture.Writes == 4);
        });

        await Exchange(async pipe =>
        {
            await DnsBrokerPipe.SendAsync(pipe, apply with { Version = 2 }, token);
            var result = await DnsBrokerPipe.ReceiveAsync<WindowsDnsBroker.Reply>(pipe, token);
            Require(result.Outcome == DnsTransactionOutcome.Rejected && fixture.Writes == 4);
        });

        await Exchange(async pipe =>
        {
            var header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, int.MaxValue);
            await pipe.WriteAsync(header, token);
        }, malformedExpected: true);
        Require(fixture.Writes == 4);

        fixture.Snapshot = review.Before;
        await Exchange(async pipe =>
        {
            await DnsBrokerPipe.SendAsync(pipe, apply, token);
            Require((await DnsBrokerPipe.ReceiveAsync<WindowsDnsBroker.Reply>(pipe, token)).NeedsVerification);
            await DnsBrokerPipe.SendAsync(pipe, true, token);
            Require((await DnsBrokerPipe.ReceiveAsync<WindowsDnsBroker.Reply>(pipe, token)).Outcome ==
                DnsTransactionOutcome.Committed && fixture.Writes == 5 && fixture.Record is null);
        });
        fixture.Record = new DnsRecoveryRecord(review.Before, proposed);
        await Exchange(async pipe =>
        {
            await DnsBrokerPipe.SendAsync(pipe, new WindowsDnsBroker.Request(1, null, Recover: true), token);
            Require((await DnsBrokerPipe.ReceiveAsync<WindowsDnsBroker.Reply>(pipe, token)).Outcome ==
                DnsTransactionOutcome.Restored && fixture.Writes == 6 && fixture.Record is null);
        });

        var native = new DnsFamilyConfiguration(2, "192.0.2.2, 192.0.2.1", null, null, null, null,
            [new(1, "https://dns.example/dns-query", 6)], [], 0, 0, 0, 0);
        var decoded = WindowsDnsTransactionPlatform.Decode(id, DnsTargetFamily.Ipv4, native);
        Require(decoded.Resolvers.Select(resolver => resolver.Address).SequenceEqual(["192.0.2.2", "192.0.2.1"]) &&
            decoded.Resolvers[1].Encryption == DnsEncryption.PreferHttps && decoded.AllowPlaintextFallback);
        ExpectUnsupported(native with { ProfileServers = "192.0.2.3" });
        ExpectUnsupported(native with { ServerProperties = [new(1, null, 1)] });
        ExpectUnsupported(native with { ServerProperties = [new(2, "https://dns.example/dns-query", 2)] });
        Console.WriteLine("PASS DNS broker IPC: peer IDs, keep, restore, disconnect, stale evidence, protocol version and frame limits");
        Console.WriteLine("PASS Windows DNS mapping: resolver order, explicit DoH, and rejection of unsupported baselines");
        return 0;

        async Task Exchange(Func<NamedPipeServerStream, Task> ui, bool brokenPipeExpected = false, bool malformedExpected = false)
        {
            var name = $"Netcheck.Test.{Guid.NewGuid():N}";
            using var server = DnsBrokerPipe.Listen(name);
            using var client = DnsBrokerPipe.ConnectToLocal(name);
            await Task.WhenAll(server.WaitForConnectionAsync(token), client.ConnectAsync(token));
            using var self = Process.GetCurrentProcess();
            using var different = Process.GetProcessesByName("System").First();
            Require(DnsBrokerPipe.IsPeer(server, self, server: false) && DnsBrokerPipe.IsPeer(client, self, server: true));
            Require(!DnsBrokerPipe.IsPeer(server, different, server: false) && !DnsBrokerPipe.IsPeer(client, different, server: true));
            var service = WindowsDnsBroker.ExecuteAsync(client, () => new DnsTransaction(fixture, fixture), token);
            await ui(server);
            try
            {
                await service;
                Require(!malformedExpected);
            }
            catch (InvalidDataException) when (malformedExpected) { }
            catch (IOException) when (brokenPipeExpected) { }
        }

        void ExpectUnsupported(DnsFamilyConfiguration settings)
        {
            try { _ = WindowsDnsTransactionPlatform.Decode(id, DnsTargetFamily.Ipv4, settings); }
            catch (NotSupportedException) { return; }
            throw new InvalidOperationException("Expected an unsupported DNS baseline.");
        }
    }

    private static void Require(bool condition)
    {
        if (!condition)
            throw new InvalidOperationException("DNS broker fixture assertion failed.");
    }

    private sealed class Fixture(DnsSnapshot before) : IDnsTransactionPlatform, IDnsRecoveryStore, IDisposable
    {
        internal DnsSnapshot Snapshot = before;
        internal DnsRecoveryRecord? Record;
        internal int Writes;
        public DnsSnapshot Read(Guid adapterId, DnsTargetFamily family) => Snapshot;
        public bool Permits(DnsChange change) => true;
        public void Write(DnsChange change)
        {
            Require(Record is not null);
            Writes++;
            Snapshot = Snapshot with { Target = change };
        }
        public IDisposable AcquireExclusive() => this;
        public DnsRecoveryRecord? Read() => Record;
        public void Persist(DnsRecoveryRecord record) => Record = record;
        public void Clear() => Record = null;
        public void Dispose() { }
    }
}
