using Netcheck.Elevation;

internal static class DnsTransactionChecks
{
    internal static int Run()
    {
        var lab = new Fixture();
        Require(lab.Apply(() => true) == DnsTransactionOutcome.Committed && lab.Store.Record is null &&
            lab.Platform.Writes == 1 && lab.Platform.Current.OtherFamily == lab.Review.Before.OtherFamily, "commit");
        lab = new Fixture();
        Require(lab.Apply(() => false) == DnsTransactionOutcome.Restored && lab.Platform.Writes == 2 &&
            lab.Store.Record is null && lab.Platform.Current.Target.Assignment == DnsTargetAssignment.Automatic &&
            lab.Platform.Current.Target.Resolvers.Count == 0 &&
            lab.Platform.Current.OtherFamily == lab.Review.Before.OtherFamily, "failed verification restores baseline");
        lab = new Fixture();
        lab.Platform.AfterWrite = () =>
        {
            lab.Platform.AfterWrite = null;
            throw new IOException("Write succeeded before the platform reported an error.");
        };
        Require(lab.Apply(() => true) == DnsTransactionOutcome.Restored && lab.Platform.Writes == 2, "write then throw");
        lab = new Fixture();
        lab.Store.AfterPersist = () => lab.Platform.Allowed = false;
        Require(lab.Apply(() => true) == DnsTransactionOutcome.Rejected && lab.Platform.Writes == 0 &&
            lab.Store.Record is null, "post-journal policy check");
        lab = new Fixture();
        lab.Store.AfterPersist = () => lab.Platform.Disappeared = true;
        Require(lab.Apply(() => true) == DnsTransactionOutcome.Rejected && lab.Platform.Writes == 0 &&
            lab.Store.Record is null, "adapter disappears after journal, before write");
        lab = new Fixture();
        lab.Store.AfterPersist = () => throw new IOException("Journal flush failed.");
        try { _ = lab.Apply(() => true); throw new InvalidOperationException("Expected journal error."); }
        catch (IOException) { Require(lab.Platform.Writes == 0, "journal failure prevents write"); }
        lab = new Fixture();
        var external = lab.Review.Proposed with { Resolvers = [new("9.9.9.9", DnsEncryption.Plaintext)] };
        Require(lab.Apply(() =>
        {
            lab.Platform.Current = lab.Platform.Current with { Target = external };
            return true;
        }) == DnsTransactionOutcome.Conflict && lab.Platform.Current.Target == external &&
            lab.Store.Record is not null && lab.Platform.Writes == 1, "external edit survives verification");
        lab = new Fixture();
        using (var cancel = new CancellationTokenSource())
        {
            lab.Platform.AfterWrite = cancel.Cancel;
            Require(lab.Apply(() => throw new InvalidOperationException("Canceled verification started."), cancel.Token) ==
                DnsTransactionOutcome.Restored && lab.Platform.Writes == 2, "cancellation restores without running verification");
        }
        lab = new Fixture();
        lab.Store.Record = new(lab.Review.Before, lab.Review.Proposed);
        lab.Platform.Current = lab.Platform.Current with { Target = lab.Review.Proposed };
        lab.Platform.Allowed = false;
        Require(lab.NewTransaction().Recover() == DnsTransactionOutcome.RecoveryRequired &&
            lab.Platform.Writes == 0 && lab.Store.Record is not null, "recovery respects current policy");
        lab.Platform.Allowed = true;
        Require(lab.NewTransaction().Recover() == DnsTransactionOutcome.Restored && lab.Platform.Writes == 1 &&
            lab.Store.Record is null, "fresh transaction restores an interrupted operation");
        lab = new Fixture();
        lab.Store.Record = new(lab.Review.Before, lab.Review.Proposed with { AdapterId = Guid.Empty });
        Require(lab.NewTransaction().Recover() == DnsTransactionOutcome.RecoveryRequired && lab.Platform.Writes == 0,
            "invalid recovery record cannot authorize a write");
        Console.WriteLine("PASS DNS transaction (11 scenarios)");
        return 0;
    }

    private static void Require(bool condition, string scenario)
    {
        if (!condition)
            throw new InvalidOperationException($"DNS transaction scenario failed: {scenario}");
    }

    private sealed class Fixture
    {
        internal readonly Store Store = new();
        internal readonly Platform Platform;
        internal readonly ReviewedDnsChange Review;

        internal Fixture()
        {
            var id = Guid.NewGuid();
            var before = new DnsSnapshot(new DnsChange(id, DnsTargetFamily.Ipv4, DnsTargetAssignment.Automatic, [], false),
                new DnsChange(id, DnsTargetFamily.Ipv6, DnsTargetAssignment.Manual,
                    [new("2606:4700:4700::1111", DnsEncryption.Plaintext)], false));
            Review = new(before, new DnsChange(id, DnsTargetFamily.Ipv4, DnsTargetAssignment.Manual,
                [new("1.1.1.1", DnsEncryption.RequireHttps, "https://cloudflare-dns.com/dns-query")], false));
            Platform = new Platform(before, Store);
        }

        internal DnsTransaction NewTransaction() => new(Platform, Store);
        internal DnsTransactionOutcome Apply(Func<bool> verify, CancellationToken token = default) =>
            NewTransaction().Apply(Review, _ => verify(), token);
    }

    private sealed class Platform(DnsSnapshot baseline, Store store) : IDnsTransactionPlatform
    {
        internal DnsSnapshot Current = baseline;
        internal int Writes;
        internal bool Allowed = true;
        internal bool Disappeared;
        internal Action? AfterWrite;
        public DnsSnapshot Read(Guid adapterId, DnsTargetFamily family) =>
            Disappeared ? throw new NotSupportedException("Adapter removed.") : Current;
        public bool Permits(DnsChange change) => Allowed;
        public void Write(DnsChange change)
        {
            Require(store.Record is not null, "journal before any write");
            Writes++;
            Current = Current with { Target = change };
            AfterWrite?.Invoke();
        }
    }

    private sealed class Store : IDnsRecoveryStore, IDisposable
    {
        internal DnsRecoveryRecord? Record;
        internal Action? AfterPersist;
        private bool _leased;
        public IDisposable AcquireExclusive()
        {
            Require(!_leased, "exclusive lease");
            _leased = true;
            return this;
        }
        public DnsRecoveryRecord? Read() => Record;
        public void Persist(DnsRecoveryRecord record)
        {
            Record = record;
            AfterPersist?.Invoke();
        }
        public void Clear() => Record = null;
        public void Dispose() => _leased = false;
    }
}
