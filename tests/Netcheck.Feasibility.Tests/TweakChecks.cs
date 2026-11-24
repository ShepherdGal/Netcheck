using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Netcheck.Elevation;

// P5 Boost: the tweak allowlist, the transaction (detect → … → commit or restore), the broker exchange and a
// crash lab that kills the broker at each step and proves an independent recovery restores the PC.
internal static class TweakChecks
{
    private static readonly Guid Nic = Guid.Parse("11111111-2222-4333-8444-555555555555");   // made-up adapter ID

    private static TweakValue[] Recommended() =>
    [
        new(TweakId.NicPowerSaving, Nic, 0),
        new(TweakId.BackgroundUpdates, Guid.Empty, 20),
    ];

    private static Dictionary<(TweakId, Guid), long?> HomePc() => new()
    {
        [(TweakId.NicPowerSaving, Nic)] = 1,
        [(TweakId.BackgroundUpdates, Guid.Empty)] = null,
        [(TweakId.Ecn, Guid.Empty)] = 0,
        [(TweakId.MediaThrottling, Guid.Empty)] = 10,
        [(TweakId.AutoTuning, Guid.Empty)] = 3,
        [(TweakId.EnergyEfficientEthernet, Nic)] = 0,
        [(TweakId.UpdateSharing, Guid.Empty)] = 0,
    };

    // ---------- allowlist ----------

    internal static int RunRules()
    {
        Require(Recommended().All(TweakRules.Valid), "recommended values are valid");
        foreach (var id in Enum.GetValues<TweakId>())
            if (!TweakRules.DriverMapped(id))
                Require(TweakRules.Valid(new(id, TweakRules.AdapterScoped(id) ? Nic : Guid.Empty, TweakRules.Target(id))), $"target of {id} is valid");
        Require(!TweakRules.Valid(new((TweakId)99, Guid.Empty, 0)), "unknown tweak");
        Require(!TweakRules.Valid(new(TweakId.NicPowerSaving, Guid.Empty, 0)), "adapter tweak without adapter");
        Require(!TweakRules.Valid(new(TweakId.Ecn, Nic, 1)), "system tweak with adapter");
        Require(!TweakRules.Valid(new(TweakId.Ecn, Guid.Empty, 2)), "ECN out of range");
        Require(!TweakRules.Valid(new(TweakId.BackgroundUpdates, Guid.Empty, 101)), "percentage out of range");
        Require(!TweakRules.Valid(new(TweakId.MediaThrottling, Guid.Empty, 0)), "throttling 0 not allowed");
        Require(!TweakRules.Valid(new(TweakId.AutoTuning, Guid.Empty, null)), "auto-tuning cannot be deleted");
        Require(TweakRules.Valid(new(TweakId.MediaThrottling, Guid.Empty, null)), "throttling may return to default");
        Console.WriteLine("PASS tweak allowlist (8 rejections, every target valid)");

        // Driver writes send a label that matches the value (live "Invalid parameter" fix, 2026-11-17).
        if (OperatingSystem.IsWindows())
            CheckDriverLabels();

        // P8 additions: power-plan tweaks are scoped to a scheme; adapter ones to an adapter; ranges are tight.
        var scheme = Guid.NewGuid();
        Require(TweakRules.PowerPlan(TweakId.WifiPowerSaving) && TweakRules.PowerPlan(TweakId.PcieLinkPower), "power-plan tweaks are scheme-scoped");
        Require(TweakRules.Valid(new(TweakId.WifiPowerSaving, scheme, 0)) && TweakRules.Valid(new(TweakId.WifiPowerSaving, scheme, 3)), "Wi-Fi power 0..3");
        Require(!TweakRules.Valid(new(TweakId.WifiPowerSaving, scheme, 4)), "Wi-Fi power 4 rejected");
        Require(!TweakRules.Valid(new(TweakId.PcieLinkPower, scheme, 3)), "PCIe link power 3 rejected");
        Require(!TweakRules.Valid(new(TweakId.PcieLinkPower, Guid.Empty, 0)), "power-plan tweak without a scheme rejected");
        Require(!TweakRules.Valid(new(TweakId.InterruptModeration, Nic, 2)) && TweakRules.Valid(new(TweakId.InterruptModeration, Nic, 0)), "on/off adapter values only");
        Require(!TweakRules.Valid(new(TweakId.GreenEthernet, Guid.Empty, 0)), "adapter tweak without adapter rejected");
        Require(!TweakRules.Valid(new(TweakId.PreferredBand, Nic, 256)) && !TweakRules.Valid(new(TweakId.PreferredBand, Nic, null)), "driver values stay small and set");
        Require(TweakRules.MaxBatch >= 16, "a full Boost list fits one batch");
        // P15: RSS / packet coalescing on-off only; cable speed is driver-mapped with room for large codes.
        Require(TweakRules.Target(TweakId.ReceiveSideScaling) == 1 && TweakRules.Target(TweakId.PacketCoalescing) == 0 &&
                TweakRules.Valid(new(TweakId.ReceiveSideScaling, Nic, 1)) && !TweakRules.Valid(new(TweakId.PacketCoalescing, Nic, 2)),
                "RSS on, packet coalescing off, on/off only");
        Require(TweakRules.DriverMapped(TweakId.SpeedDuplex) && TweakRules.Valid(new(TweakId.SpeedDuplex, Nic, 2500)) &&
                !TweakRules.Valid(new(TweakId.SpeedDuplex, Guid.Empty, 0)), "cable speed: driver value, adapter-scoped");
        if (OperatingSystem.IsWindows())
        {
            // Driver labels: the target is the label that means what Boost promises, never a near miss.
            Require(Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.PreferredBand, "Prefer 5GHz band") &&
                    Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.PreferredBand, "5 GHz preferred"), "5 GHz preference labels");
            Require(!Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.PreferredBand, "Prefer 2.4GHz band") &&
                    !Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.PreferredBand, "Prefer 6GHz band") &&
                    !Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.PreferredBand, "No Preference"), "not 2.4 / 6 GHz / none");
            Require(Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.MimoPowerSave, "No SMPS") &&
                    !Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.MimoPowerSave, "Auto SMPS"), "MIMO: No SMPS only");
            Require(Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.RoamingAggressiveness, "3. Medium") &&
                    !Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.RoamingAggressiveness, "2. Medium-Low") &&
                    !Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.RoamingAggressiveness, "4. Medium-High"), "roaming: Medium only");
            Require(Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.SpeedDuplex, "Auto Negotiation") &&
                    !Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.SpeedDuplex, "1.0 Gbps Full Duplex") &&
                    !Netcheck.Elevation.WindowsTweakPlatform.IsTargetLabel(TweakId.SpeedDuplex, "100 Mbps Full Duplex"), "cable speed: Auto only");
            string[] speeds = ["Auto Negotiation", "100 Mbps Half Duplex", "100 Mbps Full Duplex", "1.0 Gbps Full Duplex", "2.5 Gbps Full Duplex"];
            string[] codes = ["0", "3", "4", "6", "2500"];
            Require(Netcheck.Elevation.WindowsTweakPlatform.CappedSpeed(speeds, codes, 6) &&
                    Netcheck.Elevation.WindowsTweakPlatform.CappedSpeed(speeds, codes, 3) &&
                    !Netcheck.Elevation.WindowsTweakPlatform.CappedSpeed(speeds, codes, 2500) &&
                    !Netcheck.Elevation.WindowsTweakPlatform.CappedSpeed(speeds, codes, 0),
                    "cable speed offered only when fixed below the top speed or at half duplex");
        }
        Console.WriteLine("PASS P8 tweak rules (scheme scope, ranges, driver labels)");
        return 0;
    }

    // ---------- transaction ----------

    internal static int RunTransaction()
    {
        var scenarios = 0;
        void Scenario(string name, Action body) { body(); scenarios++; }

        Scenario("keep commits and clears the journal", () =>
        {
            var (pc, store, tx) = New();
            Require(tx.Apply(Recommended(), _ => true) == TweakOutcome.Committed, "committed");
            Require(pc.Values[(TweakId.NicPowerSaving, Nic)] == 0 && pc.Values[(TweakId.BackgroundUpdates, Guid.Empty)] == 20, "values set");
            Require(store.Record is null, "journal cleared");
        });
        Scenario("undo restores every value exactly", () =>
        {
            var (pc, store, tx) = New();
            var before = new Dictionary<(TweakId, Guid), long?>(pc.Values);
            Require(tx.Apply(Recommended(), _ => false) == TweakOutcome.Restored, "restored");
            Require(before.All(kv => pc.Values[kv.Key] == kv.Value), "all values back");
            Require(store.Record is null, "journal cleared");
        });
        Scenario("journal is written before the first change", () =>
        {
            var (pc, store, tx) = New();
            pc.BeforeWrite = () => Require(store.Record is { Before.Count: 2 }, "journal present at first write");
            tx.Apply(Recommended(), _ => true);
        });
        Scenario("nothing to change", () =>
        {
            var (pc, store, tx) = New();
            Require(tx.Apply([new(TweakId.AutoTuning, Guid.Empty, 3)], _ => true) == TweakOutcome.NoChange, "no change");
            Require(pc.Writes == 0 && store.Record is null, "no writes");
        });
        Scenario("invalid or duplicate batch is rejected without touching Windows", () =>
        {
            var (pc, _, tx) = New();
            Require(tx.Apply([], _ => true) == TweakOutcome.Rejected, "empty");
            Require(tx.Apply([new(TweakId.Ecn, Guid.Empty, 7)], _ => true) == TweakOutcome.Rejected, "out of range");
            Require(tx.Apply([new(TweakId.Ecn, Guid.Empty, 1), new(TweakId.Ecn, Guid.Empty, 1)], _ => true) == TweakOutcome.Rejected, "duplicate");
            Require(pc.Writes == 0, "no writes");
        });
        Scenario("managed PC or policy refusal is rejected", () =>
        {
            var (pc, store, tx) = New();
            pc.Allow = false;
            Require(tx.Apply(Recommended(), _ => true) == TweakOutcome.Rejected, "rejected");
            Require(pc.Writes == 0 && store.Record is null, "untouched");
        });
        Scenario("a current value that can't be restored exactly blocks the change", () =>
        {
            var (pc, _, tx) = New();
            pc.Values[(TweakId.MediaThrottling, Guid.Empty)] = 0; // outside the allowlist: cannot be written back
            Require(tx.Apply([new(TweakId.MediaThrottling, Guid.Empty, TweakRules.ThrottlingOff)], _ => true) == TweakOutcome.Rejected, "rejected");
            Require(pc.Writes == 0, "untouched");
        });
        Scenario("an unfinished earlier change blocks a new one", () =>
        {
            var (pc, store, tx) = New();
            store.Record = new([new(TweakId.Ecn, Guid.Empty, 0)], [new(TweakId.Ecn, Guid.Empty, 1)]);
            Require(tx.Apply(Recommended(), _ => true) == TweakOutcome.RecoveryRequired, "recovery first");
            Require(pc.Writes == 0, "untouched");
        });
        Scenario("a failing second write restores the first", () =>
        {
            var (pc, store, tx) = New();
            pc.FailOnWrite = 2;
            Require(tx.Apply(Recommended(), _ => true) == TweakOutcome.Restored, "restored");
            Require(pc.Values[(TweakId.NicPowerSaving, Nic)] == 1, "first value back");
            Require(store.Record is null, "journal cleared");
        });
        Scenario("a write Windows silently ignores fails read-back and restores", () =>
        {
            var (pc, _, tx) = New();
            pc.IgnoreWrites.Add(TweakId.BackgroundUpdates);
            var asked = false;
            Require(tx.Apply(Recommended(), _ => asked = true) == TweakOutcome.Restored, "restored");
            Require(!asked, "user is not asked to keep an unverified change");
            Require(pc.Values[(TweakId.NicPowerSaving, Nic)] == 1, "other value back");
        });
        Scenario("someone else's edit during the change is a conflict, journal kept", () =>
        {
            var (pc, store, tx) = New();
            Require(tx.Apply(Recommended(), _ =>
            {
                pc.Values[(TweakId.BackgroundUpdates, Guid.Empty)] = 50; // e.g. Group Policy refresh
                return false;
            }) == TweakOutcome.Conflict, "conflict");
            Require(pc.Values[(TweakId.BackgroundUpdates, Guid.Empty)] == 50, "foreign value preserved");
            Require(pc.Values[(TweakId.NicPowerSaving, Nic)] == 1, "own value still undone");
            Require(store.Record is not null, "journal kept for review");
        });
        Scenario("recover after a crash restores and is idempotent", () =>
        {
            var (pc, store, tx) = New();
            store.Record = new([new(TweakId.Ecn, Guid.Empty, 0)], [new(TweakId.Ecn, Guid.Empty, 1)]);
            pc.Values[(TweakId.Ecn, Guid.Empty)] = 1;
            Require(tx.Recover() == TweakOutcome.Restored, "restored");
            Require(pc.Values[(TweakId.Ecn, Guid.Empty)] == 0 && store.Record is null, "back and cleared");
            Require(tx.Recover() == TweakOutcome.NoChange, "second recover is a no-op");
        });
        Scenario("a corrupt journal is never acted on", () =>
        {
            var (pc, store, tx) = New();
            store.Corrupt = true;
            Require(tx.Recover() == TweakOutcome.RecoveryRequired, "recover refuses");
            Require(tx.Apply(Recommended(), _ => true) == TweakOutcome.RecoveryRequired, "apply refuses");
            Require(pc.Writes == 0, "untouched");
        });
        Console.WriteLine($"PASS tweak transaction ({scenarios} scenarios)");
        return 0;
    }

    private static (MemoryPlatform, MemoryStore, TweakTransaction) New()
    {
        var pc = new MemoryPlatform(HomePc());
        var store = new MemoryStore();
        return (pc, store, new TweakTransaction(pc, store));
    }

    // ---------- broker exchange ----------

    [SupportedOSPlatform("windows")]
    internal static async Task<int> RunBrokerAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var token = deadline.Token;

        async Task<(WindowsTweakBroker.Reply First, WindowsTweakBroker.Reply? Last)> Exchange(
            WindowsTweakBroker.Request request, bool? keep, MemoryPlatform pc, Func<RestorePointResult> point)
        {
            var name = $"Netcheck.BoostCheck.{Guid.NewGuid():N}";
            using var server = DnsBrokerPipe.Listen(name);
            using var client = DnsBrokerPipe.ConnectToLocal(name);
            var connect = client.ConnectAsync(token);
            await server.WaitForConnectionAsync(token);
            await connect;
            var service = WindowsTweakBroker.ExecuteAsync(client, () => new TweakTransaction(pc, new MemoryStore()), point, token);
            await DnsBrokerPipe.SendAsync(server, request, token);
            var first = await DnsBrokerPipe.ReceiveAsync<WindowsTweakBroker.Reply>(server, token);
            WindowsTweakBroker.Reply? last = null;
            if (keep is { } decision && first.NeedsVerification)
            {
                await DnsBrokerPipe.SendAsync(server, decision, token);
                last = await DnsBrokerPipe.ReceiveAsync<WindowsTweakBroker.Reply>(server, token);
            }
            await service;
            return (first, last);
        }

        var pc = new MemoryPlatform(HomePc());
        var apply = new WindowsTweakBroker.Request(1, Recommended(), RestorePoint: true, Recover: false);
        var made = 0;
        var kept = await Exchange(apply, true, pc, () => { made++; return RestorePointResult.Made; });
        Require(kept.First is { NeedsVerification: true, RestorePoint: RestorePointResult.Made }, "asks to keep after restore point");
        Require(kept.Last is { Outcome: TweakOutcome.Committed, RestorePoint: RestorePointResult.Made } && made == 1, "keep commits");
        Require(pc.Values[(TweakId.NicPowerSaving, Nic)] == 0, "value kept");

        pc = new MemoryPlatform(HomePc());
        var undone = await Exchange(apply with { RestorePoint = false }, false, pc, () => throw new InvalidOperationException("not asked"));
        Require(undone.Last is { Outcome: TweakOutcome.Restored, RestorePoint: RestorePointResult.NotRequested }, "undo restores");
        Require(pc.Values[(TweakId.NicPowerSaving, Nic)] == 1, "value back");

        pc = new MemoryPlatform(HomePc());
        var future = await Exchange(apply with { Version = 2 }, null, pc, () => RestorePointResult.Made);
        Require(future.First is { NeedsVerification: false, Outcome: TweakOutcome.Rejected } && pc.Writes == 0, "unknown version rejected");

        var bad = await Exchange(apply with { Proposed = [new(TweakId.Ecn, Guid.Empty, 9)] }, null, pc, () => RestorePointResult.Made);
        Require(bad.First.Outcome == TweakOutcome.Rejected && pc.Writes == 0, "out-of-allowlist value rejected before any work");

        var mixed = await Exchange(new WindowsTweakBroker.Request(1, Recommended(), false, Recover: true), null, pc, () => RestorePointResult.Made);
        Require(mixed.First.Outcome == TweakOutcome.Rejected && pc.Writes == 0, "recover with a payload rejected");

        Console.WriteLine("PASS tweak broker IPC: keep, undo, restore point, protocol version, allowlist, malformed recover");
        return 0;
    }

    // ---------- crash lab ----------

    private enum Phase { None, BeforeJournal, AfterJournal, AfterFirstWrite, AwaitDecision, AfterCommit }

    [SupportedOSPlatform("windows")]
    internal static async Task<int> RunCrashLabAsync()
    {
        foreach (var phase in Enum.GetValues<Phase>().Where(p => p != Phase.None))
        {
            var parent = Directory.CreateTempSubdirectory("netcheck-tweak-crash-lab-");
            try
            {
                await CrashScenarioAsync(parent, phase);
                Console.WriteLine($"PASS tweak broker killed and recovered: {phase}");
            }
            finally { parent.Delete(recursive: true); }
        }
        return 0;
    }

    [SupportedOSPlatform("windows")]
    private static async Task CrashScenarioAsync(DirectoryInfo parent, Phase phase)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var token = deadline.Token;
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User!;
        var acl = new DirectorySecurity();
        acl.SetOwner(owner);
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        acl.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        var directory = Path.Combine(parent.FullName, "private");
        new DirectoryInfo(directory).Create(acl);
        var disk = new DiskPlatform(directory, Phase.None);
        disk.Save(HomePc());

        var name = $"Netcheck.BoostCrash.{Guid.NewGuid():N}";
        using (var server = DnsBrokerPipe.Listen(name))
        {
            var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
            if (Path.GetFileNameWithoutExtension(start.FileName).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
                start.ArgumentList.Add(typeof(TweakChecks).Assembly.Location);
            foreach (var argument in new[] { "--tweak-crash-lab-child", directory, name, phase.ToString() })
                start.ArgumentList.Add(argument);
            using var worker = Process.Start(start) ?? throw new InvalidOperationException("Could not start the broker fixture.");
            try
            {
                await server.WaitForConnectionAsync(token);
                Require(DnsBrokerPipe.IsPeer(server, worker, server: false), "child identity");
                await DnsBrokerPipe.SendAsync(server, new WindowsTweakBroker.Request(1, Recommended(), false, false), token);
                if (phase is Phase.AwaitDecision or Phase.AfterCommit)
                {
                    var reply = await DnsBrokerPipe.ReceiveAsync<WindowsTweakBroker.Reply>(server, token);
                    Require(reply.NeedsVerification, "asked to keep");
                    if (phase == Phase.AfterCommit)
                        await DnsBrokerPipe.SendAsync(server, true, token);
                }
                if (phase != Phase.AwaitDecision)
                    while (!File.Exists(Path.Combine(directory, "paused")))
                        await Task.Delay(15, token);
            }
            finally
            {
                if (!worker.HasExited)
                    worker.Kill();
                await worker.WaitForExitAsync(CancellationToken.None);
            }
        }

        var atCrash = disk.Load();
        var nicAtCrash = atCrash[(TweakId.NicPowerSaving, Nic)];
        Require(nicAtCrash == (phase is Phase.BeforeJournal or Phase.AfterJournal ? 1 : 0), "first value at crash");

        // An independent process (the next app start) recovers with a fresh transaction.
        var store = new WindowsTweakRecoveryStore(directory, owner);
        TweakOutcome outcome;
        while (true)
        {
            try { outcome = new TweakTransaction(new DiskPlatform(directory, Phase.None), store).Recover(); break; }
            catch (IOException error) when ((error.HResult & 0xffff) is 32 or 33) { await Task.Delay(25, token); }
        }
        var after = disk.Load();
        if (phase is Phase.BeforeJournal or Phase.AfterCommit)
            Require(outcome == TweakOutcome.NoChange, "nothing to recover");
        else
            Require(outcome == TweakOutcome.Restored, "recovered");
        var expected = phase == Phase.AfterCommit ? 0 : 1;
        Require(after[(TweakId.NicPowerSaving, Nic)] == expected, "adapter value after recovery");
        Require(after[(TweakId.BackgroundUpdates, Guid.Empty)] == (phase == Phase.AfterCommit ? 20 : null), "policy value after recovery");
        using (store.AcquireExclusive())
            Require(store.Read() is null, "journal cleared after recovery");
    }

    [SupportedOSPlatform("windows")]
    internal static async Task<int> RunCrashChildAsync(string directory, string pipe, string phase)
    {
        if (!Enum.TryParse<Phase>(phase, out var interrupt))
            return 1;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var client = DnsBrokerPipe.ConnectToLocal(pipe);
        await client.ConnectAsync(deadline.Token);
        using var identity = WindowsIdentity.GetCurrent();
        var store = new PausingStore(directory, new WindowsTweakRecoveryStore(directory, identity.User!), interrupt);
        await WindowsTweakBroker.ExecuteAsync(client, () => new TweakTransaction(new DiskPlatform(directory, interrupt), store),
            () => RestorePointResult.NotRequested, deadline.Token);
        return 0;
    }

    private static void Pause(string directory)
    {
        File.WriteAllText(Path.Combine(directory, "paused"), "");
        Thread.Sleep(Timeout.Infinite);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void CheckDriverLabels()
    {
        string[] values = ["0", "1"], labels = ["Disabled", "Enabled"];
        Require(WindowsTweakPlatform.MatchingLabel(values, labels, "0") == "Disabled", "label for 0 is Disabled");
        Require(WindowsTweakPlatform.MatchingLabel(values, labels, "1") == "Enabled", "label for 1 is Enabled");
        Require(WindowsTweakPlatform.MatchingLabel(null, null, "42") == "42", "free-number setting keeps the number");
        Require(Throws(() => WindowsTweakPlatform.MatchingLabel(values, labels, "2")), "value the driver doesn't list");
        Require(Throws(() => WindowsTweakPlatform.MatchingLabel(values, ["Disabled"], "1")), "incomplete label list");
        Console.WriteLine("PASS driver value labels (5 checks)");
    }

    private static bool Throws(Action action)
    {
        try { action(); return false; }
        catch (NotSupportedException) { return true; }
    }

    private static void Require(bool ok, string check)
    {
        if (!ok)
            throw new InvalidOperationException($"Tweak check failed: {check}.");
    }

    // ---------- fixtures ----------

    private sealed class MemoryPlatform(Dictionary<(TweakId, Guid), long?> values) : ITweakPlatform
    {
        internal Dictionary<(TweakId, Guid), long?> Values { get; } = values;
        internal bool Allow { get; set; } = true;
        internal int FailOnWrite { get; set; }
        internal HashSet<TweakId> IgnoreWrites { get; } = [];
        internal Action? BeforeWrite { get; set; }
        internal int Writes { get; private set; }

        public TweakValue Read(TweakId id, Guid adapter) => new(id, adapter, Values[(id, adapter)]);
        public bool Permits(TweakValue value) => Allow && TweakRules.Valid(value);

        public void Write(TweakValue value)
        {
            BeforeWrite?.Invoke();
            Writes++;
            if (Writes == FailOnWrite)
                throw new IOException("Simulated write failure.");
            if (!IgnoreWrites.Contains(value.Id))
                Values[(value.Id, value.Adapter)] = value.Value;
        }
    }

    private sealed class MemoryStore : ITweakRecoveryStore
    {
        internal TweakRecoveryRecord? Record { get; set; }
        internal bool Corrupt { get; set; }
        public IDisposable AcquireExclusive() => new Lease();
        public TweakRecoveryRecord? Read() => Corrupt ? throw new InvalidDataException("corrupt") : Record;
        public void Persist(TweakRecoveryRecord record) => Record = record;
        public void Clear() => Record = null;
        private sealed class Lease : IDisposable { public void Dispose() { } }
    }

    // State survives the killed worker, so the recovering process sees exactly what it left.
    private sealed class DiskPlatform(string directory, Phase phase) : ITweakPlatform
    {
        private string State => Path.Combine(directory, "pc.json");
        private int _writes;

        public TweakValue Read(TweakId id, Guid adapter) => new(id, adapter, Load()[(id, adapter)]);
        public bool Permits(TweakValue value) => TweakRules.Valid(value);

        public void Write(TweakValue value)
        {
            var state = Load();
            state[(value.Id, value.Adapter)] = value.Value;
            Save(state);
            if (++_writes == 1 && phase == Phase.AfterFirstWrite)
                Pause(directory);
        }

        internal Dictionary<(TweakId, Guid), long?> Load() =>
            JsonSerializer.Deserialize<Entry[]>(File.ReadAllBytes(State))!.ToDictionary(e => (e.Id, e.Adapter), e => e.Value);

        internal void Save(Dictionary<(TweakId, Guid), long?> state)
        {
            var staging = State + ".new";
            File.WriteAllBytes(staging, JsonSerializer.SerializeToUtf8Bytes(state.Select(kv => new Entry(kv.Key.Item1, kv.Key.Item2, kv.Value)).ToArray()));
            File.Move(staging, State, overwrite: true);
        }

        private sealed record Entry(TweakId Id, Guid Adapter, long? Value);
    }

    private sealed class PausingStore(string directory, ITweakRecoveryStore inner, Phase phase) : ITweakRecoveryStore
    {
        public IDisposable AcquireExclusive() => inner.AcquireExclusive();
        public TweakRecoveryRecord? Read() => inner.Read();

        public void Persist(TweakRecoveryRecord record)
        {
            if (phase == Phase.BeforeJournal)
                Pause(directory);
            inner.Persist(record);
            if (phase == Phase.AfterJournal)
                Pause(directory);
        }

        public void Clear()
        {
            inner.Clear();
            if (phase == Phase.AfterCommit)
                Pause(directory);
        }
    }
}
