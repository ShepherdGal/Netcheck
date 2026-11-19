using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Netcheck.Elevation;

[SupportedOSPlatform("windows")]
internal static class DnsCrashLab
{
    private enum Phase
    {
        None, BeforeJournal, AfterJournal, AfterWrite, AwaitDecision, AfterRestore, AfterCommit,
        PartialWrite, ExternalEdit, RestoreDenied, CorruptJournal
    }

    internal static async Task<int> RunAsync()
    {
        foreach (var phase in Enum.GetValues<Phase>().Where(phase => phase != Phase.None))
        {
            var parent = Directory.CreateTempSubdirectory("netcheck-dns-crash-lab-");
            try
            {
                await RunScenarioAsync(parent, phase);
                Console.WriteLine($"PASS broker termination and restart recovery: {phase}");
            }
            finally { parent.Delete(recursive: true); }
        }
        return 0;
    }

    private static async Task RunScenarioAsync(DirectoryInfo parent, Phase phase)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = deadline.Token;
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User!;
        var acl = new DirectorySecurity();
        acl.SetOwner(owner);
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        acl.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        var directory = Path.Combine(parent.FullName, "private");
        new DirectoryInfo(directory).Create(acl);
        var id = Guid.NewGuid();
        var automatic = new DnsChange(id, DnsTargetFamily.Ipv6, DnsTargetAssignment.Automatic, [], false);
        var manual = automatic with
        {
            Family = DnsTargetFamily.Ipv4, Assignment = DnsTargetAssignment.Manual,
            Resolvers = [new("192.0.2.4", DnsEncryption.RequireHttps, "https://dns.example/query"),
                new("192.0.2.2", DnsEncryption.PreferHttps, "https://dns.example/query")],
            AllowPlaintextFallback = true
        };
        var ipv6 = phase is Phase.AfterWrite or Phase.AfterCommit;
        var baseline = ipv6 ? new DnsSnapshot(automatic, manual, "lab") : new DnsSnapshot(manual, automatic, "lab");
        var candidate = ipv6 ? automatic with
        {
            Assignment = DnsTargetAssignment.Manual, Resolvers = [new("2001:db8::1", DnsEncryption.Plaintext)]
        } : manual with { Assignment = DnsTargetAssignment.Automatic, Resolvers = [], AllowPlaintextFallback = false };
        var adapter = new DiskAdapter(directory, Phase.None);
        adapter.Save(baseline);

        await ExchangeAsync(directory, phase, token, async (pipe, worker) =>
        {
            await DnsBrokerPipe.SendAsync(pipe, new WindowsDnsBroker.Request(1, new(baseline, candidate), false), token);
            if (phase is Phase.AwaitDecision or Phase.AfterRestore or Phase.AfterCommit or Phase.ExternalEdit or
                Phase.RestoreDenied or Phase.CorruptJournal)
            {
                var reply = await DnsBrokerPipe.ReceiveAsync<WindowsDnsBroker.Reply>(pipe, token);
                Require(reply is { NeedsVerification: true, Outcome: null }, "expected retest");
                if (phase is Phase.AfterRestore or Phase.AfterCommit)
                    await DnsBrokerPipe.SendAsync(pipe, phase == Phase.AfterCommit, token);
            }
            if (phase is not (Phase.AwaitDecision or Phase.ExternalEdit or Phase.RestoreDenied or Phase.CorruptJournal))
            {
                while (!File.Exists(Path.Combine(directory, "paused")))
                    await Task.Delay(15, token);
            }
            worker.Kill();
            await worker.WaitForExitAsync(token);
        });

        var expectedAtCrash = phase switch
        {
            Phase.PartialWrite => IncompleteManual(candidate),
            Phase.AfterWrite or Phase.AwaitDecision or Phase.AfterCommit or Phase.ExternalEdit or
                Phase.RestoreDenied or Phase.CorruptJournal => candidate,
            _ => baseline.Target
        };
        Require(DnsTransaction.Matches(adapter.Read(id, baseline.Target.Family), expectedAtCrash, baseline), "state at crash");
        var store = new WindowsDnsRecoveryStore(directory, owner);
        // A terminated process can be signaled before Windows has finished releasing all its file handles.
        var lease = await OpenAfterTerminationAsync(store, token);
        using (lease)
            Require((store.Read() is not null) == (phase is not (Phase.BeforeJournal or Phase.AfterCommit)), "journal at crash");
        if (phase is Phase.PartialWrite or Phase.ExternalEdit)
        {
            var conflict = phase == Phase.PartialWrite ? expectedAtCrash : IncompleteManual(candidate);
            if (phase == Phase.ExternalEdit)
                adapter.Save(baseline with { Target = conflict });
            Require(await RecoverAsync() == DnsTransactionOutcome.Conflict, "uncertain state blocks restore");
            Require(await RecoverAsync() == DnsTransactionOutcome.Conflict, "repeated recovery preserves conflict");
            Require(DnsTransaction.Matches(adapter.Read(id, baseline.Target.Family), conflict, baseline), "conflicting settings preserved");
            using (store.AcquireExclusive())
                Require(store.Read() is not null, "journal survives conflict");
            return;
        }

        if (phase == Phase.RestoreDenied)
        {
            Require(await RecoverAsync(Phase.RestoreDenied) == DnsTransactionOutcome.RecoveryRequired, "failed restore reported");
            Require(DnsTransaction.Matches(adapter.Read(id, baseline.Target.Family), candidate, baseline), "failed restore left candidate");
            using (store.AcquireExclusive())
                Require(store.Read() is not null, "journal survives failed restore");
        }
        if (phase == Phase.CorruptJournal)
        {
            var journal = Path.Combine(directory, "dns-recovery.json");
            File.WriteAllText(journal, "{}");
            await ExchangeAsync(directory, Phase.None, token, async (pipe, worker) =>
            {
                await DnsBrokerPipe.SendAsync(pipe, new WindowsDnsBroker.Request(1, new(baseline, candidate), false), token);
                Require((await DnsBrokerPipe.ReceiveAsync<WindowsDnsBroker.Reply>(pipe, token)).Outcome ==
                    DnsTransactionOutcome.RecoveryRequired, "corrupt journal blocks another apply");
                await worker.WaitForExitAsync(token);
                Require(worker.ExitCode == 0, "worker exit");
            });
            Require(await RecoverAsync() == DnsTransactionOutcome.RecoveryRequired, "recovery reports corrupt journal");
            Require(await RecoverAsync() == DnsTransactionOutcome.RecoveryRequired, "corrupt journal remains pending");
            Require(File.ReadAllText(journal) == "{}", "corrupt journal preserved");
            Require(DnsTransaction.Matches(adapter.Read(id, baseline.Target.Family), candidate, baseline), "no write from corrupt journal");
            return;
        }
        var expectedRecovery = phase is Phase.BeforeJournal or Phase.AfterCommit
            ? DnsTransactionOutcome.NoChange : DnsTransactionOutcome.Restored;
        Require(await RecoverAsync() == expectedRecovery, "first recovery");
        Require(await RecoverAsync() == DnsTransactionOutcome.NoChange, "idempotent recovery");
        Require(DnsTransaction.Matches(adapter.Read(id, baseline.Target.Family),
            phase == Phase.AfterCommit ? candidate : baseline.Target, baseline), "final settings and other family");

        async Task<DnsTransactionOutcome?> RecoverAsync(Phase recoveryPhase = Phase.None)
        {
            DnsTransactionOutcome? outcome = null;
            await ExchangeAsync(directory, recoveryPhase, token, async (pipe, worker) =>
            {
                await DnsBrokerPipe.SendAsync(pipe, new WindowsDnsBroker.Request(1, null, true), token);
                outcome = (await DnsBrokerPipe.ReceiveAsync<WindowsDnsBroker.Reply>(pipe, token)).Outcome;
                await worker.WaitForExitAsync(token);
                Require(worker.ExitCode == 0, "worker exit");
            });
            return outcome;
        }
    }

    private static DnsChange IncompleteManual(DnsChange change) => change with
    {
        Assignment = DnsTargetAssignment.Manual,
        Resolvers = [new("192.0.2.19", DnsEncryption.Plaintext)],
        AllowPlaintextFallback = false
    };

    private static async Task<IDisposable> OpenAfterTerminationAsync(WindowsDnsRecoveryStore store, CancellationToken token)
    {
        using var cleanup = CancellationTokenSource.CreateLinkedTokenSource(token);
        cleanup.CancelAfter(TimeSpan.FromSeconds(2));
        while (true)
        {
            try { return store.AcquireExclusive(); }
            catch (IOException error) when ((error.HResult & 0xffff) is 32 or 33)
            {
                await Task.Delay(25, cleanup.Token);
            }
        }
    }

    private static async Task ExchangeAsync(string directory, Phase phase, CancellationToken token,
        Func<NamedPipeServerStream, Process, Task> exchange)
    {
        var name = $"Netcheck.CrashLab.{Guid.NewGuid():N}";
        using var server = DnsBrokerPipe.Listen(name);
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
        if (Path.GetFileNameWithoutExtension(start.FileName).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(typeof(DnsCrashLab).Assembly.Location);
        foreach (var argument in new[] { "--dns-crash-lab-child", directory, name, Environment.ProcessId.ToString(), phase.ToString() })
            start.ArgumentList.Add(argument);
        using var worker = Process.Start(start) ?? throw new InvalidOperationException("Could not start the broker fixture.");
        try
        {
            _ = worker.SafeHandle;
            await server.WaitForConnectionAsync(token);
            Require(DnsBrokerPipe.IsPeer(server, worker, server: false), "child process identity");
            await exchange(server, worker);
        }
        finally
        {
            if (!worker.HasExited)
            {
                worker.Kill();
                await worker.WaitForExitAsync(CancellationToken.None);
            }
        }
    }

    internal static async Task<int> RunChildAsync(string directory, string pipe, string parent, string phase)
    {
        if (!Enum.TryParse<Phase>(phase, out var interrupt) || !int.TryParse(parent, out var pid))
            return 1;
        using var caller = Process.GetProcessById(pid);
        _ = caller.SafeHandle;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var client = DnsBrokerPipe.ConnectToLocal(pipe);
        await client.ConnectAsync(deadline.Token);
        Require(DnsBrokerPipe.IsPeer(client, caller, server: true), "parent process identity");
        using var identity = WindowsIdentity.GetCurrent();
        var store = new WindowsDnsRecoveryStore(directory, identity.User!);
        await WindowsDnsBroker.ExecuteAsync(client, () => new DnsTransaction(new DiskAdapter(directory, interrupt),
            new InterruptedStore(directory, store, interrupt)), deadline.Token);
        return 0;
    }

    private static void Pause(string directory)
    {
        File.WriteAllText(Path.Combine(directory, "paused"), "");
        Thread.Sleep(Timeout.Infinite);
    }

    private static void Require(bool outcome, string check)
    {
        if (!outcome)
            throw new InvalidOperationException($"DNS crash lab failed: {check}.");
    }

    // The simulated adapter has no socket or Windows settings API. Persist its state so an
    // independent recovery process sees exactly the configuration left by the terminated worker.
    private sealed class DiskAdapter(string directory, Phase phase) : IDnsTransactionPlatform
    {
        private string State => Path.Combine(directory, "adapter.json");
        private int _writes;

        public DnsSnapshot Read(Guid adapterId, DnsTargetFamily family)
        {
            var state = JsonSerializer.Deserialize<DnsSnapshot>(File.ReadAllBytes(State))!;
            Require(state.Target.AdapterId == adapterId && state.Target.Family == family, "adapter identity");
            return state;
        }

        public bool Permits(DnsChange change) => true;

        public void Write(DnsChange change)
        {
            var current = Read(change.AdapterId, change.Family);
            if (phase == Phase.RestoreDenied && change.Assignment == DnsTargetAssignment.Manual)
                throw new IOException("Simulated write failure while restoring.");
            Save(current with { Target = phase == Phase.PartialWrite ? IncompleteManual(change) : change });
            _writes++;
            if ((_writes == 1 && phase is Phase.AfterWrite or Phase.PartialWrite) ||
                (_writes == 2 && phase == Phase.AfterRestore))
                Pause(directory);
        }

        internal void Save(DnsSnapshot snapshot)
        {
            var staging = State + ".new";
            using (var file = new FileStream(staging, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(file, snapshot);
                file.Flush(flushToDisk: true);
            }
            File.Move(staging, State, overwrite: true);
        }
    }

    private sealed class InterruptedStore(string directory, WindowsDnsRecoveryStore inner, Phase phase) : IDnsRecoveryStore
    {
        public IDisposable AcquireExclusive() => inner.AcquireExclusive();
        public DnsRecoveryRecord? Read() => inner.Read();

        public void Persist(DnsRecoveryRecord record)
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
