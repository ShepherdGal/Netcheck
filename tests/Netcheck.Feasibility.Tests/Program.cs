using Netcheck.Windows;
using Netcheck.Elevation;

if (args is ["--windows-discovery"])
    return Phase4Checks.RunWindows();
if (args is ["--discovery-fixtures"])
    return Phase4Checks.RunFixtures();
if (OperatingSystem.IsWindows() && args is ["--tweak-detect"])
{
    // Read-only: what Boost sees on this PC (no elevation, nothing written).
    var route = RouteDiscovery.Read(System.Net.IPAddress.Parse("1.1.1.1"));
    var adapter = route.AdapterId ?? Guid.Empty;
    foreach (var id in Enum.GetValues<TweakId>())
    {
        try
        {
            var scope = TweakRules.PowerPlan(id) ? WindowsTweakBroker.ActivePowerScheme() : TweakRules.AdapterScoped(id) ? adapter : Guid.Empty;
            var value = WindowsTweakBroker.Read(id, scope);
            var target = TweakRules.DriverMapped(id) ? WindowsTweakBroker.DriverTarget(id, scope) : TweakRules.Target(id);
            Console.WriteLine($"{id,-24} now {value.Value?.ToString() ?? "not set",-10} target {target?.ToString() ?? "none"}");
        }
        catch (Exception error) { Console.WriteLine($"{id,-24} unavailable ({error.GetType().Name}: {error.Message})"); }
    }
    return 0;
}
if (args is ["--layout-spacing"])
    return LayoutSpacingCheck.Run();
if (args is ["--tweak-rules"])
    return TweakChecks.RunRules();
if (args is ["--tweak-transaction"])
    return TweakChecks.RunTransaction();
if (OperatingSystem.IsWindows() && args is ["--tweak-broker"])
    return await TweakChecks.RunBrokerAsync();
if (OperatingSystem.IsWindows() && args is ["--tweak-crash-lab"])
    return await TweakChecks.RunCrashLabAsync();
if (OperatingSystem.IsWindows() && args is ["--tweak-crash-lab-child", var tweakDirectory, var tweakPipe, var tweakPhase])
    return await TweakChecks.RunCrashChildAsync(tweakDirectory, tweakPipe, tweakPhase);
if (args is ["--dns-transaction"])
    return DnsTransactionChecks.Run();
if (OperatingSystem.IsWindows() && args is ["--dns-journal"])
    return DnsJournalChecks.Run();
if (OperatingSystem.IsWindows() && args is ["--dns-broker"])
{
    // DNS_SERVER_PROPERTY layout must match netioapi.h (Version, ServerIndex, Type, Property); a swap silently broke DoH.
    var offsets = (System.Runtime.InteropServices.Marshal.OffsetOf<Netcheck.Windows.InterfaceDns.NativeServerProperty>("ServerIndex").ToInt32(),
        System.Runtime.InteropServices.Marshal.OffsetOf<Netcheck.Windows.InterfaceDns.NativeServerProperty>("Type").ToInt32(),
        System.Runtime.InteropServices.Marshal.OffsetOf<Netcheck.Windows.InterfaceDns.NativeServerProperty>("DohSettings").ToInt32(),
        System.Runtime.InteropServices.Marshal.SizeOf<Netcheck.Windows.InterfaceDns.NativeServerProperty>());
    if (offsets != (4, 8, 16, 24))
    {
        Console.Error.WriteLine($"FAIL DNS_SERVER_PROPERTY layout {offsets}, expected (4, 8, 16, 24)");
        return 1;
    }
    return await DnsBrokerChecks.RunAsync();
}
if (OperatingSystem.IsWindows() && args is ["--dns-crash-lab"])
    return await DnsCrashLab.RunAsync();
if (OperatingSystem.IsWindows() && args is ["--router-identity"])
    return RouterIdentityChecks.Run();
if (OperatingSystem.IsWindows() && args is ["--router-identity-live"])
    return await RouterIdentityChecks.RunLiveAsync();
if (OperatingSystem.IsWindows() && args is ["--dns-crash-lab-child", var labDirectory, var pipe, var parent, var phase])
    return await DnsCrashLab.RunChildAsync(labDirectory, pipe, parent, phase);
if (OperatingSystem.IsWindows() && args is ["--dns-journal-crash-fixture", var journalDirectory])
    DnsJournalChecks.Interrupt(journalDirectory);
if (args is ["--dns-validation"])
{
    var request = new DnsChange(Guid.NewGuid(), DnsTargetFamily.Ipv4, DnsTargetAssignment.Manual,
        [new DnsResolver("1.1.1.1", DnsEncryption.RequireHttps, "https://cloudflare-dns.com/dns-query")], false);
    Check(DnsChangeValidation.Validate(request) is null, "valid per-family DoH request");
    Check(DnsChangeValidation.Validate(request with { AdapterId = Guid.Empty }) is not null, "missing adapter");
    Check(DnsChangeValidation.Validate(request with { Family = DnsTargetFamily.Ipv6 }) is not null, "wrong address family");
    Check(DnsChangeValidation.Validate(request with { Resolvers = [request.Resolvers[0], request.Resolvers[0]] }) is not null, "duplicate");
    Check(DnsChangeValidation.Validate(request with { Resolvers = [request.Resolvers[0] with { Encryption = DnsEncryption.PreferHttps }] }) is not null,
        "unapproved fallback");
    Check(DnsChangeValidation.Validate(request with { Resolvers = [request.Resolvers[0] with { HttpsTemplate = "https://user@dns.example/" }] }) is not null,
        "embedded credentials");
    Check(DnsChangeValidation.Validate(request with { Assignment = DnsTargetAssignment.Automatic, Resolvers = [] }) is null, "automatic assignment");
    Console.WriteLine("PASS DNS change validation (7 assertions)");
    return 0;
}

(string Name, Action<Fixture> Run)[] tests =
[
    ("manual IPv4 with required DoH restores ordered resolvers and prior DoH", lab =>
    {
        var original = lab.Dns.IPv4;
        lab.Arm();
        Check(lab.Dns.IPv4.ConfiguredServers == "1.1.1.1", "IPv4 candidate was not applied");
        Check(lab.Dns.IPv4.ServerProperties.Single().Flags == 2, "required mode enabled fallback");
        Check(lab.NewRecovery().Recover(), "new recovery instance could not load the journal");
        Check(lab.Dns.IPv4.ConfiguredServers == original.ConfiguredServers, "resolver order changed");
        Check(lab.Dns.IPv4.ServerProperties.SequenceEqual(original.ServerProperties), "original DoH was not restored");
        lab.ExpectClean();
    }),
    ("manual IPv6 with preferred DoH preserves IPv4", lab =>
    {
        var originalV4 = lab.Dns.IPv4;
        var originalV6 = lab.Dns.IPv6;
        lab.Arm(ipv6: true, mode: "preferred");
        Check(lab.Dns.IPv6.ConfiguredServers == "2606:4700:4700::1111", "IPv6 candidate was not applied");
        Check(lab.Dns.IPv6.ServerProperties.Single().Flags == 6, "preferred mode did not set fallback");
        Check(lab.Dns.IPv4 == originalV4, "apply affected IPv4");
        Check(lab.NewRecovery().Recover(), "IPv6 recovery was not run");
        Check(lab.Dns.IPv4 == originalV4, "restore affected IPv4");
        Check(lab.Dns.IPv6.ConfiguredServers == originalV6.ConfiguredServers &&
              lab.Dns.IPv6.SearchList == originalV6.SearchList, "IPv6 settings or search suffix changed");
        lab.ExpectClean();
    }),
    ("automatic IPv4 resets the static list and removes candidate DoH", lab =>
    {
        lab.Dns.IPv4 = lab.Dns.IPv4 with { ConfiguredServers = null, ServerProperties = [] };
        lab.Arm(automatic: true);
        Check(lab.NewRecovery().Recover(), "automatic recovery was not run");
        Check(lab.Dns.LastServers == "", "automatic restoration did not send a reset");
        Check(lab.Dns.IPv4.ConfiguredServers is null && lab.Dns.IPv4.ServerProperties.Count == 0,
            "automatic assignment was not restored");
        lab.ExpectClean();
    }),
    ("automatic IPv6 with plaintext does not alter IPv4", lab =>
    {
        var originalV4 = lab.Dns.IPv4;
        lab.Dns.IPv6 = lab.Dns.IPv6 with { ConfiguredServers = null };
        lab.Arm(ipv6: true, mode: "plain", automatic: true);
        Check(lab.Dns.IPv6.ServerProperties.Count == 0, "plaintext mode added DoH");
        Check(lab.NewRecovery().Recover(), "automatic IPv6 recovery was not run");
        Check(lab.Dns.IPv6.ConfiguredServers is null && lab.Dns.IPv4 == originalV4, "wrong family was restored");
        lab.ExpectClean();
    }),
    ("automatic reset with stale DoH retains the recovery journal", lab =>
    {
        lab.Dns.IPv4 = lab.Dns.IPv4 with { ConfiguredServers = null, ServerProperties = [] };
        lab.Arm(automatic: true);
        lab.Dns.KeepDohOnReset = true;
        Throws<InvalidOperationException>(() => lab.NewRecovery().Recover(), "restoration failed");
        Check(lab.HasJournal && lab.Task.Active, "incomplete reset lost its recovery state");
    }),
    ("journal is present before registration and writes start after registration", lab =>
    {
        lab.Task.BeforeRegister = () =>
        {
            Check(lab.HasJournal, "journal was absent during registration");
            Check(lab.Dns.Writes == 0, "DNS was written before task registration");
        };
        lab.Dns.BeforeWrite = () => Check(lab.Task.Active && lab.HasJournal, "write was unprotected");
        lab.Arm();
        Check(lab.NewRecovery().Recover(), "recovery was not run");
        lab.ExpectClean();
    }),
    ("scheduler failure prevents DNS writes", lab =>
    {
        lab.Task.BeforeRegister = () => throw new IOException("registration failed");
        Throws<IOException>(() => lab.Arm(), "registration failed");
        Check(lab.Dns.Writes == 0 && lab.HasJournal && !lab.Task.Active, "failed registration changed DNS");
        Check(lab.NewRecovery().Recover(), "failed registration journal could not be cleared");
        lab.ExpectClean();
    }),
    ("wrong assignment mode is rejected before journaling", lab =>
    {
        Throws<InvalidOperationException>(() => lab.Arm(automatic: true), "assignment mode");
        Check(lab.Dns.Writes == 0, "invalid baseline changed DNS");
        lab.ExpectClean();
    }),
    ("write failure leaves original settings and settles recovery", lab =>
    {
        lab.Dns.BeforeWrite = () => throw new IOException("apply failed");
        var original = lab.Dns.IPv4;
        Throws<IOException>(() => lab.Arm(), "apply failed");
        Check(lab.Dns.IPv4 == original, "write failure changed the baseline");
        lab.ExpectClean();
    }),
    ("failed read-back does not report a successful write", lab =>
    {
        lab.Dns.IgnoreWrites = true;
        Throws<InvalidOperationException>(() => lab.Arm(), "did not match");
        Check(lab.Dns.Writes == 1, "unexpected extra writes");
        lab.ExpectClean();
    }),
    ("restore failure preserves journal for a later retry", lab =>
    {
        lab.Arm();
        lab.Dns.BeforeWrite = () => throw new IOException("restore failed");
        Throws<IOException>(() => lab.NewRecovery().Recover(), "restore failed");
        Check(lab.HasJournal && lab.Task.Active, "failed restore lost its recovery state");
        lab.Dns.BeforeWrite = null;
        Check(lab.NewRecovery().Recover(), "retry could not restore");
        lab.ExpectClean();
        Check(!lab.NewRecovery().Recover(), "completed recovery was not idempotent");
    }),
    ("conflicting external edit is preserved", lab =>
    {
        lab.Arm();
        lab.Dns.IPv4 = lab.Dns.IPv4 with { ConfiguredServers = "9.9.9.9" };
        Throws<InvalidOperationException>(() => lab.NewRecovery().Recover(), "differs from both");
        Check(lab.Dns.IPv4.ConfiguredServers == "9.9.9.9" && lab.Dns.Writes == 1, "external edit was overwritten");
        Check(lab.HasJournal && lab.Task.Active, "conflict lost its recovery state");
    }),
    ("duplicate arm preserves the pending transaction", lab =>
    {
        lab.Arm();
        var journal = File.ReadAllText(lab.JournalPath);
        Throws<InvalidOperationException>(() => lab.Arm(), "already exists");
        Check(lab.Dns.Writes == 1 && File.ReadAllText(lab.JournalPath) == journal, "pending operation changed");
        Check(lab.NewRecovery().Recover(), "original transaction could not be restored");
        lab.ExpectClean();
    }),
    ("corrupt journal does not authorize restoration", lab =>
    {
        lab.Arm();
        File.WriteAllText(lab.JournalPath, "{}");
        Throws<InvalidOperationException>(() => lab.NewRecovery().Recover(), "cannot be safely replayed");
        Check(lab.Dns.Writes == 1 && lab.HasJournal && lab.Task.Active, "corrupt journal changed DNS or was discarded");
    }),
    ("orphaned task cannot authorize restoration", lab =>
    {
        lab.Task.Register();
        Throws<InvalidOperationException>(() => lab.NewRecovery().Recover(), "has no journal");
        Check(lab.Dns.Writes == 0 && lab.Task.Active, "orphaned task performed an unexpected operation");
    })
];

var failed = 0;
foreach (var (name, run) in tests)
{
    using var lab = new Fixture();
    try
    {
        run(lab);
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception error)
    {
        failed++;
        Console.Error.WriteLine($"FAIL {name}: {error.Message}");
    }
}

Console.WriteLine($"{tests.Length - failed}/{tests.Length} simulated Phase 2 tests passed.");
return failed == 0 ? 0 : 1;

static void Check(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

static void Throws<TException>(Action action, string message) where TException : Exception
{
    try
    {
        action();
    }
    catch (TException error) when (error.Message.Contains(message, StringComparison.Ordinal))
    {
        return;
    }

    throw new InvalidOperationException($"Expected {typeof(TException).Name} containing '{message}'.");
}

internal sealed class Fixture : IDisposable
{
    private static readonly Guid AdapterId = Guid.Parse("3cc9f63e-1c16-44be-936c-98122f08c471");
    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("netcheck-phase2-");
    internal FakeDns Dns { get; } = new(AdapterId);
    internal FakeTask Task { get; } = new();
    internal string JournalPath => Path.Combine(_directory.FullName, "dns-recovery.json");
    internal bool HasJournal => File.Exists(JournalPath);

    internal LabDnsRecovery NewRecovery() => new(_directory.FullName, new LabDnsRoundTrip(Dns), Task);
    internal void Arm(bool ipv6 = false, string mode = "required", bool automatic = false) =>
        NewRecovery().Arm(AdapterId, ipv6, mode, automatic);

    internal void ExpectClean()
    {
        if (HasJournal || Task.Active)
        {
            throw new InvalidOperationException("Recovery journal or task was not cleaned up.");
        }
    }

    public void Dispose() => _directory.Delete(recursive: true);
}

internal sealed class FakeTask : ILabRecoveryTask
{
    internal bool Active { get; private set; }
    internal Action? BeforeRegister { get; set; }
    public bool Exists() => Active;
    public void Register()
    {
        BeforeRegister?.Invoke();
        Active = true;
    }
    public void Remove() => Active = false;
}

internal sealed class FakeDns(Guid expectedAdapter) : ILabDnsAdapter
{
    internal DnsFamilyConfiguration IPv4 { get; set; } =
        new(0, "192.0.2.53,192.0.2.54", null, "lab.invalid", "lab.invalid", null,
            [new(1, "https://resolver.invalid/dns-query", 2)], [], 1, 0, 1, 1);
    internal DnsFamilyConfiguration IPv6 { get; set; } =
        new(1, "2001:db8::53", null, "lab.invalid", "lab.invalid", null, [], [], 1, 0, 1, 1);
    internal int Writes { get; private set; }
    internal string? LastServers { get; private set; }
    internal Action? BeforeWrite { get; set; }
    internal bool IgnoreWrites { get; set; }
    internal bool KeepDohOnReset { get; set; }

    public bool ValidateTarget(Guid adapterId, bool ipv6)
    {
        if (adapterId != expectedAdapter)
        {
            throw new InvalidOperationException("DNS operation used the wrong adapter.");
        }
        return true;
    }

    public DnsFamilyConfiguration Read(Guid adapterId, bool ipv6)
    {
        ValidateTarget(adapterId, ipv6);
        return ipv6 ? IPv6 : IPv4;
    }

    public void Write(Guid adapterId, bool ipv6, string servers, IReadOnlyList<DohProperty> properties, bool updateDoh)
    {
        var current = Read(adapterId, ipv6);
        BeforeWrite?.Invoke();
        Writes++;
        LastServers = servers;
        if (IgnoreWrites)
        {
            return;
        }

        // The simulation assumes Windows clears per-server properties with the static list.
        var next = current with
        {
            ConfiguredServers = servers.Length == 0 ? null : servers,
            ServerProperties = servers.Length == 0 && !KeepDohOnReset ? [] :
                updateDoh ? properties.ToArray() : current.ServerProperties
        };
        if (ipv6)
        {
            IPv6 = next;
        }
        else
        {
            IPv4 = next;
        }
    }
}
