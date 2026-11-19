using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using Netcheck.Windows;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("The Netcheck feasibility probe requires Windows.");
    return 1;
}

if (args.Length == 0 || args is ["adapters"])
{
    WriteJson(AdapterDiscovery.Read());
    return 0;
}

if (args is ["dns", var target] && Guid.TryParse(target, out var adapterId))
{
    var adapter = AdapterDiscovery.Read().SingleOrDefault(item => item.Id == adapterId);
    if (adapter is null)
    {
        Console.Error.WriteLine("Windows did not report an adapter with that GUID.");
        return 1;
    }

    var ipv4 = ReadFamily(adapterId, ipv6: false, adapter.SupportsIpv4);
    var ipv6 = ReadFamily(adapterId, ipv6: true, adapter.SupportsIpv6);
    WriteJson(new { Adapter = adapter, IPv4 = ipv4, IPv6 = ipv6 });
    return ipv4.Error is null && ipv6.Error is null ? 0 : 1;
}

if (args is ["dns-roundtrip", var labTarget, ("ipv4" or "ipv6") and var family,
    ("plain" or "required" or "preferred") and var mode, "--disposable-vm"] &&
    Guid.TryParse(labTarget, out var labAdapter))
{
    return RunLabOperation(() => LabDnsRoundTrip.Run(labAdapter, family == "ipv6", mode));
}

if (args is ["dns-arm", var durableTarget, ("ipv4" or "ipv6") and var durableFamily,
    ("plain" or "required" or "preferred") and var durableMode,
    ("automatic" or "manual") and var assignment, "--disposable-vm"] &&
    Guid.TryParse(durableTarget, out var durableAdapter))
{
    return RunLabOperation(() =>
    {
        LabDnsRecovery.OpenInstalled().Arm(durableAdapter, durableFamily == "ipv6",
            durableMode, assignment == "automatic");
        Console.WriteLine("Candidate DNS verified. Recovery is scheduled for the next boot or in five minutes.");
    });
}

if (args is ["dns-recover"])
{
    return RunLabOperation(() => Console.WriteLine(LabDnsRecovery.OpenInstalled().Recover()
        ? "DNS restoration verified. The recovery task and journal were removed."
        : "No pending DNS recovery."));
}

Console.Error.WriteLine("""
    Usage: Netcheck.Feasibility adapters
           Netcheck.Feasibility dns <adapter-guid>
           Netcheck.Feasibility dns-roundtrip <adapter-guid> <ipv4|ipv6> <plain|required|preferred> --disposable-vm
           Netcheck.Feasibility dns-arm <adapter-guid> <ipv4|ipv6> <plain|required|preferred> <automatic|manual> --disposable-vm
           Netcheck.Feasibility dns-recover
    """);
return 2;

static int RunLabOperation(Action operation)
{
    try
    {
        operation();
        return 0;
    }
    catch (Exception error) when (error is Win32Exception or COMException or InvalidOperationException or
        NotSupportedException or JsonException or IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine(error.Message);
        return 1;
    }
}

static void WriteJson<T>(T value)
{
    var options = new JsonSerializerOptions { WriteIndented = true };
    options.Converters.Add(new JsonStringEnumConverter());
    Console.WriteLine(JsonSerializer.Serialize(value, options));
}

[SupportedOSPlatform("windows")]
static DnsRead ReadFamily(Guid adapterId, bool ipv6, bool supported)
{
    if (!supported)
    {
        return new DnsRead(false, null, null, null);
    }

    try
    {
        return new DnsRead(true, InterfaceDns.Read(adapterId, ipv6), null, null);
    }
    catch (Win32Exception error)
    {
        return new DnsRead(true, null, error.NativeErrorCode, error.Message);
    }
    catch (Exception error) when (error is NotSupportedException or EntryPointNotFoundException)
    {
        return new DnsRead(true, null, null, error.Message);
    }
}

internal sealed record DnsRead(bool Supported, DnsFamilyConfiguration? Configuration, int? NativeError, string? Error);
