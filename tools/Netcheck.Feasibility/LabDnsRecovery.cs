using System.Net;
using System.Runtime.Versioning;
using System.Text.Json;

internal sealed class LabDnsRecovery(string directory, LabDnsRoundTrip dns, ILabRecoveryTask task)
{
    private const string JournalFile = "dns-recovery.json";
    private const string LockFile = "dns-recovery.lock";

    [SupportedOSPlatform("windows")]
    internal static LabDnsRecovery OpenInstalled()
    {
        LabDnsRoundTrip.RequireAdministrator();
        var executable = GetInstalledExecutable();
        return new LabDnsRecovery(Path.GetDirectoryName(executable)!,
            new LabDnsRoundTrip(new WindowsLabDnsAdapter()), new LabRecoveryTask(executable));
    }

    internal void Arm(Guid adapterId, bool ipv6, string mode, bool automatic)
    {
        var journalPath = Path.Combine(directory, JournalFile);
        using var transactionLock = OpenLock(directory);
        RejectReparsePoint(journalPath);
        if (File.Exists(journalPath) || task.Exists())
        {
            throw new InvalidOperationException("A DNS recovery operation already exists. Run dns-recover first.");
        }

        var baseline = dns.Capture(adapterId, ipv6, mode, automatic);
        ValidateBaseline(baseline);
        var stagedJournal = journalPath + ".new";
        RejectReparsePoint(stagedJournal);
        // An interrupted staging file is never used to authorize a write.
        File.Delete(stagedJournal);
        using (var stream = new FileStream(stagedJournal, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, baseline);
            stream.Flush(flushToDisk: true);
        }
        File.Move(stagedJournal, journalPath);

        task.Register();
        try
        {
            dns.Apply(baseline);
        }
        catch
        {
            RestoreAndCleanUp(baseline, journalPath);
            throw;
        }
    }

    internal bool Recover()
    {
        var journalPath = Path.Combine(directory, JournalFile);
        using var transactionLock = OpenLock(directory);
        RejectReparsePoint(journalPath);
        if (!File.Exists(journalPath))
        {
            if (task.Exists())
            {
                throw new InvalidOperationException("The recovery task has no journal. Review the VM state.");
            }

            return false;
        }

        LabDnsBaseline? baseline;
        using (var stream = File.OpenRead(journalPath))
        {
            if (stream.Length > 65536)
            {
                throw new InvalidOperationException("The lab DNS journal exceeds its expected size.");
            }

            baseline = JsonSerializer.Deserialize<LabDnsBaseline>(stream);
        }

        if (baseline is null)
        {
            throw new InvalidOperationException("The lab DNS journal is empty.");
        }

        ValidateBaseline(baseline);
        RestoreAndCleanUp(baseline, journalPath);
        return true;
    }

    private static void ValidateBaseline(LabDnsBaseline baseline)
    {
        if (baseline.Version != 1 || baseline.AdapterId == Guid.Empty ||
            baseline.Mode is not ("plain" or "required" or "preferred") ||
            baseline.Target?.ServerProperties is null || baseline.Target.ServerProperties.Count > 16 ||
            baseline.Automatic != string.IsNullOrWhiteSpace(baseline.Target.ConfiguredServers) ||
            !string.IsNullOrEmpty(baseline.Target.ProfileServers) ||
            baseline.Target.ProfileServerProperties is not { Count: 0 } ||
            !ValidServerSettings(baseline))
        {
            throw new InvalidOperationException("The lab DNS baseline cannot be safely replayed. Review the VM state.");
        }
    }

    private static bool ValidServerSettings(LabDnsBaseline baseline)
    {
        var properties = baseline.Target.ServerProperties;
        if (baseline.Automatic)
        {
            return properties.Count == 0;
        }

        var addresses = baseline.Target.ConfiguredServers!.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
        if (addresses.Length == 0 || addresses.Any(item => !IPAddress.TryParse(item, out var address) ||
            (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) != baseline.Ipv6))
        {
            return false;
        }

        return properties.All(property => property is not null && property.ServerIndex < addresses.Length) &&
            properties.Select(property => property.ServerIndex).Distinct().Count() == properties.Count;
    }

    private void RestoreAndCleanUp(LabDnsBaseline baseline, string journalPath)
    {
        dns.Restore(baseline);
        task.Remove();
        File.Delete(journalPath);
    }

    private static string GetInstalledExecutable()
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Netcheck.Feasibility");
        var executable = Path.Combine(directory, "Netcheck.Feasibility.exe");
        if (!string.Equals(Environment.ProcessPath, executable, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Install and run the standalone VM probe at {executable}.");
        }

        RejectReparsePoint(directory);
        RejectReparsePoint(executable);
        return executable;
    }

    private static FileStream OpenLock(string directory)
    {
        var path = Path.Combine(directory, LockFile);
        RejectReparsePoint(path);
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    private static void RejectReparsePoint(string path)
    {
        try
        {
            if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidOperationException($"The protected lab path cannot be a reparse point: {path}");
            }
        }
        catch (FileNotFoundException)
        {
            // New journal and lock paths are valid inside the protected install directory.
        }
    }
}
