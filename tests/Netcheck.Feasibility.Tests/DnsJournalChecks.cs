using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Netcheck.Elevation;

[SupportedOSPlatform("windows")]
internal static class DnsJournalChecks
{
    internal static int Run()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User!;
        var parent = Directory.CreateTempSubdirectory("netcheck-dns-journal-");
        var directory = new DirectoryInfo(Path.Combine(parent.FullName, "private"));
        var journal = Path.Combine(directory.FullName, "dns-recovery.json");
        var acl = new DirectorySecurity();
        acl.SetOwner(owner);
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        acl.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        directory.Create(acl);
        try
        {
            var store = new WindowsDnsRecoveryStore(directory.FullName, owner);
            var second = new WindowsDnsRecoveryStore(directory.FullName, owner);
            Expect<InvalidOperationException>(() => store.Read());
            using (store.AcquireExclusive())
            {
                Require(store.Read() is null);
                Expect<IOException>(() => second.AcquireExclusive().Dispose());
            }

            var process = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
            if (string.Equals(Path.GetFileNameWithoutExtension(process.FileName), "dotnet", StringComparison.OrdinalIgnoreCase))
                process.ArgumentList.Add(typeof(DnsJournalChecks).Assembly.Location);
            process.ArgumentList.Add("--dns-journal-crash-fixture");
            process.ArgumentList.Add(directory.FullName);
            using var writer = Process.Start(process)!;
            if (!writer.WaitForExit(10_000))
            {
                writer.Kill();
                writer.WaitForExit();
                throw new InvalidOperationException("Journal fixture process timed out.");
            }
            Require(writer.ExitCode == 42);

            using (second.AcquireExclusive())
            {
                var restored = second.Read();
                Require(restored?.Proposed.Resolvers.Single().Address == "1.1.1.1");
                Expect<IOException>(() => second.Persist(Record()));
                var envelope = JsonNode.Parse(File.ReadAllText(journal))!.AsObject();
                envelope["Digest"] = Convert.ToBase64String(new byte[32]);
                File.WriteAllText(journal, envelope.ToJsonString());
                Expect<InvalidDataException>(() => second.Read());
                Require(File.Exists(journal));
                second.Clear(); // Fixture cleanup after checking corrupt data was retained.
                Require(second.Read() is null);
                File.WriteAllText(journal + ".pending", "interrupted staging");
                Require(second.Read() is null);
                second.Persist(Record());
                Require(second.Read()?.Proposed.Resolvers.Count == 1);
                second.Clear();
                Require(second.Read() is null);
            }

            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.ReadAndExecute, AccessControlType.Allow));
            directory.SetAccessControl(acl);
            Expect<UnauthorizedAccessException>(() => store.AcquireExclusive().Dispose());
            Console.WriteLine("PASS DNS disk journal: exclusive lease, abrupt exit, integrity rejection, retirement, and ACL rejection");
            return 0;
        }
        finally
        {
            parent.Delete(recursive: true);
        }
    }

    internal static void Interrupt(string directory)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var store = new WindowsDnsRecoveryStore(directory, identity.User!);
        using var lease = store.AcquireExclusive();
        store.Persist(Record());
        Environment.Exit(42);
    }

    private static DnsRecoveryRecord Record()
    {
        var before = new DnsChange(Guid.NewGuid(), DnsTargetFamily.Ipv4, DnsTargetAssignment.Automatic, [], false);
        return new(new DnsSnapshot(before, null), before with
        {
            Assignment = DnsTargetAssignment.Manual, Resolvers = [new("1.1.1.1", DnsEncryption.Plaintext)]
        });
    }

    private static void Expect<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }

    private static void Require(bool condition)
    {
        if (!condition)
            throw new InvalidOperationException("DNS journal fixture assertion failed.");
    }
}
