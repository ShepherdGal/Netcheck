using System.ComponentModel;
using System.Diagnostics;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Netcheck.Core.Updates;

namespace Netcheck.Elevation;

public enum InstallOutcome { Done, NothingChanged, AlreadyInstalled, Cancelled, RecoveryRequired }

[StructLayout(LayoutKind.Auto)]
public readonly record struct InstallResult(InstallOutcome Outcome, string Reason = "");

/// <summary>
/// Install, update, go back and uninstall (design plan D9). Every operation that changes Program Files is typed and runs
/// elevated:
/// <list type="bullet">
/// <item><b>Setup</b> (portable → installed): the one user-approved exception to "never elevate mutable files"
/// (design rules). The portable exe, elevated once, only copies its own folder into a new, locked
/// <c>Program Files\Netcheck</c>; it refuses when an install already exists.</item>
/// <item><b>Update / Go back / Recover</b>: served only by the protected installed copy through the same trusted broker
/// pipe as DNS and Boost. An update re-reads the release from the fixed feed itself, accepts only a newer version and
/// checks the package's SHA-256 against the release digest on its own protected copy of the file.</item>
/// </list>
/// The swap is journalled: Detect → Validate → Snapshot (move the running version aside) → Apply (move the new one in)
/// → Read back → Verify → Commit (keep the old one as "Previous") or Restore.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsInstaller
{
    public const string SetupSwitch = "--netcheck-setup";
    public const string BrokerSwitch = "--netcheck-update-broker";
    public const string UninstallSwitch = "--netcheck-uninstall";
    private const string PipePrefix = "Netcheck.Update";
    internal const string JournalName = "update-journal.json";
    private const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\Netcheck";
    private static readonly string[] Required = ["Netcheck.exe", "Netcheck.dll", "Netcheck.runtimeconfig.json", "Netcheck.Elevation.dll"];
    private const string PortableMarker = "Netcheck.portable";

    private static string ProgramFiles => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    public static string InstallDirectory => Path.Combine(ProgramFiles, "Netcheck");
    public static string PreviousDirectory => Path.Combine(ProgramFiles, "Netcheck Previous");
    private static string HoldDirectory => Path.Combine(ProgramFiles, "Netcheck Previous.new");
    private static string UpdateStaging => Path.Combine(ProgramFiles, "Netcheck Update");

    /// <summary>True when this process already runs with administrator rights.</summary>
    public static bool IsElevated => IsAdministrator();

    /// <summary>True when this copy is the protected install that may run updates and go back.</summary>
    public static bool CanUpdate => BrokerHost.IsEnabled;

    /// <summary>An update or go-back was interrupted and must be finished (restored) before anything else.</summary>
    public static bool Interrupted => !BrokerHost.JournalAbsent(JournalName);

    // ---------------------------------------------------------------- client side

    /// <summary>Portable copy: install this folder into Program Files (one UAC prompt).</summary>
    public static async Task<InstallResult> SetupAsync(CancellationToken token)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = Environment.ProcessPath ?? throw new InvalidOperationException("Netcheck executable is unavailable."),
                WorkingDirectory = AppContext.BaseDirectory,
                Arguments = FormattableString.Invariant($"{SetupSwitch} {Environment.ProcessId}"),
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            if (process is null)
                return new(InstallOutcome.NothingChanged, "setup did not start");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromMinutes(3));
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            var reason = ReadSetupReason(Environment.ProcessId);
            return process.ExitCode switch
            {
                0 => new(InstallOutcome.Done),
                3 => new(InstallOutcome.AlreadyInstalled, "Netcheck is already installed"),
                _ => new(InstallOutcome.NothingChanged, reason ?? $"setup ended with code {process.ExitCode}"),
            };
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            return new(InstallOutcome.Cancelled, "the Windows prompt was declined");
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException or OperationCanceledException)
        {
            return new(InstallOutcome.NothingChanged, error.Message);
        }
    }

    /// <summary>Installed copy: replace it with <paramref name="version"/> from a downloaded package.</summary>
    public static Task<InstallResult> UpdateAsync(AppVersion version, string package, CancellationToken token) =>
        RequestAsync(new Request(1, "update", version.ToString(), package), token);

    /// <summary>Installed copy: swap with the version kept in "Netcheck Previous".</summary>
    public static Task<InstallResult> SwitchToPreviousAsync(CancellationToken token) =>
        RequestAsync(new Request(1, "previous", null, null), token);

    /// <summary>Installed copy: finish an interrupted update by putting the earlier files back.</summary>
    public static Task<InstallResult> RecoverAsync(CancellationToken token) =>
        RequestAsync(new Request(1, "recover", null, null), token);

    private static async Task<InstallResult> RequestAsync(Request request, CancellationToken token)
    {
        try
        {
            var result = await BrokerHost.ExchangeAsync<InstallResult>(BrokerSwitch, PipePrefix, async (pipe, deadline) =>
            {
                await DnsBrokerPipe.SendAsync(pipe, request, deadline).ConfigureAwait(false);
                var reply = await DnsBrokerPipe.ReceiveAsync<Reply>(pipe, deadline).ConfigureAwait(false);
                return new InstallResult(Enum.IsDefined(reply.Outcome) ? reply.Outcome : InstallOutcome.RecoveryRequired,
                    reply.Reason is { Length: <= 600 } r ? r : "");
            }, token).ConfigureAwait(false);
            return result ?? new(InstallOutcome.NothingChanged, "only the installed app can do this");
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            return new(InstallOutcome.Cancelled, "the Windows prompt was declined");
        }
        catch (Exception error) when (error is IOException or Win32Exception or JsonException or InvalidOperationException or
            OperationCanceledException or UnauthorizedAccessException)
        {
            return new(Interrupted ? InstallOutcome.RecoveryRequired : InstallOutcome.NothingChanged, error.Message);
        }
    }

    // ---------------------------------------------------------------- elevated: setup (portable → Program Files)

    public static int RunSetup(string[] args)
    {
        if (args is not [SetupSwitch, var parent] || !int.TryParse(parent, out var pid) || pid <= 0 || !IsAdministrator())
            return 1;
        var source = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));
        var install = new DirectoryInfo(InstallDirectory);
        if (string.Equals(source.FullName, install.FullName, StringComparison.OrdinalIgnoreCase))
            return Fail(pid, "this copy is already the installed one");
        if (install.Exists)
            return 3;
        if (!Required.All(name => File.Exists(Path.Combine(source.FullName, name))))
            return Fail(pid, "this folder isn't a complete Netcheck");

        var staging = new DirectoryInfo(Path.Combine(ProgramFiles, "Netcheck Setup " + Guid.NewGuid().ToString("N")));
        try
        {
            staging.Create(InstallSecurity());
            CopyTree(source, staging, root: true);
            if (!Required.All(name => File.Exists(Path.Combine(staging.FullName, name))))
                throw new IOException("required files missing after copy");
            Directory.Move(staging.FullName, install.FullName);
            // `install` cached "doesn't exist" above; a stale cache reads Attributes as -1 (every flag, even ReparsePoint).
            install.Refresh();
            if (FirstUnprotected(install) is { } open)
            {
                Directory.Delete(install.FullName, recursive: true);
                return Fail(pid, $"the installed files weren't locked ({open})");
            }
            Register(VersionOf(install.FullName));
            return 0;
        }
        catch (Exception error)
        {
            // Top level of a short-lived elevated process: report anything, leave nothing behind.
            TryDelete(staging.FullName);
            return Fail(pid, $"{error.GetType().Name}: {error.Message}");
        }
    }

    /// <summary>The setup's failure reason, handed to the waiting portable copy through the user's temp folder.</summary>
    private static string SetupReasonPath(int parent) => Path.Combine(Path.GetTempPath(), $"Netcheck-setup-{parent}.txt");

    private static int Fail(int parent, string reason)
    {
        try { File.WriteAllText(SetupReasonPath(parent), Short(reason)); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        return 1;
    }

    private static string? ReadSetupReason(int parent)
    {
        var path = SetupReasonPath(parent);
        try
        {
            if (!File.Exists(path))
                return null;
            var text = File.ReadAllText(path);
            File.Delete(path);
            return Short(text);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>The first entry (the folder itself or anything inside) that isn't admin-owned and read-only for users.</summary>
    private static string? FirstUnprotected(DirectoryInfo root)
    {
        if (!BrokerHost.ProtectedPath(root))
            return root.Name + " " + Sddl(root);
        foreach (var entry in root.EnumerateFileSystemInfos("*", SearchOption.AllDirectories))
            if (!BrokerHost.ProtectedPath(entry))
                return Path.GetRelativePath(root.FullName, entry.FullName) + " " + Sddl(entry);
        return null;

        static string Sddl(FileSystemInfo entry)
        {
            const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
            FileSystemSecurity security = entry is DirectoryInfo d ? d.GetAccessControl(sections) : ((FileInfo)entry).GetAccessControl(sections);
            return security.GetSecurityDescriptorSddlForm(sections);
        }
    }

    private static void CopyTree(DirectoryInfo from, DirectoryInfo to, bool root)
    {
        foreach (var entry in from.EnumerateFileSystemInfos())
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException($"unexpected link at {entry.FullName}");
            // Portable data and the portable marker stay with the portable copy.
            if (root && (entry.Name.Equals("Data", StringComparison.OrdinalIgnoreCase) && entry is DirectoryInfo ||
                         entry.Name.Equals(PortableMarker, StringComparison.OrdinalIgnoreCase)))
                continue;
            var target = Path.Combine(to.FullName, entry.Name);
            if (entry is DirectoryInfo directory)
                CopyTree(directory, Directory.CreateDirectory(target), root: false);
            else
            {
                File.Copy(entry.FullName, target);
                if (!Hash(entry.FullName).SequenceEqual(Hash(target)))
                    throw new IOException($"copy mismatch at {target}");
                SetOwner(new FileInfo(target));
            }
        }
        SetOwner(to);
    }

    // ---------------------------------------------------------------- elevated: update broker

    public static Task<int> RunBrokerAsync(string[] args) =>
        BrokerHost.ServeAsync(args, BrokerSwitch, PipePrefix, async (pipe, token) =>
        {
            var request = await DnsBrokerPipe.ReceiveAsync<Request>(pipe, token).ConfigureAwait(false);
            Reply reply;
            try
            {
                reply = await ServeAsync(request, token).ConfigureAwait(false);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or HttpRequestException or
                InvalidDataException or JsonException or CryptographicException or FormatException or
                TaskCanceledException or InvalidOperationException)
            {
                reply = new Reply(Interrupted ? InstallOutcome.RecoveryRequired : InstallOutcome.NothingChanged, Short(error.Message));
            }
            using var replyDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await DnsBrokerPipe.SendAsync(pipe, reply, replyDeadline.Token).ConfigureAwait(false);
        });

    private static async Task<Reply> ServeAsync(Request request, CancellationToken token)
    {
        if (request.Version != 1)
            return new(InstallOutcome.NothingChanged, "request rejected");
        if (request.Op == "recover")
            return Recover() ? new(InstallOutcome.Done, "earlier files put back") : new(InstallOutcome.RecoveryRequired, "recovery failed");
        if (Interrupted)
            return new(InstallOutcome.RecoveryRequired, "an earlier update must be finished first");

        var installed = VersionOf(InstallDirectory) ?? throw new InvalidDataException("installed version unreadable");
        if (request is { Op: "previous", Target: null, Package: null })
        {
            var previous = new DirectoryInfo(PreviousDirectory);
            if (!previous.Exists || !Required.All(n => File.Exists(Path.Combine(previous.FullName, n))) ||
                !BrokerHost.ProtectedPath(previous) || !BrokerHost.ProtectedContents(previous) ||
                VersionOf(previous.FullName) is null)
                return new(InstallOutcome.NothingChanged, "no earlier version is kept");
            return Swap(previous.FullName);
        }
        if (request is not { Op: "update", Target: { } targetText, Package: { } package } ||
            !AppVersion.TryParse(targetText, out var target) || target <= installed ||
            !Path.IsPathFullyQualified(package) || !File.Exists(package))
            return new(InstallOutcome.NothingChanged, "request rejected");

        // Validate: the release is read again here, from the fixed feed, not taken from the caller.
        using var client = ReleaseFeed.CreateClient();
        var offer = (await ReleaseFeed.FetchAsync(client, token).ConfigureAwait(false)).FirstOrDefault(o => o.Version.Equals(target));
        if (offer is null)
            return new(InstallOutcome.NothingChanged, "that release isn't published");

        // Snapshot the package into a protected folder, then hash the protected copy (no swap after checking).
        TryDelete(UpdateStaging);
        var staging = new DirectoryInfo(UpdateStaging);
        staging.Create(InstallSecurity());
        var copy = Path.Combine(staging.FullName, offer.AssetName);
        await using (var input = new FileStream(package, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (input.Length != offer.Size)
                return Abandon(new(InstallOutcome.NothingChanged, "the download has the wrong size"));
            await using var output = new FileStream(copy, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await input.CopyToAsync(output, token).ConfigureAwait(false);
        }
        if (Convert.ToHexString(Hash(copy)) != offer.Sha256)
            return Abandon(new(InstallOutcome.NothingChanged, "the download didn't match the release fingerprint"));

        var files = Directory.CreateDirectory(Path.Combine(staging.FullName, "files"));
        Extract(copy, files);
        if (!Required.All(n => File.Exists(Path.Combine(files.FullName, n))) || VersionOf(files.FullName) is not { } got ||
            !got.Equals(target) || !HasProtectedDeploymentMarker(Path.Combine(files.FullName, "Netcheck.dll")))
            return Abandon(new(InstallOutcome.NothingChanged, "the package isn't a complete Netcheck"));
        var result = Swap(files.FullName);
        TryDelete(UpdateStaging);
        return result;

        static Reply Abandon(Reply reply)
        {
            TryDelete(UpdateStaging);
            return reply;
        }
    }

    private static void Extract(string zip, DirectoryInfo into)
    {
        var root = into.FullName + Path.DirectorySeparatorChar;
        using var archive = ZipFile.OpenRead(zip);
        long total = 0;
        foreach (var entry in archive.Entries)
        {
            var path = Path.GetFullPath(Path.Combine(into.FullName, entry.FullName));
            if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("package entry outside its folder");
            if (entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\'))
            {
                Directory.CreateDirectory(path);
                continue;
            }
            if (entry.FullName.Equals(PortableMarker, StringComparison.OrdinalIgnoreCase))
                continue;
            total += entry.Length;
            if (total > 4 * ReleaseFeed.MaxPackageBytes)
                throw new InvalidDataException("package expands too much");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            entry.ExtractToFile(path, overwrite: false);
        }
        foreach (var entry in into.EnumerateFileSystemInfos("*", SearchOption.AllDirectories))
            SetOwner(entry);
    }

    /// <summary>The swap with its journal. <paramref name="incoming"/> holds the version to run next.</summary>
    private static Reply Swap(string incoming)
    {
        var install = InstallDirectory;
        TryDelete(HoldDirectory);
        new DirectoryInfo(HoldDirectory).Create(InstallSecurity());
        var journal = new Journal(incoming);
        try
        {
            journal.Write("out");
            MoveAll(install, HoldDirectory, exeLast: true);
            journal.Write("in");
            MoveAll(incoming, install, exeLast: false);
            journal.Write("verify");
            // Read back and verify.
            var version = VersionOf(install);
            if (version is null || !Required.All(n => File.Exists(Path.Combine(install, n))) ||
                !BrokerHost.ProtectedContents(new DirectoryInfo(install)))
                throw new InvalidDataException("the new files didn't verify");
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return Recover() ? new(InstallOutcome.NothingChanged, Short(error.Message))
                : new(InstallOutcome.RecoveryRequired, Short(error.Message));
        }

        // Commit: the version that was running becomes "Previous". From here the new version stays; an unfinished
        // commit only leaves "Previous" incomplete and is finished by the next Recover.
        var installed = VersionOf(install)!;
        try
        {
            journal.Write("commit");
            CommitPrevious();
            journal.Delete();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
        }
        Register(installed);
        return new(InstallOutcome.Done, installed.ToString());
    }

    /// <summary>
    /// Moves the held (previously running) version into "Netcheck Previous". Its files are still open — that version
    /// is running this very swap — so they move one by one: Windows refuses to rename a folder holding open files.
    /// </summary>
    private static void CommitPrevious()
    {
        var previous = new DirectoryInfo(PreviousDirectory);
        if (previous.Exists)
        {
            foreach (var entry in previous.EnumerateFileSystemInfos())
            {
                if (entry is DirectoryInfo directory)
                    directory.Delete(recursive: true);
                else
                    entry.Delete();
            }
        }
        else
            previous.Create(InstallSecurity());
        MoveAll(HoldDirectory, PreviousDirectory, exeLast: false);
        Directory.Delete(HoldDirectory);
    }

    /// <summary>Restore from the journal: new files back to where they came from, the earlier files back in place.</summary>
    private static bool Recover()
    {
        var journal = Journal.Read();
        if (journal is null)
            return !Interrupted;
        try
        {
            if (journal.Phase is "commit")
            {
                // The new version was verified and stays; only finish keeping the earlier one.
                if (Directory.Exists(HoldDirectory))
                    CommitPrevious();
                journal.Delete();
                return true;
            }
            if (journal.Phase is "in" or "verify")
            {
                Directory.CreateDirectory(journal.Incoming);
                MoveAll(InstallDirectory, journal.Incoming, exeLast: true);
            }
            if (Directory.Exists(HoldDirectory))
            {
                MoveAll(HoldDirectory, InstallDirectory, exeLast: false);
                Directory.Delete(HoldDirectory);
            }
            journal.Delete();
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Moves every file; Netcheck.exe goes last when moving out and first when moving in. Folders are recreated and
    /// emptied file by file: Windows lets a running program's files be moved, but not a folder that holds an open
    /// file (the elevated helper itself loads runtimes\win\lib\…\System.Management.dll).
    /// </summary>
    private static void MoveAll(string from, string to, bool exeLast)
    {
        if (!Directory.Exists(to))
        {
            Directory.CreateDirectory(to);
            SetOwner(new DirectoryInfo(to));
        }
        var entries = new DirectoryInfo(from).EnumerateFileSystemInfos()
            .OrderBy(e => e.Name.Equals("Netcheck.exe", StringComparison.OrdinalIgnoreCase) == exeLast ? 1 : 0).ToList();
        foreach (var entry in entries)
        {
            var target = Path.Combine(to, entry.Name);
            if (entry is DirectoryInfo)
            {
                MoveAll(entry.FullName, target, exeLast);
                Directory.Delete(entry.FullName);
            }
            else
                File.Move(entry.FullName, target);
        }
    }

    // ---------------------------------------------------------------- elevated: uninstall

    /// <summary>
    /// Apps &amp; features → Uninstall. Re-launches elevated from the protected install, then removes the program,
    /// the kept earlier version, the Start menu entry and the uninstall entry. User data and recovery journals stay.
    /// </summary>
    public static int RunUninstall(string[] args)
    {
        if (!CanUpdate)
            return 1;
        if (!IsAdministrator())
        {
            try
            {
                using var process = Process.Start(new ProcessStartInfo
                {
                    FileName = Environment.ProcessPath!, Arguments = UninstallSwitch, UseShellExecute = true, Verb = "runas",
                });
                process?.WaitForExit();
                return process?.ExitCode ?? 1;
            }
            catch (Win32Exception)
            {
                return 1;
            }
        }
        if (Interrupted && !Recover())
            return 1;
        try
        {
            var trash = Path.Combine(BrokerHost.OpenRecoveryDirectory(out _).FullName, "uninstalled " + Guid.NewGuid().ToString("N"));
            Environment.CurrentDirectory = Path.GetTempPath();
            MoveAll(InstallDirectory, trash, exeLast: true);
            try
            {
                Directory.Delete(InstallDirectory);
            }
            catch (IOException)
            {
                // Still some program's working folder: Windows removes the empty folder at the next restart.
                MoveFileEx(InstallDirectory, null, 4 /* MOVEFILE_DELAY_UNTIL_REBOOT */);
            }
            TryDelete(PreviousDirectory);
            TryDelete(trash);
            // The running exe and its libraries can't be deleted yet: Windows removes them at the next restart.
            if (Directory.Exists(trash))
            {
                foreach (var file in Directory.EnumerateFiles(trash, "*", SearchOption.AllDirectories))
                    MoveFileEx(file, null, 4 /* MOVEFILE_DELAY_UNTIL_REBOOT */);
                foreach (var dir in Directory.EnumerateDirectories(trash, "*", SearchOption.AllDirectories).Reverse().Append(trash))
                    MoveFileEx(dir, null, 4);
            }
            File.Delete(ShortcutPath);
            Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, throwOnMissingSubKey: false);
            return 0;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return 1;
        }
    }

    // ---------------------------------------------------------------- shared

    private static string ShortcutPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "Netcheck.lnk");

    /// <summary>Start menu entry and the Apps &amp; features entry (version kept current on every swap).</summary>
    private static void Register(AppVersion? version)
    {
        var exe = Path.Combine(InstallDirectory, "Netcheck.exe");
        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(UninstallKey);
            key.SetValue("DisplayName", "Netcheck");
            key.SetValue("DisplayVersion", version?.ToString() ?? "");
            key.SetValue("Publisher", "ShepherdGal");
            key.SetValue("DisplayIcon", exe);
            key.SetValue("InstallLocation", InstallDirectory);
            key.SetValue("UninstallString", $"\"{exe}\" {UninstallSwitch}");
            key.SetValue("NoModify", 1, RegistryValueKind.DWord);
            key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
            var kb = new DirectoryInfo(InstallDirectory).EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length) / 1024;
            key.SetValue("EstimatedSize", (int)Math.Min(kb, int.MaxValue), RegistryValueKind.DWord);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
        }
        try
        {
            if (File.Exists(ShortcutPath))
                return;
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType is null)
                return;
            dynamic shell = Activator.CreateInstance(shellType)!;
            dynamic link = shell.CreateShortcut(ShortcutPath);
            link.TargetPath = exe;
            link.WorkingDirectory = InstallDirectory;
            link.Description = "Check your internet, find a faster DNS and apply safe tweaks.";
            link.Save();
        }
        catch (Exception error) when (error is COMException or IOException or UnauthorizedAccessException or
            Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
        }
    }

    public static AppVersion? VersionOf(string directory)
    {
        // From metadata, not FileVersionInfo: after a swap the helper still has the old Netcheck.dll loaded from this
        // very path, and the Windows version API returned that loaded module's version (seen in the live test).
        var dll = Path.Combine(directory, "Netcheck.dll");
        return File.Exists(dll) ? AppVersion.ReadFromAssembly(dll) : null;
    }

    /// <summary>A package that lacks the protected-deployment marker could never run the broker again (no way back).</summary>
    private static bool HasProtectedDeploymentMarker(string dll)
    {
        var bytes = File.ReadAllBytes(dll);
        return bytes.AsSpan().IndexOf("Netcheck.ProtectedDeployment"u8) >= 0;
    }

    private static DirectorySecurity InstallSecurity()
    {
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        var acl = new DirectorySecurity();
        acl.SetOwner(administrators);
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var (sid, rights) in new[] { (administrators, FileSystemRights.FullControl), (system, FileSystemRights.FullControl),
                     (users, FileSystemRights.ReadAndExecute) })
            acl.AddAccessRule(new FileSystemAccessRule(sid, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        return acl;
    }

    private static void SetOwner(FileSystemInfo entry)
    {
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        if (entry is DirectoryInfo directory)
        {
            var security = directory.GetAccessControl(AccessControlSections.Owner);
            security.SetOwner(administrators);
            directory.SetAccessControl(security);
        }
        else if (entry is FileInfo file)
        {
            var security = file.GetAccessControl(AccessControlSections.Owner);
            security.SetOwner(administrators);
            file.SetAccessControl(security);
        }
    }

    private static byte[] Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return SHA256.HashData(stream);
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void TryDelete(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static string Short(string text) => text.Length > 600 ? text[..600] : text;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MoveFileEx(string existing, string? replacement, int flags);

    /// <summary>The swap journal, in the admin-only recovery folder, written before every phase.</summary>
    private sealed record Journal(string Incoming, string Phase = "")
    {
        private static string PathOf => Path.Combine(BrokerHost.OpenRecoveryDirectory(out _).FullName, JournalName);

        internal void Write(string phase)
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(this with { Phase = phase });
            using var stream = new FileStream(PathOf, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
            stream.Write(bytes);
        }

        internal static Journal? Read()
        {
            try
            {
                var path = PathOf;
                return File.Exists(path) && new FileInfo(path).Length < 8192
                    ? JsonSerializer.Deserialize<Journal>(File.ReadAllBytes(path)) : null;
            }
            catch (Exception error) when (error is IOException or JsonException or UnauthorizedAccessException)
            {
                return null;
            }
        }

        internal void Delete() => File.Delete(PathOf);
    }

    internal sealed record Request(int Version, string Op, string? Target, string? Package);
    internal sealed record Reply(InstallOutcome Outcome, string? Reason = null);
}
