using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Netcheck;

/// <summary>
/// One-file build (P14): the native libraries (Skia, HarfBuzz, ANGLE, Windows management) travel inside Netcheck.exe
/// as resources. .NET's own one-file option would unpack them to %TEMP%\.net, a folder any program can write to, and
/// an elevated helper must never load code from there. So they are written out here, to a folder chosen by who runs:
/// a normal process → %LOCALAPPDATA%\Netcheck\Libraries\&lt;version&gt;; an elevated one → the admin-only
/// Program Files\Netcheck Recovery\Libraries. Every file is compared with its SHA-256 before it is loaded by full path,
/// and a mismatch is rewritten. Development builds (loose files in bin\) skip all of this.
/// </summary>
internal static class NativeLibraries
{
    private const string Prefix = "Native/";
    internal const string Management = "microsoft.management.infrastructure.native.unmanaged.dll";
    private static readonly Dictionary<string, IntPtr> Loaded = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>True when this process runs from a one-file Netcheck.exe (its assemblies have no file of their own).</summary>
#pragma warning disable IL3000 // An empty Location is exactly how a one-file app is recognised.
    internal static bool IsOneFile => string.IsNullOrEmpty(typeof(NativeLibraries).Assembly.Location);
#pragma warning restore IL3000

    /// <summary>
    /// Writes out (when needed) and loads the bundled native libraries. <paramref name="only"/> limits it to the
    /// libraries a helper needs (the elevated Boost helper needs only Windows management, never the graphics).
    /// </summary>
    internal static void Prepare(bool elevated, params string[] only)
    {
        if (!IsOneFile || !OperatingSystem.IsWindows())
            return;
        var assembly = typeof(NativeLibraries).Assembly;
        var names = assembly.GetManifestResourceNames().Where(n => n.StartsWith(Prefix, StringComparison.Ordinal))
            .Select(n => n[Prefix.Length..])
            .Where(n => only.Length == 0 || only.Contains(n, StringComparer.OrdinalIgnoreCase)).ToList();
        if (names.Count == 0)
            return;

        var folder = elevated ? Elevation.WindowsInstaller.ProtectedLibraryDirectory()
            : Path.Combine(AppPaths.ProfileData, "Libraries", AppPaths.Version.ToString());
        Directory.CreateDirectory(folder);
        foreach (var name in names)
        {
            var path = Path.Combine(folder, name);
            var bytes = Read(assembly, Prefix + name);
            if (!Matches(path, bytes))
                Write(path, bytes);
            // Load by full path, so a same-named file anywhere else (beside the exe, in Downloads) is never picked.
            Loaded[Path.GetFileNameWithoutExtension(name)] = NativeLibrary.Load(path);
        }

        if (!elevated)
            RemoveOtherVersions(Path.GetDirectoryName(folder)!, folder);

        // DllImport("libSkiaSharp") etc. resolve to the copies loaded above.
        foreach (var user in AppDomain.CurrentDomain.GetAssemblies())
            Hook(user);
        AppDomain.CurrentDomain.AssemblyLoad += (_, e) => Hook(e.LoadedAssembly);
    }

    /// <summary>Libraries unpacked by earlier versions are removed (best effort; one still running keeps its own).</summary>
    private static void RemoveOtherVersions(string parent, string keep)
    {
        foreach (var directory in Directory.EnumerateDirectories(parent))
        {
            if (string.Equals(directory, keep, StringComparison.OrdinalIgnoreCase))
                continue;
            try { Directory.Delete(directory, recursive: true); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        }
    }

    private static void Hook(Assembly assembly)
    {
        var name = assembly.GetName().Name;
        if (name is not ("SkiaSharp" or "HarfBuzzSharp" or "Avalonia.Win32" or "Microsoft.Management.Infrastructure"))
            return;
        try
        {
            NativeLibrary.SetDllImportResolver(assembly, (library, _, _) =>
                Loaded.TryGetValue(Path.GetFileNameWithoutExtension(library), out var handle) ? handle : IntPtr.Zero);
        }
        catch (InvalidOperationException)
        {
            // A resolver is already set for this assembly; the preloaded modules still win by name.
        }
    }

    private static byte[] Read(Assembly assembly, string resource)
    {
        using var stream = assembly.GetManifestResourceStream(resource) ?? throw new InvalidOperationException(resource);
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    private static bool Matches(string path, byte[] expected)
    {
        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length != expected.Length)
                return false;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return SHA256.HashData(stream).AsSpan().SequenceEqual(SHA256.HashData(expected));
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Writes to a temporary name, then moves it in place, so a half-written library is never loaded.</summary>
    private static void Write(string path, byte[] bytes)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllBytes(temporary, bytes);
        try
        {
            File.Move(temporary, path, overwrite: true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            File.Delete(temporary);
            // Another Netcheck has it open; it was written by a run that checked it the same way.
            if (!Matches(path, bytes))
                throw;
        }
    }

    /// <summary>The licence texts that ship inside the exe, as one document.</summary>
    internal static string Licences()
    {
        var assembly = typeof(NativeLibraries).Assembly;
        var parts = assembly.GetManifestResourceNames().Where(n => n.StartsWith("Licenses/", StringComparison.Ordinal))
            .OrderBy(n => n.Contains("Netcheck.txt", StringComparison.Ordinal) ? 0 : 1).ThenBy(n => n, StringComparer.Ordinal)
            .Select(n =>
            {
                using var reader = new StreamReader(assembly.GetManifestResourceStream(n)!);
                return "==== " + n["Licenses/".Length..] + " ====" + Environment.NewLine + Environment.NewLine + reader.ReadToEnd();
            });
        return string.Join(Environment.NewLine + Environment.NewLine, parts);
    }
}
