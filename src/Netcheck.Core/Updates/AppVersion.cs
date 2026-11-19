using System.Globalization;

namespace Netcheck.Core.Updates;

/// <summary>
/// A semantic version such as 1.0.0, 1.0.0-dev.3 or v1.2.0 (build metadata after '+' is ignored).
/// Ordering follows SemVer 2.0: a pre-release sorts before its release; numeric identifiers compare as numbers.
/// </summary>
public sealed class AppVersion : IComparable<AppVersion>, IEquatable<AppVersion>
{
    private readonly string[] pre;

    private AppVersion(int major, int minor, int patch, string[] pre)
    {
        Major = major;
        Minor = minor;
        Patch = patch;
        this.pre = pre;
    }

    public int Major { get; }
    public int Minor { get; }
    public int Patch { get; }
    public bool IsPreRelease => pre.Length > 0;

    public static bool TryParse(string? text, out AppVersion version)
    {
        version = null!;
        if (string.IsNullOrWhiteSpace(text) || text.Length > 64)
            return false;
        var s = text.Trim();
        if (s[0] is 'v' or 'V')
            s = s[1..];
        var plus = s.IndexOf('+', StringComparison.Ordinal);
        if (plus >= 0)
            s = s[..plus];
        var dash = s.IndexOf('-', StringComparison.Ordinal);
        var core = (dash >= 0 ? s[..dash] : s).Split('.');
        var pre = dash >= 0 ? s[(dash + 1)..].Split('.') : [];
        if (core.Length != 3 || !core.All(Number) || pre.Any(p => p.Length == 0 || !p.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')))
            return false;
        version = new AppVersion(int.Parse(core[0], CultureInfo.InvariantCulture), int.Parse(core[1], CultureInfo.InvariantCulture),
            int.Parse(core[2], CultureInfo.InvariantCulture), pre);
        return true;

        static bool Number(string p) => p.Length is > 0 and <= 9 && p.All(char.IsAsciiDigit) && (p.Length == 1 || p[0] != '0');
    }

    /// <summary>
    /// The informational version of a .NET assembly file, read from its metadata. Unlike FileVersionInfo this never
    /// asks the Windows loader, which can return a module already loaded from the same path (a running old version).
    /// </summary>
    public static AppVersion? ReadFromAssembly(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            using var pe = new System.Reflection.PortableExecutable.PEReader(stream);
            if (!pe.HasMetadata)
                return null;
            var md = System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe);
            foreach (var handle in md.GetAssemblyDefinition().GetCustomAttributes())
            {
                var attribute = md.GetCustomAttribute(handle);
                if (attribute.Constructor.Kind != System.Reflection.Metadata.HandleKind.MemberReference)
                    continue;
                var constructor = md.GetMemberReference((System.Reflection.Metadata.MemberReferenceHandle)attribute.Constructor);
                if (constructor.Parent.Kind != System.Reflection.Metadata.HandleKind.TypeReference ||
                    md.GetString(md.GetTypeReference((System.Reflection.Metadata.TypeReferenceHandle)constructor.Parent).Name)
                        != "AssemblyInformationalVersionAttribute")
                    continue;
                var blob = md.GetBlobReader(attribute.Value);
                return blob.ReadUInt16() == 1 && TryParse(blob.ReadSerializedString(), out var version) ? version : null;
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or BadImageFormatException or
            InvalidOperationException)
        {
        }
        return null;
    }

    public static AppVersion Parse(string text) =>
        TryParse(text, out var v) ? v : throw new FormatException($"Not a version: {text}");

    public int CompareTo(AppVersion? other)
    {
        if (other is null)
            return 1;
        var c = Major.CompareTo(other.Major);
        if (c == 0) c = Minor.CompareTo(other.Minor);
        if (c == 0) c = Patch.CompareTo(other.Patch);
        if (c != 0)
            return c;
        if (pre.Length == 0 || other.pre.Length == 0)
            return other.pre.Length.CompareTo(pre.Length);   // no pre-release ranks higher
        for (var i = 0; i < Math.Min(pre.Length, other.pre.Length); i++)
        {
            var a = pre[i];
            var b = other.pre[i];
            var an = a.All(char.IsAsciiDigit);
            var bn = b.All(char.IsAsciiDigit);
            c = an && bn ? (a.Length != b.Length ? a.Length.CompareTo(b.Length) : string.CompareOrdinal(a, b))
                : an ? -1 : bn ? 1 : string.CompareOrdinal(a, b);
            if (c != 0)
                return c;
        }
        return pre.Length.CompareTo(other.pre.Length);
    }

    public bool Equals(AppVersion? other) => other is not null && CompareTo(other) == 0;
    public override bool Equals(object? obj) => obj is AppVersion v && Equals(v);
    public override int GetHashCode() => ToString().GetHashCode(StringComparison.Ordinal);
    public static bool operator >(AppVersion a, AppVersion b) => a.CompareTo(b) > 0;
    public static bool operator <(AppVersion a, AppVersion b) => a.CompareTo(b) < 0;
    public static bool operator >=(AppVersion a, AppVersion b) => a.CompareTo(b) >= 0;
    public static bool operator <=(AppVersion a, AppVersion b) => a.CompareTo(b) <= 0;

    public override string ToString() =>
        FormattableString.Invariant($"{Major}.{Minor}.{Patch}") + (pre.Length > 0 ? "-" + string.Join('.', pre) : "");
}
