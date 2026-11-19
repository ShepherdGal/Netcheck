using System.Globalization;

namespace Netcheck;

// The first three values are stored as numbers in existing appearance.json files.
internal enum SpeedUnit
{
    Automatic = 0, Mbps = 1, Gbps = 2,
    BitsPerSecond, KilobitsPerSecond, AutomaticBytes, BytesPerSecond,
    KilobytesPerSecond, MegabytesPerSecond, GigabytesPerSecond
}

internal enum SpeedFamily { Bits, Bytes }

internal static class SpeedUnits
{
    private static readonly SpeedUnit[] BitScales =
        [SpeedUnit.Automatic, SpeedUnit.BitsPerSecond, SpeedUnit.KilobitsPerSecond, SpeedUnit.Mbps, SpeedUnit.Gbps];
    private static readonly SpeedUnit[] ByteScales =
        [SpeedUnit.AutomaticBytes, SpeedUnit.BytesPerSecond, SpeedUnit.KilobytesPerSecond,
            SpeedUnit.MegabytesPerSecond, SpeedUnit.GigabytesPerSecond];

    internal static IReadOnlyList<SpeedUnit> Scales(SpeedFamily family) => family == SpeedFamily.Bytes ? ByteScales : BitScales;

    internal static SpeedFamily Family(SpeedUnit preference) =>
        Array.IndexOf(ByteScales, preference) >= 0 ? SpeedFamily.Bytes : SpeedFamily.Bits;

    internal static SpeedUnit Resolve(SpeedUnit preference, double? megabits, SpeedUnit? previous = null)
    {
        if (preference is not (SpeedUnit.Automatic or SpeedUnit.AutomaticBytes))
            return preference;
        var family = Family(preference);
        var scales = Scales(family);
        if (megabits is not > 0 || !double.IsFinite(megabits.Value))
            return previous is { } held && Family(held) == family ? held : scales[3];
        var amount = megabits.Value;
        var index = amount >= Factor(scales[4]) ? 4 : amount >= Factor(scales[3]) ? 3 :
            amount >= Factor(scales[2]) ? 2 : 1;
        if (previous is { } prior && Family(prior) == family)
        {
            if (index > 1 && prior == scales[index - 1] && amount < Factor(scales[index]) * 1.10)
                return prior;
            if (index < 4 && prior == scales[index + 1] && amount >= Factor(prior) * 0.90)
                return prior;
        }
        return scales[index];
    }

    internal static string Label(SpeedUnit unit) => unit switch
    {
        SpeedUnit.BitsPerSecond => "b/s", SpeedUnit.KilobitsPerSecond => "kbps",
        SpeedUnit.Mbps => "Mbps", SpeedUnit.Gbps => "Gbps",
        SpeedUnit.BytesPerSecond => "B/s", SpeedUnit.KilobytesPerSecond => "kB/s",
        SpeedUnit.MegabytesPerSecond => "MB/s", SpeedUnit.GigabytesPerSecond => "GB/s",
        _ => "Automatic"
    };

    private static double Factor(SpeedUnit unit) => unit switch
    {
        SpeedUnit.BitsPerSecond => 0.000001, SpeedUnit.KilobitsPerSecond => 0.001,
        SpeedUnit.Gbps => 1000, SpeedUnit.BytesPerSecond => 0.000008,
        SpeedUnit.KilobytesPerSecond => 0.008, SpeedUnit.MegabytesPerSecond => 8,
        SpeedUnit.GigabytesPerSecond => 8000, _ => 1
    };

    internal static string FormatNumber(double megabits, SpeedUnit unit, bool signed = false)
    {
        if (!double.IsFinite(megabits) || (!signed && megabits < 0))
            return "—";
        var value = Math.Abs(megabits) / Factor(unit);
        var sign = megabits < 0 ? "−" : signed && megabits > 0 ? "+" : "";
        if (!double.IsFinite(value))
            return sign + $"{Math.Abs(megabits):G4} × {1 / Factor(unit):G4}";
        if (value >= 1e9)
            return sign + value.ToString("G4", CultureInfo.CurrentCulture);
        if (megabits != 0 && value < 0.001)
            return $"{sign}<{0.001:0.000}";
        var format = value >= 100 ? "N0" : value >= 10 ? "0.#" : value >= 1 ? "0.##" : "0.###";
        return sign + value.ToString(format, CultureInfo.CurrentCulture);
    }

    internal static string Format(double? megabits, SpeedUnit unit, bool signed = false) =>
        megabits is { } value && double.IsFinite(value) && (signed || value >= 0)
            ? $"{FormatNumber(value, unit, signed)} {Label(unit)}" : "Unavailable";
}
