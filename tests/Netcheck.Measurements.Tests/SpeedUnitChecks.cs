using System.Globalization;
using System.Text.Json;
using Netcheck;

internal static class SpeedUnitChecks
{
    internal static void Run()
    {
        var previousCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("en-US");
            Require(SpeedUnits.Format(1, SpeedUnit.MegabytesPerSecond), "0.125 MB/s");
            Require(SpeedUnits.Format(100, SpeedUnit.MegabytesPerSecond), "12.5 MB/s");
            Require(SpeedGaugeScale.Position(0, upload: false), 0d);
            Require(SpeedGaugeScale.Position(10, upload: false), 0.2d);
            Require(SpeedGaugeScale.Position(25, upload: false), 0.4d);
            Require(SpeedGaugeScale.Position(20, upload: true), 0.6d);
            Require(SpeedGaugeScale.Position(100, upload: true), 0.8d);
            Require(SpeedGaugeScale.Position(2000, upload: false), 1d);
            Require(SpeedGaugeScale.Describe(false, SpeedUnit.MegabytesPerSecond).Contains("12.5 MB/s"), true);
            Require(SpeedUnits.Format(1, SpeedUnit.BytesPerSecond), "125,000 B/s");
            Require(SpeedUnits.Format(0.001, SpeedUnit.BitsPerSecond), "1,000 b/s");
            Require(SpeedUnits.Format(0.004, SpeedUnit.Mbps), "0.004 Mbps");
            Require(SpeedUnits.Format(double.Epsilon, SpeedUnit.GigabytesPerSecond), "<0.001 GB/s");
            Require(SpeedUnits.Format(0, SpeedUnit.MegabytesPerSecond), "0 MB/s");
            Require(SpeedUnits.Format(null, SpeedUnit.Mbps), "Unavailable");
            Require(SpeedUnits.Format(double.NaN, SpeedUnit.Mbps), "Unavailable");
            Require(SpeedUnits.Format(-8, SpeedUnit.MegabytesPerSecond, signed: true), "−1 MB/s");
            Require(SpeedUnits.Format(8, SpeedUnit.MegabytesPerSecond, signed: true), "+1 MB/s");
            Require(SpeedUnits.Resolve(SpeedUnit.Automatic, 0.001), SpeedUnit.KilobitsPerSecond);
            Require(SpeedUnits.Resolve(SpeedUnit.Automatic, 1000), SpeedUnit.Gbps);
            Require(SpeedUnits.Resolve(SpeedUnit.AutomaticBytes, 8), SpeedUnit.MegabytesPerSecond);
            Require(SpeedUnits.Resolve(SpeedUnit.AutomaticBytes, 8000), SpeedUnit.GigabytesPerSecond);
            Require(SpeedUnits.Resolve(SpeedUnit.AutomaticBytes, 8.4, SpeedUnit.KilobytesPerSecond),
                SpeedUnit.KilobytesPerSecond);
            Require(SpeedUnits.Resolve(SpeedUnit.AutomaticBytes, 7.8, SpeedUnit.MegabytesPerSecond),
                SpeedUnit.MegabytesPerSecond);
            Require(SpeedUnits.Resolve(SpeedUnit.AutomaticBytes, 7, SpeedUnit.MegabytesPerSecond),
                SpeedUnit.KilobytesPerSecond);
            Require(SpeedUnits.Resolve(SpeedUnit.AutomaticBytes, 0, SpeedUnit.MegabytesPerSecond),
                SpeedUnit.MegabytesPerSecond);
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("de-DE");
            Require(SpeedUnits.Format(100, SpeedUnit.MegabytesPerSecond), "12,5 MB/s");
            Require(SpeedUnits.Format(double.Epsilon, SpeedUnit.GigabytesPerSecond), "<0,001 GB/s");
        }
        finally
        {
            CultureInfo.CurrentCulture = previousCulture;
        }

        var legacy = new[] { SpeedUnit.Automatic, SpeedUnit.Mbps, SpeedUnit.Gbps };
        for (var index = 0; index < legacy.Length; index++)
        {
            var saved = JsonSerializer.Deserialize<UiPreferences>(
                $$"""{"Theme":"Ocean","ReduceMotion":true,"SpeedUnit":{{index}},"KeepTemporaryFiles":true}""")!;
            Require(saved, new UiPreferences("Ocean", true, legacy[index], true));
        }
        var omitted = JsonSerializer.Deserialize<UiPreferences>("""{"Theme":"Dark","ReduceMotion":false}""")!;
        Require(omitted.SpeedUnit, SpeedUnit.Automatic);
        var bytes = new UiPreferences("Light", false, SpeedUnit.MegabytesPerSecond);
        Require(JsonSerializer.Deserialize<UiPreferences>(JsonSerializer.Serialize(bytes))!, bytes);
        Console.WriteLine("PASS decimal bit/byte conversion, scales, hysteresis, precision, locale and preference serialization");
    }

    private static void Require<T>(T actual, T expected)
    {
        if (!EqualityComparer<T>.Default.Equals(actual, expected))
            throw new InvalidOperationException($"Expected {expected}; received {actual}.");
    }
}
