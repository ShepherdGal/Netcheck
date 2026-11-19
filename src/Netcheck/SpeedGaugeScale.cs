namespace Netcheck;

internal static class SpeedGaugeScale
{
    internal const int BandCount = 5;
    private static readonly double[] Download = [0, 10, 25, 100, 300, 1000];
    private static readonly double[] Upload = [0, 1, 3, 20, 100, 1000];

    internal static double Position(double megabits, bool upload)
    {
        var limits = upload ? Upload : Download;
        var band = Math.Clamp(Array.FindLastIndex(limits, cutoff => megabits >= cutoff), 0, BandCount - 1);
        var portion = Math.Clamp((megabits - limits[band]) / (limits[band + 1] - limits[band]), 0, 1);
        return (band + portion) / BandCount;
    }

    internal static string Describe(bool upload, SpeedUnit unit)
    {
        var boundaries = (upload ? Upload : Download).Skip(1).Select(mbps => SpeedUnits.Format(mbps, unit));
        return $"Netcheck speed scale. Band boundaries: {string.Join(", ", boundaries)}.";
    }
}
