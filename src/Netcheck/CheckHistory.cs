using Netcheck.Core;
using Netcheck.Storage;

namespace Netcheck;

/// <summary>One row of History: a check from the rebuilt Check page, or one saved by the earlier version.</summary>
internal sealed record HistoryItem(Guid Id, DateTimeOffset Ended, InternetCheckResult Result, string? Kind,
    string? DnsName, string? DnsAddress, double? DnsLookupMs, bool Earlier)
{
    public CheckSummary Summary { get; } = CheckAssessment.Summarize(Result);
}

/// <summary>The app's history file (%LOCALAPPDATA%\Netcheck\history.db). Never throws to the UI.</summary>
internal static class CheckHistory
{
    /// <summary>Development switch: NETCHECK_DATA_DIR points history at another folder (e.g. a copy), so test runs
    /// never write into the user's real history.</summary>
    private static readonly HistoryStore Store = new(AppPaths.Data("history.db"));

    /// <summary>Raised on the saving thread after a check was stored.</summary>
    public static event Action? Changed;

    public static Task SaveAsync(CheckRecord check) => Task.Run(() =>
    {
        try
        {
            Store.SaveCheck(check);
            Changed?.Invoke();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException
            or Microsoft.Data.Sqlite.SqliteException)
        {
            // History is a convenience: a check that can't be saved still shows its result.
        }
    });

    /// <summary>Settings → Clear history (after the user confirms): removes every saved check. Settings and undo
    /// records are separate files and stay. False when the history couldn't be changed.</summary>
    public static Task<bool> ClearAsync() => Task.Run(() =>
    {
        try
        {
            Store.Clear();
            Changed?.Invoke();
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException
            or Microsoft.Data.Sqlite.SqliteException)
        {
            return false;
        }
    });

    /// <summary>Newest first; the notice explains anything that couldn't be read.</summary>
    public static Task<(IReadOnlyList<HistoryItem> Items, string? Notice)> LoadAsync() => Task.Run(() =>
    {
        var items = new List<HistoryItem>();
        string? notice = null;
        try
        {
            var checks = Store.LoadChecks();
            items.AddRange(checks.Checks.Select(c => new HistoryItem(c.Id, c.Result.Ended, c.Result, c.ConnectionKind,
                c.DnsName, c.DnsAddress, c.DnsLookupMs, false)));
            var runs = Store.Load();
            items.AddRange(runs.Entries.Select(e => new HistoryItem(e.Id, e.Result.Ended,
                CheckComparison.FromEarlierVersion(e.Result), null, null, null, CheckComparison.EarlierDnsLookup(e.Result), true)));
            notice = checks.Notice ?? runs.Notice;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidDataException
            or Microsoft.Data.Sqlite.SqliteException)
        {
            notice = "Your history couldn't be read: " + error.Message;
        }
        return ((IReadOnlyList<HistoryItem>)items.OrderByDescending(i => i.Ended).ToList(), notice);
    });
}

internal static class Dates
{
    /// <summary>"Today · 10:12", "Yesterday · 18:00", "Sat 14 Nov · 20:49" in local time.</summary>
    public static string When(DateTimeOffset at)
    {
        var local = at.ToLocalTime();
        var day = local.Date == DateTime.Today ? "Today"
            : local.Date == DateTime.Today.AddDays(-1) ? "Yesterday"
            : local.ToString("ddd d MMM", System.Globalization.CultureInfo.CurrentCulture);
        return $"{day} · {local:HH:mm}";
    }
}
