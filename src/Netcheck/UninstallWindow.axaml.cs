using System.ComponentModel;
using Avalonia.Controls;
using Netcheck.Elevation;

namespace Netcheck;

/// <summary>
/// Before uninstalling: if Netcheck still has the DNS switched or Boost settings applied, offer to put them back,
/// because after uninstalling the app can't. <see cref="Proceed"/> is true when the uninstall should go ahead.
/// </summary>
public sealed partial class UninstallWindow : Window
{
    private bool busy, failed;

    public UninstallWindow()
    {
        InitializeComponent();
        Body.Text = Describe();
        // Before an undo attempt: Keep = uninstall as is, Undo = undo then uninstall.
        // After a failed undo: Keep becomes Cancel, Undo becomes "Uninstall Anyway".
        KeepButton.Click += (_, _) => Finish(!failed);
        UndoButton.Click += async (_, _) =>
        {
            if (failed)
                Finish(true);
            else
                await UndoAsync();
        };
        Closing += (_, e) => e.Cancel = busy;
        UndoButton.Focus();
    }

    internal bool Proceed { get; private set; }

    /// <summary>True when something Netcheck changed is still in place (read from the installed app's data folder).</summary>
    internal static bool HasChanges => DnsSwitcher.Original is not null || BoostAdvisor.Originals is { Length: > 0 };

    private static string Describe()
    {
        var parts = new List<string>();
        if (DnsSwitcher.Original is not null)
            parts.Add("switched your DNS");
        if (BoostAdvisor.Originals is { Length: > 0 } boost)
            parts.Add(boost.Length == 1 ? "changed 1 Boost setting" : $"changed {boost.Length} Boost settings");
        return $"Netcheck {string.Join(" and ", parts)}. After uninstalling, the app can't put them back for you.";
    }

    private async Task UndoAsync()
    {
        busy = true;
        KeepButton.IsEnabled = UndoButton.IsEnabled = false;
        Heading.Text = "Undoing…";
        Body.Text = "Click Yes if your PC asks.";
        var problems = new List<string>();
        try
        {
            if (DnsSwitcher.Original is not null)
            {
                var dns = await DnsSwitcher.SwitchBackAsync();
                if (dns.Result != SwitchResult.Done)
                    problems.Add("your DNS couldn't be switched back");
            }
            if (BoostAdvisor.Originals is { Length: > 0 } originals)
            {
                var undo = await WindowsTweakBroker.ApplyAsync(originals, restorePoint: false, _ => Task.FromResult(true));
                BoostAdvisor.LogLast("undo before uninstall", undo.Outcome, undo.Reason);
                if (undo.Outcome is TweakOutcome.Committed or TweakOutcome.NoChange)
                    BoostAdvisor.ForgetOriginals();
                else
                    problems.Add("the Boost settings couldn't be put back");
            }
        }
        catch (Exception error) when (error is Win32Exception or IOException or OperationCanceledException or
            InvalidOperationException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            problems.Add("Windows didn't allow the change");
        }
        busy = false;
        if (problems.Count == 0)
        {
            Finish(true);
            return;
        }
        // Nothing is uninstalled yet; the user decides with the facts in front of them.
        Heading.Text = "Not everything was undone";
        Body.Text = char.ToUpperInvariant(problems[0][0]) + string.Join(" and ", problems)[1..] +
            ". Nothing has been uninstalled yet. You can cancel and try again from Netcheck, or uninstall anyway.";
        KeepButton.Content = "Cancel";
        UndoButton.Content = "Uninstall Anyway";
        KeepButton.IsEnabled = UndoButton.IsEnabled = true;
        failed = true;
    }

    private void Finish(bool proceed)
    {
        if (busy)
            return;
        Proceed = proceed;
        Close();
    }
}
