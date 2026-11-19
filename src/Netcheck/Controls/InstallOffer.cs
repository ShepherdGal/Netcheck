using Avalonia.Controls;
using Netcheck.Elevation;

namespace Netcheck.Controls;

/// <summary>
/// "Switching needs the installed app · Install Netcheck" (P8): on a portable copy the install is offered right where
/// the limit is hit (DNS switch, Boost apply), not in Settings. One helper so both places behave the same.
/// </summary>
internal sealed class InstallOffer
{
    private readonly TextBlock note;
    private readonly Button link;
    private string needs = "";
    private Action? next;

    internal InstallOffer(TextBlock note, Button link)
    {
        this.note = note;
        this.link = link;
        link.Click += async (_, _) =>
        {
            if (next is not null)
                next();
            else
                await InstallAsync();
        };
    }

    /// <summary>True when this copy is portable, so installing would unlock the action.</summary>
    internal static bool Offered => AppPaths.Edition == AppEdition.Portable;

    /// <summary>Shows "<paramref name="needsText"/> · Install Netcheck" on a portable copy; hides the link otherwise.</summary>
    internal void Show(string needsText)
    {
        needs = needsText;
        next = null;
        link.Content = "Install Netcheck";
        link.IsVisible = Offered;
        link.IsEnabled = true;
        note.Text = Offered ? needsText + " ·" : needsText;
    }

    internal void Hide() => link.IsVisible = false;

    private async Task InstallAsync()
    {
        link.IsEnabled = false;
        note.Text = "Installing… Click Yes if your PC asks.";
        var result = await Updater.InstallFromPortableAsync();
        link.IsEnabled = true;
        switch (result.Outcome)
        {
            case InstallOutcome.Done:
                note.Text = "Installed. Opening Netcheck…";
                link.IsVisible = false;
                break;
            case InstallOutcome.AlreadyInstalled:
                note.Text = "Netcheck is already installed ·";
                link.Content = "Open It";
                next = Updater.Restart;
                break;
            case InstallOutcome.Cancelled:
                note.Text = "Nothing changed: Windows' permission wasn't given ·";
                link.Content = "Try Again";
                break;
            default:
                note.Text = "Nothing changed ·";
                link.Content = "Try Again";
                ToolTip.SetTip(link, result.Reason);
                break;
        }
    }
}
