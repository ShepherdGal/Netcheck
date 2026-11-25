# Netcheck 1.0.0

The first public release of Netcheck: a calm Windows app that tells you, in plain words, how good your internet is, which DNS is fastest for your PC, and which safe Windows settings help.

## What's in it

- **Check:** download, upload, ping, jitter and ping loss in about 30 seconds, each with a short meaning ("Enough for several 4K streams"). Live network activity for the last minute. **How This Check Works** (Settings) shows exactly what was measured.
- **DNS:** a short race between well-known DNS services and your current one, timed the way each would really be used (encrypted where the service offers it). One click switches, one click switches back. **Make My DNS Private** turns on encrypted lookups when your DNS is already the quickest.
- **Boost:** a few safe Windows network settings, applied with a restore point first, a "Keep these changes?" countdown, and **Undo My Boost Changes**. **Things We Don't Change** lists popular tips that don't help.
- **History:** every check saved on your PC; open any two to compare before and after.
- **Settings:** app size, Mbps or MB/s, your data folder, the open-source licences, and updates from this page (at most once a day, nothing downloads without a click, **Go Back** to the previous version).

## Download

**`Netcheck.exe`**: download it and double-click it. One file, nothing to unzip, nothing else to install. Windows 10 or 11, 64-bit. Run portable, your checks stay in a `Netcheck Data` folder next to it.

SHA-256: listed with each download on this release page.

Netcheck 1.0 isn't code-signed: if Windows says **Windows protected your PC**, click **More info → Run anyway**. Compare the SHA-256 above with your download if you want to be sure it's this file.

## Good to know

- A speed check on a fast connection uses up to about 1 GB of data.
- Switching DNS and Boost need the installed app (the **Install Netcheck** button sits at the top of every screen on the portable copy). Netcheck doesn't switch DNS on work or school PCs, with a VPN on, or where DNS is set by a policy.
- No account, no tracking, no analytics.
