# Developing Netcheck

This file says where things are and how to build, check and package Netcheck.

## Folder map

| Folder | What's in it |
|---|---|
| `src/Netcheck` | The app (Avalonia UI): `Pages/` (Check, DNS, Boost, History, Settings), `Controls/`, `Theme/` (colour tokens, control styles), `Assets/` (icon, Inter font) |
| `src/Netcheck.Core` | Plain models and rules: check results, assessments, DNS list and scoring, update feed |
| `src/Netcheck.Measurements` | Speed test, ping, DNS benchmark (`Resolvers/`), system DNS timing |
| `src/Netcheck.Windows` | Read-only Windows discovery: adapters, routes, DNS, Wi-Fi, tuning |
| `src/Netcheck.Elevation` | The elevated helper: typed, allowlisted DNS and tweak transactions with a recovery journal |
| `src/Netcheck.Optimization` | Boost findings |
| `src/Netcheck.Storage` | History database (SQLite) and export |
| `src/Netcheck.TestServer` | Local fake speed/DNS servers used by the checks |
| `tests/` | Console check suites (run with `dotnet run`, see below) |
| `tools/Publish-Netcheck.ps1` | Builds the release package |
| `tools/Netcheck.Feasibility` | Lab-only privileged experiments (and `Invoke-RecoveryProbe.ps1`): disposable VM only, never on a real PC without explicit OK |
| `tools/Netcheck.TestServer.Host` | Runs the fake test server on its own for manual testing |
| `tools/IconRender` | Draws the app icon (`Assets/Netcheck-icon.svg` is the source) into `Netcheck.ico` + master PNG |
| `artifacts/` | Built packages (not in git). A portable copy keeps its checks in `Netcheck-<ver>\Data`: rebuild only with `-Replace` |
| `.dotnet-sdk/`, `.dotnet-home/` | Optional: a private copy of the pinned .NET SDK and its package cache (not in git) |

## Build

Needs the .NET SDK pinned in `global.json` (10.0.404 or a later patch) on Windows 10/11 x64.

```powershell
$dotnet = 'dotnet'   # or a private SDK copy: Join-Path $PWD '.dotnet-sdk/dotnet.exe'
& $dotnet build Netcheck.slnx
```

Run the app from `src/Netcheck/bin/Debug/.../Netcheck.exe`. Set `NETCHECK_DATA_DIR` to a scratch folder so a test run never touches real history. Only one Netcheck runs at a time, so close other copies first.

## Checks

Console programs, not a test adapter. Each prints `PASS …` lines and exits non-zero on failure.

```powershell
& $dotnet run --project tests/Netcheck.Measurements.Tests -- --dns-benchmark
```

- **Measurements.Tests:** (no switch) speed fixture, `--internet-check`, `--dns-benchmark`, `--history`, `--assessments`, `--speed-units`, `--updates`, `--compare-curl`.
- **Feasibility.Tests:** (no switch), `--discovery-fixtures`, `--windows-discovery` (read-only), `--dns-validation`, `--dns-transaction`, `--dns-journal`, `--dns-broker`, `--dns-crash-lab`, `--router-identity`, `--tweak-rules`, `--tweak-transaction`, `--tweak-broker`, `--tweak-crash-lab`, `--tweak-detect` (read-only).
- **Live, real network (read-only, small):** `--live-dns [current]`, `--live-dns-pairs`, `--router-identity-live`.
- **Live, large traffic (ask first):** `--live-check small` (~45 MB), `--live-check` (up to 300 MB).

## Package

```powershell
& .\tools\Publish-Netcheck.ps1            # new version folder + zip in artifacts\
& .\tools\Publish-Netcheck.ps1 -Replace   # rebuild the same version; keeps its Data\ folder
```

The package is self-contained (.NET included). Installing, updating and going back are built into Netcheck.exe: a portable copy offers **Install Netcheck** where an action needs the installed app; Settings offers **Update Now** and **Go Back**. Releases are published on GitHub Releases with the zip's SHA-256.

## Packages

`Directory.Build.props` turns on NuGet lock files. To update a package on purpose: restore without locked mode, review the lock-file changes, rebuild, run the checks, then

```powershell
& $dotnet list Netcheck.slnx package --vulnerable --include-transitive
```
