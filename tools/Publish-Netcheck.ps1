param(
    # Version written into the build, e.g. 1.0.0-dev.3. Defaults to the one in Netcheck.csproj.
    [string] $Version,
    # Upgrade/rollback test builds only: point the update check at the local fixture feed (127.0.0.1:47613).
    [switch] $TestFeed,
    # Rebuild an existing package folder. Its data folder (a portable copy's checks and settings: "Netcheck Data",
    # or "Data" from the first 1.0 build) is set aside first and put back afterwards: never delete it (lesson 2026-11-16).
    [switch] $Replace,
    [string] $OutputRoot = (Join-Path $PSScriptRoot '..\artifacts')
)

# One file (P14). Builds the single release asset: Netcheck.exe, self-contained and compressed.
#  - People download it and double-click it: it runs portable (data in "Netcheck Data" beside it), and its
#    Install button copies just this exe into the protected Program Files\Netcheck.
#  - The installed app updates itself from the same Netcheck.exe on GitHub Releases, checked against GitHub's SHA-256.
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$dotnet = Join-Path $root '.dotnet-sdk\dotnet.exe'
$env:DOTNET_CLI_HOME = Join-Path $root '.dotnet-home'
if (-not $Version) {
    $Version = ([xml](Get-Content (Join-Path $root 'src\Netcheck\Netcheck.csproj'))).Project.PropertyGroup.Version | Select-Object -First 1
}
$name = "Netcheck-$Version"
$publish = Join-Path $OutputRoot $name
$kept = @()
if (Test-Path $publish) {
    if (-not $Replace) { throw "$publish already exists; use -Replace to rebuild it (its data folder is kept)." }
    if (Get-Process Netcheck -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$((Resolve-Path $publish).Path)*" }) {
        throw "Netcheck is running from $publish; close it first."
    }
    foreach ($folder in 'Netcheck Data', 'Data') {
        $data = Join-Path $publish $folder
        if (Test-Path $data) {
            $aside = Join-Path $OutputRoot ("Data-kept-" + [Guid]::NewGuid().ToString('N'))
            Move-Item -LiteralPath $data -Destination $aside
            $kept += [pscustomobject]@{ Name = $folder; Aside = $aside }
        }
    }
    Remove-Item -LiteralPath $publish -Recurse -Force
}

$arguments = @('publish', (Join-Path $root 'src\Netcheck\Netcheck.csproj'), '-p:PublishProfile=Windows', "-p:Version=$Version",
    "-p:PublishDir=$publish/", '-p:UsedAvaloniaProducts=')   # "/" not "\": a "\" before the closing quote escapes it
if ($TestFeed) { $arguments += '-p:NetcheckTestFeed=true' }
try {
    & $dotnet @arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
    $files = @(Get-ChildItem -LiteralPath $publish -Recurse -File)
    if ($files.Count -ne 1 -or $files[0].Name -ne 'Netcheck.exe') { throw "Expected only Netcheck.exe, got: $($files.Name -join ', ')" }
    $exe = Join-Path $publish 'Netcheck.exe'
    $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
}
finally {
    foreach ($item in $kept) {
        New-Item -ItemType Directory -Path $publish -Force | Out-Null
        Move-Item -LiteralPath $item.Aside -Destination (Join-Path $publish $item.Name)
        Write-Host "Kept the existing '$($item.Name)' folder (portable checks and settings)."
    }
}
[pscustomobject]@{ Exe = $exe; Bytes = (Get-Item $exe).Length; Sha256 = $hash; TestFeed = [bool]$TestFeed }
