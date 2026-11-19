param(
    # Version written into the build, e.g. 1.0.0-dev.3. Defaults to the one in Netcheck.csproj.
    [string] $Version,
    # Upgrade/rollback test builds only: point the update check at the local fixture feed (127.0.0.1:47613).
    [switch] $TestFeed,
    # Rebuild an existing package folder. Its Data\ folder (a portable copy's checks and settings) is set aside
    # first and put back afterwards: never delete it (lesson 2026-11-16, review checks were lost that way).
    [switch] $Replace,
    [string] $OutputRoot = (Join-Path $PSScriptRoot '..\artifacts')
)

# Builds one release package, Netcheck-<version>-win-x64.zip, used by both editions:
#  - unzipped anywhere it runs portable (the Netcheck.portable marker; data in Data\ beside the exe);
#  - its Install button, or an update from GitHub Releases, puts it in the protected Program Files\Netcheck
#    (the installer and the updater both leave the marker out).
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
$dotnet = Join-Path $root '.dotnet-sdk\dotnet.exe'
$env:DOTNET_CLI_HOME = Join-Path $root '.dotnet-home'
if (-not $Version) {
    $Version = ([xml](Get-Content (Join-Path $root 'src\Netcheck\Netcheck.csproj'))).Project.PropertyGroup.Version | Select-Object -First 1
}
$name = "Netcheck-$Version"
$publish = Join-Path $OutputRoot $name
$keptData = $null
if (Test-Path $publish) {
    if (-not $Replace) { throw "$publish already exists; use -Replace to rebuild it (its Data folder is kept)." }
    if (Get-Process Netcheck -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$((Resolve-Path $publish).Path)*" }) {
        throw "Netcheck is running from $publish; close it first."
    }
    $data = Join-Path $publish 'Data'
    if (Test-Path $data) {
        $keptData = Join-Path $OutputRoot ("Data-kept-" + [Guid]::NewGuid().ToString('N'))
        Move-Item -LiteralPath $data -Destination $keptData
    }
    Remove-Item -LiteralPath $publish -Recurse -Force
}

$arguments = @('publish', (Join-Path $root 'src\Netcheck\Netcheck.csproj'), '-p:PublishProfile=Windows', "-p:Version=$Version",
    "-p:PublishDir=$publish\", '-p:UsedAvaloniaProducts=')
if ($TestFeed) { $arguments += '-p:NetcheckTestFeed=true' }
try {
    & $dotnet @arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }

    Set-Content -LiteralPath (Join-Path $publish 'Netcheck.portable') -Value 'This copy runs portable: its data is kept in the Data folder beside Netcheck.exe.' -Encoding utf8
    # The zip is made before any kept Data goes back, so a user's checks never end up in a release.
    $zip = Join-Path $OutputRoot "$name-win-x64.zip"
    if (Test-Path $zip) { Remove-Item -LiteralPath $zip }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($publish, $zip, [IO.Compression.CompressionLevel]::Optimal, $false)
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
}
finally {
    if ($keptData) {
        New-Item -ItemType Directory -Path $publish -Force | Out-Null
        Move-Item -LiteralPath $keptData -Destination (Join-Path $publish 'Data')
        Write-Host "Kept the existing Data folder (portable checks and settings)."
    }
}
[pscustomobject]@{ Package = $zip; Bytes = (Get-Item $zip).Length; Sha256 = $hash; TestFeed = [bool]$TestFeed }
