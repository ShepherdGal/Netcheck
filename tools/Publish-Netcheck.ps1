param(
    # Version written into the build, e.g. 1.0.0-dev.3. Defaults to the one in Netcheck.csproj.
    [string] $Version,
    # Upgrade/rollback test builds only: point the update check at the local fixture feed (127.0.0.1:47613).
    [switch] $TestFeed,
    # Rebuild an existing package folder. Its data folder (a portable copy's checks and settings: "Netcheck Data",
    # or "Data" from 1.0) is set aside first and put back afterwards: never delete it (lesson 2026-11-16).
    [switch] $Replace,
    [string] $OutputRoot = (Join-Path $PSScriptRoot '..\artifacts')
)

# One file (P14). Builds two release assets from one self-contained, compressed Netcheck.exe:
#  - Netcheck.exe — what people download: double-click and it runs portable (data in "Netcheck Data" beside it);
#    its Install button copies just this exe into the protected Program Files\Netcheck.
#  - Netcheck-<version>-win-x64.zip — the update package the installed app downloads: the one-file exe plus a full
#    1.0-style folder of the same version. A 1.0.0 updater needs that folder: during its swap its own files move away
#    and it loads what it still needs from the install folder (live test 2026-11-24: with only the exe there, the old
#    helper failed after a good swap and said "Nothing changed"). The one-file exe ignores those files (checked: it
#    loads nothing from its folder), and 1.1+ updaters take only Netcheck.exe out of the zip.
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

$common = @('-p:PublishProfile=Windows', "-p:Version=$Version", '-p:UsedAvaloniaProducts=')
if ($TestFeed) { $common += '-p:NetcheckTestFeed=true' }
$project = Join-Path $root 'src\Netcheck\Netcheck.csproj'
$stage = Join-Path $OutputRoot ("zip-" + [Guid]::NewGuid().ToString('N'))
try {
    & $dotnet publish $project @common "-p:PublishDir=$publish\" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
    $files = @(Get-ChildItem -LiteralPath $publish -Recurse -File)
    if ($files.Count -ne 1 -or $files[0].Name -ne 'Netcheck.exe') { throw "Expected only Netcheck.exe, got: $($files.Name -join ', ')" }

    # A full folder build of the same source and version, for 1.0.0 updaters; its Netcheck.exe is the one-file exe.
    & $dotnet publish $project @common '-p:PublishSingleFile=false' "-p:PublishDir=$stage\" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Compatibility publish failed.' }
    Copy-Item -LiteralPath (Join-Path $publish 'Netcheck.exe') -Destination (Join-Path $stage 'Netcheck.exe') -Force

    # The zip is made from its own folder, so a user's checks never end up in a release.
    $zip = Join-Path $OutputRoot "$name-win-x64.zip"
    if (Test-Path $zip) { Remove-Item -LiteralPath $zip }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip, [IO.Compression.CompressionLevel]::Optimal, $false)
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
    $exe = Join-Path $publish 'Netcheck.exe'
    $exeHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
}
finally {
    foreach ($folder in $stage) { if (Test-Path $folder) { Remove-Item -LiteralPath $folder -Recurse -Force } }
    foreach ($item in $kept) {
        New-Item -ItemType Directory -Path $publish -Force | Out-Null
        Move-Item -LiteralPath $item.Aside -Destination (Join-Path $publish $item.Name)
        Write-Host "Kept the existing '$($item.Name)' folder (portable checks and settings)."
    }
}
[pscustomobject]@{
    Exe = $exe; ExeBytes = (Get-Item $exe).Length; ExeSha256 = $exeHash
    Package = $zip; Bytes = (Get-Item $zip).Length; Sha256 = $hash; TestFeed = [bool]$TestFeed
}
