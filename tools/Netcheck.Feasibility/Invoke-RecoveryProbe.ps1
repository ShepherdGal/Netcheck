# Lab canary for UAC and Task Scheduler recovery. Install and run in a disposable VM.
[CmdletBinding()]
param(
    [ValidateSet('Launch', 'Arm', 'Recover', 'Status')]
    [string] $Action = 'Status'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$labDirectory = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Netcheck.Feasibility'
$installedScript = Join-Path $labDirectory 'Invoke-RecoveryProbe.ps1'
$markerPath = Join-Path $labDirectory 'canary.txt'
$journalPath = Join-Path $labDirectory 'recovery.journal'
$lockPath = Join-Path $labDirectory 'recovery.lock'
$taskName = 'Netcheck.Feasibility.RecoverCanary'
$powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'

if ($PSCommandPath -ne $installedScript) {
    throw "Install the probe at $installedScript in a disposable VM."
}

foreach ($path in $labDirectory, $installedScript, $markerPath, $journalPath, $lockPath) {
    if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Unexpected reparse point at $path."
    }
}

if ($Action -eq 'Status') {
    $marker = if (Test-Path -LiteralPath $markerPath) { Get-Content -Raw -LiteralPath $markerPath }
    [pscustomobject]@{
        Marker = $marker
        JournalPresent = Test-Path -LiteralPath $journalPath
        RecoveryTaskPresent = [bool](Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue)
    }
    return
}

if ($Action -eq 'Launch') {
    $arguments = @('-NoProfile', '-File', ('"{0}"' -f $installedScript), '-Action', 'Arm')
    $process = Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "The elevated canary returned exit code $($process.ExitCode)." }
    return
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated token is required for this action.'
}

function Write-DurableText([string] $Path, [string] $Text, [IO.FileMode] $Mode) {
    $stream = [IO.File]::Open($Path, $Mode, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

$lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($Action -eq 'Arm') {
        if ($task -or (Test-Path -LiteralPath $journalPath) -or (Test-Path -LiteralPath $markerPath)) {
            throw 'Previous probe state exists. Review it before retrying.'
        }

        # The canary has a known absent baseline. Only this file is touched by recovery.
        Write-DurableText $journalPath 'Netcheck-canary-v1:restore-absence' CreateNew
        $taskAction = New-ScheduledTaskAction -Execute $powershell -Argument (
            '-NoProfile -NonInteractive -File "{0}" -Action Recover' -f $installedScript)
        $triggers = @(
            New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
            New-ScheduledTaskTrigger -AtStartup
        )
        $taskParameters = @{
            TaskName = $taskName
            TaskPath = '\'
            Action = $taskAction
            Trigger = $triggers
            Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        }
        Register-ScheduledTask @taskParameters | Out-Null
        Write-DurableText $markerPath 'Netcheck-canary-v1:applied' CreateNew
        Write-Output 'Canary applied. Recovery will run at the deadline or on the next boot.'
        return
    }

    if (!(Test-Path -LiteralPath $journalPath)) {
        return
    }

    if ((Get-Content -Raw -LiteralPath $journalPath) -cne 'Netcheck-canary-v1:restore-absence') {
        throw 'Recovery journal is invalid.'
    }

    if (Test-Path -LiteralPath $markerPath) {
        if ((Get-Content -Raw -LiteralPath $markerPath) -cne 'Netcheck-canary-v1:applied') {
            throw 'Canary changed outside the probe. Recovery requires review.'
        }

        Remove-Item -LiteralPath $markerPath
    }

    if ($task) {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false
    }
    Remove-Item -LiteralPath $journalPath
    Write-Output 'Canary baseline restored and verified.'
}
finally {
    $lock.Dispose()
}
