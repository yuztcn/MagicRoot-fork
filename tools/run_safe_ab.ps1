#requires -Version 5.1
<#
.SYNOPSIS
    Safe adb helper for the MagicRoot P0 safe-mode A/B experiment.

.DESCRIPTION
    Generates (and, only with -Execute, runs) a small set of *safe* adb
    commands for the P0 A/B protocol.  It never:
      * builds an adb shell command containing pipe '|', ';', '&', '<', '>',
        parentheses/command substitution or backticks;
      * builds an adb shell command containing reboot / shutdown / fastboot
        style words;
      * pushes to /system, /vendor or /data/adb;
      * taps the UI for you.  The app buttons (deploy / run) stay manual.

    Default is DRY-RUN: commands are printed and the device is not touched.
    Pass -Execute to actually run them.

    Modes:
      Prepare  create the flag files locally and adb push them to
               /data/local/tmp/magic, verify them, record the current boot_id
               in <Session>/.ab-state.json.  Run this AFTER tapping
               "2. deploy assets" in the app and BEFORE tapping "3. start".
      Status   read-only checks: boot completed, boot_id, getenforce,
               KernelSU module presence, flags, safe binaries, run.log tail.
      Pull     pull run.log (if it still exists) and ab-export logs into
               <Session>/<Label>-<Arm>/, then write run.meta.json with
               boot_id_before / boot_id_after / reboot_detected.

.PARAMETER Mode
    Prepare | Status | Pull.

.PARAMETER Arm
    safe-baseline (early-abort-ms = 0) or p0-early (early-abort-ms = 4500).

.PARAMETER Session
    Session directory, e.g.
    release/publish/experiments/p0-ab/sessions/p0-ab-20261025

.PARAMETER Label
    Run label, e.g. B01 / P01.  Auto-generated from existing run dirs when
    omitted (B01, P01, B02, ...).

.PARAMETER Adb
    adb executable path (default: adb from PATH).

.PARAMETER Serial
    Optional device serial (adb -s <serial>).

.PARAMETER EarlyAbortMs
    Content of early-abort-ms for the p0-early arm (default 4500).  The
    safe-baseline arm always writes 0.

.PARAMETER WallTimeSeconds
    Optional measured total run time to store in run.meta.json.

.PARAMETER Execute
    Actually run the generated commands.  Without it everything is dry-run.

.PARAMETER SelfTest
    Offline self-test of the command generator and the safety validator.

.EXAMPLE
    powershell -File release/tools/run_safe_ab.ps1 -Mode Prepare -Arm safe-baseline `
      -Session release/publish/experiments/p0-ab/sessions/p0-ab-20261025

.EXAMPLE
    powershell -File release/tools/run_safe_ab.ps1 -Mode Prepare -Arm p0-early `
      -Session release/publish/experiments/p0-ab/sessions/p0-ab-20261025 -Execute
#>
[CmdletBinding()]
param(
    [ValidateSet('Prepare', 'Status', 'Pull')]
    [string]$Mode = 'Status',

    [ValidateSet('safe-baseline', 'p0-early')]
    [string]$Arm = 'safe-baseline',

    [string]$Session = '',

    [string]$Label = '',

    [string]$Adb = 'adb',

    [string]$Serial = '',

    [int]$EarlyAbortMs = 4500,

    [double]$WallTimeSeconds = 0,

    [switch]$Execute,

    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:WorkDir = '/data/local/tmp/magic'
$script:ExportDir = '/sdcard/Download/MagicRoot-ab'
# Quotes are rejected as well: the helper never needs to emit quoted adb shell
# commands, and rejecting them prevents accidental nested-shell injection.
$script:ForbiddenShellPattern = '[|;&<>`$(){}"'']'
$script:ForbiddenShellWords = '\b(reboot|shutdown|bootloader|fastboot|halt|poweroff)\b|\bsh\s+-c\b'
$script:ForbiddenRemotePattern = '[|;&<>`$(){}"'']'

# ---------------------------------------------------------------------------
# safety validator
# ---------------------------------------------------------------------------

function Assert-SafeShellCommand {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) {
        throw 'refusing to build an empty adb shell command'
    }
    if ($Command -match "`r|`n") {
        throw "refusing adb shell command with a newline: '$Command'"
    }
    if ($Command -match $script:ForbiddenShellPattern) {
        throw "refusing adb shell command with shell metacharacter: '$Command'"
    }
    if ($Command -match $script:ForbiddenShellWords) {
        throw "refusing adb shell command with forbidden word: '$Command'"
    }
}

function Assert-SafeRemotePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'refusing an empty device path'
    }
    if ($Path -match $script:ForbiddenRemotePattern) {
        throw "refusing device path with shell metacharacter: '$Path'"
    }
}

# ---------------------------------------------------------------------------
# command object builders
# ---------------------------------------------------------------------------

function New-BaseAdbArgs {
    $list = New-Object System.Collections.ArrayList
    if ($Serial) {
        [void]$list.Add('-s')
        [void]$list.Add($Serial)
    }
    # Leading comma prevents PowerShell from unrolling the (possibly empty)
    # collection so the caller always receives the ArrayList itself.
    return ,$list
}

function New-ShellCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [bool]$AllowFailure = $false,
        [string]$CaptureKey = ''
    )
    Assert-SafeShellCommand $Command
    $list = New-BaseAdbArgs
    [void]$list.Add('shell')
    [void]$list.Add($Command)
    $display = 'adb'
    if ($Serial) { $display += " -s $Serial" }
    $display += " shell `"$Command`""
    return [pscustomobject]@{
        Kind         = 'shell'
        Args         = $list.ToArray()
        Display      = $display
        AllowFailure = $AllowFailure
        CaptureKey   = $CaptureKey
    }
}

function New-PushCommand {
    param(
        [Parameter(Mandatory = $true)][string]$LocalPath,
        [Parameter(Mandatory = $true)][string]$RemotePath
    )
    Assert-SafeRemotePath $RemotePath
    $list = New-BaseAdbArgs
    [void]$list.Add('push')
    [void]$list.Add($LocalPath)
    [void]$list.Add($RemotePath)
    $display = 'adb'
    if ($Serial) { $display += " -s $Serial" }
    $display += " push `"$LocalPath`" $RemotePath"
    return [pscustomobject]@{
        Kind         = 'host'
        Args         = $list.ToArray()
        Display      = $display
        AllowFailure = $false
        CaptureKey   = ''
    }
}

function New-PullCommand {
    param(
        [Parameter(Mandatory = $true)][string]$RemotePath,
        [Parameter(Mandatory = $true)][string]$LocalPath,
        [bool]$AllowFailure = $false
    )
    Assert-SafeRemotePath $RemotePath
    $list = New-BaseAdbArgs
    [void]$list.Add('pull')
    [void]$list.Add($RemotePath)
    [void]$list.Add($LocalPath)
    $display = 'adb'
    if ($Serial) { $display += " -s $Serial" }
    $display += " pull $RemotePath `"$LocalPath`""
    return [pscustomobject]@{
        Kind         = 'host'
        Args         = $list.ToArray()
        Display      = $display
        AllowFailure = $AllowFailure
        CaptureKey   = ''
    }
}

# ---------------------------------------------------------------------------
# local helpers
# ---------------------------------------------------------------------------

function Get-ArmEarlyMs {
    param([string]$ArmName, [int]$Requested)
    if ($ArmName -eq 'safe-baseline') { return 0 }
    if ($Requested -lt 1) { throw "-EarlyAbortMs must be >= 1 for the p0-early arm (got $Requested)" }
    if ($Requested -gt 60000) { throw "-EarlyAbortMs must be <= 60000 (got $Requested)" }
    return $Requested
}

function Get-NextRunLabel {
    param([string]$SessionDir, [string]$ArmName)
    $prefix = 'B'
    if ($ArmName -eq 'p0-early') { $prefix = 'P' }
    $max = 0
    if ($SessionDir -and (Test-Path -LiteralPath $SessionDir)) {
        $dirs = Get-ChildItem -LiteralPath $SessionDir -Directory -ErrorAction SilentlyContinue
        foreach ($dir in $dirs) {
            if ($dir.Name -match "^$prefix(\d+)-") {
                $num = [int]$Matches[1]
                if ($num -gt $max) { $max = $num }
            }
        }
    }
    return ('{0}{1:00}' -f $prefix, ($max + 1))
}

function Get-RunDirName {
    param([string]$LabelValue, [string]$ArmName)
    return ('{0}-{1}' -f $LabelValue, $ArmName)
}

function Get-FlagStageDir {
    return (Join-Path $env:TEMP 'magicroot-ab-flags')
}

function Write-DryRunBanner {
    param([object[]]$Commands)
    Write-Host ''
    Write-Host ('DRY-RUN: {0} command(s) below are NOT executed. Add -Execute to run them.' -f $Commands.Count)
    Write-Host ''
    $index = 0
    foreach ($cmd in $Commands) {
        $index++
        Write-Host ('  [{0}] {1}' -f $index, $cmd.Display)
    }
    Write-Host ''
}

function Invoke-GeneratedCommands {
    param([object[]]$Commands)
    $captures = @{}
    foreach ($cmd in $Commands) {
        Write-Host ('> ' + $cmd.Display)
        $adbArgs = $cmd.Args
        $output = ''
        $exitCode = 0
        try {
            $output = (& $Adb @adbArgs 2>&1 | Out-String).Trim()
            $exitCode = $LASTEXITCODE
        } catch {
            Write-Host ('  ERROR: ' + $_.Exception.Message)
            throw
        }
        if ($output.Length -gt 0) {
            foreach ($line in ($output -split "`r?`n")) {
                Write-Host ('    ' + $line)
            }
        }
        if ($cmd.CaptureKey) {
            $captures[$cmd.CaptureKey] = $output
        }
        if ($exitCode -ne 0 -and -not $cmd.AllowFailure) {
            throw ("command failed (exit $exitCode): " + $cmd.Display + "`n" + $output)
        }
        if ($exitCode -ne 0) {
            Write-Host ("    (exit $exitCode ignored: allowed failure)")
        }
    }
    return $captures
}

function Write-StateFile {
    param(
        [string]$SessionDir,
        [hashtable]$State
    )
    if (-not $SessionDir) { return }
    if (-not (Test-Path -LiteralPath $SessionDir)) {
        New-Item -ItemType Directory -Force -Path $SessionDir | Out-Null
    }
    $path = Join-Path $SessionDir '.ab-state.json'
    ($State | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $path -Encoding utf8
}

function Read-StateFile {
    param([string]$SessionDir)
    if (-not $SessionDir) { return $null }
    $path = Join-Path $SessionDir '.ab-state.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Write-FlagFiles {
    param(
        [string]$StageDir,
        [string]$ArmName,
        [int]$EarlyMs,
        [bool]$Create = $true
    )
    if ($Create -and -not (Test-Path -LiteralPath $StageDir)) {
        New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
    }
    $earlyValue = [string](Get-ArmEarlyMs -ArmName $ArmName -Requested $EarlyMs)
    if ($Create) {
        Set-Content -LiteralPath (Join-Path $StageDir 'safe-mode') -Value '1' -NoNewline -Encoding ascii
        Set-Content -LiteralPath (Join-Path $StageDir 'early-abort-ms') -Value $earlyValue -NoNewline -Encoding ascii
        Set-Content -LiteralPath (Join-Path $StageDir 'ab-export') -Value '1' -NoNewline -Encoding ascii
    }
    return [pscustomobject]@{
        SafeMode   = Join-Path $StageDir 'safe-mode'
        EarlyAbort = Join-Path $StageDir 'early-abort-ms'
        AbExport   = Join-Path $StageDir 'ab-export'
        EarlyValue = $earlyValue
    }
}

# ---------------------------------------------------------------------------
# command-list builders
# ---------------------------------------------------------------------------

function Get-PrepareCommands {
    param([object]$Flags)
    $commands = New-Object System.Collections.ArrayList
    [void]$commands.Add((New-ShellCommand -Command ("mkdir -p " + $script:WorkDir)))
    # Clear stale ab-export files from previous runs; run.sh recreates the dir
    # on the next successful DONE.  Pull the previous run before calling this.
    [void]$commands.Add((New-ShellCommand -Command ('rm -rf ' + $script:ExportDir)))
    [void]$commands.Add((New-ShellCommand -Command (
        'rm -f {0}/safe-mode {0}/early-abort-ms {0}/ab-export' -f $script:WorkDir)))
    [void]$commands.Add((New-PushCommand -LocalPath $Flags.SafeMode -RemotePath ($script:WorkDir + '/safe-mode')))
    [void]$commands.Add((New-PushCommand -LocalPath $Flags.EarlyAbort -RemotePath ($script:WorkDir + '/early-abort-ms')))
    [void]$commands.Add((New-PushCommand -LocalPath $Flags.AbExport -RemotePath ($script:WorkDir + '/ab-export')))
    [void]$commands.Add((New-ShellCommand -Command ('ls -l {0}/safe-mode {0}/early-abort-ms {0}/ab-export' -f $script:WorkDir)))
    [void]$commands.Add((New-ShellCommand -Command ('cat {0}/early-abort-ms' -f $script:WorkDir)))
    [void]$commands.Add((New-ShellCommand -Command 'getprop sys.boot_completed'))
    [void]$commands.Add((New-ShellCommand -Command 'cat /proc/sys/kernel/random/boot_id' -CaptureKey 'boot_id'))
    [void]$commands.Add((New-ShellCommand -Command 'getenforce'))
    [void]$commands.Add((New-ShellCommand -Command 'grep kernelsu /proc/modules' -AllowFailure $true -CaptureKey 'modules'))
    [void]$commands.Add((New-ShellCommand -Command ('ls -l {0}/t64560_v36_safe {0}/t64560_cred_safe' -f $script:WorkDir) -AllowFailure $true -CaptureKey 'safe_bins'))
    return $commands.ToArray()
}

function Get-PullDryRunCommands {
    param([string]$RunDir)
    $commands = New-Object System.Collections.ArrayList
    [void]$commands.Add((New-ShellCommand -Command 'getprop sys.boot_completed'))
    [void]$commands.Add((New-ShellCommand -Command 'cat /proc/sys/kernel/random/boot_id' -CaptureKey 'boot_id'))
    [void]$commands.Add((New-ShellCommand -Command ('ls -l {0}/run.log' -f $script:WorkDir) -AllowFailure $true -CaptureKey 'work_log'))
    [void]$commands.Add((New-PullCommand -RemotePath ($script:WorkDir + '/run.log') -LocalPath (Join-Path $RunDir 'run.log') -AllowFailure $true))
    [void]$commands.Add((New-ShellCommand -Command ('ls -l {0}' -f $script:ExportDir) -AllowFailure $true -CaptureKey 'exports'))
    [void]$commands.Add([pscustomobject]@{
        Kind         = 'note'
        Args         = @()
        Display      = ('adb pull {0}/run-<epoch>-<pid>.log "{1}\ab-export-run-<epoch>-<pid>.log"  # repeat per export file' -f $script:ExportDir, $RunDir)
        AllowFailure = $true
        CaptureKey   = ''
    })
    return $commands.ToArray()
}

function Get-StatusCommands {
    $commands = New-Object System.Collections.ArrayList
    [void]$commands.Add((New-ShellCommand -Command 'getprop sys.boot_completed'))
    [void]$commands.Add((New-ShellCommand -Command 'cat /proc/sys/kernel/random/boot_id' -CaptureKey 'boot_id'))
    [void]$commands.Add((New-ShellCommand -Command 'getenforce'))
    [void]$commands.Add((New-ShellCommand -Command 'grep kernelsu /proc/modules' -AllowFailure $true -CaptureKey 'modules'))
    [void]$commands.Add((New-ShellCommand -Command 'pm path com.aoki.magicroot' -AllowFailure $true))
    [void]$commands.Add((New-ShellCommand -Command (
        'ls -l {0}/safe-mode {0}/early-abort-ms {0}/ab-export' -f $script:WorkDir) -AllowFailure $true -CaptureKey 'flags'))
    [void]$commands.Add((New-ShellCommand -Command ('cat {0}/early-abort-ms' -f $script:WorkDir) -AllowFailure $true -CaptureKey 'early'))
    [void]$commands.Add((New-ShellCommand -Command (
        'ls -l {0}/t64560_v36_safe {0}/t64560_cred_safe' -f $script:WorkDir) -AllowFailure $true -CaptureKey 'safe_bins'))
    [void]$commands.Add((New-ShellCommand -Command ('ls -l {0}/run.log' -f $script:WorkDir) -AllowFailure $true -CaptureKey 'work_log'))
    [void]$commands.Add((New-ShellCommand -Command ('tail -n 5 {0}/run.log' -f $script:WorkDir) -AllowFailure $true))
    [void]$commands.Add((New-ShellCommand -Command ('ls -l {0}' -f $script:ExportDir) -AllowFailure $true -CaptureKey 'exports'))
    return $commands.ToArray()
}

# ---------------------------------------------------------------------------
# mode implementations
# ---------------------------------------------------------------------------

function Invoke-Prepare {
    if (-not $Session) {
        throw '-Session is required for -Mode Prepare (e.g. release/publish/experiments/p0-ab/sessions/p0-ab-20261025)'
    }
    $earlyMs = Get-ArmEarlyMs -ArmName $Arm -Requested $EarlyAbortMs
    $labelValue = $Label
    if (-not $labelValue) { $labelValue = Get-NextRunLabel -SessionDir $Session -ArmName $Arm }
    $runDirName = Get-RunDirName -LabelValue $labelValue -ArmName $Arm
    $flagDir = Get-FlagStageDir
    $flags = Write-FlagFiles -StageDir $flagDir -ArmName $Arm -EarlyMs $EarlyAbortMs -Create ([bool]$Execute)
    $commands = Get-PrepareCommands -Flags $flags

    Write-Host ('Arm: {0}  early-abort-ms={1}  label={2}  session={3}' -f $Arm, $flags.EarlyValue, $labelValue, $Session)
    Write-Host 'Note: tap "2. deploy assets" in the app BEFORE this step, then tap "3. start" AFTER it.'
    Write-Host 'Note: Prepare clears /sdcard/Download/MagicRoot-ab; make sure the previous run was pulled first.'
    if (-not $Execute) {
        Write-DryRunBanner -Commands $commands
        Write-Host ('Would write session state: {0}' -f (Join-Path $Session '.ab-state.json'))
        return 0
    }

    $captures = Invoke-GeneratedCommands -Commands $commands
    $bootId = ''
    if ($captures.ContainsKey('boot_id')) { $bootId = ($captures['boot_id'] -split "`r?`n")[0].Trim() }
    $bootDone = ''
    # boot_completed is the first command output; read it again explicitly is cheap but already printed above.
    if ($captures.ContainsKey('boot_completed')) { $bootDone = $captures['boot_completed'] }
    Write-Host ''
    Write-Host ('boot_id_before = {0}' -f $bootId)
    if ($captures.ContainsKey('modules') -and ($captures['modules'] -match 'kernelsu')) {
        Write-Warning 'kernelsu is already Live in this boot: reject this boot and restart the device before running.'
    }
    if ($captures.ContainsKey('safe_bins') -and ($captures['safe_bins'] -notmatch 't64560_v36_safe')) {
        Write-Warning 'safe assets not found in /data/local/tmp/magic: tap "2. deploy assets" and verify before running.'
    }
    $state = @{
        mode             = 'Prepare'
        arm              = $Arm
        label            = $labelValue
        run_dir          = $runDirName
        early_abort_ms   = [int]$flags.EarlyValue
        boot_id          = $bootId
        prepared_at      = (Get-Date).ToString('o')
    }
    Write-StateFile -SessionDir $Session -State $state
    Write-Host ''
    Write-Host ('State saved: ' + (Join-Path $Session '.ab-state.json'))
    Write-Host 'Next: tap "3. start" in the app, wait for DONE/FAIL/reboot, then run:'
    Write-Host ('  powershell -File release/tools/run_safe_ab.ps1 -Mode Pull -Arm {0} -Session "{1}" -Label {2} -Execute' -f $Arm, $Session, $labelValue)
    return 0
}

function Invoke-Status {
    $commands = Get-StatusCommands
    if (-not $Execute) {
        Write-DryRunBanner -Commands $commands
        return 0
    }
    $captures = Invoke-GeneratedCommands -Commands $commands
    Write-Host ''
    Write-Host 'Status summary:'
    if ($captures.ContainsKey('boot_id')) {
        Write-Host ('  boot_id      : ' + (($captures['boot_id'] -split "`r?`n")[0].Trim()))
    }
    if ($captures.ContainsKey('early')) {
        Write-Host ('  early-abort  : ' + (($captures['early'] -split "`r?`n")[0].Trim()))
    }
    if ($captures.ContainsKey('modules')) {
        $mods = $captures['modules']
        if ($mods -match 'kernelsu') {
            Write-Warning 'kernelsu is Live in the current boot: cold-boot before the next A/B run.'
        } else {
            Write-Host '  kernelsu     : not live (clean cold boot)'
        }
    }
    if ($captures.ContainsKey('safe_bins') -and ($captures['safe_bins'] -match 't64560_v36_safe')) {
        Write-Host '  safe assets  : present'
    } else {
        Write-Warning 'safe assets not found under /data/local/tmp/magic (deploy assets first).'
    }
    if ($captures.ContainsKey('exports') -and ($captures['exports'] -match 'run-')) {
        Write-Host '  ab-export    : exported log(s) found (Pull them before the next run)'
    }
    return 0
}

function Invoke-Pull {
    if (-not $Session) {
        throw '-Session is required for -Mode Pull'
    }
    $state = Read-StateFile -SessionDir $Session
    $labelValue = $Label
    if (-not $labelValue -and $state -and $state.label) { $labelValue = [string]$state.label }
    if (-not $labelValue) { $labelValue = Get-NextRunLabel -SessionDir $Session -ArmName $Arm }
    $runDirName = Get-RunDirName -LabelValue $labelValue -ArmName $Arm
    $runDir = Join-Path $Session $runDirName

    if (-not $Execute) {
        Write-Host ('Would create run dir: {0}' -f $runDir)
        $commands = Get-PullDryRunCommands -RunDir $runDir
        Write-DryRunBanner -Commands $commands
        Write-Host ('Would then write: {0}' -f (Join-Path $runDir 'run.meta.json'))
        return 0
    }

    if (-not (Test-Path -LiteralPath $runDir)) {
        New-Item -ItemType Directory -Force -Path $runDir | Out-Null
    }
    $commands = New-Object System.Collections.ArrayList
    [void]$commands.Add((New-ShellCommand -Command 'getprop sys.boot_completed'))
    [void]$commands.Add((New-ShellCommand -Command 'cat /proc/sys/kernel/random/boot_id' -CaptureKey 'boot_id'))
    [void]$commands.Add((New-ShellCommand -Command ('ls -l {0}/run.log' -f $script:WorkDir) -AllowFailure $true -CaptureKey 'work_log'))
    [void]$commands.Add((New-ShellCommand -Command ('ls -l {0}' -f $script:ExportDir) -AllowFailure $true -CaptureKey 'exports'))

    $captures = Invoke-GeneratedCommands -Commands $commands
    $bootIdAfter = ''
    if ($captures.ContainsKey('boot_id')) { $bootIdAfter = ($captures['boot_id'] -split "`r?`n")[0].Trim() }
    $sources = New-Object System.Collections.ArrayList

    $hasWorkLog = $false
    if ($captures.ContainsKey('work_log')) {
        $workOut = $captures['work_log']
        if ($workOut -match 'run\.log') { $hasWorkLog = $true }
    }
    if ($hasWorkLog) {
        $pullCmd = New-PullCommand -RemotePath ($script:WorkDir + '/run.log') -LocalPath (Join-Path $runDir 'run.log')
        $null = Invoke-GeneratedCommands -Commands @($pullCmd)
        [void]$sources.Add('run.log')
    }

    $exportFiles = @()
    if ($captures.ContainsKey('exports')) {
        foreach ($line in ($captures['exports'] -split "`r?`n")) {
            if ($line -match '(/sdcard/Download/MagicRoot-ab/[^\s]+\.log)\s*$') {
                $exportFiles += $Matches[1]
            }
        }
    }
    foreach ($remote in $exportFiles) {
        $baseName = ($remote -split '/')[-1]
        $localName = 'ab-export-' + $baseName
        $pullCmd = New-PullCommand -RemotePath $remote -LocalPath (Join-Path $runDir $localName) -AllowFailure $true
        $null = Invoke-GeneratedCommands -Commands @($pullCmd)
        [void]$sources.Add($localName)
    }

    if ($sources.Count -eq 0) {
        Write-Warning 'no run.log and no ab-export log found: nothing to pull. The run may have been cleaned already.'
        return 1
    }

    $bootIdBefore = ''
    if ($state -and $state.boot_id) { $bootIdBefore = [string]$state.boot_id }
    $rebootDetected = $false
    if ($bootIdBefore -and $bootIdAfter -and ($bootIdBefore -ne $bootIdAfter)) {
        $rebootDetected = $true
    }
    $meta = [ordered]@{
        label            = $labelValue
        arm              = $Arm
        boot_id_before   = $bootIdBefore
        boot_id_after    = $bootIdAfter
        reboot_detected  = $rebootDetected
        sources          = @($sources)
        pulled_at        = (Get-Date).ToString('o')
    }
    if ($WallTimeSeconds -gt 0) { $meta['wall_time_seconds'] = $WallTimeSeconds }
    if ($state -and $state.prepared_at) { $meta['prepared_at'] = [string]$state.prepared_at }
    $metaPath = Join-Path $runDir 'run.meta.json'
    ($meta | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $metaPath -Encoding utf8

    Write-Host ''
    Write-Host ('Pulled {0} source(s) into {1}' -f $sources.Count, $runDir)
    Write-Host ('Wrote {0}' -f $metaPath)
    if ($rebootDetected) {
        Write-Warning 'boot_id changed: mark this run as REBOOT and exclude it from acceptance.'
    }
    Write-Host 'Next: fill/check the session manifest, then run parse_safe_ab.py on the session directory.'
    return 0
}

# ---------------------------------------------------------------------------
# offline self-test
# ---------------------------------------------------------------------------

function Invoke-SelfTest {
    $failures = New-Object System.Collections.ArrayList
    $stage = Join-Path $env:TEMP 'magicroot-ab-selftest'
    foreach ($armName in @('safe-baseline', 'p0-early')) {
        $flags = Write-FlagFiles -StageDir $stage -ArmName $armName -EarlyMs 4500
        $expected = if ($armName -eq 'safe-baseline') { '0' } else { '4500' }
        if ($flags.EarlyValue -ne $expected) {
            [void]$failures.Add("arm $armName produced early-abort value $($flags.EarlyValue), expected $expected")
        }
        $commands = Get-PrepareCommands -Flags $flags
        foreach ($cmd in $commands) {
            if ($cmd.Kind -eq 'shell') {
                try { Assert-SafeShellCommand ($cmd.Args[-1]) } catch { [void]$failures.Add($_.Exception.Message) }
            }
        }
        if ($commands.Count -lt 8) { [void]$failures.Add("prepare command list too short for $armName") }
    }
    $statusCommands = Get-StatusCommands
    foreach ($cmd in $statusCommands) {
        if ($cmd.Kind -eq 'shell') {
            try { Assert-SafeShellCommand ($cmd.Args[-1]) } catch { [void]$failures.Add($_.Exception.Message) }
        }
    }
    $pullCommands = Get-PullDryRunCommands -RunDir 'run-dir'
    foreach ($cmd in $pullCommands) {
        if ($cmd.Kind -eq 'shell') {
            try { Assert-SafeShellCommand ($cmd.Args[-1]) } catch { [void]$failures.Add($_.Exception.Message) }
        }
    }
    # negative tests: dangerous strings must be rejected
    $bad = @(
        'echo 1 > /data/local/tmp/magic/safe-mode',
        'cat /proc/modules | grep kernelsu',
        'grep kernelsu /proc/modules; id',
        'reboot',
        'sh -c "id"',
        'ls /data/local/tmp/magic && id'
    )
    foreach ($candidate in $bad) {
        $rejected = $false
        try { Assert-SafeShellCommand $candidate } catch { $rejected = $true }
        if (-not $rejected) { [void]$failures.Add("dangerous command was NOT rejected: $candidate") }
    }
    if ($failures.Count -gt 0) {
        Write-Host 'SELFTEST FAILED:'
        foreach ($f in $failures) { Write-Host ('  - ' + $f) }
        return 1
    }
    Write-Host ('SELFTEST PASSED: prepare/status/pull generators are shell-safe (no pipe/semicolon/reboot).')
    return 0
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

try {
    if ($SelfTest) {
        exit (Invoke-SelfTest)
    }
    switch ($Mode) {
        'Prepare' { exit (Invoke-Prepare) }
        'Status'  { exit (Invoke-Status) }
        'Pull'    { exit (Invoke-Pull) }
        default   { throw "unknown mode: $Mode" }
    }
} catch {
    Write-Host ('ERROR: ' + $_.Exception.Message)
    if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace }
    exit 1
}
