param(
    [string]$Serial = "",
    [string]$Adb = "",
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not $Adb) {
    $candidate = Get-Command adb.exe -ErrorAction SilentlyContinue
    if ($candidate) {
        $Adb = $candidate.Source
    } elseif (Test-Path "C:\Users\HourG\Downloads\mly-fw\sdk\platform-tools\adb.exe") {
        $Adb = "C:\Users\HourG\Downloads\mly-fw\sdk\platform-tools\adb.exe"
    } else {
        throw "adb.exe not found; pass -Adb <path>"
    }
}
if (-not $OutDir) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutDir = Join-Path $root "logs\adb-pull\$stamp"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Adb-Args {
    param([string[]]$Args)
    $all = @()
    if ($Serial) { $all += @("-s", $Serial) }
    $all += $Args
    & $Adb @all
}

$devices = @(Adb-Args @("devices"))
$devices | Set-Content (Join-Path $OutDir "adb-devices.txt") -Encoding utf8
if (-not ($devices -match "\sdevice$")) {
    throw "no authorized adb device"
}
Adb-Args @("shell", "getprop ro.product.model; getprop ro.build.version.release; uname -r") |
    Set-Content (Join-Path $OutDir "device.txt") -Encoding utf8

function Pull-RootFile {
    param([string]$Remote, [string]$Name)
    $local = Join-Path $OutDir $Name
    # Root-only /data/local/tmp files: read through su, not adb pull.
    $out = Adb-Args @("exec-out", "su", "-c", "cat '$Remote' 2>/dev/null")
    if ($LASTEXITCODE -eq 0 -and $out) {
        $out | Set-Content $local -Encoding utf8
        Write-Host "pulled $Remote -> $local ($($out.Count) lines)"
        return $true
    }
    # Fallback for a world-readable copy.
    Adb-Args @("pull", $Remote, $local) 2>$null | Out-Null
    if (Test-Path $local) {
        Write-Host "pulled $Remote -> $local"
        return $true
    }
    Write-Host "missing $Remote"
    return $false
}

$found = 0
foreach ($item in @(
    @("/data/local/tmp/magic/run.log", "last-run.log"),
    @("/data/local/tmp/magic/98260.log", "last-98260.log"),
    @("/data/local/tmp/magic/98260-su-entry.log", "last-su-entry.log"),
    @("/data/local/tmp/magic/run.log.exported", "last-run.exported.log")
)) {
    if (Pull-RootFile $item[0] $item[1]) { $found++ }
}

Write-Host ""
Write-Host "ADB log pull complete: $OutDir"
Write-Host "files=$found"
if ($found -eq 0) {
    Write-Host "No log found. Run the chain once, or check /data/local/tmp/magic/."
}
