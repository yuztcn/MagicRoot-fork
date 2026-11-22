param(
    [Parameter(Mandatory = $true)][string]$NdkBin,
    [string]$Project = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
$strip = Join-Path $NdkBin "llvm-strip.exe"
if (-not (Test-Path $strip)) { throw "llvm-strip not found: $strip" }

$roots = @(
    (Join-Path $Project "main\app\assets"),
    (Join-Path $Project "main\compose-app\app\src\main\jniLibs\arm64-v8a")
) | Where-Object { Test-Path $_ }

$saved = 0
foreach ($root in $roots) {
    Get-ChildItem $root -Recurse -File | ForEach-Object {
        $name = $_.Name
        if ($name -match '\.ko$' -or $name -match '^libandroidx\.') { return }
        $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
        if ($bytes.Length -lt 4 -or $bytes[0] -ne 0x7f -or $bytes[1] -ne 0x45 -or
            $bytes[2] -ne 0x4c -or $bytes[3] -ne 0x46) { return }
        $before = $_.Length
        & $strip --strip-all $_.FullName
        if ($LASTEXITCODE -ne 0) { throw "strip failed: $($_.FullName)" }
        $after = (Get-Item $_.FullName).Length
        if ($after -lt $before) {
            $delta = $before - $after
            $saved += $delta
            Write-Host ("STRIP {0,-32} {1,10} -> {2,10}  -{3}" -f $name, $before, $after, $delta)
        }
    }
}
Write-Host "TOTAL_SAVED=$saved"
