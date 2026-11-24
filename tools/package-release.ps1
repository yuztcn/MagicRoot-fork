param(
    [string]$Project = (Split-Path -Parent $PSScriptRoot),
    [string]$Release = $null
)
$ErrorActionPreference = "Stop"
$project = (Resolve-Path $Project).Path.TrimEnd('\')
if (-not $Release) { $Release = Join-Path $project "release-1.0.6" }
New-Item -ItemType Directory -Force -Path $Release | Out-Null

$apk = Join-Path $project "MagicRoot-1.0.6.apk"
$legacy = Join-Path $project "MagicRoot-legacy-1.0.6.apk"
if (-not (Test-Path $apk)) { throw "missing APK: $apk" }
if (-not (Test-Path $legacy)) { throw "missing Legacy APK: $legacy" }

$files = @()
$files += Get-ChildItem (Join-Path $project "main") -Recurse -File | Where-Object {
    $_.FullName -notmatch '\\build\\|\\\.gradle\\|\\\.gradle-home\\|\\local\.properties$' -and
    $_.Name -notmatch '^(MagicRoot\.apk|local\.properties)$' -and
    $_.Extension -notmatch '^\.(apk|keystore|jks)$'
}
foreach ($tree in @("binary-sources")) {
    $p = Join-Path $project $tree
    if (Test-Path $p) { $files += Get-ChildItem $p -Recurse -File }
}
foreach ($name in @("LICENSE", "NOTICE.md", "LICENSES", "THIRD_PARTY_NOTICES.md", "build-binaries.ps1",
                    "BINARY-SOURCES.md", "README-1.0.6-release.md", "SOURCE-MANIFEST.txt",
                    "docs/ADAPT-ROOTD-STP-REPRO.md",
                    "docs/susfs-honor-adaptation-2026-10-29.md",
                    "docs/spacegate-3.3-analysis.md",
                    "tools/package-release.ps1", "tools/check_susfs_guard.py",
                    "tools/build-susfs-honor.sh")) {
    $p = Join-Path $project $name
    if (Test-Path $p) {
        if ((Get-Item $p).PSIsContainer) { $files += Get-ChildItem $p -Recurse -File }
        else { $files += Get-Item $p }
    }
}
$adapt = Join-Path $project "docs\adaptation"
if (Test-Path $adapt) { $files += Get-ChildItem $adapt -Recurse -File }

$files = $files | Sort-Object -Property FullName -Unique

$stage = Join-Path $Release ".source-stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null
foreach ($f in $files) {
    $rel = $f.FullName.Substring($project.Length).TrimStart('\')
    if ($rel -match '(^|\\)(build|\.gradle|\.gradle-home)(\\|$)') { continue }
    if ($rel -match '(^|\\)local\.properties$') { continue }
    if ($rel -match '\.(apk|keystore|jks)$') { continue }
    $dest = Join-Path $stage $rel
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
    Copy-Item $f.FullName $dest -Force
}
$out = Join-Path $Release "MagicRoot-1.0.6-source.zip"
if (Test-Path $out) { Remove-Item $out -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $out -CompressionLevel Optimal
Remove-Item $stage -Recurse -Force
Write-Host "source zip: $out ($((Get-Item $out).Length) bytes)"

