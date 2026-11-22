param(
    [string]$NdkHome = $env:ANDROID_NDK_HOME,
    [string]$Out = "build/binaries",
    [switch]$Install98260
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$tmp = Join-Path $root "build\tmp"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$env:TMP = $tmp; $env:TEMP = $tmp; $env:TMPDIR = $tmp
if (-not $NdkHome) { $NdkHome = Join-Path $root "ndk" }
$clang = Join-Path $NdkHome "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd"
if (-not (Test-Path $clang)) {
    $clang = Join-Path $NdkHome "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android31-clang.cmd"
}
if (-not (Test-Path $clang)) {
    throw "Android NDK clang not found under $NdkHome. Use NDK r28c (28.2.13676358) and pass -NdkHome."
}

# Actual released 98260 6.12 binaries: custom MagicRoot port with
# --no-real-cred, not the early upstream reference binary.  The source and
# exact expected SHA256s are in binary-sources/98260-6.12/.
$portScript = Join-Path $root "binary-sources\98260-6.12\build-98260-6.12.ps1"
if (-not (Test-Path $portScript)) { throw "missing $portScript" }
foreach ($kernel in @("61258", "6138")) {
    $args = @("-Kernel", $kernel, "-NdkHome", $NdkHome, "-Out", (Join-Path $Out "98260-6.12"))
    if ($Install98260) { $args += "-Install" }
    & powershell -NoProfile -ExecutionPolicy Bypass -File $portScript @args
    if ($LASTEXITCODE -ne 0) { throw "98260 $kernel build failed" }
}

# 64560 audit builds.  All available helper sources are included; the release
# APK keeps the previously validated 64560 binaries.
$legacy = @(
    @{ Name = "addrcalc"; Src = "binary-sources\64560\native\addrcalc.c" },
    @{ Name = "kaslr_slide_61258"; Src = "binary-sources\64560\native\kaslr_slide_61258.c" },
    @{ Name = "kaslr_slide_6138"; Src = "binary-sources\64560\native\kaslr_slide_6138.c" },
    @{ Name = "kaslr_slide_6123"; Src = "binary-sources\64560\native\kaslr_slide_6123.c" },
    @{ Name = "ko_patch"; Src = "binary-sources\64560\native\ko_patch.c"; Extra = "binary-sources\64560\native\throne_patch.c" },
    @{ Name = "ksu_grant"; Src = "binary-sources\64560\native\ksu_grant.c" },
    @{ Name = "forker"; Src = "binary-sources\64560\native\forker.c" },
    @{ Name = "wait_helper"; Src = "binary-sources\64560\native\wait_helper.c" },
    @{ Name = "t64560_v36"; Src = "binary-sources\64560\upstream-honeclick\t64560_v36.c" },
    @{ Name = "t64560_cred"; Src = "binary-sources\64560\upstream-honeclick\perf_cred_honor.c" },
    @{ Name = "cred_target"; Src = "binary-sources\64560\native\cred_target.c" }
)
$legacyDir = Join-Path $Out "64560-audit"
$legacyDir = Join-Path $root $legacyDir
New-Item -ItemType Directory -Force -Path $legacyDir | Out-Null
foreach ($target in $legacy) {
    $src = Join-Path $root $target.Src
    if (-not (Test-Path $src)) { Write-Warning "missing source: $($target.Src)"; continue }
    $binary = Join-Path $legacyDir $target.Name
    $sources = @($src)
    if ($target.Extra) { $sources += (Join-Path $root $target.Extra) }
    & $clang -std=gnu11 -O2 -pthread $sources -o $binary
    if ($LASTEXITCODE -eq 0) {
        $hash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Host "$hash  $($target.Name)  (64560 audit)"
    } else {
        Write-Warning "64560 audit build failed: $($target.Name)"
    }
}
Write-Host "NDK=$NdkHome"
Write-Host "BUILD_BINARIES_DONE"
