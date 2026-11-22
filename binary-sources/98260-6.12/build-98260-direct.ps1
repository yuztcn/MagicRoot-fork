param(
    [ValidateSet('61258','61258b','61258c','6138','6123','6138y','g856','g142','aph112')]
    [string]$Kernel = '61258',
    [string]$NdkHome = $env:ANDROID_NDK_HOME,
    [string]$Out = "build/binaries/98260-6.12",
    [switch]$Install
)
$ErrorActionPreference = "Stop"
$dir = $PSScriptRoot
$root = (Resolve-Path (Join-Path $dir "..\..")).Path
if (-not $NdkHome) { $NdkHome = Join-Path $root "ndk" }
$tmp = Join-Path $root "build\tmp"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$env:TMP = $tmp; $env:TEMP = $tmp; $env:TMPDIR = $tmp
$cc = Join-Path $NdkHome "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd"
if (-not (Test-Path $cc)) { throw "NDK clang not found: $cc (use NDK r28c)" }
$outDir = Join-Path $root $Out
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$defs = @()
if ($Kernel -eq '61258b') { $defs += '-DPC98260_TARGET_61258B' }
if ($Kernel -eq '61258c') { $defs += '-DPC98260_TARGET_61258C' }
if ($Kernel -eq '6138') { $defs += '-DPC98260_TARGET_6138' }
if ($Kernel -eq '6123') { $defs += '-DPC98260_TARGET_6123' }
if ($Kernel -eq '6138y') { $defs += '-DPC98260_TARGET_6138Y' }
if ($Kernel -eq 'g856') { $defs += '-DPC98260_TARGET_G856' }
if ($Kernel -eq 'g142') { $defs += '-DPC98260_TARGET_G142' }
if ($Kernel -eq 'aph112') { $defs += '-DPC98260_TARGET_APH112' }
$bin = Join-Path $outDir "exploit-android-key-ptr-$Kernel"
$su = Join-Path $outDir "pc98260-su-$Kernel"
& $cc -std=gnu11 -O2 -w -pthread -static -I$dir @defs -o $bin `
    (Join-Path $dir "uaf_plant_61258.c") (Join-Path $dir "stubs.c") (Join-Path $dir "rootd.c")
if ($LASTEXITCODE -ne 0) { throw "build failed: $Kernel" }
& $cc -std=gnu11 -O2 -w -static -o $su (Join-Path $dir "su98260.c")
if ($LASTEXITCODE -ne 0) { throw "su build failed" }
$bh = (Get-FileHash -LiteralPath $bin -Algorithm SHA256).Hash.ToLowerInvariant()
$sh = (Get-FileHash -LiteralPath $su -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "$bh  exploit-android-key-ptr ($Kernel)"
Write-Host "$sh  pc98260-su ($Kernel)"
Write-Warning "This legacy static NDK recipe is not byte-identical to the shipped on-device dynamic-PIE payloads; install only for an intentional rebuild."
if ($Install) {
    $sub = "98260-$Kernel"
    if ($Kernel -eq '61258') { $sub = "98260" }
    $asset = Join-Path $root "main\app\assets\$sub"
    Copy-Item $bin (Join-Path $asset "exploit-android-key-ptr") -Force
    Copy-Item $su (Join-Path $asset "pc98260-su") -Force
    Write-Host "installed $Kernel into $asset"
}
