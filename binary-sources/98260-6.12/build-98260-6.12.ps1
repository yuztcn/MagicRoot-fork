param(
    [ValidateSet('61258','61258b','61258c','6138','6123','6138y','g856','g142','aph112','g52d15')]
    [string]$Kernel = '61258',
    [string]$NdkHome = $env:ANDROID_NDK_HOME,
    [string]$Out = "build/binaries/98260-6.12",
    [switch]$Install,
    [switch]$VerifyRecordedHash
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
if ($Kernel -eq '61258c') { $defs += '-DPC98260_TARGET_61258C'; $defs += '-s' }
if ($Kernel -eq '6138') { $defs += '-DPC98260_TARGET_6138' }
if ($Kernel -eq '6123') { $defs += '-DPC98260_TARGET_6123' }
if ($Kernel -eq '6138y') { $defs += '-DPC98260_TARGET_6138Y' }
if ($Kernel -eq 'g856') { $defs += '-DPC98260_TARGET_G856' }
if ($Kernel -eq 'g142') { $defs += '-DPC98260_TARGET_G142' }
if ($Kernel -eq 'aph112') { $defs += '-DPC98260_TARGET_APH112' }
if ($Kernel -eq 'g52d15') { $defs += '-DPC98260_TARGET_G52D15' }
$bin = Join-Path $outDir "exploit-android-key-ptr-$Kernel"
$su = Join-Path $outDir "pc98260-su-$Kernel"
# Shipped payloads are dynamic bionic PIE (built on-device; Termux/NDK has no
# static bionic libc).  Do not re-add -static: it changes the binary shape and
# invalidates the hash gate below.
& $cc -std=gnu11 -O2 -w -pthread -I$dir @defs -o $bin `
    (Join-Path $dir "uaf_plant_61258.c") (Join-Path $dir "stubs.c") (Join-Path $dir "rootd.c")
if ($LASTEXITCODE -ne 0) { throw "build failed: $Kernel" }
& $cc -std=gnu11 -O2 -w -static -o $su (Join-Path $dir "su98260.c")
if ($LASTEXITCODE -ne 0) { throw "su build failed" }
$suHash = '8838ab17e38252492df3761b74126855bde8a77ed5ab02255b67ebef81376ab1'
$expect = @{
    # Current shipped hashes after the 2026-11-11 hard-hit reclaim rebuild
    # (order>=1 whole-slab proof + pre-faulted trace scan buffer + O_SYNC log + exec gate/exec-ok reap).
    # 2026-11-13: all nine 6.12 profiles were rebuilt on-device with the
    # trace-tail fix (tracefs rejects SEEK_END; stream to EOF and keep the
    # newest cap), the raw event-id self-calibration, the one-scan-per-churn
    # round change and the watcher hold-only fix.  g142's trace/raw paths were
    # validated on-device as shell; the other profiles are compile-verified
    # with their own target headers, not yet run on their kernels.
    # They come from the recorded on-device Termux clang 21.1.8 dynamic-PIE
    # recipe.  The Windows NDK compiler is not byte-identical, so hash mismatch
    # is fatal only with -VerifyRecordedHash on that exact toolchain.
    '61258'  = @('0fd3ff76cce3288252a2cf6f8ad64463f21542ab29f007fcdfda1dd36a0c0b4d',$suHash)
    '61258b' = @('5c76d21c012c000241c4716563da13b323a015d5b0f93902f717eba42b7ac10b',$suHash)
    '61258c' = @('f203ce9e58323e44155354e945e480bcec4267e3f9ec57f4f68611814a13513e',$suHash)
    '6138'   = @('6c7126208ab4e139df3614519160da17dff8f5265d4c1d3177fab8442c3eda7a',$suHash)
    '6123'   = @('fecaa9c7c58b5b0da03c90c3c3a3af5232504967d685fda4528179249ba2d29c',$suHash)
    '6138y'  = @('0f7c58b031e6e2bce059febe445576ef4a06b99ec380a9e2f5805901f3a867f0',$suHash)
    'g856'   = @('38444791c48c63a8e09343d893d20a934c9daa3caaa38c1415db583f2f906c79',$suHash)
    'g142'   = @('36dc9e61224ae3dce3961a607949af5f114368507c2bb5d2a361f50810b39523',$suHash)
    'aph112' = @('5c76d21c012c000241c4716563da13b323a015d5b0f93902f717eba42b7ac10b',$suHash)
    # g52d15 (6.12.81): built on-device with Termux clang 21.1.8 dynamic-PIE
    # recipe on 2026-11-20; see docs/6.12.81-G52D15-ADAPT.md.
    'g52d15' = @('f69df321ecde8504da9fc0710ddfe79ce8f00512548e77e774fb3c01ac48096f',$suHash)
}
$bh = (Get-FileHash -LiteralPath $bin -Algorithm SHA256).Hash.ToLowerInvariant()
$sh = (Get-FileHash -LiteralPath $su -Algorithm SHA256).Hash.ToLowerInvariant()
$binaryMatches = $bh -eq $expect[$Kernel][0]
$suMatches = $sh -eq $expect[$Kernel][1]
if ($VerifyRecordedHash -and -not $binaryMatches) { throw "binary hash mismatch: $bh" }
if ($VerifyRecordedHash -and -not $suMatches) { throw "su hash mismatch: $sh" }
Write-Host "$bh  exploit-android-key-ptr ($Kernel) recorded_match=$binaryMatches"
Write-Host "$sh  pc98260-su ($Kernel) recorded_match=$suMatches"
if (-not $VerifyRecordedHash -and (-not $binaryMatches -or -not $suMatches)) {
    Write-Warning "NDK output differs from the recorded on-device hash; use -VerifyRecordedHash only with the recorded Termux clang 21.1.8 recipe."
}
if ($Install) {
    $sub = if ($Kernel -eq '6138') { "98260-6138" } elseif ($Kernel -eq '61258b') { "98260-61258b" } elseif ($Kernel -eq '61258c') { "98260-61258c" } elseif ($Kernel -eq '6123') { "98260-6123" } elseif ($Kernel -eq '6138y') { "98260-6138y" } elseif ($Kernel -eq 'g856') { "98260-g856" } elseif ($Kernel -eq 'g142') { "98260-g142" } elseif ($Kernel -eq 'aph112') { "98260-aph112" } elseif ($Kernel -eq 'g52d15') { "98260-g52d15" } else { "98260" }
    $asset = Join-Path $root "main\app\assets\$sub"
    Copy-Item $bin (Join-Path $asset "exploit-android-key-ptr") -Force
    Copy-Item $su (Join-Path $asset "pc98260-su") -Force
    Write-Host "installed $Kernel into $asset"
}
