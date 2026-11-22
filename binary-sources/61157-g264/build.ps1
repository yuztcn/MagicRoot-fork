<#
  build.ps1 - build the exploit binaries for your device.

  Prerequisites:
    * exploit/offsets.h   (python tools/make-offsets.py --syms syms.txt)
    * a toolchain: zig 0.13+ (auto-detected) or an Android NDK (aarch64 clang)

  Usage:
    powershell -ExecutionPolicy Bypass -File exploit\build.ps1
    powershell -ExecutionPolicy Bypass -File exploit\build.ps1 -Zig C:\zig\zig.exe
#>
param(
  [string]$Zig = '',
  [string]$Ndk = '',
  [string]$Out = ''
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = Split-Path -Parent $here
if (-not $Out) { $Out = Join-Path $root 'bin' }
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Say($m) { Write-Host $m }

# ---- sanity: offsets ------------------------------------------------------
$off = Join-Path $here 'offsets.h'
if (-not (Test-Path $off)) {
  Say '[fail] exploit\offsets.h is missing.'
  Say '       python tools\make-offsets.py --syms <your syms.txt> --out exploit\offsets.h'
  Say '       see docs/08-porting.md'
  exit 2
}
$txt = Get-Content $off -Raw
foreach ($k in 'TIMER_LINK','CRED_LINK','SELINUX_LINK','LINK_USER_NS','LINK_ROOT_USER','LINK_GROUPS','LINK_UCOUNTS') {
  if ($txt -notmatch ("#define\s+" + $k + "\s+UINT64_C\(0x[0-9a-fA-F]+\)")) {
    Say ("[fail] offsets.h has no valid " + $k); exit 2
  }
}
Say '[ok] offsets.h present'

# ---- pick a compiler ------------------------------------------------------
$cc = $null
if ($Zig) {
  if (-not (Test-Path $Zig)) { Say "[fail] zig not found: $Zig"; exit 3 }
  $cc = @($Zig, 'cc', '-target', 'aarch64-linux-musl')
} else {
  $zig = Get-Command zig -ErrorAction SilentlyContinue
  if (-not $zig) {
    foreach ($c in @(
        (Join-Path $root 'zig\zig.exe'),
        (Join-Path (Split-Path -Parent $root) 'zig-windows-x86_64-0.13.0\zig.exe'))) {
      if (Test-Path $c) { $zig = Get-Item $c; break }
    }
  }
  if ($zig) { $cc = @($zig.Source, 'cc', '-target', 'aarch64-linux-musl') }
}

if (-not $cc) {
  foreach ($cand in @($Ndk,
      (Get-ChildItem "$env:LOCALAPPDATA\Android\Sdk\ndk" -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1).FullName)) {
    if (-not $cand) { continue }
    $clang = Get-ChildItem -Path $cand -Recurse -Filter 'aarch64-linux-android*-clang.cmd' -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if ($clang) { $cc = @($clang.FullName); break }
  }
}

if (-not $cc) {
  Say '[fail] no toolchain found.'
  Say '       install zig (https://ziglang.org/download/) and put zig.exe on PATH or in .\zig\zig.exe,'
  Say '       or install the Android NDK and pass -Ndk <ndk-dir>'
  exit 3
}
Say ('[ok] toolchain: ' + ($cc -join ' '))

$common = @('-O2','-std=gnu11','-D_GNU_SOURCE','-static','-fno-stack-protector',
            '-fno-pic','-no-pie','-I',$here)

function Build($name, [string[]]$srcs, [string[]]$extra) {
  $dst = Join-Path $Out $name
  $args = @()
  $args += $cc[1..($cc.Count-1)]
  $args += $common
  $args += $srcs
  $args += $extra
  $args += @('-o', $dst)
  Say ('[build] ' + $name)
  & $cc[0] @args
  if ($LASTEXITCODE -ne 0) { Say ("[fail] " + $name + " build failed"); exit 4 }
  $len = (Get-Item $dst).Length
  Say ('[ok] ' + $name + '  ' + $len + ' bytes')
}

Build 'brm_plant' @(
  (Join-Path $here 'uaf_plant.c'),
  (Join-Path $here 'pc98260_rootd.c')) @('-pthread')

Build 'pc98260_su' @((Join-Path $here 'pc98260_su.c')) @('-pthread')

Say ''
Say 'Next:'
Say '  ROOT.bat /finasu       (Windows, after adb is on PATH or in .\bin\)'
Say '  or push manually and run:  brm_plant --slide 0x<slide>'
