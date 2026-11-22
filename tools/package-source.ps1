param(
    [string]$Project = (Split-Path -Parent $PSScriptRoot),
    [string]$Output = "C:\Users\HourG\Downloads\MagicRoot\MagicRoot-1.0.6-source.zip"
)
$ErrorActionPreference = "Stop"
$project = (Resolve-Path $Project).Path.TrimEnd('\')
$stage = Join-Path $env:TEMP ("magicroot-source-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $stage | Out-Null

$excludedDirs = @(
    '.git', '.gradle', '.gradle-home', '.idea', 'build', '__pycache__',
    'work', '.dsh', 'tmp'
)
$excludedExts = @('.apk', '.idsig', '.keystore', '.jks', '.zip', '.log')
$excludedNames = @('local.properties')

$roots = @('main', 'binary-sources', 'tools', 'docs', 'LICENSES')
$files = New-Object System.Collections.Generic.List[System.IO.FileInfo]
foreach ($root in $roots) {
    $p = Join-Path $project $root
    if (-not (Test-Path $p)) { continue }
    Get-ChildItem $p -Recurse -File | ForEach-Object { $files.Add($_) }
}
Get-ChildItem $project -File | ForEach-Object { $files.Add($_) }

$selected = @()
foreach ($f in ($files | Sort-Object FullName -Unique)) {
    $rel = $f.FullName.Substring($project.Length).TrimStart('\')
    $parts = $rel -split '\\'
    if ($parts | Where-Object { $excludedDirs -contains $_ }) { continue }
    if ($excludedExts -contains $f.Extension.ToLowerInvariant()) { continue }
    if ($excludedNames -contains $f.Name) { continue }
    if ($f.Name -like 'MagicRoot-*.apk') { continue }
    $selected += $f
}

foreach ($f in $selected) {
    $rel = $f.FullName.Substring($project.Length).TrimStart('\')
    $dest = Join-Path $stage $rel
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
    Copy-Item $f.FullName $dest -Force
}

$required = @(
    'main\compose-app\app\src\main\java\com\aoki\magicroot\MainActivity.java',
    'main\compose-app\app\src\main\java\com\aoki\magicroot\RunProgress.java',
    'main\compose-app\app\src\main\java\com\aoki\magicroot\KernelLogHelper.java',
    'main\compose-app\app\src\main\java\com\aoki\magicroot\LiveLogStore.java',
    'tools\tests\LiveLogStoreTest.java',
    'docs\ONEKEYJB-REFERENCE.md',
    'docs\ONEKEYJB-PRECISE-HIT.md',
    'tools\check.sh',
    'main\app\assets\98260-61821-117\target.sh',
    'main\app\assets\98260-61821-117\syms_117.txt',
    'main\app\assets\98260-61821-117\ksu-template-117-kernelsu.ko',
    'main\app\assets\98260-61821-117\ksu-template-117-bakasu.ko',
    'main\app\assets\98260-61821-117\ksu-template-117-fina.ko',
    'main\app\assets\98260-61821-117\ksu-template-117-next.ko',
    'main\app\assets\98260-61821-117\ksu-template-117-sukisu.ko',
    'tools\gen_6157_integrity.py',
    'main\app\assets\6157-integrity.tsv',
    'tools\kernel_profiles.json',
    'tools\asset_dedup_map.json',
    'tools\test_kaslr_g142.py',
    'tools\test_98260_finalize.py',
    'tools\test_98260_uaf_lifecycle.py',
    'tools\test_cleanup_contract.py',
    'tools\patch_sukisu_lateload.py',
    'tools\ExportKernelKallsyms.java',
    'tools\test_termux_su_entry.py',
    'tools\tests\RunProgressTest.java',
    'tools\tests\KernelLogHelperTest.java',
    'main\app\assets\98260-g142\exploit-android-key-ptr',
    'main\app\assets\98260-g142\pc98260-su',
    'main\app\assets\98260-g142\SHA256SUMS.txt',
    'main\app\assets\98260-g142\syms_g142_nova.txt',
    'docs\SUKISU-NOVA-SUPPORT.md',
    'main\app\assets\kaslr_slide_aph136g142',
    'main\app\assets\kaslr-98937\poc98937',
    'main\app\assets\kaslr-98937\slide98937',
    'main\app\assets\kaslr-98937\slide98937.c',
    'main\app\assets\kaslr-98937\run98937.sh',
    'main\app\assets\kaslr-98937\targets.conf',
    'main\app\assets\kaslr-98937\README.md',
    'binary-sources\64560\kaslr_slide_aph136g142.c',
    'binary-sources\98260-6.12\pc98260_target_g142.h',
    'docs\612-G142-OPTIMIZATION.md',
    'docs\APH136G142-ADAPT.md',
    'LICENSES\Honor-UBL-Adaptation-MIT.txt',
    'docs\adaptation\46-98260-susfs-off-finalize.md',
    'docs\adaptation\47-6157-termux-su-entry.md',
    'main\app\assets\98260-g264\exploit-android-key-ptr',
    'main\app\assets\98260-g8d6\exploit-android-key-ptr',
    'main\app\assets\98260-g8d6\pc98260-su',
    'main\app\assets\98260-g8d6\target.sh',
    'main\app\assets\98260-g893\exploit-android-key-ptr',
    'main\app\assets\98260-g893\pc98260-su',
    'main\app\assets\98260-g893\target.sh',
    'main\app\assets\98260-g893\syms_g893_kernelsu.txt',
    'main\app\assets\98260-g893\syms_g893_bakasu.txt',
    'main\app\assets\98260-g893\syms_g893_fina.txt',
    'main\app\assets\98260-g893\syms_g893_next.txt',
    'main\app\assets\98260-g893\syms_g893_sukisu.txt',
    'main\app\assets\98260-g893\syms_g893_nova.txt',
    'main\app\assets\98260-g4b36\exploit-android-key-ptr',
    'main\app\assets\98260-g4b36\target.sh',
    'main\app\assets\98260-g4b36\SHA256SUMS.txt',
    'main\app\assets\syms_g4b36.txt',
    'main\app\assets\syms_g4b36_nova.txt',
    'binary-sources\98260-6.12\pc98260_target_g4b36.h',
    'docs\6.12.38-G4B36-ADAPT.md',
    'main\app\assets\98260-g52d15\exploit-android-key-ptr',
    'main\app\assets\98260-g52d15\target.sh',
    'main\app\assets\98260-g52d15\SHA256SUMS.txt',
    'main\app\assets\syms_g52d15.txt',
    'main\app\assets\syms_g52d15_nova.txt',
    'binary-sources\98260-6.12\pc98260_target_g52d15.h',
    'docs\6.12.81-G52D15-ADAPT.md',
    'main\app\assets\98260-gaaa\exploit-android-key-ptr',
    'main\app\assets\98260-gaaa\pc98260-su',
    'main\app\assets\98260-gaaa\target.sh',
    'main\app\assets\98260\exploit-android-key-ptr',
    'binary-sources\98260-6.12\uaf_plant_61258.c',
    'main\app\assets\98260-g84\exploit-android-key-ptr',
    'main\app\assets\98260-g84\pc98260-su',
    'main\app\assets\g264\ksm-g84-base.ko',
    'main\app\assets\98260-g856\exploit-android-key-ptr',
    'main\app\assets\98260-gce849\exploit-android-key-ptr',
    'main\app\assets\98260-g5859\exploit-android-key-ptr',
    'main\app\assets\98260-g54d\exploit-android-key-ptr',
    'main\app\assets\98260-g40b1\exploit-android-key-ptr',
    'main\app\assets\98260-g8a496\exploit-android-key-ptr',
    'main\app\assets\98260-g8a496\pc98260-su',
    'main\app\assets\98260-g8a496\target.sh',
    'main\app\assets\98260-g2e1f\exploit-android-key-ptr',
    'main\app\assets\98260-g2e1f\pc98260-su',
    'main\app\assets\98260-g2e1f\target.sh',
    'main\app\assets\98260-ge9da\exploit-android-key-ptr',
    'main\app\assets\g264\ksm-g7d-base.ko',
    'main\app\assets\g264\ksm-gce849-base.ko',
    'main\app\assets\g264\ksm-g5859-base.ko',
    'main\app\assets\g264\ksm-g54d-base.ko',
    'main\app\assets\g264\ksm-g40b1-base.ko',
    'main\app\assets\g264\ksm-g8a496-base.ko',
    'main\app\assets\g264\ksm-g2e1f-base.ko',
    'main\app\assets\g264\ksm-g8d6-base.ko',
    'main\app\assets\g264\ksm-gaaa-base.ko',
    'main\app\assets\g264\ksm-ge9da-base.ko',
    'main\app\assets\g264\syms-g264.txt',
    'main\app\assets\g264\syms-g7d.txt',
    'main\app\assets\g264\syms-gaaa.txt',
    'main\app\assets\g264\syms-g3306.txt',
    'main\app\assets\g264\syms-g84.txt',
    'main\app\assets\g264\syms-g77f.txt',
    'main\app\assets\g264\syms-gce849.txt',
    'main\app\assets\g264\syms-g5859.txt',
    'main\app\assets\g264\syms-g54d.txt',
    'main\app\assets\g264\syms-g40b1.txt',
    'main\app\assets\g264\syms-g8a496.txt',
    'main\app\assets\g264\syms-g2e1f.txt',
    'main\app\assets\g264\syms-g8d6.txt',
    'main\app\assets\g264\syms-ge9da.txt',
    'binary-sources\6157-g264',
    'binary-sources\61157-g264\rebase_cga_module.py',
    'binary-sources\61157-g264\cga-profiles.json',
    'binary-sources\61157-g264\cga-feature-restore.json',
    'tools\test_cga_feature_restore.py',
    'tools\test_init_cred_patch.py',
    'tools\test_runtime_syms.py',
    'tools\sync_init_cred_symbols.py',
    'tools\sync_manager_symbols.py',
    'docs\RUNTIME-SYM-COMPLETION.md',
    'binary-sources\64560\native\throne_patch.c',
    'binary-sources\64560\native\throne_patch.h',
    'main\app\assets\ksu6157-m6',
    'main\app\assets\98260-6689\exploit-android-key-ptr',
    'main\app\assets\98260-6689\pc98260-su',
    'binary-sources\6689\pc98260_target_6689.h',
    'docs\6157-CGA-FEATURE-RESTORE.md',
    'docs\INIT-CRED-LATELOAD.md',
    'docs\6157-SUPPORT-AUDIT.md',
    'docs\6157-SUCCESS-CHAIN-REBASE.md',
    'docs\61128-OLD-KERNELS-ADAPT.md',
    'docs\61157-GAAA-ADAPT.md',
    'docs\98260-EKROOT-1.67-REVERSE.md',
    'docs\M6-SHELL-19-ANALYSIS.md',
    'tools\audit_6157_chain.py',
    'tools\test_61128_adaptation.py',
    'docs\6.1.157-G84-BOOT-VERIFY.md',
    'docs\6.6.89-ADAPT.md',
    'docs\KERNEL-FLAVOR-AUDIT.md',
    'BINARY-SOURCES.md',
    'SOURCE-MANIFEST.txt',
    'LICENSES\HOneClick-NOASSERTION.md'
)
foreach ($r in $required) {
    if (-not (Test-Path (Join-Path $stage $r))) {
        throw "source package missing required path: $r"
    }
}

if (Test-Path $Output) { Remove-Item $Output -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $Output -CompressionLevel Optimal
$hash = (Get-FileHash $Output -Algorithm SHA256).Hash
$sumPath = "$Output.sha256.txt"
"$hash  $(Split-Path -Leaf $Output)" | Set-Content -Path $sumPath -Encoding ASCII

Write-Host "files=$($selected.Count) size=$((Get-Item $Output).Length) sha256=$hash"
Write-Host "source zip: $Output"
Write-Host "checksum:  $sumPath"
Remove-Item $stage -Recurse -Force
