#!/usr/bin/env python3
"""Source-package mirror of tools/package-source.ps1 (Linux/Android).

The PowerShell script remains the Windows entry point; this Python version
keeps the same roots, exclusions and required-path checks so the release
source zip can be produced on-device.
"""
import argparse
import hashlib
import os
import zipfile

EXCLUDED_DIRS = {'.git', '.gradle', '.gradle-home', '.idea', 'build',
                 '__pycache__', 'work', '.dsh', 'tmp'}
EXCLUDED_EXTS = {'.apk', '.idsig', '.keystore', '.jks', '.zip', '.log'}
EXCLUDED_NAMES = {'local.properties'}
ROOTS = ['main', 'binary-sources', 'tools', 'docs', 'LICENSES']

REQUIRED = [
    'main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java',
    'main/compose-app/app/src/main/java/com/aoki/magicroot/RunProgress.java',
    'main/compose-app/app/src/main/java/com/aoki/magicroot/KernelLogHelper.java',
    'main/compose-app/app/src/main/java/com/aoki/magicroot/LiveLogStore.java',
    'tools/tests/LiveLogStoreTest.java',
    'docs/ONEKEYJB-REFERENCE.md',
    'docs/ONEKEYJB-PRECISE-HIT.md',
    'tools/check.sh',
    'tools/gen_6157_integrity.py',
    'main/app/assets/6157-integrity.tsv',
    'tools/kernel_profiles.json',
    'tools/test_kaslr_g142.py',
    'tools/asset_dedup_map.json',
    'tools/tests/RunProgressTest.java',
    'tools/tests/KernelLogHelperTest.java',
    'main/app/assets/98260-g142/exploit-android-key-ptr',
    'main/app/assets/98260-g142/pc98260-su',
    'main/app/assets/98260-g142/SHA256SUMS.txt',
    'main/app/assets/kaslr_slide_aph136g142',
    'main/app/assets/kaslr-98937/poc98937',
    'main/app/assets/kaslr-98937/slide98937',
    'main/app/assets/kaslr-98937/slide98937.c',
    'main/app/assets/kaslr-98937/run98937.sh',
    'main/app/assets/kaslr-98937/targets.conf',
    'main/app/assets/kaslr-98937/README.md',
    'binary-sources/64560/kaslr_slide_aph136g142.c',
    'binary-sources/98260-6.12/pc98260_target_g142.h',
    'docs/612-G142-OPTIMIZATION.md',
    'docs/APH136G142-ADAPT.md',
    'LICENSES/Honor-UBL-Adaptation-MIT.txt',
    'main/app/assets/98260-g264/exploit-android-key-ptr',
    'main/app/assets/98260-g8d6/exploit-android-key-ptr',
    'main/app/assets/98260-g8d6/pc98260-su',
    'main/app/assets/98260-g8d6/target.sh',
    'main/app/assets/98260-g893/exploit-android-key-ptr',
    'main/app/assets/98260-g893/pc98260-su',
    'main/app/assets/98260-g893/target.sh',
    'main/app/assets/98260-g893/syms_g893_kernelsu.txt',
    'main/app/assets/98260-g893/syms_g893_bakasu.txt',
    'main/app/assets/98260-g893/syms_g893_fina.txt',
    'main/app/assets/98260-g893/syms_g893_next.txt',
    'main/app/assets/98260-g893/syms_g893_sukisu.txt',
    'main/app/assets/98260-gaaa/exploit-android-key-ptr',
    'main/app/assets/98260-gaaa/pc98260-su',
    'main/app/assets/98260-gaaa/target.sh',
    'main/app/assets/98260-g84/exploit-android-key-ptr',
    'main/app/assets/98260-g84/pc98260-su',
    'main/app/assets/g264/ksm-g84-base.ko',
    'main/app/assets/98260-g856/exploit-android-key-ptr',
    'main/app/assets/98260-gce849/exploit-android-key-ptr',
    'main/app/assets/98260-g5859/exploit-android-key-ptr',
    'main/app/assets/98260-g54d/exploit-android-key-ptr',
    'main/app/assets/98260-g40b1/exploit-android-key-ptr',
    'main/app/assets/98260-g8a496/exploit-android-key-ptr',
    'main/app/assets/98260-g8a496/pc98260-su',
    'main/app/assets/98260-g8a496/target.sh',
    'main/app/assets/98260-g2e1f/exploit-android-key-ptr',
    'main/app/assets/98260-g2e1f/pc98260-su',
    'main/app/assets/98260-g2e1f/target.sh',
    'main/app/assets/98260-ge9da/exploit-android-key-ptr',
    'main/app/assets/g264/ksm-g7d-base.ko',
    'main/app/assets/g264/ksm-gce849-base.ko',
    'main/app/assets/g264/ksm-g5859-base.ko',
    'main/app/assets/g264/ksm-g54d-base.ko',
    'main/app/assets/g264/ksm-g40b1-base.ko',
    'main/app/assets/g264/ksm-g8a496-base.ko',
    'main/app/assets/g264/ksm-g2e1f-base.ko',
    'main/app/assets/g264/ksm-g8d6-base.ko',
    'main/app/assets/g264/ksm-gaaa-base.ko',
    'main/app/assets/g264/ksm-ge9da-base.ko',
    'main/app/assets/g264/syms-g264.txt',
    'main/app/assets/g264/syms-g7d.txt',
    'main/app/assets/g264/syms-gaaa.txt',
    'main/app/assets/g264/syms-g3306.txt',
    'main/app/assets/g264/syms-g84.txt',
    'main/app/assets/g264/syms-g77f.txt',
    'main/app/assets/g264/syms-gce849.txt',
    'main/app/assets/g264/syms-g5859.txt',
    'main/app/assets/g264/syms-g54d.txt',
    'main/app/assets/g264/syms-g40b1.txt',
    'main/app/assets/g264/syms-g8a496.txt',
    'main/app/assets/g264/syms-g2e1f.txt',
    'main/app/assets/g264/syms-g8d6.txt',
    'main/app/assets/g264/syms-ge9da.txt',
    'binary-sources/6157-g264',
    'binary-sources/61157-g264/rebase_cga_module.py',
    'binary-sources/61157-g264/cga-profiles.json',
    'binary-sources/61157-g264/cga-feature-restore.json',
    'binary-sources/6157-g264/build-feature-restore.sh',
    'tools/test_cga_feature_restore.py',
    'tools/test_init_cred_patch.py',
    'tools/sync_init_cred_symbols.py',
    'binary-sources/64560/native/throne_patch.c',
    'binary-sources/64560/native/throne_patch.h',
    'docs/6157-CGA-FEATURE-RESTORE.md',
    'docs/INIT-CRED-LATELOAD.md',
    'main/app/assets/ksu6157-m6',
    'main/app/assets/98260-6689/exploit-android-key-ptr',
    'main/app/assets/98260-6689/pc98260-su',
    'binary-sources/6689/pc98260_target_6689.h',
    'docs/6157-SUPPORT-AUDIT.md',
    'docs/6157-SUCCESS-CHAIN-REBASE.md',
    'docs/61128-OLD-KERNELS-ADAPT.md',
    'docs/61157-GAAA-ADAPT.md',
    'docs/98260-EKROOT-1.67-REVERSE.md',
    'docs/M6-SHELL-19-ANALYSIS.md',
    'tools/audit_6157_chain.py',
    'tools/test_61128_adaptation.py',
    'docs/6.1.157-G84-BOOT-VERIFY.md',
    'docs/6.6.89-ADAPT.md',
    'docs/KERNEL-FLAVOR-AUDIT.md',
    'BINARY-SOURCES.md',
    'SOURCE-MANIFEST.txt',
    'LICENSES/HOneClick-NOASSERTION.md',
]


def excluded(rel):
    parts = rel.split('/')
    if any(p in EXCLUDED_DIRS for p in parts):
        return True
    name = parts[-1]
    ext = os.path.splitext(name)[1].lower()
    return ext in EXCLUDED_EXTS or name in EXCLUDED_NAMES


def collect(project):
    selected = []
    for root in ROOTS:
        base = os.path.join(project, root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS)
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, project).replace(os.sep, '/')
                if not excluded(rel):
                    selected.append((rel, full))
    for name in sorted(os.listdir(project)):
        full = os.path.join(project, name)
        if not os.path.isfile(full):
            continue
        if excluded(name):
            continue
        selected.append((name, full))
    # sort/dedupe
    by_rel = {}
    for rel, full in selected:
        by_rel[rel] = full
    return [(rel, by_rel[rel]) for rel in sorted(by_rel)]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    project = os.path.dirname(here)
    ap = argparse.ArgumentParser()
    ap.add_argument('--project', default=project)
    ap.add_argument('--output', default='/sdcard/cccodroid/MagicRoot-1.0.6-source.zip')
    args = ap.parse_args()
    project = os.path.abspath(args.project)
    files = collect(project)
    rels = {rel for rel, _ in files}
    def present(p):
        return p in rels or any(r.startswith(p + '/') for r in rels)
    missing = [p for p in REQUIRED if not present(p)]
    if missing:
        raise SystemExit('source package missing required path: ' + ', '.join(missing))
    out = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + '.tmp'
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel, full in files:
            z.write(full, rel)
    os.replace(tmp, out)
    h = hashlib.sha256()
    with open(out, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    digest = h.hexdigest()
    with open(out + '.sha256.txt', 'w', encoding='ascii') as f:
        f.write('%s  %s\n' % (digest, os.path.basename(out)))
    print('files=%d size=%d sha256=%s' % (len(files), os.path.getsize(out), digest))
    print('source zip:', out)
    print('checksum:  ', out + '.sha256.txt')


if __name__ == '__main__':
    main()
