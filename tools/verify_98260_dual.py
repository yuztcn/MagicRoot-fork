#!/usr/bin/env python3
"""Offline verification of both CVE-2026-98260 second-chain variants.

Checks (per kernel variant):
  * main/app/assets/98260[-6138]/ binaries against the local SHA256SUMS.txt and
    against the Lead port manifests (port/98260-honor-61258 /
    port/98260-honor-61238);
  * target.sh carries the exact kernel build + pinned hashes;
  * the shared stage machine selects the per-kernel directory from uname -r and
    keeps the fail-stop markers;
  * app asset lists deploy both variants; clean.sh handles both dirs;
  * versionName/versionCode of the compose build.
Usage (from the MagicRoot-Enhanced-1.0.4-98260 root):
    python tools/verify_98260_dual.py
"""
from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
ROOT = WS.parent
ASSETS = WS / 'main' / 'app' / 'assets'
VARIANTS = [
    {
        'name': '6.12.58',
        'dir': ASSETS / '98260',
        'kernel': '6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k',
        'port': ROOT / 'port' / '98260-honor-61258',
        'sums': ['exploit-android-perf', 'exploit-android-perf-chain',
                 'exploit-android-key-ptr', 'pc98260-su', 'run98260.sh', 'target.sh'],
        'manifest_bins': ['exploit-android-perf', 'exploit-android-perf-chain',
                          'exploit-android-key-ptr', 'pc98260-su'],
    },
    {
        'name': '6.12.38',
        'dir': ASSETS / '98260-6138',
        'kernel': '6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k',
        'port': ROOT / 'port' / '98260-honor-61238',
        'sums': ['exploit-android-perf', 'exploit-android-perf-chain',
                 'exploit-android-key-ptr', 'pc98260-su', 'target.sh'],
        'manifest_bins': ['exploit-android-perf', 'exploit-android-perf-chain',
                          'exploit-android-key-ptr', 'pc98260-su'],
    },
]

ok = True


def sha(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def check(cond: bool, msg: str) -> None:
    global ok
    print(('OK   ' if cond else 'FAIL ') + msg)
    ok = ok and cond


print('== assets binaries vs manifests ==')
for v in VARIANTS:
    d: Path = v['dir']
    print(f'-- {v["name"]}: {d}')
    manifest = {}
    for line in (d / 'SHA256SUMS.txt').read_text(encoding='ascii').splitlines():
        parts = line.split()
        if len(parts) == 2:
            manifest[parts[1]] = parts[0]
    for name in v['sums']:
        p = d / name
        check(p.exists() and name in manifest and sha(p) == manifest[name],
              f'{v["name"]}/{name} sha256 vs local manifest')
    port_manifest = {}
    pf = v['port'] / 'SHA256SUMS.txt'
    for line in pf.read_text(encoding='ascii').splitlines():
        parts = line.split()
        if len(parts) == 2:
            port_manifest[parts[1]] = parts[0]
    for name in v['manifest_bins']:
        port_name = name
        if name == 'pc98260-su':
            port_name = 'pc98260-su-client'
        p = d / name
        check(sha(p) == port_manifest.get(port_name),
              f'{v["name"]}/{name} == port/{v["port"].name}/SHA256SUMS.txt')

print()
print('== target.sh kernel strings + pinned hashes ==')
for v in VARIANTS:
    t = (v['dir'] / 'target.sh').read_text(encoding='utf-8')
    check(v['kernel'] in t, f'{v["name"]} target.sh has exact kernel string')
    local = {}
    for line in (v['dir'] / 'SHA256SUMS.txt').read_text(encoding='ascii').splitlines():
        parts = line.split()
        if len(parts) == 2:
            local[parts[1]] = parts[0]
    for name in v['manifest_bins']:
        check(local.get(name, 'MISSING') in t,
              f'{v["name"]} target.sh pins sha256 of {name}')

print()
print('== shared stage machine dispatch ==')
run = (ASSETS / '98260' / 'run98260.sh').read_text(encoding='utf-8')
for v in VARIANTS:
    check(v['kernel'] in run, f'run98260.sh dispatches {v["name"]} kernel')
check('B=$D/98260-6138' in run, 'run98260.sh selects $D/98260-6138 for 6.12.38')
check('park_fail' in run and 'parked_retained' in run, 'run98260.sh keeps parked/retained guards')
check('do_timer_create+0xac' in run, 'preflight anchors do_timer_create+0xac')

print()
print('== kernel profiles / clean.sh / app lists ==')
kp = (ASSETS / 'kernel_profiles.sh').read_text(encoding='utf-8')
for v in VARIANTS:
    check(v['kernel'] in kp, f'kernel_profiles.sh has {v["name"]} profile')
clean = (ASSETS / 'clean.sh').read_text(encoding='utf-8')
check('$D/98260-6138' in clean, 'clean.sh removes $D/98260-6138')
for java in [WS / 'main' / 'compose-app' / 'app' / 'src' / 'main' / 'java' / 'com' / 'aoki' / 'magicroot' / 'MainActivity.java',
             WS / 'main' / 'app' / 'src' / 'com' / 'aoki' / 'magicroot' / 'MainActivity.java']:
    src = java.read_text(encoding='utf-8')
    check('98260-6138/exploit-android-perf' in src, f'{java.name} deploys 98260-6138 assets')
    check('WORK + "/98260-6138"' in src, f'{java.name} stages into $WORK/98260-6138')

print()
print('== version ==')
g = (WS / 'main' / 'compose-app' / 'app' / 'build.gradle.kts').read_text(encoding='utf-8')
check('versionCode = 13' in g and '1.0.6' in g, 'compose version 1.0.6 (vc13)')

print()
print('RESULT:', 'ALL OK' if ok else 'PROBLEMS FOUND')
sys.exit(0 if ok else 1)
