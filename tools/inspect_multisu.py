#!/usr/bin/env python3
"""Inspect the provided MultiSU binaries: LKM vermagic/version, zip contents,
APK ksud payloads, and compare with current assets."""
from __future__ import annotations

import hashlib
import re
import struct
import sys
import zipfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MS = Path(r"<LOCAL_USER>user\Documents\MultiSU")
WS = Path(__file__).resolve().parent.parent


def sha8(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16]


def ko_info(p: Path):
    d = p.read_bytes()
    m = re.search(rb"vermagic=([^\x00]{1,120})", d)
    verm = m.group(1).decode("utf-8", "replace") if m else "?"
    ver = ""
    for pat in (rb"KernelSU version (\d+)", rb"version: %u", rb"version=(\d+)"):
        mm = re.search(pat, d)
        if mm:
            ver = mm.group(1).decode() if mm.groups() else pat.decode()
            break
    vstr = ""
    for pat in (rb"v4\.\d+\.\d+[^\x00]{0,40}", rb"v3\.\d+\.\d+[^\x00]{0,30}"):
        mm = re.search(pat, d)
        if mm:
            vstr = mm.group(0).decode("utf-8", "replace")
            break
    return verm, ver, vstr


print("=== MultiSU flat files ===")
for p in sorted(MS.iterdir()):
    print(f"  {p.name:52} {p.stat().st_size:>10} B  sha256:{sha8(p)}")

print("\n=== LKM details ===")
for name in ("aarch64_android16-6.12_kernelsunext.ko",
             "lkm-aarch64-android16-6.12_kernelsu.ko",
             "lkm-aarch64-android16-6.12_sukisu.ko"):
    p = MS / name
    if p.exists():
        verm, ver, vstr = ko_info(p)
        print(f"  {name}\n    vermagic={verm!r}\n    version_str={ver!r} {vstr!r}")

print("\n=== zips ===")
for name in ("FinaSU_v1.0.10_kernel-bundle.zip", "BakaSUManager-release.zip"):
    p = MS / name
    if not p.exists():
        continue
    print(f"  {name}:")
    with zipfile.ZipFile(p) as z:
        for i in z.infolist():
            print(f"    {i.filename}  {i.file_size} B")
            if i.filename.lower().endswith(".ko"):
                data = z.read(i.filename)
                m = re.search(rb"vermagic=([^\x00]{1,120})", data)
                print("      vermagic=", m.group(1).decode("utf-8", "replace") if m else "?")

print("\n=== APKs: ksud payload / package info ===")
for name in ("FinaSU_v1.0.10_33034-release.apk",
             "KernelSU_Next_v3.4.2_33355-release.apk",
             "SukiSU_v4.2.1-r2_41068-release.apk"):
    p = MS / name
    if not p.exists():
        continue
    print(f"  {name}:")
    with zipfile.ZipFile(p) as z:
        for i in z.infolist():
            n = i.filename
            if ("lib/arm64-v8a/" in n and n.endswith(".so")) or "ksud" in n.lower():
                print(f"    {n}  {i.file_size} B")
        for cand in ("lib/arm64-v8a/libksud.so", "assets/ksud"):
            if cand in z.namelist():
                data = z.read(cand)
                out = WS / "refs/managers/msu" / (name.split("_")[0].lower() + "-ksud")
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(data)
                out.chmod(0o755)
                print(f"    extracted -> {out} ({len(data)} B)")

print("\n=== executable versions (from filename, check after push) ===")
for name in ("ksud-aarch64-linux-android", "ksud-aarch64-linux-android-kernelsunext",
             "ksud-aarch64-linux-android-sukisu"):
    p = MS / name
    if p.exists():
        print(f"  {name}: {p.stat().st_size} B sha256:{sha8(p)}")
