#!/usr/bin/env python3
"""Offline verification of the CVE-2026-98260 second-chain assets.

Checks:
  * main/app/assets/98260/<4 binaries> exist and match assets/98260/SHA256SUMS.txt;
  * the same manifest matches the Lead-provided port/98260-honor-61258/SHA256SUMS.txt
    (Honor 6.12.58 adapted build, NDK r28c);
  * run98260.sh / target.sh / clean.sh contain the required fail-stop markers.

Usage (from the MagicRoot-Enhanced-1.0.4-98260 root):
    python tools/verify_98260_assets.py [--port <dir>]
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
ASSETS = WS / "main" / "app" / "assets" / "98260"
MANIFEST = ASSETS / "SHA256SUMS.txt"
DEFAULT_PORT = Path(r"C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260\port\98260-honor-61258")

BINARIES = [
    "exploit-android-perf",
    "exploit-android-perf-chain",
    "exploit-android-key-ptr",
]

# pc98260-su ships at assets/pc98260-su (top level) and is staged for every
# 98260 profile that needs it; the 98260/ dir itself carries only the three
# binaries above plus run98260.sh / target.sh / run6157_full.sh / SHA256SUMS.txt.
SU_CANDIDATES = [
    ASSETS.parent / "pc98260-su",
    ASSETS.parent / "98260-6658" / "pc98260-su",
]

MARKERS = {
    "run98260.sh": [
        "MAGICROOT_ENABLE_98260", "parked_check", "98260_SUCCESS=1",
        "MAGICROOT_98260_PREFLIGHT", "pc98260-root.sock", "selinux", "cred",
        "--check", "parked_mark",
    ],
    "target.sh": [
        "CHAIN_98260_KERNEL", "CHAIN_98260_MODELS",
        "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k",
    ],
}
CLEAN_MARKERS = ["CLEAN_98260", "pc98260-root.sock", "exploit-android", ".98260-parked"]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_manifest(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and len(parts[0]) == 64:
            out[parts[1]] = parts[0].lower()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=str(DEFAULT_PORT))
    args = ap.parse_args()
    port = Path(args.port)
    problems: list[str] = []

    if not MANIFEST.exists():
        print(f"FAIL missing manifest: {MANIFEST}")
        return 1
    manifest = read_manifest(MANIFEST)
    actual = {}
    print("== assets/98260 binaries vs assets manifest ==")
    for name in BINARIES:
        p = ASSETS / name
        if not p.exists():
            problems.append(f"missing binary {name}")
            print(f"MISSING {name}")
            continue
        dig = sha256(p)
        actual[name] = dig
        want = manifest.get(name)
        ok = want == dig
        print(f"{'OK ' if ok else 'BAD'} {name:32s} size={p.stat().st_size:8d} sha256={dig}")
        if not ok:
            problems.append(f"manifest mismatch {name}: {dig} != {want}")

    print("\n== pc98260-su presence ==")
    su_found = None
    for cand in SU_CANDIDATES:
        if cand.is_file():
            su_found = cand
            break
    if su_found is None:
        problems.append("pc98260-su missing (checked top-level and 98260-6658)")
        print("MISSING pc98260-su")
    else:
        print(f"OK   pc98260-su at {su_found.relative_to(WS)} "
              f"size={su_found.stat().st_size} sha256={sha256(su_found)}")

    print("\n== assets manifest vs port/98260-honor-61258/SHA256SUMS.txt ==")
    port_manifest_path = port / "SHA256SUMS.txt"
    if port_manifest_path.exists():
        port_manifest = read_manifest(port_manifest_path)
        # port file uses pc98260-su-client; assets use pc98260-su (same bytes).
        alias = {"pc98260-su": "pc98260-su-client"}
        for name in BINARIES:
            pname = alias.get(name, name)
            want = port_manifest.get(pname)
            got = actual.get(name)
            ok = want is not None and want == got
            print(f"{'OK ' if ok else 'BAD'} {name:32s} port={want} assets={got}")
            if not ok:
                problems.append(f"port mismatch {name}: assets={got} port={want}")
    else:
        print(f"WARN port manifest not found: {port_manifest_path}")

    print("\n== device-side script markers ==")
    for fname, markers in MARKERS.items():
        p = ASSETS / fname
        text = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
        for m in markers:
            if m not in text:
                problems.append(f"{fname} missing marker {m!r}")
                print(f"BAD  {fname}: missing {m!r}")
        print(f"OK   {fname} markers checked ({len(markers)})")

    clean = WS / "main" / "app" / "assets" / "clean.sh"
    ctext = clean.read_text(encoding="utf-8", errors="replace") if clean.exists() else ""
    for m in CLEAN_MARKERS:
        if m not in ctext:
            problems.append(f"clean.sh missing marker {m!r}")
            print(f"BAD  clean.sh: missing {m!r}")
    print(f"OK   clean.sh markers checked ({len(CLEAN_MARKERS)})")

    print("\n== RESULT ==")
    if problems:
        print("PROBLEMS:")
        for p in problems:
            print(" -", p)
        return 1
    print("All 98260 assets/markers verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
