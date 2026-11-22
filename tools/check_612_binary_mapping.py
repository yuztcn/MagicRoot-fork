#!/usr/bin/env python3
"""Guard the 6.12 production assets against CPU-B / 1.0.2B binaries.

CPU-B maps the main process to CPU6 and victim exec to CPU7 (pin_cpu(6) /
pin_cpu(7)); the normal 6.12 mapping is CPU0 / CPU1.  CPU-B is an experiment
only and can cause reboot-prone core allocation on the 6.12 target.

This checker is deliberately hash-based: it does not need a disassembler and
can run in CI.  The known CPU-B hashes below are from the released CPU-B /
1.0.2B APKs.
"""

from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

NORMAL = {
    "t64560_v36": "2fa5f00d7d243921b145fee9c4855388c4a1dd7835aeb5a36d2ff5cc496615fa",
    "t64560_cred": "928abcf78d7829c64933d7f6d837016f77399c20958602e1692a8d655cd8ed6b",
}
SAFE = {
    "t64560_v36_safe": "b48d7007cf844cfa54c16962312544dacb16dc024f65db48a350efb8a242cd27",
    "t64560_cred_safe": "5f862a6de63680eacec21fb43e85cc957f911c788bf033aed36b7951beb3f143",
}
FORBIDDEN = {
    # MagicRoot 1.0.2B
    "6641090103284276b1e45080f4b337bbb77da0a3c6d8e806a2bab63ee232a699": "1.0.2B t64560_v36",
    "07b85cd6871565786fb75336cec90a9fdd1db43600c65bed4a67be7221382084": "1.0.2B t64560_cred",
    # MagicRoot 1.0.1 CPU-B
    "3edfa3dbe7612810787c2812fb9a6ec094e6cbcc1410e7eced549e5dc986b61f": "1.0.1-cpuB t64560_v36",
    "b98b6627a28dea3f6b8526390689cda837b5d6da70dfaa76ab027cc052adc5c7": "1.0.1-cpuB t64560_cred",
}
PATHS = [
    ROOT / "release/source/MagicRoot-1.0.2-main/app/assets",
    ROOT / "MagicRoot-1.0.2/app/assets",
    ROOT / "release/publish/apk/MagicRoot-main-6.12.apk",
]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_asset(name: str, data: bytes, errors: list[str], notes: list[str]) -> None:
    h = sha(data)
    if name in NORMAL:
        if h != NORMAL[name]:
            errors.append(f"{name}: hash {h} != normal {NORMAL[name]}")
        else:
            notes.append(f"OK normal {name} {h[:16]}")
    if name in SAFE:
        if h != SAFE[name]:
            errors.append(f"{name}: hash {h} != safe {SAFE[name]}")
        else:
            notes.append(f"OK safe {name} {h[:16]}")
    if h in FORBIDDEN:
        errors.append(f"{name}: FORBIDDEN {FORBIDDEN[h]} ({h[:16]})")


def main() -> int:
    errors: list[str] = []
    notes: list[str] = []
    for path in PATHS:
        if not path.exists():
            errors.append(f"missing path: {path}")
            continue
        if path.suffix == ".apk":
            with zipfile.ZipFile(path) as z:
                for name in (*NORMAL, *SAFE):
                    asset = f"assets/{name}"
                    if asset not in z.namelist():
                        errors.append(f"{path.name}: missing {asset}")
                        continue
                    check_asset(name, z.read(asset), errors, notes)
        else:
            for name in (*NORMAL, *SAFE):
                p = path / name
                if not p.exists():
                    if name in SAFE:
                        notes.append(f"SKIP safe (not synced): {p}")
                        continue
                    errors.append(f"{p}: missing")
                    continue
                check_asset(name, p.read_bytes(), errors, notes)
    for line in notes:
        print(line)
    for line in errors:
        print("ERROR:", line)
    print("CPU_MAPPING_GUARD:", "FAIL" if errors else "PASS")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
