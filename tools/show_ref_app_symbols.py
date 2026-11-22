#!/usr/bin/env python3
"""Print app-specific symbols (low text range) + CLI strings per binary."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
WS = Path(__file__).resolve().parent.parent
A = WS / "refs/analysis"

TARGETS = [
    "assets/core/cred.bin", "assets/core/patch.bin", "assets/core/perm.bin",
    "assets/core/resolve.bin", "assets/core/writer.bin", "assets/core/loadgen.bin",
    "assets/t64560_v36", "assets/t64560_v42", "assets/forker",
    "assets/ksu_grant", "assets/perf_cred", "assets/perf_cred_sukisu",
    "assets/su_forward",
]


def base(rel: str) -> Path:
    return A / rel.replace("/", "_").replace("\\", "_")


for rel in TARGETS:
    b = base(rel)
    print("=" * 100)
    print(rel)
    syms = []
    for line in b.with_suffix(".symbols.txt").read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"0x([0-9a-f]+)\s+(\d+)\s+(.*)", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        syms.append((addr, int(m.group(2)), m.group(3)))
    # app code usually below 0x402800 (before libc start)
    app = [s for s in syms if 0x400000 <= s[0] < 0x402800 and s[1] > 0]
    print("-- app symbols --")
    for addr, size, name in sorted(app, key=lambda x: x[0])[:80]:
        print(f"  {addr:#08x} {size:6d} {name}")
    # usage / option strings
    print("-- CLI-ish strings --")
    usage = []
    for line in b.with_suffix(".interesting.txt").read_text(encoding="utf-8", errors="replace").splitlines():
        if re.search(r"usage|Usage|argv|--|\[|\]|<|>=|option|mode|target|attempt|drain|victim|timers|nfrag|size|ms\b", line):
            usage.append(line)
    for line in usage[:80]:
        print("  ", line[:150])
