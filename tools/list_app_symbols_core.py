#!/usr/bin/env python3
"""List app-code symbols (low .text window) for each core binary."""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
AN = Path(__file__).resolve().parent.parent / "refs/analysis"
BINS = ["cred.bin", "patch.bin", "perm.bin", "resolve.bin", "writer.bin", "loadgen.bin"]
for name in BINS:
    p = AN / ("assets_core_" + name + ".symbols.txt")
    if not p.exists():
        print("missing", p)
        continue
    rows = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"0x([0-9a-f]+)\s+(\d+)\s+(.*)", line)
        if m:
            rows.append((int(m.group(1), 16), int(m.group(2)), m.group(3)))
    app = [r for r in rows if 0x21a000 <= r[0] <= 0x222000 and r[1] > 0]
    print("=" * 100)
    print(f"assets/core/{name}: {len(app)} symbols in 0x21a000..0x222000")
    for addr, size, sym in sorted(app):
        print(f"  {addr:#08x} {size:6d} {sym}")
