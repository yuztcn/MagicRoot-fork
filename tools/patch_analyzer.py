#!/usr/bin/env python3
"""Improve analyzer: artifact naming, _start/entry disassembly, syscall comments."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
A = WS / "tools/analyze_ref_bins.py"
t = A.read_text(encoding="utf-8")

# 1) artifact naming: keep full base name (cred.bin -> cred.bin.symbols.txt)
t = t.replace('base.with_suffix(".strings.txt")', 'base.with_name(base.name + ".strings.txt")')
t = t.replace('base.with_suffix(".interesting.txt")', 'base.with_name(base.name + ".interesting.txt")')
t = t.replace('base.with_suffix(".symbols.txt")', 'base.with_name(base.name + ".symbols.txt")')
t = t.replace('base.with_suffix(".imports.txt")', 'base.with_name(base.name + ".imports.txt")')
t = t.replace('base.with_suffix(".disasm.txt")', 'base.with_name(base.name + ".disasm.txt")')

# 2) target selection: add _start and small binaries; annotate syscalls
t = t.replace(
'''    cand = [s for s in funcs if s["name"] in ("main", "entry") or wanted.search(s["name"])]
    cand.sort(key=lambda s: (s["name"] != "main", -s["size"]))
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    lines = []
    for f in cand[:24]:''',
'''    cand = [s for s in funcs if s["name"] in ("main", "entry", "_start")
            or wanted.search(s["name"])]
    cand.sort(key=lambda s: (s["name"] != "main", s["name"] != "_start", -s["size"]))
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    lines = []
    for f in cand[:24]:''')

t = t.replace(
'''        lines.append(f"\\n===== {f['name']} @ {hex(f['value'])} size={f['size']}")
        n = 0
        for ins in md.disasm(d[off:off + size], f["value"]):
            line = f"{ins.address:x}: {ins.mnemonic}\\t{ins.op_str}"''',
'''        lines.append(f"\\n===== {f['name']} @ {hex(f['value'])} size={f['size']}")
        n = 0
        last_x8 = None
        for ins in md.disasm(d[off:off + size], f["value"]):
            line = f"{ins.address:x}: {ins.mnemonic}\\t{ins.op_str}"
            if ins.mnemonic in ("mov", "movz", "movn") and ins.op_str.startswith("x8, "):
                try:
                    last_x8 = int(ins.op_str.split("#")[-1], 0)
                except ValueError:
                    last_x8 = None
            if ins.mnemonic == "svc" and last_x8 is not None:
                line += f"   ; syscall {last_x8}"
                last_x8 = None''')

# 3) small stripped binaries: disassemble _start even without funcs list entry
t = t.replace(
'''    targeted = []''',
'''    if not funcs:
        raw = struct.unpack_from("<Q", d, 0x18)[0]
        f = dict(name="_entry", value=raw, size=min(6000, len(d) - (v2o(segs, raw) or 0)))
        funcs = [f]
    targeted = []''')

A.write_text(t, encoding="utf-8", newline="\n")
print("analyzer patched")
