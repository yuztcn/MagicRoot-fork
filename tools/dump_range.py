#!/usr/bin/env python3
"""Dump a vaddr range from a static binary."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

p = Path(sys.argv[1])
va = int(sys.argv[2], 0)
size = int(sys.argv[3], 0)
d = p.read_bytes()
e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
e_phnum = struct.unpack_from("<H", d, 0x38)[0]
off = None
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    typ = struct.unpack_from("<I", d, o)[0]
    p_off, p_va, _, p_filesz, _ = struct.unpack_from("<QQQQQ", d, o + 8)
    if typ == 1 and p_va <= va < p_va + p_filesz:
        off = p_off + (va - p_va)
        break
if off is None:
    print("not mapped")
    raise SystemExit(1)
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
for ins in md.disasm(d[off:off + size], va):
    print(f"{ins.address:x}: {ins.mnemonic:10s} {ins.op_str}")
