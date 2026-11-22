#!/usr/bin/env python3
"""Annotated disassembly of selected functions with symbol/string/syscall comments."""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_bakasu_lkm import parse_elf, read_symtab  # noqa: E402
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM  # noqa: E402

WS = Path(__file__).resolve().parent.parent
ZIP = WS / "refs/oneplus-v270-zip"
OUT = WS / "refs/analysis/annotated"
OUT.mkdir(parents=True, exist_ok=True)


def load_img(d: bytes):
    e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
    e_phnum = struct.unpack_from("<H", d, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", d, o)[0]
        p_off, p_va, _, p_filesz, _ = struct.unpack_from("<QQQQQ", d, o + 8)
        if p_type == 1:
            segs.append((p_va, p_filesz, p_off))
    return segs


def v2o(segs, va):
    for va0, sz, off in segs:
        if va0 <= va < va0 + sz:
            return off + (va - va0)
    return None


def cstr(d, off, n=160):
    if off is None or off >= len(d):
        return None
    end = d.find(b"\0", off, min(len(d), off + n))
    if end < 0:
        end = min(len(d), off + n)
    s = d[off:end]
    if not s or any(b < 32 or b >= 127 for b in s):
        return None
    return s.decode("ascii", "replace")


def annotate(bin_path: Path, names: list[str], out_name: str | None = None):
    d = bin_path.read_bytes()
    segs = load_img(d)
    _, secs = parse_elf(bin_path)
    syms = read_symtab(d, secs)
    by_addr = {}
    for s in syms:
        if s["shndx"] and s["size"] and s["name"]:
            by_addr.setdefault(s["value"], []).append(s["name"])
    funcs = [s for s in syms if s["typ"] == 2 and s["name"] in names and s["shndx"]]
    if not funcs:
        print("no functions", names)
        return
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    out = []
    for f in funcs:
        off = v2o(segs, f["value"])
        if off is None:
            continue
        out.append(f"\n########## {f['name']} @ {f['value']:#x} size={f['size']}")
        reg_page = {}
        n = 0
        for ins in md.disasm(d[off:off + min(f["size"], 20000)], f["value"]):
            line = f"{ins.address:x}: {ins.mnemonic:8s} {ins.op_str}"
            m = re.match(r"adrp\s+x(\d+), #(0x[0-9a-f]+)", ins.mnemonic + " " + ins.op_str)
            if ins.mnemonic == "adrp":
                mm = re.match(r"x(\d+), #(0x[0-9a-f]+)", ins.op_str)
                if mm:
                    reg_page[int(mm.group(1))] = int(mm.group(2), 16)
            elif ins.mnemonic == "add":
                mm = re.match(r"x(\d+), x(\d+), #(0x[0-9a-f]+)", ins.op_str)
                if mm and int(mm.group(1)) == int(mm.group(2)):
                    page = reg_page.get(int(mm.group(1)))
                    if page is not None:
                        va = page + int(mm.group(3), 16)
                        s = cstr(d, v2o(segs, va))
                        if s:
                            line += f"   ; \"{s[:90]}\""
            elif ins.mnemonic in ("bl", "b") and "#" in ins.op_str:
                try:
                    tgt = int(ins.op_str.split("#")[-1], 16)
                except ValueError:
                    tgt = None
                if tgt is not None:
                    hits = by_addr.get(tgt)
                    if hits:
                        line += f"   ; -> {hits[0]}"
                    else:
                        # nearest symbol below
                        near = max((a for a in by_addr if a <= tgt), default=None)
                        if near is not None and tgt - near < 0x800:
                            line += f"   ; -> {by_addr[near][0]}+{tgt-near:#x}"
            if ins.mnemonic in ("mov", "movz") and ins.op_str.startswith("x8, "):
                try:
                    line += f"   ; syscall {int(ins.op_str.split('#')[-1], 0)}"
                except ValueError:
                    pass
            if ins.mnemonic == "svc":
                line += "   ; SVC"
            out.append(line)
            n += 1
            if n > 2200:
                out.append("...truncated")
                break
    txt = "\n".join(out)
    if out_name:
        (OUT / out_name).write_text(txt + "\n", encoding="utf-8", errors="replace")
        print("wrote", OUT / out_name, len(txt), "bytes")
    else:
        print(txt)


if __name__ == "__main__":
    args = sys.argv[1:]
    annotate(Path(args[0]), args[1].split(","), args[2] if len(args) > 2 else None)
