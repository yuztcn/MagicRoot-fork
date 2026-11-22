#!/usr/bin/env python3
"""Verify the provided 6.12.58 g42fcf008ff5c profile.

This is a host-side consistency check: it re-reads the derived constants from
the stored vmlinux ELF/BTF and the generated syms tables.  It does not execute
the Android exploit.
"""
from __future__ import annotations

import hashlib
import re
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

WS = Path(__file__).resolve().parent.parent
VMLINUX = Path(r"C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260\work\boot-provided\vmlinux.elf")
BTF = Path(r"C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260\work\boot-provided\kernel.btf")
H = WS / "binary-sources/98260-6.12/pc98260_target_61258c.h"
A = WS / "main/app/assets"

CHECKS = {
    "LINK_SELINUX_STATE": "selinux_state",
    "LINK_INIT_USER_NS": "init_user_ns",
    "LINK_ROOT_USER": "root_user",
    "LINK_INIT_GROUPS": "init_groups",
    "LINK_INIT_UCOUNTS": "init_ucounts",
    "GEOM_MEMSTART_ADDR": "memstart_addr",
}
EXPECTED_U64 = {
    "LINK_ALLOC_TIMER": 0xFFFFFFC08051A1E8,
    "LINK_ALLOC_CRED": 0xFFFFFFC08018C904,
    "LINK_ALLOC_TASK": 0xFFFFFFC0801BF9C8,
}
FLAVORS = ["", "_resukisu", "_next", "_sukisu", "_fina"]


def symbols(path: Path) -> dict[str, int]:
    out = {}
    with path.open("rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if sec.name != ".symtab":
                continue
            for sym in sec.iter_symbols():
                if sym.name and sym["st_shndx"] != "SHN_UNDEF":
                    out.setdefault(sym.name, sym["st_value"])
    return out


def header_defines(text: str) -> dict[str, int]:
    out = {}
    for m in re.finditer(r"#define\s+(\w+)\s+UINT64_C\((0x[0-9a-fA-F]+)\)", text):
        out[m.group(1)] = int(m.group(2), 16)
    for m in re.finditer(r"#define\s+(GEO_\w+)\s+(0x[0-9a-fA-F]+|\d+)", text):
        out[m.group(1)] = int(m.group(2), 0)
    return out


def btf_offsets(blob: bytes) -> dict[str, dict[str, int]]:
    magic, ver, _flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from(
        "<HBBIIIII", blob, 0
    )
    assert magic == 0xEB9F and ver == 1
    types_blob = blob[hdr_len + type_off:hdr_len + type_off + type_len]
    strings = blob[hdr_len + str_off:hdr_len + str_off + str_len]

    def s(off: int) -> str:
        end = strings.find(b"\0", off)
        return strings[off:end].decode("utf-8", "replace")

    p = 0
    tid = 1
    types = {}
    while p < len(types_blob):
        name_off, info, size_type = struct.unpack_from("<III", types_blob, p)
        vlen = info & 0xFFFF
        kind = (info >> 24) & 0x1F
        p += 12
        members = []
        if kind in (4, 5):
            for _ in range(vlen):
                mn, mt, mo = struct.unpack_from("<III", types_blob, p)
                p += 12
                members.append((s(mn), mt, mo))
        elif kind == 3:
            p += 12
        elif kind == 1:
            p += 4
        elif kind == 6:
            p += 8 * vlen
        elif kind == 19:
            p += 12 * vlen
        elif kind == 13:
            p += 8 * vlen
        elif kind == 14:
            p += 4
        elif kind == 15:
            p += 12 * vlen
        elif kind == 17:
            p += 4
        types[tid] = (s(name_off), kind, size_type, members)
        tid += 1
    out = {}
    for _tid, (name, kind, size, members) in types.items():
        if kind not in (4, 5):
            continue
        if name in ("task_struct", "cred", "k_itimer"):
            out[name] = {"size": size, **{m[0]: m[2] // 8 for m in members}}
    return out


def main() -> int:
    syms = symbols(VMLINUX)
    text = H.read_text(encoding="utf-8")
    hdr = header_defines(text)
    fail = 0

    for macro, symbol in CHECKS.items():
        got = hdr.get(macro)
        want = syms.get(symbol)
        ok = got == want
        print(f"{'PASS' if ok else 'FAIL'} {macro} {symbol} header={got and hex(got)} vmlinux={want and hex(want)}")
        fail += not ok
    for macro, want in EXPECTED_U64.items():
        ok = hdr.get(macro) == want
        print(f"{'PASS' if ok else 'FAIL'} {macro} header={hdr.get(macro) and hex(hdr[macro])}")
        fail += not ok

    btf = btf_offsets(BTF.read_bytes())
    checks = [
        ("task_struct", "cred", 0x900),
        ("task_struct", "real_cred", 0x8F8),
        ("task_struct", "comm", 0x910),
        ("k_itimer", "it", 0x78),
        ("cred", None, 0xB8),
    ]
    for struct_name, member, want in checks:
        ent = btf.get(struct_name, {})
        got = ent.get("size") if member is None else ent.get(member)
        ok = got == want
        print(f"{'PASS' if ok else 'FAIL'} BTF {struct_name}{'.' + member if member else '.size'}={got and hex(got)}")
        fail += not ok

    for suffix in FLAVORS:
        syms_file = A / f"syms_61258c{suffix}.txt"
        if not syms_file.exists():
            print(f"FAIL missing {syms_file.name}")
            fail += 1
            continue
        names = {line.split()[0] for line in syms_file.read_text().splitlines() if line.split()}
        print(f"PASS syms {syms_file.name} entries={len(names)}")
    exe = A / "98260-61258c/exploit-android-key-ptr"
    print(f"{'PASS' if exe.exists() else 'FAIL'} exploit {exe.name} sha256={hashlib.sha256(exe.read_bytes()).hexdigest() if exe.exists() else '-'}")
    if not exe.exists():
        fail += 1
    print("RESULT", "PASS" if fail == 0 else f"FAIL ({fail})")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
