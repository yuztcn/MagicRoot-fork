#!/usr/bin/env python3
"""Inventory all ELF binaries / kernel modules in the extracted reference zip."""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\refs\oneplus-v270-zip")


def elf_header(d: bytes):
    if len(d) < 0x40 or d[:4] != b"\x7fELF":
        return None
    ei_class = d[4]
    ei_data = d[5]
    e_type = struct.unpack_from("<H" if ei_data == 1 else ">H", d, 0x10)[0]
    e_machine = struct.unpack_from("<H" if ei_data == 1 else ">H", d, 0x12)[0]
    fmt = "<" if ei_data == 1 else ">"
    if ei_class == 2:
        e_entry = struct.unpack_from(fmt + "Q", d, 0x18)[0]
        e_phoff = struct.unpack_from(fmt + "Q", d, 0x20)[0]
        e_shoff = struct.unpack_from(fmt + "Q", d, 0x28)[0]
        e_phentsize = struct.unpack_from(fmt + "H", d, 0x36)[0]
        e_phnum = struct.unpack_from(fmt + "H", d, 0x38)[0]
        e_shentsize = struct.unpack_from(fmt + "H", d, 0x3A)[0]
        e_shnum = struct.unpack_from(fmt + "H", d, 0x3C)[0]
        e_shstrndx = struct.unpack_from(fmt + "H", d, 0x3E)[0]
    else:
        e_entry = struct.unpack_from(fmt + "I", d, 0x18)[0]
        e_phoff = struct.unpack_from(fmt + "I", d, 0x1C)[0]
        e_shoff = struct.unpack_from(fmt + "I", d, 0x20)[0]
        e_phentsize = struct.unpack_from(fmt + "H", d, 0x2A)[0]
        e_phnum = struct.unpack_from(fmt + "H", d, 0x2C)[0]
        e_shentsize = struct.unpack_from(fmt + "H", d, 0x2E)[0]
        e_shnum = struct.unpack_from(fmt + "H", d, 0x30)[0]
        e_shstrndx = struct.unpack_from(fmt + "H", d, 0x32)[0]
    # sections & symbol counts
    secs = []
    if e_shoff and e_shnum and e_shentsize:
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            if ei_class == 2:
                sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size = struct.unpack_from(fmt + "IIQQQQ", d, o)
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size = struct.unpack_from(fmt + "IIIIII", d, o)
            secs.append((sh_name, sh_type, sh_off, sh_size))
    symcount = 0
    dynsym = 0
    if secs and e_shstrndx < len(secs):
        strbase = secs[e_shstrndx][2]
        for name_off, sh_type, sh_off, sh_size in secs:
            end = d.find(b"\x00", strbase + name_off)
            name = d[strbase + name_off:end].decode("ascii", "replace")
            if name == ".symtab":
                symcount = sh_size // (24 if ei_class == 2 else 16)
            if name == ".dynsym":
                dynsym = sh_size // (24 if ei_class == 2 else 16)
    shn = e_shnum
    return dict(cls=ei_class, data=ei_data, type=e_type, machine=e_machine,
                entry=e_entry, secs=len(secs), syms=symcount, dynsyms=dynsym,
                size=len(d))


print("file\tsize\tsha256_16\tclass\ttype\tmachine\tentry\tsections\tsyms\tdynsyms\tkind")
byhash = {}
for p in sorted(ROOT.rglob("*")):
    if not p.is_file():
        continue
    d = p.read_bytes()
    h = hashlib.sha256(d).hexdigest()
    hdr = elf_header(d)
    kind = ""
    if hdr:
        kind = {183: "aarch64", 62: "x86_64", 40: "arm"}.get(hdr["machine"], str(hdr["machine"]))
        if hdr["type"] == 1:
            kind += "-ET_REL"
        elif hdr["type"] == 2:
            kind += "-EXEC"
        elif hdr["type"] == 3:
            kind += "-DYN"
    elif p.suffix == ".bin":
        kind = "not-elf"
    print(f"{p.relative_to(ROOT)}\t{len(d)}\t{h[:16]}\t"
          f"{hdr['cls'] if hdr else '-'}\t{hdr['type'] if hdr else '-'}\t"
          f"{hdr['machine'] if hdr else '-'}\t{hdr['entry'] if hdr else '-'}\t"
          f"{hdr['secs'] if hdr else '-'}\t{hdr['syms'] if hdr else '-'}\t"
          f"{hdr['dynsyms'] if hdr else '-'}\t{kind}")
    byhash.setdefault(h, []).append(str(p.relative_to(ROOT)))

print("\n=== duplicate hashes ===")
for h, files in byhash.items():
    if len(files) > 1:
        print(h[:16], files)
