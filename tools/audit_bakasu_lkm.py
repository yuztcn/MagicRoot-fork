#!/usr/bin/env python3
"""Audit BakaSU LKM candidates against MagicRoot's ko_patch symbol patching.

Outputs a report to docs/reference/bakasu-lkm-audit.md.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import zipfile
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
UP = WS / "refs" / "upstream" / "bakasu"
LKM_DIR = UP / "lkm"
DOCS = WS / "docs" / "reference"
DOCS.mkdir(parents=True, exist_ok=True)

SHN_UNDEF = 0
SHN_ABS = 0xFFF1


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_elf(path: Path):
    d = path.read_bytes()
    if d[:4] != b"\x7fELF" or d[4] != 2:
        raise ValueError("not ELF64")
    e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
    shstr_off = struct.unpack_from("<Q", d, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
    sections = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name = struct.unpack_from("<I", d, o)[0]
        typ = struct.unpack_from("<I", d, o + 4)[0]
        flags = struct.unpack_from("<Q", d, o + 8)[0]
        addr, off, size = struct.unpack_from("<QQQ", d, o + 0x10)
        link, info = struct.unpack_from("<II", d, o + 0x28)
        entsize = struct.unpack_from("<Q", d, o + 0x38)[0]
        end = d.index(b"\0", shstr_off + name)
        nm = d[shstr_off + name:end].decode("utf-8", "replace")
        sections.append(dict(name=nm, type=typ, flags=flags, addr=addr, off=off,
                             size=size, link=link, info=info, entsize=entsize))
    return d, sections


def section_by_name(sections, name):
    for s in sections:
        if s["name"] == name:
            return s
    return None


def read_modinfo(d, sections):
    s = section_by_name(sections, ".modinfo")
    info = {}
    if not s:
        return info
    blob = d[s["off"]:s["off"] + s["size"]]
    for entry in blob.split(b"\0"):
        if b"=" in entry:
            k, v = entry.split(b"=", 1)
            info[k.decode()] = v.decode("utf-8", "replace")
    return info


def read_symtab(d, sections):
    symtab = section_by_name(sections, ".symtab")
    strtab_s = None
    for s in sections:
        if s["name"] == ".strtab":
            strtab_s = s
    if not symtab or not strtab_s:
        return []
    strtab = d[strtab_s["off"]:strtab_s["off"] + strtab_s["size"]]
    out = []
    n = symtab["size"] // 24
    for i in range(n):
        o = symtab["off"] + i * 24
        st_name, st_info, st_other, st_shndx = struct.unpack_from("<IBBH", d, o)
        st_value, st_size = struct.unpack_from("<QQ", d, o + 8)
        end = strtab.index(b"\0", st_name)
        name = strtab[st_name:end].decode("utf-8", "replace")
        out.append(dict(name=name, shndx=st_shndx, value=st_value,
                        bind=st_info >> 4, typ=st_info & 0xF, size=st_size))
    return out


def read_versions(d, sections):
    """Return {symbol_name: crc} from __versions, best effort."""
    s = section_by_name(sections, "__versions")
    if not s:
        return {}
    strtab_s = section_by_name(sections, ".strtab")
    if not strtab_s:
        return {}
    strtab = d[strtab_s["off"]:strtab_s["off"] + strtab_s["size"]]
    out = {}
    n = s["size"] // 64
    for i in range(n):
        o = s["off"] + i * 64
        crc = struct.unpack_from("<Q", d, o)[0]
        name_off = struct.unpack_from("<Q", d, o + 8)[0]
        if 0 <= name_off < len(strtab):
            end = strtab.index(b"\0", name_off)
            name = strtab[name_off:end].decode("utf-8", "replace")
            out[name] = crc
    return out


def load_syms(path: Path):
    """Parse MagicRoot syms_*.txt: '<name> 0x<link_addr>' per line."""
    names = set()
    if not path.exists():
        return names
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].lower().startswith("0x"):
            names.add(parts[0])
    return names


def extract_lkms():
    LKM_DIR.mkdir(parents=True, exist_ok=True)
    report = []
    zips = {
        "6.6": UP / "nightly" / "aarch64-android15-6.6-lkm.zip",
        "6.12": UP / "nightly" / "aarch64-android16-6.12-lkm.zip",
        "6.18": UP / "nightly" / "aarch64-android17-6.18-lkm.zip",
    }
    # user-provided copies as fallback/compare
    extra = {
        "6.6-user": UP / "BakaSU-lkm-android15-6.6.zip",
    }
    for kmi, zp in list(zips.items()) + list(extra.items()):
        if not zp.exists():
            report.append({"kmi": kmi, "error": "zip missing"})
            continue
        z = zipfile.ZipFile(zp)
        names = z.namelist()
        entry = names[0]
        outdir = LKM_DIR / kmi
        outdir.mkdir(parents=True, exist_ok=True)
        out = outdir / Path(entry).name
        out.write_bytes(z.read(entry))
        report.append({"kmi": kmi, "zip": str(zp), "entry": entry, "path": str(out)})
        # also record new-style single .ko provided by user
    new_ko = UP / "lkm-aarch64-android15-6.6_kernelsu.new.ko"
    if new_ko.exists():
        outdir = LKM_DIR / "6.6-new"
        outdir.mkdir(parents=True, exist_ok=True)
        out = outdir / new_ko.name
        out.write_bytes(new_ko.read_bytes())
        report.append({"kmi": "6.6-new", "zip": str(new_ko), "entry": new_ko.name, "path": str(out)})
    return report


def main():
    extracted = extract_lkms()
    lines = ["# BakaSU LKM audit (for MagicRoot ko_patch integration)", ""]
    main_syms = load_syms(WS / "main" / "app" / "assets" / "syms_61258.txt")
    ml_syms = load_syms(WS / "refs" / "multikernel" / "app" / "assets" / "syms_66.txt")
    lines.append(f"MagicRoot syms_61258.txt symbols: {len(main_syms)}  "
                 f"syms_66.txt symbols: {len(ml_syms)}")
    lines.append("")
    rows = []
    for item in extracted:
        if "path" not in item:
            lines.append(f"- {item}")
            continue
        p = Path(item["path"])
        d, sections = parse_elf(p)
        modinfo = read_modinfo(d, sections)
        syms = read_symtab(d, sections)
        undef = [s for s in syms if s["shndx"] == SHN_UNDEF and s["bind"] != 0]
        versions = read_versions(d, sections)
        row = {
            "kmi": item["kmi"],
            "entry": item["entry"],
            "size": p.stat().st_size,
            "sha256": sha256_file(p),
            "vermagic": modinfo.get("vermagic"),
            "name": modinfo.get("name"),
            "undefined": len(undef),
            "defined_abs": sum(1 for s in syms if s["shndx"] == SHN_ABS),
            "versions": len(versions),
            "undefined_names": sorted({s["name"] for s in undef}),
        }
        rows.append(row)

    for r in rows:
        lines.append(f"## {r['kmi']} — {r['entry']}")
        lines.append("")
        lines.append(f"- size: {r['size']}")
        lines.append(f"- sha256: `{r['sha256']}`")
        lines.append(f"- vermagic: `{r['vermagic']}`")
        lines.append(f"- name: `{r['name']}`")
        lines.append(f"- undefined dynamic symbols: {r['undefined']}")
        lines.append(f"- SHN_ABS symbols: {r['defined_abs']}")
        lines.append(f"- __versions entries: {r['versions']}")
        un = r["undefined_names"]
        # symbol coverage against both syms tables
        cov61258 = len([n for n in un if n in main_syms])
        cov66 = len([n for n in un if n in ml_syms])
        lines.append(f"- covered by syms_61258.txt: {cov61258}/{len(un)}")
        lines.append(f"- covered by syms_66.txt: {cov66}/{len(un)}")
        missing_61258 = [n for n in un if n not in main_syms][:40]
        if r["kmi"].startswith("6.12"):
            lines.append(f"- missing in syms_61258 (first 40): {missing_61258}")
        if r["kmi"].startswith("6.6"):
            missing_66 = [n for n in un if n not in ml_syms][:40]
            lines.append(f"- missing in syms_66 (first 40): {missing_66}")
        lines.append("")
        print(f"{r['kmi']:8s} {r['size']:8d} {r['sha256'][:16]} undef={r['undefined']:4d} "
              f"abs={r['defined_abs']:4d} versions={r['versions']:4d} vermagic={r['vermagic']}")

    (DOCS / "bakasu-lkm-audit.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (DOCS / "bakasu-lkm-audit.json").write_text(
        json.dumps(rows, indent=2), encoding="utf-8")
    print("wrote", DOCS / "bakasu-lkm-audit.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
