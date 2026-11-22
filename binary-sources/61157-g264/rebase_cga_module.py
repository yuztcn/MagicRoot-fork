#!/usr/bin/env python3
"""Deterministically rebase the g264 CGA module onto audited 6.1.128 builds.

The tool is a static ELF rewriter.  It never loads a module or executes an
input payload.  `extract` converts external kallsyms into a compact manifest;
`apply`/`verify` need only the locked g264 base and that manifest.

Only three classes of bytes may change:

* st_value fields of high-address SHN_ABS kernel symbols;
* the absolute qword in every live 16-byte .text.ksustub slot;
* the release token in the single .modinfo vermagic string.

Every other byte difference is rejected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import struct

BASE_SHA256 = os.environ.get(
    "CGA_BASE_SHA256", "6381ad16a904af8d7d2a702e04994ed22c3fd01c6e00229ec584634034a56c09")
KERNEL_START = 0xFFFFFFC000000000
SHN_ABS = 0xFFF1
SHT_SYMTAB = 2
SHT_STRTAB = 3
ALIASES = {
    "__flush_icache_range": "caches_clean_inval_pou",
    "__flush_dcache_area": "dcache_clean_inval_poc",
}
EXPECTED_ABS = int(os.environ.get("CGA_EXPECTED_ABS", "225"), 0)
EXPECTED_LIVE_STUBS = int(os.environ.get("CGA_EXPECTED_STUBS", "220"), 0)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Section:
    name: str
    kind: int
    flags: int
    offset: int
    size: int
    link: int
    ent_size: int


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    shndx: int
    offset: int


class Elf64:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 64 or data[:5] != b"\x7fELF\x02" or data[5] != 1:
            raise ValueError("not a little-endian ELF64 file")
        if struct.unpack_from("<H", data, 18)[0] != 183:
            raise ValueError("not an AArch64 ELF")
        shoff = struct.unpack_from("<Q", data, 40)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
        if shentsize < 64 or shnum == 0 or shoff + shentsize * shnum > len(data):
            raise ValueError("invalid section table")
        raw = []
        for index in range(shnum):
            off = shoff + index * shentsize
            name_off, kind, flags, _, offset, size, link, _, _, ent_size = \
                struct.unpack_from("<IIQQQQIIQQ", data, off)
            raw.append((name_off, kind, flags, offset, size, link, ent_size))
        if shstrndx >= len(raw):
            raise ValueError("invalid section-name table index")
        strings = raw[shstrndx]
        if strings[1] != SHT_STRTAB or strings[3] + strings[4] > len(data):
            raise ValueError("invalid section-name table")
        self.sections: list[Section] = []
        for name_off, kind, flags, offset, size, link, ent_size in raw:
            if name_off >= strings[4]:
                raise ValueError("invalid section name offset")
            # SHT_NOBITS sections have an in-memory size but no file bytes.
            if kind != 8 and offset + size > len(data):
                raise ValueError("invalid section bounds")
            start = strings[3] + name_off
            end = data.find(b"\0", start, strings[3] + strings[4])
            if end < 0:
                raise ValueError("unterminated section name")
            self.sections.append(Section(
                data[start:end].decode("utf-8", "replace"),
                kind, flags, offset, size, link, ent_size))

    def section(self, name: str) -> Section:
        for section in self.sections:
            if section.name == name:
                return section
        raise ValueError(f"missing section {name}")

    def symbols(self) -> list[Symbol]:
        symtab = next((s for s in self.sections if s.kind == SHT_SYMTAB), None)
        if symtab is None or symtab.ent_size != 24:
            raise ValueError("missing ELF64 symtab")
        if symtab.link >= len(self.sections):
            raise ValueError("invalid symtab string table")
        strings = self.sections[symtab.link]
        if strings.kind != SHT_STRTAB:
            raise ValueError("symtab does not link to a string table")
        out = []
        for offset in range(symtab.offset, symtab.offset + symtab.size, 24):
            name_off, _, _, shndx, value, _ = struct.unpack_from("<IBBHQQ", self.data, offset)
            start = strings.offset + name_off
            if name_off >= strings.size:
                raise ValueError("symbol name outside string table")
            end = self.data.find(b"\0", start, strings.offset + strings.size)
            if end < 0:
                raise ValueError("unterminated symbol name")
            out.append(Symbol(self.data[start:end].decode("utf-8", "replace"),
                              value, shndx, offset))
        return out


def read_elf_symbols(path: Path) -> dict[str, int]:
    """Return the first definition of every named symbol in an ELF64 file."""
    elf = Elf64(path.read_bytes())
    result: dict[str, int] = {}
    for symbol in elf.symbols():
        if symbol.name and symbol.shndx != 0:
            result.setdefault(symbol.name, symbol.value)
    return result


def _base_symbols(data: bytes) -> tuple[Elf64, dict[str, Symbol], dict[int, str]]:
    if sha256(data) != BASE_SHA256:
        raise ValueError("g264 CGA base hash mismatch")
    elf = Elf64(data)
    by_name: dict[str, Symbol] = {}
    by_addr: dict[int, str] = {}
    for symbol in elf.symbols():
        if symbol.shndx != SHN_ABS or symbol.value < KERNEL_START:
            continue
        if not symbol.name:
            raise ValueError(f"unnamed absolute symbol at 0x{symbol.offset:x}")
        if symbol.name in by_name:
            raise ValueError(f"duplicate absolute symbol {symbol.name}")
        if symbol.value in by_addr:
            raise ValueError(f"duplicate absolute address 0x{symbol.value:x}")
        by_name[symbol.name] = symbol
        by_addr[symbol.value] = symbol.name
    if len(by_name) != EXPECTED_ABS:
        raise ValueError(f"expected {EXPECTED_ABS} absolute symbols, found {len(by_name)}")
    return elf, by_name, by_addr


def _stub_slots(data: bytes, elf: Elf64, by_addr: dict[int, str]) -> list[tuple[int, int, str]]:
    section = elf.section(".text.ksustub")
    if section.size % 16:
        raise ValueError("invalid .text.ksustub size")
    slots = []
    for relative in range(0, section.size, 16):
        offset = section.offset + relative + 8
        value = struct.unpack_from("<Q", data, offset)[0]
        if value == 0:
            continue
        if value < KERNEL_START:
            raise ValueError(f"invalid stub address 0x{value:x} at 0x{offset:x}")
        if value not in by_addr:
            raise ValueError(f"unmapped stub address 0x{value:x} at 0x{offset:x}")
        slots.append((offset, value, by_addr[value]))
    if len(slots) != EXPECTED_LIVE_STUBS:
        raise ValueError(f"expected {EXPECTED_LIVE_STUBS} live stubs, found {len(slots)}")
    return slots


def resolve_stub(value: int, old_by_addr: dict[int, str],
                 symbols: dict[str, int]) -> int:
    """Resolve one old absolute stub target; never guess an unknown address."""
    name = old_by_addr.get(value)
    if name is None:
        raise ValueError(f"unknown stub address 0x{value:x}")
    target = symbols.get(name)
    if target is None:
        raise ValueError(f"missing target symbol {name}")
    return target


def _vermagic(data: bytes, elf: Elf64) -> tuple[int, int, str]:
    section = elf.section(".modinfo")
    body = data[section.offset:section.offset + section.size]
    marker = b"vermagic="
    first = body.find(marker)
    if first < 0 or body.find(marker, first + 1) >= 0:
        raise ValueError("expected exactly one .modinfo vermagic")
    release_start = first + len(marker)
    release_end = body.find(b" ", release_start)
    terminator = body.find(b"\0", release_start)
    if release_end < 0 or terminator < 0 or release_end > terminator:
        raise ValueError("malformed vermagic")
    release = body[release_start:release_end].decode("ascii")
    if not release.startswith("6.1."):
        raise ValueError(f"unexpected base vermagic {release}")
    return section.offset + release_start, release_end - release_start, release


def _patch_vermagic(buf: bytearray, elf: Elf64, kernel: str) -> tuple[int, int]:
    offset, length, _ = _vermagic(bytes(buf), elf)
    encoded = kernel.encode("ascii")
    if len(encoded) != length:
        raise ValueError("target vermagic length differs from the base")
    buf[offset:offset + length] = encoded
    return offset, length


def rebase_module(base: bytes, profile: dict) -> tuple[bytes, dict]:
    """Rewrite one audited profile and reject every unexplained byte change."""
    elf, by_name, by_addr = _base_symbols(base)
    symbols = profile.get("symbols")
    if not isinstance(symbols, dict):
        raise ValueError("profile has no symbol map")
    if set(symbols) != set(by_name):
        missing = sorted(set(by_name) - set(symbols))
        extra = sorted(set(symbols) - set(by_name))
        raise ValueError(f"symbol map mismatch missing={missing[:5]} extra={extra[:5]}")
    if profile.get("abs_count") != EXPECTED_ABS:
        raise ValueError("profile absolute-symbol count mismatch")
    if profile.get("stub_count") != EXPECTED_LIVE_STUBS:
        raise ValueError("profile stub count mismatch")
    for name, value in symbols.items():
        if not isinstance(value, int) or value < KERNEL_START:
            raise ValueError(f"invalid target address for {name}")

    slots = _stub_slots(base, elf, by_addr)
    buf = bytearray(base)
    allowed: set[int] = set()

    for name, symbol in by_name.items():
        target = symbols[name]
        struct.pack_into("<Q", buf, symbol.offset + 8, target)
        if target != symbol.value:
            allowed.update(range(symbol.offset + 8, symbol.offset + 16))

    for offset, old_value, name in slots:
        target = resolve_stub(old_value, by_addr, symbols)
        struct.pack_into("<Q", buf, offset, target)
        if target != old_value:
            allowed.update(range(offset, offset + 8))

    vstart, vlength = _patch_vermagic(buf, elf, profile["kernel"])
    _, _, base_kernel = _vermagic(base, elf)
    if profile["kernel"] != base_kernel:
        allowed.update(range(vstart, vstart + vlength))

    output = bytes(buf)
    _audit_difference(base, output, allowed)
    return output, {
        "abs": len(by_name),
        "stubs": len(slots),
        "changed_bytes": sum(a != b for a, b in zip(base, output)),
    }


def _audit_difference(base: bytes, output: bytes, allowed: set[int]) -> None:
    if len(base) != len(output):
        raise ValueError("module output length changed")
    for offset, (old, new) in enumerate(zip(base, output)):
        if old != new and offset not in allowed:
            raise ValueError(f"unexplained byte change at 0x{offset:x}")


def verify_module(base: bytes, profile: dict, candidate: bytes) -> dict:
    expected, report = rebase_module(base, profile)
    if candidate != expected:
        if len(candidate) == len(expected):
            diff = next(i for i, (a, b) in enumerate(zip(candidate, expected)) if a != b)
            raise ValueError(f"output differs from deterministic rebuild at 0x{diff:x}")
        raise ValueError("output size differs from deterministic rebuild")
    return report


def _parse_pairs(values: list[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        name, sep, value = item.partition("=")
        if not sep or not name or not value or name in result:
            raise ValueError(f"invalid or duplicate --{label} {item!r}")
        result[name] = value
    return result


def cmd_extract(args) -> None:
    base = args.base.read_bytes()
    if sha256(base) != BASE_SHA256:
        raise ValueError("g264 CGA base hash mismatch")
    elf, by_name, by_addr = _base_symbols(base)
    _stub_slots(base, elf, by_addr)
    vmlinux = _parse_pairs(args.vmlinux, "vmlinux")
    boots = _parse_pairs(args.boot_sha256, "boot-sha256")
    kernels = _parse_pairs(args.kernel, "kernel")
    names = set(vmlinux)
    if not names or set(boots) != names or set(kernels) != names:
        raise ValueError("--vmlinux, --boot-sha256 and --kernel must name the same profiles")
    profiles = {}
    for name in sorted(names):
        target = read_elf_symbols(Path(vmlinux[name]))
        missing = sorted(key for key in by_name
                         if target.get(ALIASES.get(key, key)) is None)
        if missing:
            raise ValueError(f"{name}: missing target symbols {missing}")
        profiles[name] = {
            "kernel": kernels[name],
            "boot_sha256": boots[name],
            "output": f"ksm-{name}-base.ko",
            "abs_count": EXPECTED_ABS,
            "stub_count": EXPECTED_LIVE_STUBS,
            "symbols": {key: target[ALIASES.get(key, key)] for key in by_name},
        }
        print(f"EXTRACT {name} symbols={len(profiles[name]['symbols'])} "
              f"kernel={kernels[name]}")
    doc = {"format": 1, "base_sha256": BASE_SHA256, "profiles": profiles}
    args.output.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(f"WROTE {args.output}")


def load_doc(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("format") != 1 or doc.get("base_sha256") != BASE_SHA256:
        raise ValueError("unsupported CGA profile manifest")
    return doc


def selected(doc: dict, only: str | None):
    names = sorted(doc["profiles"])
    if only:
        if only not in doc["profiles"]:
            raise ValueError(f"unknown profile {only}")
        names = [only]
    for name in names:
        yield name, doc["profiles"][name]


def cmd_apply(args) -> None:
    doc = load_doc(args.profiles)
    base = args.base.read_bytes()
    for name, profile in selected(doc, args.only):
        output, report = rebase_module(base, profile)
        digest = sha256(output)
        destination = args.output_root / profile["output"]
        if args.check:
            if not destination.is_file() or destination.read_bytes() != output:
                raise ValueError(f"{name}: output is stale or differs from deterministic rebuild")
            if profile.get("generated_sha256") != digest:
                raise ValueError(f"{name}: manifest output hash mismatch")
            print(f"OK {name} abs={report['abs']} stubs={report['stubs']} "
                  f"changed_bytes={report['changed_bytes']} sha256={digest}")
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            mode = destination.stat().st_mode if destination.exists() else 0o755
            destination.write_bytes(output)
            os.chmod(destination, mode)
            profile["generated_sha256"] = digest
            print(f"WROTE {name} abs={report['abs']} stubs={report['stubs']} "
                  f"changed_bytes={report['changed_bytes']} sha256={digest} "
                  f"path={destination}")
    if not args.check:
        args.profiles.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    ex = sub.add_parser("extract", help="create target maps from reconstructed vmlinux files")
    ex.add_argument("--base", type=Path, required=True)
    ex.add_argument("--vmlinux", action="append", default=[], metavar="NAME=PATH")
    ex.add_argument("--boot-sha256", action="append", default=[], metavar="NAME=SHA256")
    ex.add_argument("--kernel", action="append", default=[], metavar="NAME=UNAME_R")
    ex.add_argument("--output", type=Path, required=True)
    ex.set_defaults(func=cmd_extract)
    for name, check in (("apply", False), ("verify", True)):
        sub_parser = sub.add_parser(name, help="write or verify deterministic CGA modules")
        sub_parser.add_argument("--base", type=Path, required=True)
        sub_parser.add_argument("--profiles", type=Path, required=True)
        sub_parser.add_argument("--output-root", type=Path, required=True)
        sub_parser.add_argument("--only")
        sub_parser.set_defaults(func=cmd_apply, check=check)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
