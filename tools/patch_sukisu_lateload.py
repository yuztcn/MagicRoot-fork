#!/usr/bin/env python3
"""Patch the SukiSU late-load-only input-hook cleanup to a no-op.

MagicRoot loads this LKM late.  In that mode upstream core/init.c deliberately
skips ksu_ksud_init(), including INIT_WORK(stop_input_hook_work), but
on_post_fs_data() still schedules that work.  The uninitialized list triggers
WARN_ON(!list_empty(&work->entry)).  Returning from the cleanup is correct for
this late-load-only template because no input kprobe/work was installed.

This tool intentionally patches only a hash-locked, relocatable ELF template at
its named function symbol.  It is not a general module binary editor.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "main/app/assets/ksu-template-sukisu.ko"
OUTPUT = ROOT / "main/app/assets/ksu-template-sukisu-lateload.ko"
INPUT_SHA256 = "9f999173fa65b3eb3a90e2becf2bf5ec42a5c5f7d58106802aaa9f8c16f71048"
FUNCTION = "ksu_stop_input_hook_runtime"
AARCH64_RET = bytes.fromhex("c0035fd6")
# Keep the first ADRP and LDRB intact: both carry relocations that the kernel
# applies again at insmod.  Patch the following TBNZ, which has no relocation
# and returns before any stack or workqueue operation.
PATCH_OFFSET = 8
EXPECTED_PATCH_INSN = bytes.fromhex("c9010037")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def elf_layout(data: bytes) -> tuple[list[dict], list[str]]:
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
        raise ValueError("expected little-endian ELF64")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    if header[1] != 1 or header[2] != 183:
        raise ValueError("expected an AArch64 relocatable module")
    shoff, shentsize, shnum, shstrndx = header[6], header[11], header[12], header[13]
    if shentsize != 64 or shnum <= shstrndx:
        raise ValueError("invalid ELF section table")
    sections = []
    for index in range(shnum):
        values = struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)
        sections.append({
            "name_offset": values[0], "type": values[1], "offset": values[4],
            "size": values[5], "link": values[6], "info": values[7],
            "addr": values[3], "entsize": values[9],
        })
    names = sections[shstrndx]
    table = data[names["offset"]:names["offset"] + names["size"]]
    for section in sections:
        end = table.find(b"\0", section["name_offset"])
        section["name"] = table[section["name_offset"]:end].decode("ascii")
    return sections, [str(s["name"]) for s in sections]


def symbol_file_offset(data: bytes, name: str) -> int:
    sections, _ = elf_layout(data)
    for symtab in sections:
        if symtab["type"] != 2 or symtab["entsize"] != 24:
            continue
        strings = sections[symtab["link"]]
        strdata = data[strings["offset"]:strings["offset"] + strings["size"]]
        for offset in range(symtab["offset"], symtab["offset"] + symtab["size"], 24):
            name_offset, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", data, offset)
            end = strdata.find(b"\0", name_offset)
            symbol = strdata[name_offset:end].decode("utf-8", errors="replace")
            if symbol != name:
                continue
            if info & 0x0F != 2 or shndx == 0 or shndx >= len(sections) or size < 4:
                raise ValueError(f"unexpected symbol type/layout for {name}")
            section = sections[shndx]
            file_offset = section["offset"] + value
            if file_offset + 4 > len(data):
                raise ValueError("symbol points outside the file")
            return file_offset
    raise ValueError(f"symbol not found: {name}")


def assert_no_relocation(data: bytes, file_offset: int) -> None:
    """Fail if the bytes we replace are a relocation site in their section."""
    sections, _ = elf_layout(data)
    owner_index = -1
    target_offset = -1
    for index, section in enumerate(sections):
        if section["type"] == 8:  # SHT_NOBITS has no file bytes.
            continue
        if section["offset"] <= file_offset < section["offset"] + section["size"]:
            owner_index = index
            target_offset = section["addr"] + file_offset - section["offset"]
            break
    if owner_index < 0:
        raise ValueError("patch offset does not belong to an ELF section")
    for section in sections:
        if section["type"] not in (4, 9) or section["info"] != owner_index:
            continue  # SHT_RELA=4, SHT_REL=9
        entry_size = section["entsize"] or (24 if section["type"] == 4 else 16)
        for offset in range(section["offset"], section["offset"] + section["size"], entry_size):
            relocation_offset = struct.unpack_from("<Q", data, offset)[0]
            if relocation_offset == target_offset:
                raise ValueError("refusing to patch an ELF relocation site")


def patch(data: bytes) -> bytes:
    if sha256(data) != INPUT_SHA256:
        raise ValueError("input SHA-256 does not match the audited SukiSU template")
    offset = symbol_file_offset(data, FUNCTION) + PATCH_OFFSET
    if data[offset:offset + 4] != EXPECTED_PATCH_INSN:
        raise ValueError("unexpected instruction at relocation-safe patch site")
    assert_no_relocation(data, offset)
    output = bytearray(data)
    output[offset:offset + 4] = AARCH64_RET
    return bytes(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=INPUT)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        raise SystemExit("input and output must be different files")
    result = patch(args.input.read_bytes())
    args.output.write_bytes(result)
    print(f"input_sha256={INPUT_SHA256}")
    print(f"output_sha256={sha256(result)}")
    print(f"function={FUNCTION} patch=ret_at_plus_{PATCH_OFFSET} bytes={len(result)}")


if __name__ == "__main__":
    main()
