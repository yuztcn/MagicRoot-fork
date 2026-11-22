#!/usr/bin/env python3
"""Static reverse-engineering of every native binary in the reference v2.7.0
zip: ELF layout, symbols, imports, strings, call graph and targeted
disassembly.  Outputs are written under refs/analysis/ (not shipped)."""
from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_bakasu_lkm import parse_elf, read_symtab  # noqa: E402
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM  # noqa: E402

WS = Path(__file__).resolve().parent.parent
ROOT = WS / "refs/oneplus-v270-zip"
OUT = WS / "refs/analysis"
OUT.mkdir(parents=True, exist_ok=True)
OURS = WS / "main/app/assets"

INTERESTING = re.compile(
    rb"(/sys/|/proc/|/dev/|/data/|/system/|/vendor/|/sdcard/|/storage/|"
    rb"tracepoint|trace_pipe|sched_blocked|kmem_cache|perf|futex|pipe|msg|"
    rb"selinux|permissive|enforce|cred|uid|gid|caps?|cap_|modprobe|finit|"
    rb"insmod|module|kaslr|slide|symbol|kallsyms|KernelSU|ksu|magisk|su_|"
    rb"ioctl|syscall|mmap|mprotect|ptrace|posix|cpu.timer|timer|uaf|spray|"
    rb"fork|exec|root|grant|reboot|manager|signature|dynamic|worker|victim)")


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def elf_map(d: bytes):
    """Return (segments [(vaddr, filesz, off)], sections, symbols)."""
    e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
    e_phnum = struct.unpack_from("<H", d, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", d, o)[0]
        p_offset, p_vaddr, _, p_filesz, _ = struct.unpack_from("<QQQQQ", d, o + 8)
        if p_type == 1:  # PT_LOAD
            segs.append((p_vaddr, p_filesz, p_offset))
    d2, sections = parse_elf(Path()) if False else (None, [])
    # parse_elf needs a path; use a lightweight inline parse here
    e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size = struct.unpack_from("<IIQQQQ", d, o)
        secs.append(dict(name_off=sh_name, type=sh_type, flags=sh_flags, addr=sh_addr,
                         off=sh_off, size=sh_size))
    strbase = secs[e_shstrndx]["off"] if e_shstrndx < len(secs) else 0
    for s in secs:
        end = d.find(b"\0", strbase + s["name_off"])
        s["name"] = d[strbase + s["name_off"]:end].decode("ascii", "replace")
    return segs, secs


def v2o(segs, va):
    for vaddr, filesz, off in segs:
        if vaddr <= va < vaddr + filesz:
            return off + (va - vaddr)
    return None


def extract_strings(d: bytes, mn=4):
    out = []
    cur = bytearray()
    for b in d:
        if 32 <= b < 127 or b in (9,):
            cur.append(b)
        else:
            if len(cur) >= mn:
                out.append(cur.decode("ascii", "replace"))
            cur = bytearray()
    if len(cur) >= mn:
        out.append(cur.decode("ascii", "replace"))
    return out


def str_at(d, segs, va, n=120):
    off = v2o(segs, va)
    if off is None:
        return None
    end = d.find(b"\0", off, off + n)
    if end < 0:
        end = off + n
    s = d[off:end]
    if not s or any(b < 32 or b >= 127 for b in s):
        return None
    return s.decode("ascii", "replace")


def analyze_target(p: Path):
    rel = p.relative_to(ROOT).as_posix()
    d = p.read_bytes()
    segs, secs = elf_map(d)
    hdr = struct.unpack_from("<H", d, 0x10)[0], struct.unpack_from("<H", d, 0x12)[0]
    syms = []
    try:
        _, sections = parse_elf(p)
        syms = read_symtab(d, sections)
    except Exception as exc:
        print("symtab error", rel, exc)
    strings = extract_strings(d)
    interesting = sorted({s for s in strings if INTERESTING.search(s.encode())})
    # write artifacts
    base = OUT / rel.replace("\\", "_").replace("/", "_")
    base.parent.mkdir(parents=True, exist_ok=True)
    (base.with_name(base.name + ".strings.txt")).write_text("\n".join(strings) + "\n",
                                                  encoding="utf-8", errors="replace")
    (base.with_name(base.name + ".interesting.txt")).write_text("\n".join(interesting) + "\n",
                                                      encoding="utf-8", errors="replace")
    funcs = [s for s in syms if s["typ"] == 2 and s["shndx"] and s["name"]]
    funcs.sort(key=lambda s: s["size"], reverse=True)
    (base.with_name(base.name + ".symbols.txt")).write_text(
        "\n".join(f"{hex(s['value'])} {s['size']:6d} {s['name']}" for s in funcs) + "\n",
        encoding="utf-8", errors="replace")
    undef = [s for s in syms if s["shndx"] == 0 and s["bind"] != 0]
    (base.with_name(base.name + ".imports.txt")).write_text(
        "\n".join(sorted({s["name"] for s in undef})) + "\n", encoding="utf-8", errors="replace")

    if not funcs:
        raw = struct.unpack_from("<Q", d, 0x18)[0]
        f = dict(name="_entry", value=raw, size=min(6000, len(d) - (v2o(segs, raw) or 0)))
        funcs = [f]
    targeted = []
    wanted = re.compile(r"(exploit|perf|cred|trace|futex|msg|patch|resolve|writer|perm|"
                        r"fork|spray|uaf|timer|slide|kaslr|selinux|grant|reboot|ioctl|mmap|"
                        r"mprotect|syscall|exec|setup|init|main|run|core)", re.I)
    cand = [s for s in funcs if s["name"] in ("main", "entry", "_start")
            or wanted.search(s["name"])]
    cand.sort(key=lambda s: (s["name"] != "main", s["name"] != "_start", -s["size"]))
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    lines = []
    for f in cand[:24]:
        off = v2o(segs, f["value"])
        if off is None:
            continue
        size = min(f["size"], 12000)
        lines.append(f"\n===== {f['name']} @ {hex(f['value'])} size={f['size']}")
        n = 0
        last_x8 = None
        for ins in md.disasm(d[off:off + size], f["value"]):
            line = f"{ins.address:x}: {ins.mnemonic}\t{ins.op_str}"
            if ins.mnemonic in ("mov", "movz", "movn") and ins.op_str.startswith("x8, "):
                try:
                    last_x8 = int(ins.op_str.split("#")[-1], 0)
                except ValueError:
                    last_x8 = None
            if ins.mnemonic == "svc" and last_x8 is not None:
                line += f"   ; syscall {last_x8}"
                last_x8 = None
            # annotate rodata string references from adrp immediate
            if ins.mnemonic == "adrp" and "#0x" in ins.op_str:
                try:
                    page = int(ins.op_str.split("#")[1].split(",")[0], 16)
                    # adrp operand is absolute page; try strings around page
                    for delta in range(0, 0x1000, 8):
                        s = str_at(d, segs, page + delta, 60)
                        if s and len(s) > 6:
                            line += f"   ; -> \"{s[:70]}\""
                            break
                except Exception:
                    pass
            lines.append(line)
            n += 1
            if n >= 1500:
                lines.append("... (truncated)")
                break
        targeted.append(f["name"])
    (base.with_name(base.name + ".disasm.txt")).write_text("\n".join(lines) + "\n",
                                                 encoding="utf-8", errors="replace")

    summary = dict(path=rel, size=len(d), sha256=sha(p),
                   type=hdr[0], machine=hdr[1],
                   funcs=len(funcs), imports=len({s["name"] for s in undef}),
                   strings=len(strings), interesting=len(interesting),
                   targeted=targeted)
    return summary


def main() -> int:
    targets = []
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT).as_posix()
        if not (rel.startswith("assets/") or rel.endswith(".dex")):
            continue
        d = p.read_bytes()
        if d[:4] == b"\x7fELF":
            targets.append(p)
    print("targets:", [t.relative_to(ROOT).as_posix() for t in targets])
    summaries = []
    for p in targets:
        print("analyzing", p.relative_to(ROOT))
        summaries.append(analyze_target(p))
    # compare with our assets
    ours = {}
    for name in ("forker", "t64560_v36", "ksu_grant", "addrcalc"):
        q = OURS / name
        if q.exists():
            ours[name] = sha(q)
    json.dump({"binaries": summaries, "our_hashes": ours},
              (OUT / "summary.json").open("w", encoding="utf-8"), indent=2)
    print("wrote", OUT / "summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
