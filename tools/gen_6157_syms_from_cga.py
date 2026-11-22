#!/usr/bin/env python3
"""Generate per-build 6.1.x symbol tables from the CGA base modules.

`g264/ksm-<build>-base.ko` is linked against the exact vendor kernel and keeps
every resolved kernel symbol as an SHN_ABS entry at its link-time (slide=0)
address; `ko_slide_patch` later adds the boot slide.  The manager-KO test path
reuses the same addresses: `ko_patch` reads `name 0xADDR`, adds the same slide
and rewrites the module's undefined-symbol entries, so a manager-extracted LKM
can be loaded on that build without borrowing another kernel's table.

Usage:
    python3 tools/gen_6157_syms_from_cga.py [--check]

Outputs: main/app/assets/g264/syms-<build>.txt
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "main/app/assets"
G264 = ASSETS / "g264"
CGA_PROFILES = ROOT / "binary-sources/61157-g264/cga-profiles.json"
SUCCESS_PROFILES = ROOT / "binary-sources/61157-g264/success-profiles.json"
SYMS_ELP_AN00 = ASSETS / "61157/syms_elp_an00.txt"
SYMS_G264_61157 = ASSETS / "61157/syms_g264.txt"
LINK_BIAS_61157 = 0x78000000

KEY_SYMBOLS = (
    "commit_creds",
    "prepare_creds",
    "override_creds",
    "revert_creds",
    "kallsyms_lookup_name",
    "_printk",
    "init_cred",
)


def find_readelf() -> str:
    for name in ("readelf", "llvm-readelf"):
        path = shutil.which(name)
        if path:
            return path
    raise SystemExit("readelf/llvm-readelf not found")


def parse_abs_symbols(elf: Path) -> list[tuple[str, int]]:
    out = subprocess.run(
        [find_readelf(), "-sW", str(elf)],
        check=True, capture_output=True, text=True, errors="replace",
    ).stdout
    syms: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[6] != "ABS":
            continue
        value = parts[1]
        name = parts[7]
        if not name or not re.fullmatch(r"[0-9a-fA-F]+", value):
            continue
        addr = int(value, 16)
        if addr == 0:
            continue
        # STT_FILE/STT_SECTION entries carry no useful kernel address.
        if name.endswith((".c", ".h", ".S")) or name.startswith("$"):
            continue
        syms.setdefault(name, addr)
    return sorted(syms.items())


def load_extra_symbols() -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    want_names: set[str] = set()
    if CGA_PROFILES.is_file():
        doc = json.loads(CGA_PROFILES.read_text(encoding="utf-8"))
        for build, prof in doc.get("profiles", {}).items():
            extra = prof.get("extra_symbols") or {}
            if extra:
                out[build] = {k: int(v) for k, v in extra.items()}
                want_names.update(out[build].keys())
    if SUCCESS_PROFILES.is_file():
        sdoc = json.loads(SUCCESS_PROFILES.read_text(encoding="utf-8"))
        for build, prof in sdoc.get("profiles", {}).items():
            bmap = out.setdefault(build, {})
            groups = prof.get("groups")
            if groups is not None:
                bmap.setdefault("init_groups", int(groups))
                bmap.setdefault("init_cred", int(groups) + 8)
            for sym_name, key in (
                ("init_user_ns", "user_ns"),
                ("root_user", "root_user"),
                ("init_ucounts", "ucounts"),
                ("sig_enforce", "sig_enforce"),
            ):
                val = prof.get(key)
                if val is not None:
                    bmap.setdefault(sym_name, int(val))
            sel_m7 = prof.get("selinux_minus7")
            if sel_m7 is not None:
                bmap.setdefault("selinux_state", int(sel_m7) + 7)
    if SYMS_ELP_AN00.is_file() and want_names:
        g7d_map = out.setdefault("g7d", {})
        for line in SYMS_ELP_AN00.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in want_names:
                addr = int(parts[1], 16)
                if addr >= 0xFFFFFFC080000000:
                    addr -= LINK_BIAS_61157
                g7d_map.setdefault(parts[0], addr)
    if SYMS_G264_61157.is_file():
        g264_map = out.setdefault("g264", {})
        for line in SYMS_G264_61157.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                addr = int(parts[1], 16)
                if addr >= 0xFFFFFFC080000000:
                    addr -= LINK_BIAS_61157
                g264_map.setdefault(parts[0], addr)
    return out


def render(base: Path, extra_by_build: dict[str, dict[str, int]]) -> tuple[Path, str, int, list[str]]:
    build = base.name[len("ksm-"):-len("-base.ko")]
    out = G264 / f"syms-{build}.txt"
    sym_map = dict(parse_abs_symbols(base))
    for name, addr in extra_by_build.get(build, {}).items():
        sym_map.setdefault(name, addr)
    syms = sorted(sym_map.items())
    text = "# 6.1.x CGA-resolved symbols; generated by tools/gen_6157_syms_from_cga.py\n"
    text += "".join(f"{name} 0x{addr:x}\n" for name, addr in syms)
    present = {name for name, _ in syms}
    missing = [name for name in KEY_SYMBOLS if name not in present]
    return out, text, len(syms), missing


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="fail instead of rewriting stale/missing tables")
    args = ap.parse_args()
    bases = sorted(G264.glob("ksm-*-base.ko"))
    if not bases:
        raise SystemExit(f"no CGA base modules under {G264}")
    extra_by_build = load_extra_symbols()
    stale = 0
    for base in bases:
        out, text, count, missing = render(base, extra_by_build)
        if missing:
            print(f"FAIL {out.name}: missing key symbols {','.join(missing)}",
                  file=sys.stderr)
            return 1
        if args.check:
            if not out.is_file() or out.read_text(encoding="utf-8") != text:
                print(f"FAIL stale/missing {out.relative_to(ROOT)}", file=sys.stderr)
                stale = 1
        else:
            out.write_text(text, encoding="utf-8", newline="\n")
        print(f"{out.name}: {count} symbols")
    if stale:
        return 1
    print("PASS 6157 CGA symbol tables current" if args.check
          else "WROTE 6157 CGA symbol tables")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
