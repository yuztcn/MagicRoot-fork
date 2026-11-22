#!/usr/bin/env python3
"""Generate an extended MagicRoot syms table for a BakaSU LKM.

MagicRoot's ko_patch resolves non-exported kernel symbols to SHN_ABS absolute
addresses taken from a syms table (``<name> 0x<link_addr>`` where
``runtime = link_addr + kaslr_slide``).  The stock syms_61258.txt was built for
the official KernelSU LKM; the BakaSU build imports a slightly different set.
This tool unions the stock table with every still-undefined symbol found in the
live ``/proc/kallsyms`` snapshot (as root, with kptr_restrict=0).

Usage:
  gen_syms.py --kallsyms <dump> --slide 0x252aa00000 \
              --base main/app/assets/syms_61258.txt \
              --lkm <bakasu 6.12 template.ko> \
              --out main/app/assets/syms_61258_bakasu.txt
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_bakasu_lkm import parse_elf, read_symtab  # noqa: E402

MASK = (1 << 64) - 1


def load_kallsyms(path: Path):
    syms = {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            addr, typ, name = parts[0], parts[1], parts[2]
            if not name or name.startswith("$"):
                continue
            if len(parts) >= 4 and "[" in parts[3]:
                continue  # module symbol, not kernel text/data
            try:
                v = int(addr, 16)
            except ValueError:
                continue
            if v == 0:
                continue
            # first occurrence wins (kallsyms may list aliases)
            syms.setdefault(name, v)
    return syms


def load_base_syms(path: Path):
    out = {}
    if not path.exists():
        return out
    for line in path.read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].lower().startswith("0x"):
            out[parts[0]] = int(parts[1], 16)
    return out


def undefined_symbols(lkm: Path):
    d, sections = parse_elf(lkm)
    syms = read_symtab(d, sections)
    names = []
    for s in syms:
        if s["shndx"] == 0 and s["bind"] != 0 and s["name"]:
            names.append(s["name"])
    return sorted(set(names))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kallsyms", required=True)
    ap.add_argument("--slide", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--lkm", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", default=None)
    args = ap.parse_args()

    slide = int(args.slide, 0)
    ks = load_kallsyms(Path(args.kallsyms))
    base = load_base_syms(Path(args.base))
    undef = undefined_symbols(Path(args.lkm))

    # Link address = runtime address - slide (as a 64-bit wrap-around value).
    def to_link(runtime: int) -> int:
        return (runtime - slide) & MASK

    added, missing = [], []
    for name in undef:
        if name in base:
            continue
        if name in ks:
            base[name] = to_link(ks[name])
            added.append(name)
        else:
            missing.append(name)

    # Sanity check the anchor used by run.sh.
    anchor = "_printk"
    ok_anchor = None
    if anchor in ks and anchor in base:
        ok_anchor = to_link(ks[anchor]) == base[anchor]

    out_lines = [f"{name} 0x{addr:016x}" for name, addr in sorted(base.items())]
    out = Path(args.out)
    out.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    report = [
        f"# syms generation report for {Path(args.lkm).name}",
        "",
        f"slide: 0x{slide:x}",
        f"kallsyms symbols: {len(ks)}",
        f"base syms: {len(base) - len(added)}",
        f"undefined in LKM: {len(undef)}",
        f"added from kallsyms: {len(added)}",
        f"still missing: {len(missing)}",
        f"_printk anchor consistent: {ok_anchor}",
        "",
        "## added",
        *[f"- {n}" for n in added],
        "",
        "## missing",
        *[f"- {n}" for n in missing],
        "",
    ]
    text = "\n".join(report)
    if args.report:
        Path(args.report).write_text(text, encoding="utf-8")
    print(text)
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
