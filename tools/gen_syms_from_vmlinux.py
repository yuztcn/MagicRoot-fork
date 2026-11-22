#!/usr/bin/env python3
"""Generate per-flavor syms tables from a vmlinux ELF for a given KMI.

The kernel ELF (vmlinux) provides the exact link-time addresses; the module
template provides the exact set of undefined symbols that need rebasing.
Output format matches ko_patch.c: "<name> 0x<addr>" per line.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_bakasu_lkm import parse_elf, read_symtab  # noqa: E402
from elftools.elf.elffile import ELFFile  # noqa: E402

WS = Path(__file__).resolve().parent.parent
A = WS / "main/app/assets"
TEMPLATES = {
    "resukisu": "ksu-template-bakasu.ko",
    "kernelsu": "ksu-template.ko",
    "next": "ksu-template-next.ko",
    "sukisu": "ksu-template-sukisu.ko",
    "fina": "ksu-template-fina.ko",
}


def elf_symbols(path: Path) -> dict[str, int]:
    out: dict[str, int] = {}
    with path.open("rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise SystemExit(f"{path}: no .symtab")
        for sym in symtab.iter_symbols():
            name = sym.name
            if not name or name.startswith("$"):
                continue
            shndx = sym["st_shndx"]
            if isinstance(shndx, str) or shndx == 0:  # UNDEF
                continue
            # first definition wins; kernel aliases are usually identical
            out.setdefault(name, sym["st_value"])
    return out


def module_undefined(path: Path) -> list[str]:
    data, sections = parse_elf(path)
    syms = read_symtab(data, sections)
    return sorted({s["name"] for s in syms
                   if s["shndx"] == 0 and s["bind"] != 0 and s["name"]})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vmlinux", required=True)
    ap.add_argument("--profile", required=True, choices=["61258", "6138", "61258c"])
    ap.add_argument("--write", action="store_true",
                    help="write/replace syms_<profile>[_<flavor>].txt in assets")
    ap.add_argument("--flavors", default="",
                    help="comma-separated subset (default: all five)")
    args = ap.parse_args()

    symbols = elf_symbols(Path(args.vmlinux))
    print(f"vmlinux symbols: {len(symbols)}")
    total_missing = 0
    only = {x.strip() for x in args.flavors.split(",") if x.strip()}
    for flavor, template in TEMPLATES.items():
        if only and flavor not in only:
            continue
        undef = module_undefined(A / template)
        missing = [n for n in undef if n not in symbols]
        total_missing += len(missing)
        print(f"{flavor:9s} undefined={len(undef):3d} "
              f"missing={len(missing):3d}"
              + (f" sample={missing[:5]}" if missing else ""))
        if missing:
            continue
        lines = [f"{name} 0x{symbols[name]:x}" for name in undef]
        suffix = "" if flavor == "kernelsu" else f"_{flavor}"
        out = A / f"syms_{args.profile}{suffix}.txt"
        if args.write:
            out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            print(f"  wrote {out.name} ({len(lines)} lines)")
        elif out.exists():
            old = {}
            for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    old[parts[0]] = int(parts[1], 0)
            mismatch = [n for n in undef if n in old and old[n] != symbols[n]]
            print(f"  existing {out.name}: names={len(old)} address_mismatch={len(mismatch)}")
    print("TOTAL MISSING", total_missing)
    return 0 if total_missing == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
