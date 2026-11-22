#!/usr/bin/env python3
"""Compute and audit the 6.12.38 symbol tables required by the 6.12 templates.

Resolution source: the existing syms_6138[_flavor].txt tables, whose addresses
were generated from the 6.12.38 link-time map.  The script computes the exact
set of undefined symbols per template and verifies every one resolves; it writes
a required-set report under refs/kernel-audit/syms-6138-required/.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from elftools.elf.elffile import ELFFile

WS = Path(__file__).resolve().parent.parent
A = WS / "main" / "app" / "assets"
OUT = WS / "refs" / "kernel-audit" / "syms-6138-required"
OUT.mkdir(parents=True, exist_ok=True)

FLAVORS = [
    ("kernelsu", "ksu-template.ko", "syms_6138.txt"),
    ("resukisu", "ksu-template-bakasu.ko", "syms_6138_bakasu.txt"),
    ("next", "ksu-template-next.ko", "syms_6138_next.txt"),
    ("sukisu", "ksu-template-sukisu.ko", "syms_6138_sukisu.txt"),
    ("fina", "ksu-template-fina.ko", "syms_6138_fina.txt"),
]

ANCHORS = {
    "prepare_creds": 0xFFFFFFC080B8A21C,
    "selinux_state": 0xFFFFFFC0826663C8,
}


def module_undefined(path: Path) -> list[str]:
    with path.open("rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise SystemExit(f"{path}: no .symtab")
        return sorted({s.name for s in symtab.iter_symbols()
                       if s["st_shndx"] == "SHN_UNDEF" and s.name
                       and not s.name.startswith("$")})


def parse_syms(path: Path) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, addr = line.split()[:2]
        out[name] = int(addr, 0)
    return out


def main() -> int:
    lines = [
        "# 6.12.38 required syms audit",
        "",
        "Resolution source: existing `syms_6138[_flavor].txt` address tables.",
        "",
        "| flavor | template | required | resolved | missing | asset lines | extra | asset sha256 |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    bad = 0
    for flavor, tpl, syms_name in FLAVORS:
        undef = module_undefined(A / tpl)
        syms = parse_syms(A / syms_name)
        missing = [n for n in undef if n not in syms]
        if missing:
            bad += len(missing)
        resolved = {n: syms[n] for n in undef if n in syms}
        extra = sorted(set(syms) - set(undef))
        out = OUT / f"{flavor}.txt"
        out.write_text("".join(f"{n} 0x{resolved[n]:x}\n" for n in undef),
                       encoding="utf-8", newline="\n")
        digest = hashlib.sha256((A / syms_name).read_bytes()).hexdigest()
        lines.append(
            f"| {flavor} | `{tpl}` | {len(undef)} | {len(resolved)} | {len(missing)} | "
            f"{len(syms)} | {len(extra)} | `{digest[:16]}` |")
        if missing:
            lines.append(f"\n- **{flavor} missing**: {', '.join(missing)}")
    lines += ["", "Anchor checks:"]
    for name, want in ANCHORS.items():
        got = parse_syms(A / "syms_6138.txt").get(name)
        ok = got == want
        lines.append(f"- `{name}` = `0x{got:x}` (expected `0x{want:x}`): "
                     f"{'OK' if ok else 'MISMATCH'}")
        if not ok:
            bad += 1
    lines += ["", f"Result: {'FAIL' if bad else 'missing=0; all required symbols resolved'}"]
    report = WS / "docs" / "reference" / "syms-6138-audit.md"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(lines))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
