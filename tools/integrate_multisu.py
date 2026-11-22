#!/usr/bin/env python3
"""Integrate the MultiSU 6.12 KMI LKMs: extract the FinaSU 6.12 module, check
which undefined symbols are already covered by the existing syms tables, and
generate per-flavor syms for the 6.12.58 profile when needed."""
from __future__ import annotations

import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_bakasu_lkm import parse_elf, read_symtab  # noqa: E402

WS = Path(__file__).resolve().parent.parent
MS = Path(r"<LOCAL_USER>user\Documents\MultiSU")
A = WS / "main/app/assets"


def undefined(lkm: Path):
    d, sections = parse_elf(lkm)
    syms = read_symtab(d, sections)
    return sorted({s["name"] for s in syms
                   if s["shndx"] == 0 and s["bind"] != 0 and s["name"]})


def load_syms(path: Path):
    out = set()
    for line in path.read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].lower().startswith("0x"):
            out.add(parts[0])
    return out


def version_string(path: Path):
    d = path.read_bytes()
    for pat in (rb"KernelSU version (\d+)", rb"v(\d+)\.\d+\.\d+"):
        m = re.search(pat, d)
        if m:
            return m.group(0).decode("utf-8", "replace")
    return "?"


# 1. extract FinaSU 6.12 LKM from its kernel bundle
fina_src = None
with zipfile.ZipFile(MS / "FinaSU_v1.0.10_kernel-bundle.zip") as z:
    name = "arm64/android16-6.12_kernelsu.ko"
    data = z.read(name)
    fina_src = A / "ksu-template-fina.ko"
    fina_src.write_bytes(data)
    print("extracted", name, "->", fina_src.name, len(data), "B",
          version_string(fina_src))

# 2. copy the MultiSU 6.12 LKMs for next/sukisu
for src, dst in [
    (MS / "aarch64_android16-6.12_kernelsunext.ko", A / "ksu-template-next.ko"),
    (MS / "lkm-aarch64-android16-6.12_sukisu.ko", A / "ksu-template-sukisu.ko"),
]:
    dst.write_bytes(src.read_bytes())
    print("copied", src.name, "->", dst.name, dst.stat().st_size, "B",
          version_string(dst))

# 3. update FinaSU ksud fallback from v1.0.10
with zipfile.ZipFile(MS / "FinaSU_v1.0.10_33034-release.apk") as z:
    data = z.read("lib/arm64-v8a/libksud.so")
    (A / "ksud_fina").write_bytes(data)
    (A / "ksud_fina").chmod(0o755)
    print("ksud_fina <- v1.0.10 libksud.so", len(data), "B")

# 4. coverage check for the existing syms tables
print("\n=== syms coverage ===")
for lkm_name in ("ksu-template-next.ko", "ksu-template-sukisu.ko",
                 "ksu-template-fina.ko"):
    p = A / lkm_name
    u = undefined(p)
    for profile in ("61258", "6138"):
        base = load_syms(A / f"syms_{profile}.txt")
        missing = [n for n in u if n not in base]
        print(f"  {lkm_name}: undefined={len(u)} profile={profile} "
              f"missing={len(missing)} {missing[:8]}")
