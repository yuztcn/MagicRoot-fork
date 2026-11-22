#!/usr/bin/env python3
import argparse
import hashlib
import re
import shutil
import subprocess
from io import BytesIO
from pathlib import Path

from elftools.elf.elffile import ELFFile

TEMPLATE_SHA256 = "7e25d68419d08535d35e3630d9f0ff1a08e97a7026d36e878991eecb13554d9f"
KERNEL_RELEASE = "6.18.21-android17-5-ge186062ea75f-abogki564062290-4k"
MISSING = {
    "override_creds", "revert_creds", "__get_task_comm", "ebitmap_cmp",
    "krealloc_noprof", "kvrealloc_noprof", "tracepoint_srcu",
}
TARGET_SYMBOLS = {
    "do_timer_create": 0xffffffc0803e1f18,
    "prepare_creds": 0xffffffc08014cd64,
    "commit_creds": 0xffffffc08033f3f8,
    "selinux_state": 0xffffffc08299a6f0,
    "sized_strscpy": 0xffffffc08017d86c,
    "ebitmap_equal": 0xffffffc08019c4cc,
    "krealloc_node_align_noprof": 0xffffffc0801eaa04,
    "kvrealloc_node_align_noprof": 0xffffffc0802d49a8,
}


def read_kallsyms(path):
    symbols = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 3 and re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", fields[0]):
            name, value = fields[2], fields[0]
        elif len(fields) >= 2 and re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", fields[1]):
            name, value = fields[0], fields[1]
        else:
            continue
        symbols.setdefault(name, int(value, 16))
    return symbols


def symbols(path):
    elf = ELFFile(BytesIO(path.read_bytes()))
    table = elf.get_section_by_name(".symtab")
    if table is None:
        raise RuntimeError(f"{path}: missing .symtab")
    return list(table.iter_symbols()), elf


def undefined(path):
    entries, _ = symbols(path)
    return {s.name for s in entries if s["st_shndx"] == "SHN_UNDEF" and s.name}


def tool(name, directory):
    result = shutil.which(name, path=directory) if directory else shutil.which(name)
    if not result:
        raise RuntimeError(f"missing LLVM tool: {name}; pass --llvm-dir")
    return result


def main():
    source_dir = Path(__file__).resolve().parent
    root = source_dir.parent.parent
    assets = root / "main/app/assets/98260-61821-brm"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, default=assets / "ksu-template.ko")
    parser.add_argument("--kallsyms", type=Path, required=True)
    parser.add_argument("--syms", type=Path, default=assets / "syms_61821_brm.txt")
    # Historical recipe only.  The shipped g186 template is now upstream
    # 115 (same bytes as 98260-h1c/ksu-template-115.ko); never overwrite it.
    parser.add_argument("--output", type=Path,
                        default=root / "build/61821-brm/ksu-template-61821-kernelsu.legacy.ko")
    parser.add_argument("--build-dir", type=Path, default=root / "build/61821-brm")
    parser.add_argument("--llvm-dir")
    parser.add_argument("--ko-patch", type=Path)
    args = parser.parse_args()

    digest = hashlib.sha256(args.template.read_bytes()).hexdigest()
    if digest != TEMPLATE_SHA256:
        raise SystemExit(f"unexpected official template: sha256={digest}, expected={TEMPLATE_SHA256}")
    kernel = read_kallsyms(args.kallsyms)
    for name, address in TARGET_SYMBOLS.items():
        if kernel.get(name) != address:
            raise SystemExit(f"target mismatch: {name}={kernel.get(name)!r}, expected={address:#x}")
    if not MISSING.isdisjoint(kernel):
        raise SystemExit("target already exports one or more compatibility symbols; review before replacing them")
    if not MISSING <= undefined(args.template):
        raise SystemExit("the supplied template does not have the expected seven unresolved symbols")

    args.build_dir.mkdir(parents=True, exist_ok=True)
    compat = args.build_dir / "ksu_brm_compat.o"
    subprocess.run([
        tool("clang", args.llvm_dir), "--target=aarch64-linux-android", "-march=armv8.5-a",
        "-c", str(source_dir / "ksu_brm_compat.S"), "-o", str(compat),
    ], check=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        tool("ld.lld", args.llvm_dir), "-r", str(args.template), str(compat), "-o", str(args.output),
    ], check=True)

    needed = undefined(args.output)
    missing = sorted(needed - kernel.keys())
    if missing:
        raise SystemExit("unresolved target symbols: " + ",".join(missing))
    entries, elf = symbols(args.output)
    for name in MISSING:
        matches = [s for s in entries if s.name == name and s["st_shndx"] != "SHN_UNDEF"]
        if not matches:
            raise SystemExit(f"compatibility definition missing: {name}")
    if not elf.get_section_by_name(".gnu.linkonce.this_module"):
        raise SystemExit("module metadata missing after partial link")
    versions = elf.get_section_by_name("__versions")
    if versions is None or versions["sh_size"] != 0:
        raise SystemExit("unexpected MODVERSIONS records after partial link")
    modinfo = elf.get_section_by_name(".modinfo").data()
    if b"brm_compat=honor-6.18.21-ge186-v1\0" not in modinfo:
        raise SystemExit("BRM compatibility marker missing")

    _, template_elf = symbols(args.template)
    template_symtab = template_elf.get_section_by_name(".symtab")
    init_relocations = template_elf.get_section_by_name(".rela.init.text")
    init_calls = {
        template_symtab.get_symbol(r["r_info_sym"]).name
        for r in init_relocations.iter_relocations()
    } if init_relocations else set()
    sepolicy_calls = {
        "apply_kernelsu_rules", "cache_sid", "setup_ksu_cred",
        "escape_to_root_for_init", "setenforce",
    }
    if not sepolicy_calls <= init_calls:
        raise SystemExit("SELinux late-load handoff is incomplete: " + ",".join(sorted(sepolicy_calls - init_calls)))
    print("SELINUX_HANDOFF_OK apply_rules+cache_sid+setup_cred+escape+enforce")

    table = {}
    for line in args.syms.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 2:
            name, address = fields[0], int(fields[1], 16)
            if kernel.get(name) != address:
                raise SystemExit(f"existing symbol table disagrees with target: {name}")
            table[name] = address
    table.update({name: kernel[name] for name in needed})
    args.syms.write_text(
        "".join(f"{name} 0x{table[name]:016x}\n" for name in sorted(table, key=lambda n: (table[n], n))),
        encoding="utf-8", newline="\n",
    )
    print(f"COMPAT_OK missing_resolved={len(MISSING)} undefined={len(needed)} table={len(table)}")
    print(f"TEMPLATE_SHA256={digest}")
    print(f"OUTPUT_SHA256={hashlib.sha256(args.output.read_bytes()).hexdigest()} output={args.output}")

    if args.ko_patch:
        patched = args.build_dir / "ksu-patched-check.ko"
        result = subprocess.run([
            str(args.ko_patch), str(args.output), str(patched), str(args.syms), "0", KERNEL_RELEASE,
        ], check=True, text=True, capture_output=True)
        print(result.stdout, end="")
        if "MISSING=0" not in result.stdout or f"VERMAGIC={KERNEL_RELEASE} SMP" not in result.stdout:
            raise SystemExit("static ko_patch verification failed")


if __name__ == "__main__":
    main()
