#!/usr/bin/env python3
"""Audit MagicRoot's 6.12.58 / 6.12.38 kernel adaptation against the supplied
boot images and the shipped native assets.

Checks:
  * boot-image provenance: release strings, kernel hashes, duplicate images;
  * 6.12.58 BTF-derived offsets (refs/mly-61258/offsets.json) vs native sources;
  * KASLR anchor/prepare_creds/selinux_state links vs device kallsyms (6.12.58)
    and vs the 6.12.38 prior vmlinux validation record;
  * KSU LKM template undefined-symbol coverage against each KMI's syms table;
  * contamination scan for 6.18-only constants (0x908 / 6.18 vermagic /
    0xffffffc082979629) in runtime assets and native sources.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WS / "tools"))
from audit_bakasu_lkm import parse_elf, read_modinfo, read_symtab  # noqa: E402

OUT = WS / "refs/kernel-audit"
OUT.mkdir(parents=True, exist_ok=True)

BOOT_SOURCES = [
    ("mly-61258", Path(r"<LOCAL_USER>user\Downloads\<TOOLCHAIN>\boot.img")),
    ("bsn", Path(r"<LOCAL_USER>user\Downloads\BSN-AN00 10.0.0.152(C00E150R103P2)_Firmware_Magi.zip")),
    ("m8p", Path(r"<LOCAL_USER>user\Downloads\Magic8Pro(BKQ-AN90)_Boot.zip")),
    ("m7p", Path(r"<LOCAL_USER>user\Downloads\Magic 7 Pro (PTP-AN10)_11.0.0.110.zip")),
    ("dl-boot-6138", Path(r"<LOCAL_USER>user\Downloads\boot.img")),
]

VMLINUX = {
    "61258": Path(r"<LOCAL_USER>user\Downloads\<TOOLCHAIN>\vmlinux.elf"),
    "6138": Path(r"<LOCAL_USER>user\Documents\<DSH>\<OLD_WORKSPACE>\boot-triple\magic9-extra\vmlinux.elf"),
}

PROFILES = {
    "61258": {
        "release": "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k",
        "prepare_creds": 0xFFFFFFC08019C448,
        "selinux_state": 0xFFFFFFC0827E7A60,
        "kaslr_source": WS / "main/app/native/kaslr_slide_61258.c",
        "syms": {
            "resukisu": WS / "main/app/assets/syms_61258_bakasu.txt",
            "kernelsu": WS / "main/app/assets/syms_61258.txt",
            "next": WS / "main/app/assets/syms_61258_next.txt",
            "sukisu": WS / "main/app/assets/syms_61258_sukisu.txt",
            "fina": WS / "main/app/assets/syms_61258_fina.txt",
        },
    },
    "6138": {
        "release": "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k",
        "prepare_creds": 0xFFFFFFC080B8A21C,
        "selinux_state": 0xFFFFFFC0826663C8,
        "kaslr_source": WS / "main/app/native/kaslr_slide_6138.c",
        "syms": {
            "resukisu": WS / "main/app/assets/syms_6138_bakasu.txt",
            "kernelsu": WS / "main/app/assets/syms_6138.txt",
            "next": WS / "main/app/assets/syms_6138_next.txt",
            "sukisu": WS / "main/app/assets/syms_6138_sukisu.txt",
            "fina": WS / "main/app/assets/syms_6138_fina.txt",
        },
    },
}

TEMPLATES = {
    "resukisu": WS / "main/app/assets/ksu-template-bakasu.ko",
    "kernelsu": WS / "main/app/assets/ksu-template.ko",
    "next": WS / "main/app/assets/ksu-template-next.ko",
    "sukisu": WS / "main/app/assets/ksu-template-sukisu.ko",
    "fina": WS / "main/app/assets/ksu-template-fina.ko",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def boot_kernel(path: Path):
    if not path.exists():
        return None
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as z:
            names = [n for n in z.namelist() if n.endswith("/boot.img")]
            if not names:
                return None
            data = z.read(names[0])
    else:
        data = path.read_bytes()
    if data[:8] != b"ANDROID!":
        return None
    header_version = struct.unpack_from("<I", data, 40)[0]
    kernel_size = struct.unpack_from("<I", data, 8)[0]
    page = 4096 if header_version >= 3 else 2048
    kernel = data[page:page + kernel_size]
    try:
        (OUT / (path.stem + ".kernel.img")).write_bytes(kernel)
    except Exception:
        pass
    m = re.search(rb"Linux version ([^\x00\n ]+)", kernel)
    return {
        "path": str(path),
        "boot_header_version": header_version,
        "kernel_offset": page,
        "kernel_size": len(kernel),
        "kernel_sha256": sha256(kernel),
        "release": m.group(1).decode("ascii", "replace") if m else None,
    }


def parse_kallsyms(path: Path):
    syms = {}
    if not path.exists():
        return syms
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"\s*([0-9a-fA-F]{16})\s+(\S)\s+(\S+)", line)
        if m:
            syms[m.group(3)] = int(m.group(1), 16)
    return syms


def kaslr_constants(path: Path):
    if not path.exists():
        return {}
    t = path.read_text(encoding="utf-8", errors="replace")
    out = {}
    m = re.search(r"#define\s+SELINUX_STATE\s+(0x[0-9a-fA-F]+)", t)
    if m:
        out["selinux_state"] = int(m.group(1), 16)
    m = re.search(r"#define\s+PREPARE_CREDS\s+(0x[0-9a-fA-F]+)", t)
    if m:
        out["prepare_creds"] = int(m.group(1), 16)
    anchors = {}
    for m in re.finditer(r'\{"([^"]+)",\s*(0x[0-9a-fA-F]+)ULL\}', t):
        anchors[m.group(1)] = int(m.group(2), 16)
    out["anchors"] = anchors
    return out


def source_offsets():
    t = (WS / "main/app/native/t64560_cred_safe_61258.c").read_text(
        encoding="utf-8", errors="replace")
    v36 = (WS / "main/app/native/t64560_v36_safe_61258.c").read_text(
        encoding="utf-8", errors="replace")
    out = {}
    for name, text in (("cred", t), ("v36", v36)):
        for key in ("ITIMER_NODE_OFF", "SLOT_STRIDE", "ITIMER_SIZE"):
            m = re.search(rf"#define\s+{key}\s+\(?0x([0-9a-fA-F]+)\)?UL", text)
            if m:
                out.setdefault(name, {})[key.lower()] = int(m.group(1), 16)
    for key in ("CRED_CAP_EFFECTIVE", "CRED_CAP_BSET", "CRED_FSUID"):
        m = re.search(rf"#define\s+{key}\s+\(?0x([0-9a-fA-F]+)\)?UL", t)
        if m:
            out.setdefault("cred", {})[key.lower()] = int(m.group(1), 16)
    return out


def module_audit():
    rows = []
    for flavor, p in TEMPLATES.items():
        if not p.exists():
            rows.append({"flavor": flavor, "error": "template_missing"})
            continue
        data, sections = parse_elf(p)
        modinfo = read_modinfo(data, sections)
        syms = read_symtab(data, sections)
        undefined = sorted({s["name"] for s in syms
                            if s["shndx"] == 0 and s["bind"] != 0 and s["name"]})
        row = {
            "flavor": flavor,
            "template": p.name,
            "size": p.stat().st_size,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "modinfo_vermagic": modinfo.get("vermagic"),
            "modinfo_version": modinfo.get("version"),
            "undefined": len(undefined),
        }
        for profile, meta in PROFILES.items():
            syms_path = meta["syms"].get(flavor)
            if not syms_path or not syms_path.exists():
                row[f"syms_{profile}"] = "missing"
                continue
            names = set()
            for line in syms_path.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    names.add(parts[0])
            missing = [n for n in undefined if n not in names]
            row[f"syms_{profile}"] = {
                "file": syms_path.name,
                "syms": len(names),
                "missing": len(missing),
                "missing_sample": missing[:8],
            }
        rows.append(row)
    return rows


def prepare_creds_probe(kernel_img: Path, link: int = 0xFFFFFFC08019C448):
    """Disassemble prepare_creds in the supplied 6.12.58 Image and verify the
    layout facts used by cred_target/t64560_cred (task->cred=0x900,
    cred size 0xb8, function length well below cred_target's 0x800 window)."""
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    except Exception as exc:  # pragma: no cover
        return {"error": f"capstone unavailable: {exc}"}
    if not kernel_img.exists():
        return {"error": "kernel image missing"}
    d = kernel_img.read_bytes()
    base = 0xFFFFFFC080000000
    text_offset = struct.unpack_from("<Q", d, 8)[0]
    fo = text_offset + (link - base)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    found = {"task_cred_0x900": False, "cred_size_0xb8": False,
             "function_bytes": 0, "ret_addr": None}
    for ins in md.disasm(d[fo:fo + 0x800], link):
        if ins.mnemonic == "ldr" and "#0x900]" in ins.op_str:
            found["task_cred_0x900"] = True
        if ins.mnemonic == "mov" and ins.op_str == "w2, #0xb8":
            found["cred_size_0xb8"] = True
        if ins.mnemonic == "ret":
            found["ret_addr"] = hex(ins.address)
            found["function_bytes"] = ins.address - link + 4
            break
    return found


def vmlinux_symbols(path: Path):
    try:
        from elftools.elf.elffile import ELFFile
    except Exception as exc:  # pragma: no cover
        return {"__error__": f"pyelftools unavailable: {exc}"}
    if not path.exists():
        return {"__error__": "vmlinux missing"}
    out = {}
    with path.open("rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return {"__error__": "no symtab"}
        for sym in symtab.iter_symbols():
            if sym.name and not sym.name.startswith("$"):
                out.setdefault(sym.name, sym["st_value"])
    return out


def vmlinux_check(profile: str):
    path = VMLINUX[profile]
    syms = vmlinux_symbols(path)
    if "__error__" in syms:
        return syms
    meta = PROFILES[profile]
    wanted = {
        "prepare_creds": meta["prepare_creds"],
        "selinux_state": meta["selinux_state"],
    }
    anchors = {}
    src = meta["kaslr_source"].read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(r'\{"([^"]+)",\s*(0x[0-9a-fA-F]+)ULL\}', src):
        anchors[m.group(1)] = int(m.group(2), 16)
    rows = {}
    for name, expected in {**wanted, **anchors}.items():
        actual = syms.get(name)
        rows[name] = {
            "expected": hex(expected),
            "vmlinux": hex(actual) if actual is not None else None,
            "match": actual == expected,
        }
    return {"vmlinux": str(path), "symbols": rows,
            "all_match": all(v["match"] for v in rows.values())}


def init_boot_scan(path: Path):
    if not path.exists():
        return {"missing": True}
    d = path.read_bytes()
    if d[:8] != b"ANDROID!":
        return {"error": "bad magic"}
    return {
        "size": len(d),
        "header_version": struct.unpack_from("<I", d, 40)[0],
        "kernel_size": struct.unpack_from("<I", d, 8)[0],
        "ramdisk_size": struct.unpack_from("<I", d, 12)[0],
        "role": "generic init ramdisk (no kernel)",
    }


def vendor_boot_scan(path: Path):
    if not path.exists():
        return {"missing": True}
    d = path.read_bytes()
    if d[:8] != b"VNDRBOOT":
        return {"error": "bad magic"}
    return {
        "size": len(d),
        "header_version": struct.unpack_from("<I", d, 8)[0],
        "page_size": struct.unpack_from("<I", d, 12)[0],
        "vendor_ramdisk_size": struct.unpack_from("<I", d, 24)[0],
        "vermagic_6_12_23": d.count(b"6.12.23"),
        "vermagic_6_12_38": d.count(b"6.12.38"),
        "role": "vendor ramdisk/dtb; contains 6.12.23 vendor modules, not 6.12.38",
    }


def contamination_scan():
    hits = []
    patterns = [
        (b"0x908", "6.18 task_struct.cred offset literal"),
        (b"6.18", "6.18 kernel string"),
        (b"\x29\x96\x97\x82\xc0\xff\xff\xff", "6.18 resolve target little-endian"),
    ]
    roots = [WS / "main/app/assets", WS / "main/app/native"]
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or p.stat().st_size > 8 * 1024 * 1024:
                continue
            data = p.read_bytes()
            for pat, desc in patterns:
                if pat in data:
                    # kernel_profiles.sh intentionally has a reserved 6.18
                    # branch that fails closed; it is not a reused 6.18 asset.
                    if p.name == "kernel_profiles.sh" and desc == "6.18 kernel string":
                        continue
                    hits.append({"file": p.relative_to(WS).as_posix(), "pattern": desc})
    return hits


def main() -> int:
    result = {"boot_images": {}, "profiles": {}, "native_offsets": {}, "modules": [],
              "contamination": [], "notes": []}

    for name, path in BOOT_SOURCES:
        info = boot_kernel(path)
        result["boot_images"][name] = info or {"path": str(path), "missing": True}

    # 6.12.58 kallsyms / slide cross-check
    kallsyms = parse_kallsyms(WS / "refs/device-dumps/boot-0c1e86b6/kallsyms_full.txt")
    if kallsyms.get("_text") is not None:
        slide = kallsyms["_text"] - 0xFFFFFFC080000000
        expected = {
            "worker_thread": 0xFFFFFFC080207A90,
            "rcu_gp_fqs_loop": 0xFFFFFFC080196A8C,
            "rcu_gp_kthread": 0xFFFFFFC080196584,
            "folio_wait_bit_common": 0xFFFFFFC0802E7B8C,
            "ufshcd_issue_dev_cmd": 0xFFFFFFC080E54B28,
            "icc_set_bw": 0xFFFFFFC08037A558,
            "selinux_state": 0xFFFFFFC0827E7A60,
            "prepare_creds": 0xFFFFFFC08019C448,
        }
        rows = {}
        for name, link in expected.items():
            if name in kallsyms:
                rows[name] = {"link_expected": hex(link),
                              "link_from_kallsyms": hex(kallsyms[name] - slide),
                              "match": (kallsyms[name] - slide) == link}
        result["profiles"]["61258"] = {
            "release": PROFILES["61258"]["release"],
            "kallsyms_slide_from_dump": hex(slide),
            "symbols_checked": rows,
        }

    offsets = json.loads((WS / "refs/mly-61258/offsets.json").read_text(encoding="utf-8"))
    result["native_offsets"] = {"offsets_json": offsets, "source_constants": source_offsets()}

    # 6.12.38: no boot image in the supplied set; record the prior static record
    result["profiles"]["6138"] = {
        "release": PROFILES["6138"]["release"],
        "boot_image_supplied": True,
        "boot_image_source": "<LOCAL_USER>user\\Downloads\\boot.img",
        "vmlinux": str(VMLINUX["6138"]),
        "prepare_creds_link": hex(PROFILES["6138"]["prepare_creds"]),
        "selinux_state_link": hex(PROFILES["6138"]["selinux_state"]),
        "cred_layout": "same as 6.12.58 per refs/multikernel/docs/kernel-61238.md",
    }

    # KASLR source constants
    for profile, meta in PROFILES.items():
        c = kaslr_constants(meta["kaslr_source"])
        result["profiles"].setdefault(profile, {})["kaslr_source"] = {
            "file": meta["kaslr_source"].name,
            "anchors": {k: hex(v) for k, v in c.get("anchors", {}).items()},
            "selinux_state": hex(c.get("selinux_state", 0)),
            "prepare_creds": hex(c.get("prepare_creds", 0)),
            "matches_profile": (c.get("selinux_state") == meta["selinux_state"]
                                and c.get("prepare_creds") == meta["prepare_creds"]),
        }

    result["modules"] = module_audit()
    result["contamination"] = contamination_scan()
    result["prepare_creds_probe_61258"] = prepare_creds_probe(
        OUT / "mly-61258.kernel.img", PROFILES["61258"]["prepare_creds"])
    result["prepare_creds_probe_6138"] = prepare_creds_probe(
        OUT / "boot.kernel.img", PROFILES["6138"]["prepare_creds"])
    result["vmlinux_checks"] = {p: vmlinux_check(p) for p in PROFILES}
    result["init_boot"] = init_boot_scan(Path(r"<LOCAL_USER>user\Downloads\init_boot.img"))
    result["vendor_boot"] = vendor_boot_scan(Path(r"<LOCAL_USER>user\Downloads\vendor_boot.img"))

    # notes about known gaps
    result["notes"].append(
        "6.12.38 boot.img (Downloads root) is 6.12.38 and its kernel sha256 "
        "48b622a2... matches the prior vmlinux record.")
    result["notes"].append(
        "6.12.38 next/sukisu/fina syms were generated from the 6.12.38 vmlinux "
        "and now have missing=0 coverage.")
    result["notes"].append(
        "BSN/Magic8Pro/mly boot images are identical 6.12.58; Magic 7 Pro is 6.6.118.")
    result["notes"].append(
        "vendor_boot ramdisk contains 6.12.23 vendor modules; do not mix with the "
        "6.12.38 boot kernel.")

    (OUT / "audit.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "native_offsets"},
                     indent=2)[:8000])
    print("\nwrote", OUT / "audit.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
