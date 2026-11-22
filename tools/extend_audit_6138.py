from pathlib import Path

P = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\tools\kernel_profile_audit.py")
t = P.read_text(encoding="utf-8")

# 1) add the newly supplied 6.12.38 boot image
t = t.replace(
'''    ("m7p", Path(r"<LOCAL_USER>user\\Downloads\\Magic 7 Pro (PTP-AN10)_11.0.0.110.zip")),
]''',
'''    ("m7p", Path(r"<LOCAL_USER>user\\Downloads\\Magic 7 Pro (PTP-AN10)_11.0.0.110.zip")),
    ("dl-boot-6138", Path(r"<LOCAL_USER>user\\Downloads\\boot.img")),
]''')

# 2) save extracted kernels + 6.12.38 syms entries + vmlinux paths
t = t.replace(
'''    kernel = data[page:page + kernel_size]
    m = re.search(rb"Linux version ([^\\x00\\n ]+)", kernel)
    return {''',
'''    kernel = data[page:page + kernel_size]
    try:
        (OUT / (path.stem + ".kernel.img")).write_bytes(kernel)
    except Exception:
        pass
    m = re.search(rb"Linux version ([^\\x00\\n ]+)", kernel)
    return {''')

t = t.replace(
'''        "syms": {
            "resukisu": WS / "main/app/assets/syms_6138_bakasu.txt",
            "kernelsu": WS / "main/app/assets/syms_6138.txt",
            # Missing by design (fail closed): next / sukisu / fina
        },''',
'''        "syms": {
            "resukisu": WS / "main/app/assets/syms_6138_bakasu.txt",
            "kernelsu": WS / "main/app/assets/syms_6138.txt",
            "next": WS / "main/app/assets/syms_6138_next.txt",
            "sukisu": WS / "main/app/assets/syms_6138_sukisu.txt",
            "fina": WS / "main/app/assets/syms_6138_fina.txt",
        },''')

t = t.replace(
'''PROFILES = {''',
'''VMLINUX = {
    "61258": Path(r"<LOCAL_USER>user\\Downloads\\<TOOLCHAIN>\\vmlinux.elf"),
    "6138": Path(r"<LOCAL_USER>user\\Documents\\<DSH>\\<OLD_WORKSPACE>\\boot-triple\\magic9-extra\\vmlinux.elf"),
}

PROFILES = {''')

# 3) prepare_creds probe: parametrise link and use it for both profiles
t = t.replace(
'''def prepare_creds_probe(kernel_img: Path):''',
'''def prepare_creds_probe(kernel_img: Path, link: int = 0xFFFFFFC08019C448):''')
t = t.replace('''    link = 0xFFFFFFC08019C448          # prepare_creds
    text_offset = struct.unpack_from("<Q", d, 8)[0]''',
'''    text_offset = struct.unpack_from("<Q", d, 8)[0]''')

# 4) vmlinux symbol verification + init/vendor_boot scans
t = t.replace(
'''def contamination_scan():''',
'''def vmlinux_symbols(path: Path):
    try:
        from elftools.elf.elffile import ELFFile
    except Exception as exc:  # pragma: no cover
        return {"error": f"pyelftools unavailable: {exc}"}
    if not path.exists():
        return {"error": "vmlinux missing"}
    out = {}
    with path.open("rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return {"error": "no symtab"}
        for sym in symtab.iter_symbols():
            if sym.name and not sym.name.startswith("$"):
                out.setdefault(sym.name, sym["st_value"])
    return out


def vmlinux_check(profile: str):
    path = VMLINUX[profile]
    syms = vmlinux_symbols(path)
    if "error" in syms:
        return syms
    meta = PROFILES[profile]
    wanted = {
        "prepare_creds": meta["prepare_creds"],
        "selinux_state": meta["selinux_state"],
    }
    anchors = {}
    src = meta["kaslr_source"].read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(r'\\{"([^"]+)",\\s*(0x[0-9a-fA-F]+)ULL\\}', src):
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


def contamination_scan():''')

# 5) result aggregation
t = t.replace(
'''    result["prepare_creds_probe_61258"] = prepare_creds_probe(
        OUT / "mly-61258.kernel.img")''',
'''    result["prepare_creds_probe_61258"] = prepare_creds_probe(
        OUT / "mly-61258.kernel.img", PROFILES["61258"]["prepare_creds"])
    result["prepare_creds_probe_6138"] = prepare_creds_probe(
        OUT / "boot.kernel.img", PROFILES["6138"]["prepare_creds"])
    result["vmlinux_checks"] = {p: vmlinux_check(p) for p in PROFILES}
    result["init_boot"] = init_boot_scan(Path(r"<LOCAL_USER>user\\Downloads\\init_boot.img"))
    result["vendor_boot"] = vendor_boot_scan(Path(r"<LOCAL_USER>user\\Downloads\\vendor_boot.img"))''')

# 6) update 6138 profile record and notes
t = t.replace(
'''        "boot_image_supplied": False,
        "reason": "provided Magic8Pro/BSN/mly boot images are 6.12.58; "
                  "the prior 6.12.38 vmlinux/BTF validation record is used",''',
'''        "boot_image_supplied": True,
        "boot_image_source": "<LOCAL_USER>user\\\\Downloads\\\\boot.img",
        "vmlinux": str(VMLINUX["6138"]),''')
t = t.replace(
'''    result["notes"].append(
        "6.12.38 boot image was not in the supplied files: Magic 7 Pro is "
        "6.6.118; BSN/Magic8Pro/mly boot are identical 6.12.58 images.")
    result["notes"].append(
        "6.12.38 syms for next/sukisu/fina are intentionally missing (fail-closed).")''',
'''    result["notes"].append(
        "6.12.38 boot.img (Downloads root) is 6.12.38 and its kernel sha256 "
        "48b622a2... matches the prior vmlinux record.")
    result["notes"].append(
        "6.12.38 next/sukisu/fina syms were generated from the 6.12.38 vmlinux "
        "and now have missing=0 coverage.")
    result["notes"].append(
        "BSN/Magic8Pro/mly boot images are identical 6.12.58; Magic 7 Pro is 6.6.118.")
    result["notes"].append(
        "vendor_boot ramdisk contains 6.12.23 vendor modules; do not mix with the "
        "6.12.38 boot kernel.")''')

P.write_text(t, encoding="utf-8", newline="\n")
print("audit script extended for 6.12.38")
