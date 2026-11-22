#!/usr/bin/env python3
"""Extend the kernel audit with prepare_creds disassembly evidence and
whitelist the intentional 6.18 reserved profile string."""
from __future__ import annotations

from pathlib import Path

P = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\tools\kernel_profile_audit.py")
t = P.read_text(encoding="utf-8")

# contamination whitelist
t = t.replace(
'''            for pat, desc in patterns:
                if pat in data:
                    hits.append({"file": p.relative_to(WS).as_posix(), "pattern": desc})''',
'''            for pat, desc in patterns:
                if pat in data:
                    # kernel_profiles.sh intentionally has a reserved 6.18
                    # branch that fails closed; it is not a reused 6.18 asset.
                    if p.name == "kernel_profiles.sh" and desc == "6.18 kernel string":
                        continue
                    hits.append({"file": p.relative_to(WS).as_posix(), "pattern": desc})''')

# prepare_creds disassembly probe
t = t.replace(
'''def contamination_scan():''',
'''def prepare_creds_probe(kernel_img: Path):
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
    link = 0xFFFFFFC08019C448          # prepare_creds
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


def contamination_scan():''')

t = t.replace(
'''    result["modules"] = module_audit()
    result["contamination"] = contamination_scan()''',
'''    result["modules"] = module_audit()
    result["contamination"] = contamination_scan()
    result["prepare_creds_probe_61258"] = prepare_creds_probe(
        OUT / "mly-61258.kernel.img")''')

P.write_text(t, encoding="utf-8", newline="\n")
print("audit script extended")
