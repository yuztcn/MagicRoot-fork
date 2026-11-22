#!/usr/bin/env python3
"""Static verification of the built MagicRoot BakaSU APK.

Checks:
- package/version
- required asset set with sizes + sha256 (BakaSU and official backends)
- key script assets contain the flavor-aware markers
- no accidental device-specific data
Writes docs/reference/apk-verify.md.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import zipfile
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
APK = WS / "main" / "app" / "MagicRoot.apk"
AAPT = Path(r"<LOCAL_USER>user\Downloads\<TOOLCHAIN>\sdk\build-tools\37.0.0\aapt2.exe")
DOCS = WS / "docs" / "reference"

# (asset name, expected sha256 prefix or None, note)
REQUIRED = [
    ("ksu-template-bakasu.ko", "18105ef8e8aba5b1", "BakaSU 4.2.0-rc3 KMI 6.12 LKM template (508792 B)"),
    ("ksu_flavor", None, "flavor marker resukisu"),
    ("syms_61258_bakasu.txt", "0a1be238f3d4cd71", "6.12.58 BakaSU syms (274)"),
    ("syms_6138_bakasu.txt", "ef440bd11cf673ed", "6.12.38 BakaSU syms (274)"),
    ("ksu-template.ko", None, "official KernelSU 3.3.1 6.12 template (fallback)"),
    ("ksu-template-next.ko", None, "KernelSU-Next 3.4.2 native 6.12 LKM (MultiSU)"),
    ("ksu-template-sukisu.ko", None, "SukiSU 4.2.1-r2 native 6.12 LKM (MultiSU)"),
    ("ksu-template-fina.ko", "616e01a3de04048c", "FinaSU 1.2.1 native 6.12 LKM (MultiSU bundle)"),
    ("syms_61258_next.txt", None, "6.12.58 next syms"),
    ("syms_61258_sukisu.txt", None, "6.12.58 sukisu syms"),
    ("syms_61258_fina.txt", None, "6.12.58 fina syms"),
    ("t64560_v36", None, "6.12 permissive writer"),
    ("t64560_cred", "eec3cc1ab2bd301b", "6.12 v42 cred writer MAXVICTIM=32"),

    ("su_entry.sh", None, "PMX v1.6 su entry + Termux wrapper patch"),
    ("kernel_profiles.sh", None, "flavor-aware profiles"),
    ("root_stage.sh", None, "flavor-aware root stage"),
    ("syms_61258.txt", None, "official syms 61258"),
    ("syms_6138.txt", None, "official syms 6138"),
    ("syms_6138_next.txt", "ef440bd11cf673ed", "6.12.38 next syms (274)"),
    ("syms_6138_sukisu.txt", "ef440bd11cf673ed", "6.12.38 sukisu syms (274)"),
    ("syms_6138_fina.txt", "ef440bd11cf673ed", "6.12.38 fina syms (274)"),
    ("syms_g4b36.txt", "18844a6a1f376084", "6.12.38 g4b36 official syms (274)"),
    ("syms_g4b36_nova.txt", "18844a6a1f376084", "6.12.38 g4b36 nova syms (274)"),
    ("98260-g4b36/exploit-android-key-ptr", "1a2a7c314fab2827", "g4b36 98260 real-cred payload"),
    ("98260-g4b36/target.sh", "765ec972fd9c4447", "g4b36 target metadata"),
    ("98260-g4b36/SHA256SUMS.txt", None, "g4b36 pinned asset hashes"),

    # CVE-2026-98260 experimental second chain (Honor 6.12.58 adapted build).
    ("98260/exploit-android-perf", "1954bf48011f8e7f", "98260 SELinux writer placeholder (superseded by key-ptr)"),
    ("98260/exploit-android-perf-chain", "1954bf48011f8e7f", "98260 cred/UID0 stage placeholder (superseded by key-ptr)"),
    ("98260/exploit-android-key-ptr", "0fd3ff76cce32882", "98260 dual fake/real-cred (6.12.58, free-gated bounded 4096-write precise reclaim, same-4K-half triple)"),
    ("pc98260-su", "8838ab17e3825249", "98260 rootd client (top-level asset staged for all 98260 profiles)"),
    ("98260/run98260.sh", None, "98260 device-side fail-stop stage machine"),
    ("98260/target.sh", None, "98260 target constants (kernel/models/hashes)"),
    ("98260/SHA256SUMS.txt", None, "98260 pinned asset hashes"),
]

SCRIPT_MARKERS = {
    # Template/flavor selection lives in kernel_profiles.sh; run.sh only reads
    # the selected paths (see the flavor check at the top of the chain).
    "assets/run.sh": [b"KSU_FLAVOR=", b"manager_ksud_missing", b"MAGICROOT_KSU_FLAVOR",
                       b"FAIL=ksu_grant", b"GRANT_RETRY", b"ksu-official.ko",
                       b"MODULE_WAIT_POLL", b"KASLR_CROSS_CHECK", b"KASLR_REGRAB", b"KO_PATCH_SELF_CHECK",
                       b"CRED_LEAK_SELF_CHECK", b"KSU_GRANT_METHOD",
                       b"MAGICROOT_KERNEL_UMOUNT", b"MAGICROOT_SELINUX_HIDE",
                       b"KERNEL_UMOUNT=", b"SELINUX_HIDE=",
                       b"CRED_SCHEME=v42", b"GRAB_EARLY_STOP",
                       b"MAGICROOT_ADB_ROOT", b"MAGICROOT_SU_ENTRY", b"ADB_ROOT=",
                       b"MAGICROOT_CHAIN", b"chain_98260_not_enabled", b"run98260.sh"],
    "assets/98260/run98260.sh": [b"MAGICROOT_ENABLE_98260", b"parked_check",
                                  b"98260_SUCCESS=1", b"MAGICROOT_98260_PREFLIGHT",
                                  b"pc98260-root.sock", b"parked_mark",
                                  b"98260_MANAGER_LATELOAD_RC",
                                  b"98260_MANAGER_PACKAGES=untouched",
                                  b"98260_MANAGER_PAIR=strict",
                                  b"98260_MANAGER_CONNECTED=1",
                                  b"98260_CLEANUP=pending reason=ksu_su_proof",
                                  b"98260_KSU_SU_WAIT="],
    "assets/98260/target.sh": [b"CHAIN_98260_KERNEL", b"CHAIN_98260_MODELS",
                                b"6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k"],
    "assets/clean.sh": [b"CLEAN_98260", b"pc98260-root.sock", b"exploit-android"],
    "assets/kernel_profiles.sh": [b"KSU_FLAVORS", b"ksu_flavor_pkg", b"ksu_select_ko",
                                  b"ksu-template-bakasu.ko", b"ko-$flavor.ko",
                                  b"PROFILE_KASLR_PREPARE_LINK",
                                  b"select_chain_98260_profile"],
    "assets/root_stage.sh": [b"ROOT_STAGE_FLAVOR=", b"manager add", b"com.resukisu.resukisu",
                             b"debug set-manager", b"ROOT_STAGE_EXPECTED_FLAVOR",
                             b"kernel dynamic-manager", b"ROOT_STAGE_MANAGER_CONNECTED",
                             b"dynamic grant", b"ROOT_STAGE_DYNAMIC_GRANT_RC",
                             b"ROOT_STAGE_PACKAGES=untouched",
                             b"SOFT_REBOOT_REPAIR", b"ROOT_STAGE_PRESERVE", b"DYNAMIC_MANAGER_FILE",
                             b"ROOT_STAGE_FEATURE_", b"apply_feature",
                             b"ROOT_STAGE_ADB_ROOT", b"SU_ENTRY_RESULT",
                             b"ROOT_STAGE_ALLOW_SHELL_MODE"],
}

# UI evidence compiled into classes.dex (success page + home layout + toggles).
UI_MARKERS = ["提权完成", "提权完成，但软重启有风险", "fake / real 双分支与 late-load",
              "OneKey / onekeyjb", "以上为上次运行记录",
              "导出日志", "返回主页", "运行选项", "内核后端", "软重启修复",
              "kernel_umount", "selinux_hide", "real_cred", "ADB Root", "su entry", "恢复默认参数",
              "运行参数修改提醒", "确认修改", "作者：酷安@青木信史",
              "预检模式", "98260-rootd（临时）", "版本 1.0.6"]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if not APK.exists():
        print("APK missing:", APK)
        return 1
    rows, problems = [], []
    size = APK.stat().st_size
    with zipfile.ZipFile(APK) as z:
        names = {n: z.getinfo(n).file_size for n in z.namelist()}
        asset_names = [n for n in names if n.startswith("assets/")]
        by_tail = {}
        for n in asset_names:
            by_tail[n.split("/", 1)[1]] = n
        for want, sha_prefix, note in REQUIRED:
            key = by_tail.get(want)
            if not key:
                problems.append(f"missing asset {want}")
                rows.append((want, "-", "-", "MISSING"))
                continue
            data = z.read(key)
            digest = sha256(data)
            ok = sha_prefix is None or digest.startswith(sha_prefix)
            if not ok:
                problems.append(f"hash mismatch {want}: {digest[:16]} != {sha_prefix}")
            rows.append((want, str(len(data)), digest[:32], note))
        for n, markers in SCRIPT_MARKERS.items():
            data = z.read(n)
            for m in markers:
                if m not in data:
                    problems.append(f"{n} missing marker {m!r}")
        # UI strings are compiled into classes.dex.
        dex_blob = b"".join(z.read(n) for n in names
                            if n.endswith(".dex") and n.startswith("classes"))
        for marker in UI_MARKERS:
            if marker.encode("utf-8") not in dex_blob:
                problems.append(f"classes.dex missing UI marker {marker!r}")
        # Informational: total asset payload
        payload = sum(len(z.read(n)) for n in asset_names)

    badging = ""
    if AAPT.exists():
        badging = subprocess.run([str(AAPT), "dump", "badging", str(APK)],
                                 capture_output=True, text=True).stdout
    pkg = [ln for ln in badging.splitlines() if ln.startswith("package:")]
    lines = ["# MagicRoot BakaSU APK 閳?static verification", "",
             f"- apk: `{APK}`",
             f"- size: {size} B",
             f"- asset payload: {payload} B ({len(asset_names)} entries)",
             f"- badging: {pkg[0] if pkg else 'aapt2 unavailable'}", "",
             "| asset | size | sha256 | note |", "|---|---:|---|---|"]
    for name, sz, digest, note in rows:
        lines.append(f"| `{name}` | {sz} | `{digest}` | {note} |")
    lines += ["", "## Result", ""]
    if problems:
        lines.append("**PROBLEMS**")
        lines += [f"- {p}" for p in problems]
    else:
        lines.append("All required assets and flavor markers present.")
    out = "\n".join(lines) + "\n"
    DOCS.mkdir(parents=True, exist_ok=True)
    (DOCS / "apk-verify.md").write_text(out, encoding="utf-8")
    print(out)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())


