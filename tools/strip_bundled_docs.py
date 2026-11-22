#!/usr/bin/env python3
"""Remove the last bundled-ksud references and update user-facing docs."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent


def patch(path: Path, pairs, required=True):
    p = Path(path)
    t = p.read_text(encoding="utf-8", errors="replace")
    for old, new in pairs:
        if old not in t:
            if required:
                print("WARN missing in", p.name, ":", old[:70])
            continue
        t = t.replace(old, new, 1)
    p.write_text(t, encoding="utf-8", newline="\n")
    print("patched", p.relative_to(WS))


# ------------------------------------------------------- kernel_profiles ---
K = WS / "main/app/assets/kernel_profiles.sh"
patch(K, [
    ('''ksu_flavor_ksud() {
    # Bundled fallback userspace binary name.
    case "$1" in
        resukisu) echo "ksud_bakasu" ;;
        fina)     echo "ksud_fina" ;;
        kernelsu) echo "ksud" ;;
        sukisu)   echo "ksud_sukisu" ;;
        next)     echo "ksud_next" ;;
        *)        echo "ksud" ;;
    esac
}

''', ''),
    ('    KSU_KSud=$(ksu_flavor_ksud "$KSU_FLAVOR")\n', ''),
])

# ------------------------------------------------------------- MainActivity -
J = WS / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java"
patch(J, [
    ('''    private static String managerAssetOf(String flavor) {
        switch (flavor) {
            case "fina": return "ksud_fina";
            case "kernelsu": return "ksud";
            case "sukisu": return "ksud_sukisu";
            case "next": return "ksud_next";
            default: return "ksud_bakasu";
        }
    }

''', ''),
    ('''    private String extractManagerKsud(String flavor) {
        String pkg = managerPkgOf(flavor);
        String bundled = "fallback=" + managerAssetOf(flavor);
        try {''',
     '''    private String extractManagerKsud(String flavor) {
        String pkg = managerPkgOf(flavor);
        try {'''),
    ('return "管理器里没有可用 ksud，使用内置兜底 " + bundled;',
     'return "管理器里没有可用 ksud（" + pkg + "），请安装或更新对应管理器后重试";'),
    ('return "管理器未安装（" + pkg + "），使用内置兜底 " + bundled;',
     'return "管理器未安装（" + pkg + "），请先安装该管理器";'),
    ('// bundled files remain the fallback.',
     '// the matching manager app must be installed (no bundled userspace fallback).'),
])

# ---------------------------------------------------------------- verify ----
V = WS / "tools/verify_apk.py"
patch(V, [
    ('"assets/run.sh": [b"KSU_FLAVOR=", b"ksud_bakasu", b"MAGICROOT_KSU_FLAVOR",',
     '"assets/run.sh": [b"KSU_FLAVOR=", b"manager_ksud_missing", b"MAGICROOT_KSU_FLAVOR",'),
])

# --------------------------------------------------------------- README ----
R = WS / "main/README.md"
patch(R, [
    ('/data/adb/ksud <- ksud_bakasu（BakaSU 4.2.0）',
     '/data/adb/ksud <- 从已安装管理器 APK 提取的 ksud'),
    ('| `resukisu` | BakaSU 4.2.0-rc3 | `com.resukisu.resukisu` | `ksud_bakasu` | 6.12 原生模板 |',
     '| `resukisu` | BakaSU 4.2.0-rc3 | `com.resukisu.resukisu` | 从管理器提取 | 6.12 原生模板 |'),
    ('| `fina` | FinaSU 1.0.8 | `me.yuki.fina` | `ksud_fina` | 6.12 兼容模板（uapi6） |',
     '| `fina` | FinaSU 1.0.10 | `me.yuki.fina` | 从管理器提取 | 6.12 原生模板 |'),
    ('内置 ksud。各 flavor 可用 `$WORK/ko-<flavor>.ko` 覆盖内置 LKM 模板；',
     '**不再内置 ksud**：请先安装对应管理器，否则运行会快速失败并提示安装。各 flavor 可用 `$WORK/ko-<flavor>.ko` 覆盖内置 LKM 模板；'),
], required=False)

# --------------------------------------------------------- release notes ----
# package_release.py notes mention "5 种管理器后端" only; nothing to change.
print("done")
