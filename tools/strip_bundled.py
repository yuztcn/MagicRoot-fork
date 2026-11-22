#!/usr/bin/env python3
"""Size/cleanup pass:

- drop the bundled manager APK (users install the correct manager themselves);
- drop all bundled ksud fallbacks: the userspace binary is always extracted from
  the installed manager APK, and the run fails fast with a clear hint when the
  manager is missing;
- drop the obsolete *_safe debug payloads and the whole safe-mode plumbing;
- stop deleting /sdcard/Download/MagicRoot logs on every run.
"""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
A = WS / "main/app/assets"

# ---------------------------------------------------------------- assets ----
for name in (
    "BakaSU-manager.apk",
    "t64560_v36_safe", "t64560_cred_safe",
    "ksud", "ksud_bakasu", "ksud_fina", "ksud_next", "ksud_sukisu",
):
    p = A / name
    if p.exists():
        p.unlink()
        print("removed asset", name)


def patch(path: Path, pairs):
    t = path.read_text(encoding="utf-8", errors="replace")
    for old, new in pairs:
        if old not in t:
            raise SystemExit(f"anchor missing in {path.name}: {old[:80]}")
        t = t.replace(old, new, 1)
    path.write_text(t, encoding="utf-8", newline="\n")
    print("patched", path.name)


# ----------------------------------------------------------- MainActivity ----
J = WS / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java"
patch(J, [(
    '''            "t64560_v36", "t64560_v36_safe", "cred_target", "t64560_cred", "t64560_cred_safe",
            "ksu_grant", "ksud", "ksud_bakasu", "ksud_fina", "ksud_next",
            "ksud_sukisu", "ksu_flavor",
            "ksu-template.ko", "ksu-template-bakasu.ko", "ksu-template-fina.ko",
            "ksu-template-next.ko", "ksu-template-sukisu.ko", "BakaSU-manager.apk",''',
    '''            "t64560_v36", "cred_target", "t64560_cred",
            "ksu_grant", "ksu_flavor",
            "ksu-template.ko", "ksu-template-bakasu.ko", "ksu-template-fina.ko",
            "ksu-template-next.ko", "ksu-template-sukisu.ko",''')])

# ------------------------------------------------------------------ run.sh ---
R = A / "run.sh"
patch(R, [
    # safe-mode plumbing
    ('''# Optional safe-mode experiment path.  Production behavior is unchanged unless
# one of these files exists or MAGICROOT_SAFE_MODE=1 is exported by a test harness.
SAFE_MODE=${MAGICROOT_SAFE_MODE:-0}
[ -f "$D/safe-mode" ] && SAFE_MODE=1
case "$SAFE_MODE" in 1) ;; *) SAFE_MODE=0 ;; esac
EARLY_ABORT_MS=0
if [ "$SAFE_MODE" = "1" ]; then
    EARLY_ABORT_MS=4500
    if [ -f "$D/early-abort-ms" ]; then
        EARLY_ABORT_MS=$(cat "$D/early-abort-ms" 2>/dev/null || echo 4500)
    fi
    case "$EARLY_ABORT_MS" in ''|*[!0-9]*) EARLY_ABORT_MS=4500 ;; esac
    [ "$EARLY_ABORT_MS" -le 60000 ] 2>/dev/null || EARLY_ABORT_MS=4500
fi
AB_EXPORT=0
[ -f "$D/ab-export" ] && AB_EXPORT=1
SAFE_SLACK=64
if [ -f "$D/drain-slack" ]; then
    SAFE_SLACK=$(cat "$D/drain-slack" 2>/dev/null || echo 64)
    case "$SAFE_SLACK" in ''|*[!0-9]*) SAFE_SLACK=64 ;; esac
    { [ "$SAFE_SLACK" -ge 16 ] && [ "$SAFE_SLACK" -le 4096 ]; } 2>/dev/null || SAFE_SLACK=64
fi''',
     '''AB_EXPORT=0
[ -f "$D/ab-export" ] && AB_EXPORT=1'''),
    # chmod list
    ('''chmod 755 "$D"/kaslr_slide_61258 "$D"/kaslr_slide_6138 "$D"/ko_patch \\
    "$D"/addrcalc "$D"/t64560_v36 "$D"/t64560_v36_safe "$D"/cred_target \\
    "$D"/t64560_cred "$D"/t64560_cred_safe "$D"/ksu_grant "$D"/wait_helper \\
    "$D"/forker "$D"/ksud "$D"/ksud_bakasu "$D"/ksud_fina \\
    "$D"/ksud_sukisu "$D"/ksud_next "$D"/su_overlay_helper \\
    "$D"/su_forward 2>/dev/null''',
     '''chmod 755 "$D"/kaslr_slide_61258 "$D"/kaslr_slide_6138 "$D"/ko_patch \\
    "$D"/addrcalc "$D"/t64560_v36 "$D"/cred_target \\
    "$D"/t64560_cred "$D"/ksu_grant "$D"/wait_helper \\
    "$D"/forker "$D"/su_overlay_helper "$D"/su_forward 2>/dev/null'''),
    ('echo "SAFE_MODE=$SAFE_MODE EARLY_ABORT_MS=$EARLY_ABORT_MS SLACK=$SAFE_SLACK AB_EXPORT=$AB_EXPORT"',
     'echo "AB_EXPORT=$AB_EXPORT"'),
    # extraction: no bundled fallback
    ('''#   * fall back to the bundled per-flavor ksud asset when the manager is not
#     installed or no usable payload is found.
# The app writes the manager signing tuple to $D/manager_sig through
# PackageManager; root_stage falls back to `ksud debug get-sign`.
# ---------------------------------------------------------------------------
KSU_FLAVOR=$(ksu_flavor_normalize "$KSU_FLAVOR")
KSU_MANAGER_PKG=$(ksu_flavor_pkg "$KSU_FLAVOR")
KSU_MANAGER_LABEL=$(ksu_flavor_label "$KSU_FLAVOR")
EXPECT_KVER=$(ksu_flavor_kver "$KSU_FLAVOR")
EXPECT_UAPI=$(ksu_flavor_uapi "$KSU_FLAVOR")
KSUD_BUNDLED="$D/$(ksu_flavor_ksud "$KSU_FLAVOR")"
[ -f "$KSUD_BUNDLED" ] || KSUD_BUNDLED="$D/ksud"
KSUD="$KSUD_BUNDLED"
KSUD_EXTRACTED="$D/ksud_${KSU_FLAVOR}"''',
     '''#   * there is no bundled ksud fallback any more: the matching manager must be
#     installed by the user, otherwise the run fails with a clear hint.
# The app writes the manager signing tuple to $D/manager_sig through
# PackageManager; root_stage falls back to `ksud debug get-sign`.
# ---------------------------------------------------------------------------
KSU_FLAVOR=$(ksu_flavor_normalize "$KSU_FLAVOR")
KSU_MANAGER_PKG=$(ksu_flavor_pkg "$KSU_FLAVOR")
KSU_MANAGER_LABEL=$(ksu_flavor_label "$KSU_FLAVOR")
EXPECT_KVER=$(ksu_flavor_kver "$KSU_FLAVOR")
EXPECT_UAPI=$(ksu_flavor_uapi "$KSU_FLAVOR")
KSUD=""
KSUD_EXTRACTED="$D/ksud_${KSU_FLAVOR}"'''),
    ('''    if [ "$_found" = "1" ]; then
        KSUD="$KSUD_EXTRACTED"
        echo "KSUD_SOURCE=manager-apk path=$KSUD"
    else
        rm -f "$KSUD_EXTRACTED" 2>/dev/null || true
        echo "KSUD_SOURCE=bundled path=$KSUD reason=no_usable_payload_in_manager_apk"
    fi
else
    echo "KSUD_SOURCE=bundled path=$KSUD reason=manager_not_installed_or_unzip_missing"
fi
[ -x "$KSUD" ] || KSUD="$KSUD_BUNDLED"
chmod 755 "$KSUD" 2>/dev/null || true''',
     '''    if [ "$_found" = "1" ]; then
        KSUD="$KSUD_EXTRACTED"
        echo "KSUD_SOURCE=manager-apk path=$KSUD"
    fi
else
    echo "KSUD_SOURCE=none reason=manager_not_installed_or_unzip_missing"
fi
if [ -z "$KSUD" ] || [ ! -x "$KSUD" ]; then
    echo "FAIL=manager_ksud_missing manager=$KSU_MANAGER_PKG flavor=$KSU_FLAVOR"
    echo "HINT=install the matching manager app first; MagicRoot now extracts the userspace ksud from that APK (no bundled copy)"
    echo "HINT_MANAGERS=resukisu com.resukisu.resukisu / fina me.yuki.fina / kernelsu me.weishu.kernelsu / sukisu com.sukisu.ultra / next com.rifsxd.ksunext"
    exit 3
fi
chmod 755 "$KSUD" 2>/dev/null || true'''),
    # remove safe-mode binary override
    ('''if [ "$SAFE_MODE" = "1" ]; then
    V36_BIN="$D/t64560_v36_safe"
    CRED_BIN="$D/t64560_cred_safe"
    [ -x "$V36_BIN" ] || { echo "FAIL=missing_safe_bin name=t64560_v36_safe"; exit 2; }
    [ -x "$CRED_BIN" ] || { echo "FAIL=missing_safe_bin name=t64560_cred_safe"; exit 2; }
fi
run_v36() {
    if [ "$SAFE_MODE" = "1" ]; then
        T64560_SAFE=1 T64560_MIN_DRAIN_MS=500 T64560_DRAIN_MAX_MS=8000 \\
        T64560_DRAIN_SLACK="$SAFE_SLACK" T64560_EARLY_ABORT_MS="$EARLY_ABORT_MS" T64560_EARLY_ABORT_STALL_MS=1000 T64560_EARLY_ABORT_MARGIN=4 \\
        "$V36_BIN" "$@"
    else
        "$V36_BIN" "$@"
    fi
}
run_cred() {
    if [ "$SAFE_MODE" = "1" ]; then
        MAGICROOT_CAPBND_OK="$MARK/CAPBND_OK" MAGICROOT_PHASE2_MARKER="$MARK/PHASE2_DONE" MAGICROOT_VERIFY_PID="$TARGET_PID" \\
        T64560_SAFE=1 T64560_MIN_DRAIN_MS=500 T64560_DRAIN_MAX_MS=8000 \\
        T64560_DRAIN_SLACK="$SAFE_SLACK" T64560_EARLY_ABORT_MS="$EARLY_ABORT_MS" T64560_EARLY_ABORT_STALL_MS=1000 T64560_EARLY_ABORT_MARGIN=4 \\
        "$CRED_BIN" "$@"
    else
        MAGICROOT_CAPBND_OK="$MARK/CAPBND_OK" MAGICROOT_PHASE2_MARKER="$MARK/PHASE2_DONE" MAGICROOT_VERIFY_PID="$TARGET_PID" \\
        "$CRED_BIN" "$@"
    fi
}''',
     '''run_v36() {
    "$V36_BIN" "$@"
}
run_cred() {
    MAGICROOT_CAPBND_OK="$MARK/CAPBND_OK" MAGICROOT_PHASE2_MARKER="$MARK/PHASE2_DONE" MAGICROOT_VERIFY_PID="$TARGET_PID" \\
        "$CRED_BIN" "$@"
}'''),
    # keep previous logs (do not wipe Download/MagicRoot on every run)
    ('rm -rf /data/local/tmp/.magicroot-exec /storage/emulated/0/Download/MagicRoot 2>/dev/null',
     'rm -rf /data/local/tmp/.magicroot-exec 2>/dev/null'),
])

# ------------------------------------------------------------- root_stage ---
S = A / "root_stage.sh"
t = S.read_text(encoding="utf-8")
# drop MANAGER_APK from the flavor table
for line in (
    '        MANAGER_APK="$D/BakaSU-manager.apk"\n',
    '        MANAGER_APK=""\n',
):
    t = t.replace(line, "")
# drop the bundled manager install block
old_install = '''if [ -z "$TARGET_PKG" ] && [ -n "$MANAGER_APK" ] && [ -f "$MANAGER_APK" ]; then
    echo "ROOT_STAGE_MANAGER_INSTALL_BEGIN=$MGR"
    pm install -r "$MANAGER_APK" 2>&1 | tail -3
    echo "ROOT_STAGE_MANAGER_INSTALL_RC=$?"
    if pm path "$MGR" >/dev/null 2>&1; then
        TARGET_PKG="$MGR"
        echo "ROOT_STAGE_MANAGER_INSTALLED=$MGR"
    else
        warn "manager_install_failed package=$MGR"
    fi
fi
'''
if old_install not in t:
    raise SystemExit("root_stage install block anchor missing")
t = t.replace(old_install, '''if [ -z "$TARGET_PKG" ]; then
    warn "manager_not_installed package=$MGR (register the installed manager app and rerun)"
fi
''', 1)
# ksud source: extracted copy only (plus an already installed /data/adb/ksud)
old_ksud = '''# Userspace ksud: prefer the copy the app extracted from the installed manager
# APK (MAGICROOT_KSUD), then the per-flavor file in the work dir, then the
# bundled fallback shipped inside the APK.
KSUD_SRC=${MAGICROOT_KSUD:-}
if [ -z "$KSUD_SRC" ] || [ ! -f "$KSUD_SRC" ]; then
    for _c in "$D/ksud_${FLAVOR}" "$D/$(case "$FLAVOR" in
            resukisu) echo ksud_bakasu ;; fina) echo ksud_fina ;;
            kernelsu) echo ksud ;; sukisu) echo ksud_sukisu ;;
            *) echo ksud_next ;; esac)"; do
        [ -f "$_c" ] && { KSUD_SRC="$_c"; break; }
    done
fi
[ -n "$KSUD_SRC" ] || KSUD_SRC="$D/ksud"'''
if old_ksud not in t:
    raise SystemExit("root_stage ksud anchor missing")
t = t.replace(old_ksud, '''# Userspace ksud: the app extracted it from the installed manager APK
# (MAGICROOT_KSUD) or a previous run already installed /data/adb/ksud.
KSUD_SRC=${MAGICROOT_KSUD:-}
if [ -z "$KSUD_SRC" ] || [ ! -f "$KSUD_SRC" ]; then
    if [ -f "$D/ksud_${FLAVOR}" ]; then
        KSUD_SRC="$D/ksud_${FLAVOR}"
    elif [ -x "$ADB/ksud" ]; then
        KSUD_SRC="$ADB/ksud"
        echo "ROOT_STAGE_KSUD_EXISTING_ONLY"
    else
        echo "ROOT_STAGE_FAIL=ksud_source_missing hint=install_matching_manager_apk"
        exit 12
    fi
fi''', 1)
# header comment
t = t.replace('#   resukisu = BakaSU (default):   $D/ksud_bakasu, com.resukisu.resukisu,\n#                                  $D/BakaSU-manager.apk, kernel dynamic-manager',
              '#   resukisu = BakaSU (default):   extracted ksud, com.resukisu.resukisu,\n#                                  kernel dynamic-manager')
S.write_text(t, encoding="utf-8", newline="\n")
print("patched root_stage.sh")

# ---------------------------------------------------------- verify_apk.py ---
V = WS / "tools/verify_apk.py"
vt = V.read_text(encoding="utf-8")
for line in (
    '    ("ksud_bakasu", "73be215ff616c154", "BakaSU 4.2.0 ksud (5955840 B)"),\n',
    '    ("BakaSU-manager.apk", "4fb6335a610b5bec", "BakaSU manager com.resukisu.resukisu 35252"),\n',
    '    ("ksud", None, "official KernelSU 3.3.1 ksud (fallback)"),\n',
    '    ("ksud_fina", None, "FinaSU 1.0.8 userspace (extracted from manager APK)"),\n',
    '    ("ksud_next", None, "KernelSU-Next 3.4.2 userspace (extracted from manager APK)"),\n',
    '    ("ksud_sukisu", None, "SukiSU 4.2.1-r2 userspace (extracted from manager APK)"),\n',
):
    vt = vt.replace(line, "")
V.write_text(vt, encoding="utf-8", newline="\n")
print("patched verify_apk.py")
