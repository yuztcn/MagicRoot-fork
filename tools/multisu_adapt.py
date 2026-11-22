#!/usr/bin/env python3
"""MultiSU multi-KMI integration:
- per-flavor native 6.12 LKM templates + matching syms tables (fail closed when
  a KMI/backend syms table is missing);
- FinaSU updated to v1.0.10 (kernel 33034) with its own ksud;
- success-page kernel version lines share the same (non-grey) color.
"""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent


def patch(path: Path, pairs):
    p = Path(path)
    t = p.read_text(encoding="utf-8", errors="replace")
    for old, new in pairs:
        if old not in t:
            print("WARN missing in", p.name, ":", old[:70])
            continue
        t = t.replace(old, new, 1)
    p.write_text(t, encoding="utf-8", newline="\n")
    print("patched", p.relative_to(WS))


# ------------------------------------------------------- kernel_profiles ---
K = WS / "main/app/assets/kernel_profiles.sh"
patch(K, [
    # FinaSU v1.0.10
    ('        fina)     echo "33020" ;;', '        fina)     echo "33034" ;;'),
    # per-flavor 6.12-native templates
    ('''# Bundled LKM template for the current kernel profile.  The template decides
# which syms table is used (BakaSU template -> *_bakasu superset table).
ksu_select_ko() {
    profile="$1"   # 61258 | 6138
    flavor="$2"
    case "$flavor" in
        resukisu)
            KO_TEMPLATE="$D/ksu-template-bakasu.ko"
            KO_COMPAT="native"
            ;;
        fina)
            # FinaSU is a uapi-6 fork; use the BakaSU uapi-6 template as the
            # bundled fallback unless the user supplies ko-fina.ko.
            KO_TEMPLATE="$D/ksu-template-bakasu.ko"
            KO_COMPAT="compat-uapi6-bakasu"
            ;;
        kernelsu)
            KO_TEMPLATE="$D/ksu-template.ko"
            KO_COMPAT="native"
            ;;
        sukisu|next)
            # Both are uapi-5 official-compatible forks; bundled fallback is
            # the official 6.12 template unless ko-<flavor>.ko is provided.
            KO_TEMPLATE="$D/ksu-template.ko"
            KO_COMPAT="compat-uapi5-official"
            ;;
        *)
            KO_TEMPLATE="$D/ksu-template-bakasu.ko"
            KO_COMPAT="native"
            ;;
    esac
    # Explicit per-flavor override always wins.
    if [ -f "$D/ko-$flavor.ko" ]; then
        KO_TEMPLATE="$D/ko-$flavor.ko"
        KO_COMPAT="override"
    fi
    case "$KO_TEMPLATE" in
        *bakasu.ko) SYMS="$D/syms_${profile}_bakasu.txt" ;;
        *)          SYMS="$D/syms_${profile}.txt" ;;
    esac
}''',
     '''# Per-flavor native 6.12 KMI LKM template + matching syms table.
# The reference MultiSU bundle provides native android16-6.12 LKMs for all five
# backends, so each flavor now uses its own kernel module (no cross-flavor
# compatibility fallback).
ksu_select_ko() {
    profile="$1"   # 61258 | 6138
    flavor="$2"
    FLAVOR_SYMS_MISSING=0
    case "$flavor" in
        resukisu)
            KO_TEMPLATE="$D/ksu-template-bakasu.ko"
            SYMS="$D/syms_${profile}_bakasu.txt"
            KO_COMPAT="native-6.12-bakasu"
            ;;
        kernelsu)
            KO_TEMPLATE="$D/ksu-template.ko"
            SYMS="$D/syms_${profile}.txt"
            KO_COMPAT="native-6.12-kernelsu"
            ;;
        next)
            KO_TEMPLATE="$D/ksu-template-next.ko"
            SYMS="$D/syms_${profile}_next.txt"
            KO_COMPAT="native-6.12-kernelsu-next"
            ;;
        sukisu)
            KO_TEMPLATE="$D/ksu-template-sukisu.ko"
            SYMS="$D/syms_${profile}_sukisu.txt"
            KO_COMPAT="native-6.12-sukisu"
            ;;
        fina)
            KO_TEMPLATE="$D/ksu-template-fina.ko"
            SYMS="$D/syms_${profile}_fina.txt"
            KO_COMPAT="native-6.12-finasu"
            ;;
        *)
            KO_TEMPLATE="$D/ksu-template.ko"
            SYMS="$D/syms_${profile}.txt"
            KO_COMPAT="native-6.12-kernelsu"
            ;;
    esac
    # Explicit per-flavor override always wins.
    if [ -f "$D/ko-$flavor.ko" ]; then
        KO_TEMPLATE="$D/ko-$flavor.ko"
        KO_COMPAT="override"
    fi
    # Fail closed: a template without a matching syms table for this KMI would
    # resolve against another kernel's addresses and crash the module.
    if [ ! -f "$KO_TEMPLATE" ] || [ ! -f "$SYMS" ]; then
        FLAVOR_SYMS_MISSING=1
        echo "KSU_FLAVOR_UNSUPPORTED flavor=$flavor profile=$profile template=$KO_TEMPLATE syms=$SYMS"
    fi
}'''),
    # export the flag
    ('            export MAGICROOT_KSU_TEMPLATE="$KO_TEMPLATE"\n            export MAGICROOT_KSU_COMPAT="$KO_COMPAT"\n            return 0\n            ;;\n        6.12.38',
     '            export MAGICROOT_KSU_TEMPLATE="$KO_TEMPLATE"\n            export MAGICROOT_KSU_COMPAT="$KO_COMPAT"\n            export MAGICROOT_FLAVOR_SYMS_MISSING="$FLAVOR_SYMS_MISSING"\n            return 0\n            ;;\n        6.12.38'),
    # second profile (6138) export too
    ('            export MAGICROOT_KSU_TEMPLATE="$KO_TEMPLATE"\n            export MAGICROOT_KSU_COMPAT="$KO_COMPAT"\n            return 0\n            ;;\n        6.6.*)',
     '            export MAGICROOT_KSU_TEMPLATE="$KO_TEMPLATE"\n            export MAGICROOT_KSU_COMPAT="$KO_COMPAT"\n            export MAGICROOT_FLAVOR_SYMS_MISSING="$FLAVOR_SYMS_MISSING"\n            return 0\n            ;;\n        6.6.*)'),
])

# ------------------------------------------------------------------ run.sh --
R = WS / "main/app/assets/run.sh"
patch(R, [
    ('''KERNEL_PROFILE="$PROFILE_ID"
echo "KERNEL_ACTUAL=$ACTUAL_KERNEL"''',
     '''KERNEL_PROFILE="$PROFILE_ID"
if [ "${MAGICROOT_FLAVOR_SYMS_MISSING:-0}" = "1" ] || [ "${FLAVOR_SYMS_MISSING:-0}" = "1" ]; then
    echo "FAIL=flavor_syms_unavailable profile=$KERNEL_PROFILE flavor=$KSU_FLAVOR"
    echo "HINT=no matching LKM/syms for this kernel KMI and backend (fail-closed; using another KMI's addresses would crash the module)"
    echo "HINT_SUPPORT=6.12.58: all five backends; 6.12.38: resukisu/kernelsu only until syms_6138_<flavor>.txt is generated"
    exit 2
fi
echo "KERNEL_ACTUAL=$ACTUAL_KERNEL"'''),
    # include syms in the profile echo for debugging
    ('echo "KSU_EXPECT=version=$EXPECT_KVER uapi=$EXPECT_UAPI template=$KO_TEMPLATE compat=$KO_COMPAT"',
     'echo "KSU_EXPECT=version=$EXPECT_KVER uapi=$EXPECT_UAPI template=$KO_TEMPLATE syms=$SYMS compat=$KO_COMPAT"'),
])

# ------------------------------------------------------------- root_stage ---
S = WS / "main/app/assets/root_stage.sh"
patch(S, [('        EXPECT_KVER=33020; EXPECT_UAPI=6 ;;',
           '        EXPECT_KVER=33034; EXPECT_UAPI=6 ;;')])

# ------------------------------------------------------------- MiuixHost ----
M = WS / "main/compose-app/app/src/main/kotlin/com/aoki/magicroot/MiuixHost.kt"
patch(M, [
    ('''                    Text(
                        text = kernelText.substring(gitSplit + 1),
                        fontSize = 9.sp,
                        lineHeight = 13.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.fillMaxWidth(),
                    )''',
     '''                    Text(
                        text = kernelText.substring(gitSplit + 1),
                        fontSize = 9.5.sp,
                        lineHeight = 14.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MiuixTheme.colorScheme.onSurface,
                        modifier = Modifier.fillMaxWidth(),
                    )'''),
])
print("done")
