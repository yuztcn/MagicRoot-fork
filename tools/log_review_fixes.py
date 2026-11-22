#!/usr/bin/env python3
"""Log-review follow-up fixes:

1. do not emit the expected `manager list` error on backends without the
   `manager` subcommand (it showed up as a confusing error line in a healthy
   success log);
2. make a Live-module / selected-backend version mismatch explicit
   (ROOT_STAGE_FLAVOR_MISMATCH marker + REUSE_FLAVOR_MISMATCH in run.sh),
   because the fast-repair path cannot probe the live module's flavor from
   userspace;
3. clarify the success-page hint (temp root is already active; manager is for
   persistent root authorization).
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


# ------------------------------------------------------------ root_stage ---
S = WS / "main/app/assets/root_stage.sh"
patch(S, [
    # flavor mismatch marker next to the existing warnings
    ("""if [ -n "$KSU_KERNEL_VERSION" ] && [ "$KSU_KERNEL_VERSION" != "$EXPECT_KVER" ]; then
    warn "kernel_version_mismatch flavor=$FLAVOR actual=$KSU_KERNEL_VERSION expected=$EXPECT_KVER"
fi
if [ -n "$KSU_UAPI" ] && [ "$KSU_UAPI" != "$EXPECT_UAPI" ]; then
    warn "uapi_mismatch flavor=$FLAVOR actual=$KSU_UAPI expected=$EXPECT_UAPI"
fi""",
     """MISMATCH=0
if [ -n "$KSU_KERNEL_VERSION" ] && [ "$KSU_KERNEL_VERSION" != "$EXPECT_KVER" ]; then
    warn "kernel_version_mismatch flavor=$FLAVOR actual=$KSU_KERNEL_VERSION expected=$EXPECT_KVER"
    MISMATCH=1
fi
if [ -n "$KSU_UAPI" ] && [ "$KSU_UAPI" != "$EXPECT_UAPI" ]; then
    warn "uapi_mismatch flavor=$FLAVOR actual=$KSU_UAPI expected=$EXPECT_UAPI"
    MISMATCH=1
fi
if [ "$MISMATCH" = "1" ]; then
    # The live LKM was loaded for a different backend/version; reuse may still
    # work but registration semantics can differ.  Record it so run.sh can
    # surface the mismatch instead of reporting a silent success.
    {
        echo "REUSE_FLAVOR_MISMATCH=1 flavor=$FLAVOR actual_version=${KSU_KERNEL_VERSION:-unknown} actual_uapi=${KSU_UAPI:-unknown} expected_version=$EXPECT_KVER expected_uapi=$EXPECT_UAPI"
    } > "$D/root_stage_flavor_mismatch"
    echo "ROOT_STAGE_FLAVOR_MISMATCH=1"
fi"""),
    # manager list only when the subcommand exists
    ("""    if "$ADB/ksud" manager --help >/dev/null 2>&1; then
        echo "ROOT_STAGE_MANAGER_CMD2=manager-add\"""",
     """    MGR_LIST_SUPPORTED=0
    if "$ADB/ksud" manager --help >/dev/null 2>&1; then
        MGR_LIST_SUPPORTED=1
        echo "ROOT_STAGE_MANAGER_CMD2=manager-add\""""),
    ("""    echo "ROOT_STAGE_MANAGER_LIST=$("$ADB/ksud" manager list 2>&1 | head -5 | tr '\\n' '|')\"""",
     """    if [ "${MGR_LIST_SUPPORTED:-0}" = "1" ]; then
        echo "ROOT_STAGE_MANAGER_LIST=$("$ADB/ksud" manager list 2>&1 | head -5 | tr '\\n' '|')"
    else
        echo "ROOT_STAGE_MANAGER_LIST=skipped(no manager subcommand; dynamic-manager path used)"
    fi"""),
])

# ------------------------------------------------------------------ run.sh --
R = WS / "main/app/assets/run.sh"
patch(R, [(
    """        if "$D/ksu_grant"; then
            cat "$MARK/ROOT_ID" 2>/dev/null
            echo "MODULE_LIVE_FAST_REPAIR_OK"
            echo "DONE"
            exit 0
        fi""",
    """        if "$D/ksu_grant"; then
            cat "$MARK/ROOT_ID" 2>/dev/null
            if [ -f "$D/root_stage_flavor_mismatch" ]; then
                cat "$D/root_stage_flavor_mismatch"
                echo "HINT=the live LKM does not match the selected backend; reboot (or switch back) before relying on this backend's manager"
            fi
            echo "MODULE_LIVE_FAST_REPAIR_OK"
            echo "DONE"
            exit 0
        fi"""
)])

# ------------------------------------------------------------- MiuixHost ----
M = WS / "main/compose-app/app/src/main/kotlin/com/aoki/magicroot/MiuixHost.kt"
patch(M, [(
    """                Text(
                    text = "提示：打开 " + state.ksuManagerLabel +
                        " 管理器完成 root 授权后，返回 MagicRoot 验证 su。",""",
    """                Text(
                    text = "提示：临时 root 已生效；需要持久 root 或授权其他应用时，请打开 " +
                        state.ksuManagerLabel + " 管理器处理。","""
)])
print("done")
