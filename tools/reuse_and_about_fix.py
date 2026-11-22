#!/usr/bin/env python3
"""Fix the kernel-module reuse mis-detection and polish the About entry.

Root cause of "module Live but reuse fails":
- run.sh fell back to the FULL exploit chain when the fast repair could not get
  root.  A Live module cannot be reloaded (KO_PATCH_SKIPPED), so the full chain
  only wasted minutes and could destabilize the kernel.
- root_stage auto-enabled the shell_su_adb_only feature when the user kept
  "allow shell" off; the shell spawned by Stellar/Shizuku is not an adbd/ksu
  descendant, so the next GRANT_ROOT attempt got EPERM even though the module
  was loaded with allow_shell=1.

This patch:
1. fails fast with actionable hints when a Live module cannot be granted;
2. keeps shell_su_adb_only opt-in (marker file), so reuse keeps working;
3. shrinks/moves the "关于" entry into the header status row.
"""
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


# ------------------------------------------------------------------ run.sh --
R = WS / "main/app/assets/run.sh"
patch(R, [(
    """    echo "MODULE_LIVE_FAST_REPAIR_FAILED"
    if [ "$(getenforce)" = "Permissive" ]; then
        echo "FAIL=reuse_root_stage"
        exit 8
    fi
    # Fast repair failed only because the inherited SELinux context cannot
    # write /data/adb. Fall back to the minimum SELinux-only fix, then retry
    # root_stage; do not reload the module.
    echo "MODULE_ALREADY_LIVE_ENFORCING"
    MODULE_ALREADY_LIVE_ENFORCING=1
fi""",
    """    echo "MODULE_LIVE_FAST_REPAIR_FAILED"
    # A Live module cannot be replaced: ko_patch is skipped and finit_module
    # would hit the module name conflict.  The old behavior continued the full
    # exploit chain anyway (wasting minutes and risking a kernel crash), so be
    # explicit instead: reuse only works when GRANT_ROOT can still reach uid=0.
    if [ -f "$D/force-full" ] || [ "${MAGICROOT_FORCE_FULL:-0}" = "1" ]; then
        echo "REUSE_OVERRIDE=force_full"
        echo "MODULE_ALREADY_LIVE_ENFORCING"
        MODULE_ALREADY_LIVE_ENFORCING=1
    else
        echo "FAIL=reuse_module_live_not_grantable"
        echo "REUSE_CHECK=module_live_uid=$(id -u 2>/dev/null) enforce=$(getenforce 2>/dev/null)"
        echo "HINT=module already Live this boot but GRANT_ROOT did not return uid=0, so root is not reusable"
        echo "HINT_FIX=reboot, then rerun with the default bootstrap (the LKM is only replaceable across boots)"
        echo "HINT_CAUSE=shell_su_adb_only or an emptied allowlist blocks non-adbd shells; keep it disabled or reboot"
        echo "HINT_DEBUG=touch $D/force-full to run the legacy full chain instead"
        exit 8
    fi
fi"""
)])

# ------------------------------------------------------------- root_stage ---
S = WS / "main/app/assets/root_stage.sh"
patch(S, [(
    """if [ "$UI_ALLOW_SHELL" != "1" ]; then
    if "$ADB/ksud" feature set shell_su_adb_only 1 >/dev/null 2>&1 ||
       "$ADB/ksud" feature set 6 1 >/dev/null 2>&1; then
        echo "ROOT_STAGE_SHELL_SU=adb_only"
    else
        echo "ROOT_STAGE_SHELL_SU=unrestricted (shell_su_adb_only unavailable)"
    fi
else
    echo "ROOT_STAGE_SHELL_SU=unrestricted (user enabled allow shell)"
fi""",
    """if [ "$UI_ALLOW_SHELL" != "1" ] && [ -f "$D/enable_shell_adb_only" ]; then
    # Opt-in only: this confines shell su to adbd/ksu descendants, but it also
    # blocks GRANT_ROOT from the Stellar/Shizuku shell, which breaks the
    # "module already Live" reuse path.  Keep it behind a marker file.
    if "$ADB/ksud" feature set shell_su_adb_only 1 >/dev/null 2>&1 ||
       "$ADB/ksud" feature set 6 1 >/dev/null 2>&1; then
        echo "ROOT_STAGE_SHELL_SU=adb_only(opt-in)"
    else
        echo "ROOT_STAGE_SHELL_SU=unrestricted (shell_su_adb_only unavailable)"
    fi
elif [ "$UI_ALLOW_SHELL" != "1" ]; then
    echo "ROOT_STAGE_SHELL_SU=unrestricted_bootstrap (keeps GRANT_ROOT reusable)"
else
    echo "ROOT_STAGE_SHELL_SU=unrestricted (user enabled allow shell)"
fi"""
)])

# ------------------------------------------------------------- MiuixHost ----
M = WS / "main/compose-app/app/src/main/kotlin/com/aoki/magicroot/MiuixHost.kt"
patch(M, [
    # 1. put a compact "关于" text link next to the status pill
    ("""                StatusPill(
                    text = when {
                        state.running -> "运行中"
                        state.busy -> "处理中"
                        else -> "就绪"
                    },
                    color = when {
                        state.running -> MiuixTheme.colorScheme.primaryContainer
                        state.busy -> MiuixTheme.colorScheme.secondaryContainer
                        else -> MiuixTheme.colorScheme.tertiaryContainer
                    },
                )
            }""",
     """                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusPill(
                        text = when {
                            state.running -> "运行中"
                            state.busy -> "处理中"
                            else -> "就绪"
                        },
                        color = when {
                            state.running -> MiuixTheme.colorScheme.primaryContainer
                            state.busy -> MiuixTheme.colorScheme.secondaryContainer
                            else -> MiuixTheme.colorScheme.tertiaryContainer
                        },
                    )
                    Spacer(Modifier.width(2.dp))
                    Text(
                        text = "关于",
                        fontSize = 10.sp,
                        color = MiuixTheme.colorScheme.primary,
                        modifier = Modifier
                            .clickable { state.showAbout = true }
                            .padding(horizontal = 6.dp, vertical = 6.dp),
                    )
                }
            }"""),
    # 2. kernel line: no more large About pill
    ("""            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "内核 ${state.kernelVersion}",
                    fontSize = 9.5.sp,
                    lineHeight = 13.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.weight(1f),
                )
                Box(
                    modifier = Modifier
                        .background(
                            color = MiuixTheme.colorScheme.surfaceContainerHigh,
                            shape = RoundedCornerShape(12.dp),
                        )
                        .clickable { state.showAbout = true }
                        .padding(horizontal = 10.dp, vertical = 4.dp),
                ) {
                    Text(
                        text = "关于",
                        fontSize = 10.sp,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                }
            }""",
     """            Text(
                text = "内核 ${state.kernelVersion}",
                fontSize = 9.5.sp,
                lineHeight = 13.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )"""),
])
print("done")
