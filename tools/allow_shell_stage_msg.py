#!/usr/bin/env python3
"""Align root_stage messages with the new allow_shell default-off policy."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
S = WS / "main/app/assets/root_stage.sh"
t = S.read_text(encoding="utf-8")


def sub(old: str, new: str):
    global t
    if old not in t:
        raise SystemExit("anchor missing: " + old[:80])
    t = t.replace(old, new, 1)


sub('''# The chain bootstrap-loads the module with allow_shell=1 so that the
# grant-root ioctl passes on devices with an empty ksu allowlist.  When the
# user did not enable "allow shell", confine shell su to adbd/ksu ancestors.''',
    '''# allow_shell 默认关闭；只有当用户在 UI 打开「allow shell」或显式同意
# bootstrap 时，模块才会以 allow_shell=1 加载。shell_su_adb_only 仍是可选的
# 收紧项（放 $D/enable_shell_adb_only 才启用）。''')

sub('''if [ "$UI_ALLOW_SHELL" != "1" ] && [ -f "$D/enable_shell_adb_only" ]; then
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
fi''',
    '''if [ -f "$D/enable_shell_adb_only" ]; then
    # Opt-in only: this confines shell su to adbd/ksu descendants, but it also
    # blocks GRANT_ROOT from the Stellar/Shizuku shell, which breaks the
    # "module already Live" reuse path.  Keep it behind a marker file.
    if "$ADB/ksud" feature set shell_su_adb_only 1 >/dev/null 2>&1 ||
       "$ADB/ksud" feature set 6 1 >/dev/null 2>&1; then
        echo "ROOT_STAGE_SHELL_SU=adb_only(opt-in)"
    else
        echo "ROOT_STAGE_SHELL_SU=unrestricted (shell_su_adb_only unavailable)"
    fi
elif [ "$UI_ALLOW_SHELL" = "1" ] || [ "${MAGICROOT_BOOTSTRAP_SHELL:-0}" = "1" ]; then
    echo "ROOT_STAGE_SHELL_SU=allow_shell_requested"
else
    echo "ROOT_STAGE_SHELL_SU=default_off (allow_shell=0)"
fi''')

sub('''# Restore the saved allowlist backup (root-only path) so the next module load
# no longer needs the allow_shell bootstrap.''',
    '''# Restore the saved allowlist backup (root-only path) so a future cold boot
# can pass GRANT_ROOT without enabling allow_shell.''')

S.write_text(t, encoding="utf-8", newline="\n")
print("patched root_stage allow_shell messaging")
