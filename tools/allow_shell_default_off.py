#!/usr/bin/env python3
"""allow_shell must default OFF in run.sh:

- remove the hidden `BOOTSTRAP_SHELL=1` default (which made LOAD_ALLOW_SHELL=1
  even when the UI switch was off);
- bootstrap now requires explicit consent: UI「allow shell」, env
  MAGICROOT_BOOTSTRAP_ALLOW_SHELL=1, or $WORK/bootstrap_allow_shell marker;
- grant failures explain that a cold boot needs an allowlisted shell.
"""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
R = WS / "main/app/assets/run.sh"
t = R.read_text(encoding="utf-8")


def sub(old: str, new: str):
    global t
    if old not in t:
        raise SystemExit("anchor missing: " + old[:80])
    t = t.replace(old, new, 1)


sub('''# Bootstrap allow_shell: the grant-root ioctl is gated by the LKM's
# allowed_for_su checker; on a device whose ksu allowlist is empty the module
# must be loaded with allow_shell=1 or the fast-repair root stage gets EPERM.
# The UI "allow shell" switch still controls whether shell su stays
# unrestricted; root_stage confines it to adb/ksu ancestors when bootstrap-only.
BOOTSTRAP_SHELL=${MAGICROOT_BOOTSTRAP_ALLOW_SHELL:-1}
[ -f "$D/no_bootstrap_allow_shell" ] && BOOTSTRAP_SHELL=0
case "$BOOTSTRAP_SHELL" in 1) ;; *) BOOTSTRAP_SHELL=0 ;; esac
LOAD_ALLOW_SHELL=$ALLOW_SHELL
if [ "$ALLOW_SHELL" != "1" ] && [ "$BOOTSTRAP_SHELL" = "1" ]; then
    LOAD_ALLOW_SHELL=1
fi''',
    '''# allow_shell 默认关闭（UI「allow shell」默认关，模块因此也以 allow_shell=0 加载）。
# 冷启动时 GRANT_ROOT 需要 shell 在 allowlist 中，或显式同意 bootstrap：
#   - UI 打开「allow shell」；或
#   - MAGICROOT_BOOTSTRAP_ALLOW_SHELL=1；或
#   - 放置 $D/bootstrap_allow_shell（高级用户）
# 未同意时若 grant 失败，会给出明确提示，不会静默放宽 shell 权限。
BOOTSTRAP_SHELL=${MAGICROOT_BOOTSTRAP_ALLOW_SHELL:-0}
[ -f "$D/bootstrap_allow_shell" ] && BOOTSTRAP_SHELL=1
case "$BOOTSTRAP_SHELL" in 1) ;; *) BOOTSTRAP_SHELL=0 ;; esac
LOAD_ALLOW_SHELL=$ALLOW_SHELL
if [ "$ALLOW_SHELL" != "1" ] && [ "$BOOTSTRAP_SHELL" = "1" ]; then
    LOAD_ALLOW_SHELL=1
fi''')

sub('echo "ALLOW_SHELL=$ALLOW_SHELL LOAD_ALLOW_SHELL=$LOAD_ALLOW_SHELL BOOTSTRAP_SHELL=$BOOTSTRAP_SHELL"',
    '''echo "ALLOW_SHELL=$ALLOW_SHELL LOAD_ALLOW_SHELL=$LOAD_ALLOW_SHELL BOOTSTRAP_SHELL=$BOOTSTRAP_SHELL"
if [ "$LOAD_ALLOW_SHELL" != "1" ]; then
    echo "ALLOW_SHELL_NOTE=off (cold-boot root_stage needs an allowlisted shell; enable 「allow shell」 and reboot if grant fails)"
fi''')

sub('echo "HINT_FIX=reboot, then rerun with the default bootstrap (the LKM is only replaceable across boots)"',
    'echo "HINT_FIX=reboot, then rerun after enabling 「allow shell」 (needed for the first cold boot; the LKM is only replaceable across boots)"')

sub('echo "HINT_FIX=this build bootstrap-loads allow_shell=1; if you disabled it (\\$WORK/no_bootstrap_allow_shell) remove it, reboot and rerun"',
    'echo "HINT_FIX=allow_shell is off and the shell is not allowlisted; enable 「allow shell」 (or set MAGICROOT_BOOTSTRAP_ALLOW_SHELL=1), then reboot and rerun"')

R.write_text(t, encoding="utf-8", newline="\n")
print("patched run.sh allow_shell defaults")

# UI subtitle
M = WS / "main/compose-app/app/src/main/kotlin/com/aoki/magicroot/MiuixHost.kt"
mt = M.read_text(encoding="utf-8")
old_ui = 'subtitle = "默认闭 · 引导自动开",'
if old_ui in mt:
    mt = mt.replace(old_ui, 'subtitle = "默认关 · 冷启动首次需开",', 1)
    M.write_text(mt, encoding="utf-8", newline="\n")
    print("patched allow shell subtitle")
else:
    print("WARN UI subtitle anchor missing")

# README note
RD = WS / "main/README.md"
rt = RD.read_text(encoding="utf-8", errors="replace")
if "allow_shell 默认关闭" not in rt:
    rt = rt.replace("## 构建", """## allow_shell 默认关闭

模块默认以 `allow_shell=0` 加载；冷启动时 `grantsure root_stage` 需要 shell 在
ksu allowlist 中，否则需显式同意 bootstrap（UI「allow shell」或
`MAGICROOT_BOOTSTRAP_ALLOW_SHELL=1`）。未同意时 grant 失败会提示开启并重启。

## 构建""", 1)
    RD.write_text(rt, encoding="utf-8", newline="\n")
    print("README note added")
