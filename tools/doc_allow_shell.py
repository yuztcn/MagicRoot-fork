#!/usr/bin/env python3
"""Record the allow_shell default-off change in DEVICE-VERIFY."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
dv = WS / "docs/DEVICE-VERIFY.md"
t = dv.read_text(encoding="utf-8", errors="replace")
if "## 20. allow_shell 默认关闭" not in t:
    t = t.rstrip() + """

---

## 20. allow_shell 默认关闭（2026-10-25 17:40）

**发现的问题**：`run.sh` 里 `ALLOW_SHELL` 默认虽然是 0，但存在隐藏的
`BOOTSTRAP_SHELL=${MAGICROOT_BOOTSTRAP_ALLOW_SHELL:-1}`：
即使 UI「allow shell」关闭，模块仍会以 `allow_shell=1` 加载（日志
`ALLOW_SHELL=0 LOAD_ALLOW_SHELL=1 BOOTSTRAP_SHELL=1`），与“默认不开启”不符。

**修改**

- `BOOTSTRAP_SHELL` 默认改为 **0**；`LOAD_ALLOW_SHELL` 只取 UI 的 `ALLOW_SHELL`
  值，默认 0（模块以 `allow_shell=0` 加载）；
- bootstrap 需显式同意，三种方式：
  1. UI 打开「allow shell」；
  2. 环境变量 `MAGICROOT_BOOTSTRAP_ALLOW_SHELL=1`；
  3. 高级用户放置 `$WORK/bootstrap_allow_shell`；
  旧的 `no_bootstrap_allow_shell` 标记移除；
- 日志新增 `ALLOW_SHELL_NOTE=off` 说明；grant 失败提示改为
  “启用「allow shell」后重启重试”；
- root_stage 的 `ROOT_STAGE_SHELL_SU` 状态改为
  `default_off (allow_shell=0)` / `allow_shell_requested`；
- UI「allow shell」副标题改为「默认关 · 冷启动首次需开」。

**影响/使用**

- 默认（allow_shell=0）下，冷启动的 `GRANT_ROOT` 需要 shell 已在 ksu allowlist
  中（例如管理器已授权 shell）；若 allowlist 为空，则需开启「allow shell」后
  **重启并重跑**（Live 模块无法替换参数）；
- 这是安全取舍：不再在用户不知情时赋予 shell 临时 root 能力；
- 已用 `bash -n` 对 `run.sh`/`root_stage.sh` 做语法检查（设备离线期间无法做
  真机配置回显验证，下一次连接设备后可用
  `MAGICROOT_PREFLIGHT_ONLY=1 sh run.sh` 查看
  `ALLOW_SHELL=0 LOAD_ALLOW_SHELL=0 BOOTSTRAP_SHELL=0`）。
"""
    dv.write_text(t, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §20 appended")
else:
    print("already present")
