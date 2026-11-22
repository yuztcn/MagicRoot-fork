#!/usr/bin/env python3
"""Document the reuse-detection fix, real log export and About placement."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
dv = WS / "docs/DEVICE-VERIFY.md"
t = dv.read_text(encoding="utf-8", errors="replace")
if "## 14. reuse 误判修复" not in t:
    t = t.rstrip() + """

---

## 14. reuse 误判修复 + 导出日志实测（2026-10-25 16:30）

**现场日志（error.txt）分析**

1. `清理失败: java.lang.IllegalStateException: Stellar/Shizuku 均不可用`
   —— 应用启动后 Shell binder 尚未就绪，清理/部署第一次点击就失败。
   修复：`shellProcess()` 现在对「均不可用」最多重试 5 次（每次 600ms），
   Stellar/Shizuku 刚连上时也能继续。
2. `管理器文件提取（KernelSU）: manager-not-installed` /
   `管理器签名提取: unavailable` —— 默认后端 KernlSU 未安装管理器，属预期的
   内置兜底路径（提示文案已改为「使用内置兜底」）。
3. **reuse 误判（核心）**：`MODULE_ALREADY_LIVE` → fast repair 的
   `ksu_grant` 报 EPERM，旧逻辑仍继续跑完整漏洞链；但 Live 模块无法替换
   （`KO_PATCH_SKIPPED reason=module_already_live`），只浪费时间且可能扰动内核。
   根因之一：上一轮 root_stage 自动开启了 `shell_su_adb_only`，Stellar/Shizuku
   拉起的 shell 不是 adbd/ksu 后代，之后的 GRANT_ROOT 因此被拒。

**修复**

- `run.sh`：Live 模块 + fast repair 失败时**不再进入完整链**，而是重试一次后
  输出 `FAIL=reuse_module_live_not_grantable` 与重启提示；
  `$WORK/force-full` 可显式恢复旧行为（调试用）。
- `root_stage.sh`：`shell_su_adb_only` 改为**opt-in**（`$WORK/enable_shell_adb_only`
  才启用），避免破坏后续 reuse。
- 成功页「导出日志」接入真实导出：复制到
  `/sdcard/Download/MagicRoot/magicroot-success-<ts>.txt`（与失败日志同目录），
  校验文件非空后在成功页内联显示成功/失败与路径、字节数；内存中的 run log
  作为兜底来源（清理工作目录后仍可导出）。

**真机验证**（同一 boot，模块 Live）

- 旧构建下 app 侧 fast repair 失败：`grant_root_rc=-1 EPERM` → 新逻辑快速
  `FAIL=reuse_module_live_not_grantable`，不再启动全链；
- 清除历史 `shell_su_adb_only` 后重新验证：
  `MODULE_LIVE_FAST_REPAIR_OK` → `DONE`，成功页出现（耗时 00:10）；
- 点击「导出日志」输出：
  `日志已导出: /sdcard/Download/MagicRoot/magicroot-success-1792917270332.txt (4139 B)`，
  `ls` 确认文件 4139 B。
- 成功页布局修复：内核版本占整行，不再挤压竖排；「关于」入口改为状态栏行内
  的小号文字链接（10sp），「就绪」胶囊保持右上角。

截图：`docs/screenshots/magicroot-success-export.png`、
`docs/screenshots/magicroot-header-about-link.png`。
"""
    dv.write_text(t, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §14 appended")
else:
    print("already present")

# screenshots
for src, dst in [
    (".probe/verify_export.png", "docs/screenshots/magicroot-success-export.png"),
    (".probe/verify_success_page.png", "docs/screenshots/magicroot-success-page.png"),
    (".probe/verify_home.png", "docs/screenshots/magicroot-header-about-link.png"),
]:
    s = WS / src
    if s.exists():
        (WS / dst).write_bytes(s.read_bytes())
        print("screenshot", dst)
