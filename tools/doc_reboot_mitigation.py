#!/usr/bin/env python3
"""Record the reboot-diagnosis/mitigation pass in DEVICE-VERIFY."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
dv = WS / "docs/DEVICE-VERIFY.md"
t = dv.read_text(encoding="utf-8", errors="replace")
if "## 18. 准备阶段重启" not in t:
    t = t.rstrip() + """

---

## 18. 准备阶段重启诊断与缓解（2026-10-25 17:20）

用户反馈：链路在「准备链路」阶段容易导致设备很快重启；可直接导出日志后读取。
现场最后一次运行日志（`/data/local/tmp/magic/run.log` / stage.log，boot_id
`30059683…`）：

```text
STAGE_MARK=RUN_CLEAN_DONE  time=17:07:44 uptime=72
== 1. KASLR ==  KASLR_ACCEPTED slide=0x2d9b000000 votes=5917 anchors=5
== 2. patch KernelSU module ==  PATCHED=226 MISSING=0
== 3. SELinux permissive ==
attempt=1 … attempt=7 (slab baseline 256/256) → 设备在此处重启
```

**结论**：重启发生在 **SELinux permissive 竞态阶段**（模块尚未加载、SELinux 仍
Enforcing），而不是 App/日志层；该次运行在开机仅 **72 秒**、系统负载很高时启动，
竞态 spray 的堆状态与稳定启动时差异很大，panic/重启概率显著升高。日志读取本身
正常（App 内日志显示正常，问题仅是“刚开机就跑”），因此修复方向是**启动前等待 +
减少残留扰动 + 保留证据**。

**已实施**

1. **开机稳定闸门**（run.sh preflight）：在进入 KASLR/竞态前等待
   `uptime>=120s && sys.boot_completed=1 && load<=20 && MemAvailable>=1GB`，
   最长 240s；超时则 `FAIL=preflight_timeout` 并提示稍后重试（不再直接开跑）。
   - 真机验证：设备 uptime 618s/load 15 → `PREFLIGHT_OK`；
     人为设置 `MAX_LOAD=0, MAX_WAIT=3` → `FAIL=preflight_timeout` + 提示。
   - 可用 `$WORK/skip-preflight` 或 `MAGICROOT_SKIP_PREFLIGHT=1` 跳过；
     App 进度会显示「等待系统稳定」。
2. **竞态前清理**：permissive 前 `pkill forker/grab.sh/trace_pipe_raw` 并 sleep 1s，
   避免 KASLR 抓取残留进程继续占用内存/CPU。
3. **中断日志自动导出**：App 启动后 4s、以及每次新运行前，会把残留 run.log +
   `marks/PERMISSIVE_STARTED` 导出到
   `/sdcard/Download/MagicRoot/prev-run-<ts>.txt`，然后才清理/覆盖。
   真机用 dummy 日志验证：导出文件包含 `DUMMY_RUN_LOG` 与
   `=== PERMISSIVE_STARTED ===` 段。
4. **pstore 保留**：root_stage 拿到 root 后尝试把 `/sys/fs/pstore` 复制到
   `$WORK/pstore-last` 与 `/sdcard/Download/MagicRoot/pstore-last`（下次成功运行时
   可用于分析上一次崩溃的 console-ramoops）。
5. 若仍重启：重新打开 App 会自动导出上次日志；再次运行会先等待系统稳定
   （通常开机后静置 2 分钟以上即可通过闸门）。竞态本身存在固有 panic 风险，
   无法完全消除，只能降低概率并保留取证。
"""
    dv.write_text(t, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §18 appended")
else:
    print("already present")
