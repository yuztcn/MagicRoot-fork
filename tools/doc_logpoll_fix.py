#!/usr/bin/env python3
"""Document the app-log stall diagnosis/fix (run.log polling) in DEVICE-VERIFY."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
dv = WS / "docs/DEVICE-VERIFY.md"
t = dv.read_text(encoding="utf-8", errors="replace")
if "## 19. App 日志停在" not in t:
    t = t.rstrip() + """

---

## 19. App 日志停在「开始执行 run.sh」根因与修复（2026-10-25 17:32）

**现场**

- App 运行日志停在最后一条 App 侧消息 `开始执行 run.sh（日志同时写入 …/run.log）`，
  进度 2%「准备链路」一直不动；
- 同时设备上的 `/data/local/tmp/magic/run.log` 已推进到 KASLR / patch / permissive
  attempt=30…50；
- 17:28 的应用退出记录（`dumpsys activity exit-info`）：
  `reason=10 (USER REQUESTED) subreason=22 (REMOVE TASK) description=remove task`
  —— 用户在界面“看起来卡住”后把 App 从最近任务划掉，App 死亡导致
  Stellar/Shizuku 拉起的 run.sh 随即被终止（日志停在 attempt=50，无 FAIL、无重启）。

**根因**：Stellar/Shizuku 子进程的 stdout 管道在竞态阶段不实时投递数据（日志文件
在增长而 App 收不到行），App 之前以 stdout 流作为 UI 日志来源，于是 UI 冻结。

**修复**

- UI 日志/进度改为**轮询 run.log**（每 1.5s `tail` 增量）作为权威来源；
  子进程 stdout 仅做 drain 防止管道阻塞；`DONE/FAIL`、进度阶段都从文件行解析；
- 真机 stub 验证：run 开始 4s 时界面已显示 `TEST_LOG_START/1/2/3`，8s 显示
  `DONE`，不再卡在启动行（截图 `docs/screenshots/magicroot-live-log-polling.png`）；
- App 启动后 4/12/25/40s 重试导出上次残留日志到
  `/sdcard/Download/MagicRoot/prev-run-<ts>.txt`（含 `PERMISSIVE_STARTED` 标记）。
  真机验证：被划掉的那次运行日志（7,398 B，attempt 1–50 + 中断标记）已成功自动导出。

**注意**

- App 被划掉/强停会连带终止正在运行的链路（remote 子进程随宿主死亡）。
  日志会保留并自动导出，但链路需重新执行；运行期间请勿从最近任务移除 App。
- 若设备在 permissive 竞态阶段 panic/重启，属于漏洞竞态固有风险，见 §18 的
  preflight/清理/取证措施。
"""
    dv.write_text(t, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §19 appended")
else:
    print("already present")
