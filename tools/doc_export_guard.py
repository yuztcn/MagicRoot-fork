from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
size = "3,822,818 B"
sha = "da8da5c8d610083396c6786f9991a5f20f21084b3b7b3a55e0814e729211764f"

doc = WS / "docs/reference/kernel-adaptation-61258-61238.md"
t = doc.read_text(encoding="utf-8")
import re
t = re.sub(r"size = `[^`]+`", f"size = `{size}`", t)
t = re.sub(r"sha256 = `[0-9a-f]{64}`", f"sha256 = `{sha}`", t)
doc.write_text(t, encoding="utf-8", newline="\n")
print("adaptation doc build hash updated")

dv = WS / "docs/DEVICE-VERIFY.md"
dt = dv.read_text(encoding="utf-8")
if "## 22. PREFLIGHT_WAIT" not in dt:
    dt = dt.rstrip() + """

---

## 22. PREFLIGHT_WAIT 阶段禁止重复导出日志（2026-10-25 19:45）

**问题**：App 启动后的 stale-log 自动导出重试（4/12/25/40s）没有判断“是否正在跑链”。
如果用户在启动后很快点「开始提权」，这些重试会在 PREFLIGHT_WAIT 阶段继续执行：
把**当前正在写的 run.log** 当成上次残留日志导出到 `prev-run-*.txt`，并把 run.log
改名为 `run.log.exported`，导致 preflight 之后的日志轮询丢行/重复导出。

**修复**（MainActivity）：

- `runInProgress` 保护：launch 重试与 `exportStaleRunLog("launch")` 在运行中直接返回；
- 新增 `staleExportDone` 一次性标记：成功导出后，后续重试不再检查/导出；
- `exportStaleRunLog` 加 `synchronized`，避免 4s/12s 两个重试并发导出同一个文件；
- 唯一允许在运行开始时执行的是 `exportStaleRunLog("before-run")`，它在 run.log
  被删除、新进程启动之前执行，只导出上一次的残留日志，不影响本次 PREFLIGHT_WAIT。

构建：APK 3,822,818 B
sha256 `da8da5c8d610083396c6786f9991a5f20f21084b3b7b3a55e0814e729211764f`
（`tools/verify_apk.py` 通过）。真机验证待设备连接。
"""
    dv.write_text(dt, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §22 appended")
else:
    print("§22 already present")
