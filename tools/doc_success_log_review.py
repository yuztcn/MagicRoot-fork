#!/usr/bin/env python3
"""Record the success-log review and repackage the release."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
dv = WS / "docs/DEVICE-VERIFY.md"
t = dv.read_text(encoding="utf-8", errors="replace")
if "## 15. 成功日志复核" not in t:
    t = t.rstrip() + """

---

## 15. 成功日志复核（2026-10-25 16:38，4097 B）

导出的 `magicroot-success-1792917484717.txt` 与 app 内快照
`magicroot-success-1792917476219.log` 内容一致（同尺寸/哈希），关键行：

```text
KSUD_SOURCE=manager-apk path=/data/local/tmp/magic/ksud_resukisu
MODULE_LIVE_FAST_REPAIR_TRY
grant_root_rc=0 errno=0
ROOT_STAGE_ENV uid=0 context=u:r:ksu:s0 enforce=Enforcing
ROOT_STAGE_KERNEL_VERSION=35252 UAPI=6 EXPECTED_FLAVOR=resukisu
ROOT_STAGE_SIG_SIZE=887 HASH=d3469712… SOURCE=app-package-manager
ROOT_STAGE_MANAGER_CMD=kernel-dynamic-manager
ROOT_STAGE_MANAGER_LIST=skipped(no manager subcommand; dynamic-manager path used)
ROOT_STAGE_MANAGER_CONNECTED=1 after=1s
ROOT_STAGE_SHELL_SU=unrestricted_bootstrap (keeps GRANT_ROOT reusable)
ROOT_STAGE_ALLOWLIST=no_backup
ROOT_STAGE_SU_CHECK=0
ROOT_STAGE_OK
MODULE_LIVE_FAST_REPAIR_OK
DONE
```

复核结论：无 WARN/FAIL；管理器连接、签名提取（PackageManager，887/d3469712…）、
ksud 提取（manager-apk）、动态管理器登记、su 自检全部正常。本次修正的日志噪音
（BakaSU 无 `manager` 子命令时的 `unrecognized subcommand`）已消除。

**存在/已记录的潜在问题**

1. `MODULE_LIVE_FLAVOR_HINT`：fast repair 无法从用户态探测 Live 模块的 flavor。
   已增加 `ROOT_STAGE_FLAVOR_MISMATCH` 标记：root_stage 发现版本/uapi 与所选后端
   不一致时写 `$D/root_stage_flavor_mismatch`，run.sh 在 fast repair 成功时输出
   `REUSE_FLAVOR_MISMATCH=1` 并提示重启/切回对应后端（本次日志无该标记）。
2. `ROOT_STAGE_ALLOWLIST=no_backup`：设备 ksu allowlist 为空，reuse 依赖
   bootstrap `allow_shell=1`。若用户放置 `$WORK/no_bootstrap_allow_shell`，
   fast repair 会按新逻辑快速失败并提示重启，属预期。
3. `ROOT_STAGE_SHELL_SU=unrestricted_bootstrap`：为保持 reuse 可用，本次不再自动
   启用 `shell_su_adb_only`；Stellar/adb shell 在本 boot 内可获得临时 root。
   需要收紧时可放置 `$WORK/enable_shell_adb_only`（会牺牲复用路径）。
4. 成功页「耗时」只统计 fast repair（约 10s），不代表完整链耗时，属正常。
"""
    dv.write_text(t, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §15 appended")
else:
    print("already present")
