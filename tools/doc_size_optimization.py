#!/usr/bin/env python3
"""Record the APK size/cleanup pass in DEVICE-VERIFY."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
dv = WS / "docs/DEVICE-VERIFY.md"
t = dv.read_text(encoding="utf-8", errors="replace")
if "## 17. 体积优化" not in t:
    t = t.rstrip() + """

---

## 17. 体积优化 + 去内置管理器/ksud + 去 safe 调试（2026-10-25 17:03）

用户要求：不再内置管理器，用户自行安装正确管理器；删除无用的 `_safe` 调试载荷；
进行 APK 体积优化。

**移除内容**

- `BakaSU-manager.apk`（10,150,216 B）——不再随 APK 内置任何管理器；
- 5 份内置 ksud（`ksud`/`ksud_bakasu`/`ksud_fina`/`ksud_next`/`ksud_sukisu`，
  合计约 31.3 MB）——运行链路改为**只从已安装管理器 APK 提取**用户态 ksud；
- `t64560_v36_safe`、`t64560_cred_safe` 以及 run.sh 中整段 SAFE_MODE/
  EARLY_ABORT/drain-slack/run_v36/run_cred 包装逻辑；
- root_stage 中内置管理器 APK 的 `pm install` 自动安装逻辑。

**行为变化**

- 未安装对应管理器时，运行在提取阶段快速失败：
  `FAIL=manager_ksud_missing` + 安装提示（实测 kernelsu 未安装时 <1s 返回，
  且不会启动任何漏洞链进程）；
- 已安装管理器时，从 APK 的 `lib/arm64-v8a/libksud.so`（或重命名库）提取
  ksud，签名由 PackageManager 计算；
- `run.sh` 不再在每次运行前删除 `/sdcard/Download/MagicRoot`，历史日志保留。

**体积结果**

| 项 | 优化前 | 优化后 | 变化 |
|---|---:|---:|---:|
| main APK | 36,600,016 B | **4,042,271 B** | −32,557,745 B（−88.9%） |

**真机回归**（移除内置文件后的 4.0 MB APK）

- 已安装 BakaSU 管理器：部署时自动提取 `ksud_resukisu`（manager-apk），
  fast repair 成功页出现，导出日志 4,120 B；
- 未安装 KernelSU 管理器时：`FAIL=manager_ksud_missing` 快速失败，无漏洞链进程。
"""
    dv.write_text(t, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §17 appended")
else:
    print("already present")
