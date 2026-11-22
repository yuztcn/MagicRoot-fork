#!/usr/bin/env python3
"""Record the MultiSU multi-KMI integration in DEVICE-VERIFY."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
dv = WS / "docs/DEVICE-VERIFY.md"
t = dv.read_text(encoding="utf-8", errors="replace")
if "## 16. MultiSU 多内核" not in t:
    t = t.rstrip() + """

---

## 16. MultiSU 多内核（KMI）适配复核（2026-10-25 16:57）

参考提供的 `MultiSU/` 目录补充了 android16-6.12 KMI 的原生 LKM，五个后端不再
共用兼容模板：

| flavor | 6.12 LKM（内置） | 版本 | 6.12.58 syms | 6.12.38 syms |
|---|---|---|---|---|
| resukisu | `ksu-template-bakasu.ko` | 35252 | `syms_61258_bakasu.txt` | `syms_6138_bakasu.txt` |
| kernelsu | `ksu-template.ko` | 32680 | `syms_61258.txt` | `syms_6138.txt` |
| next | `ksu-template-next.ko`（MultiSU 500656 B） | 33355 | `syms_61258_next.txt` | 尚未生成 → fail-closed |
| sukisu | `ksu-template-sukisu.ko`（MultiSU 601056 B） | 41068 | `syms_61258_sukisu.txt` | 尚未生成 → fail-closed |
| fina | `ksu-template-fina.ko`（FinaSU 1.0.10 bundle 590848 B） | 33034 | `syms_61258_fina.txt` | 尚未生成 → fail-closed |

- FinaSU 同步升级到 v1.0.10（33034），`ksud_fina` 取自该 APK 的 `libksud.so`
  （`ksud 1.0.10 (uapi: 6)`）。
- 新 syms 由 `tools/gen_syms.py` 以 boot-0c1e86b6 的 kallsyms（slide
  0x252aa00000）生成：next +4 / sukisu +21 / fina +9 个符号，均
  `still missing: 0`、`_printk anchor consistent: True`。
- 设备端 `ko_patch` 验证（vermagic 重写到本机 6.12.58）：

```text
next    PATCHED=227 MISSING=0
sukisu  PATCHED=245 MISSING=0
fina    PATCHED=232 MISSING=0
```

- KMI × flavor 支持矩阵（真机 profile 测试）：

```text
6.12.58: resukisu/fina/kernelsu/sukisu/next  missing=0（全部可用）
6.12.38: resukisu/kernelsu missing=0；fina/sukisu/next missing=1（fail-closed）
```

6.12.38 缺少对应的 kallsyms dump，无法为三个新模板生成正确的 syms；此时
`run.sh` 会输出 `FAIL=flavor_syms_unavailable` 并拒绝加载（绝不使用另一内核的
地址），避免错配崩溃。提供 6.12.38 dump 后可用同一工具补齐。

成功页内核版本展示同时修正：两行均为正文色，不再将 git/构建后缀置灰。
截图：`docs/screenshots/magicroot-success-export.png`。
"""
    dv.write_text(t, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §16 appended")
else:
    print("already present")
