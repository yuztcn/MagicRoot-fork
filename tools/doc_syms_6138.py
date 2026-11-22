from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
p = WS / "docs" / "DEVICE-VERIFY.md"
t = p.read_text(encoding="utf-8")
t = t.replace("| next | `ksu-template-next.ko`（MultiSU 500656 B） | 33355 | `syms_61258_next.txt` | 尚未生成 → fail-closed |",
              "| next | `ksu-template-next.ko`（MultiSU 500656 B） | 33355 | `syms_61258_next.txt` | `syms_6138_next.txt` |")
t = t.replace("| sukisu | `ksu-template-sukisu.ko`（MultiSU 601056 B） | 41068 | `syms_61258_sukisu.txt` | 尚未生成 → fail-closed |",
              "| sukisu | `ksu-template-sukisu.ko`（MultiSU 601056 B） | 41068 | `syms_61258_sukisu.txt` | `syms_6138_sukisu.txt` |")
t = t.replace("| fina | `ksu-template-fina.ko`（FinaSU 1.2.0 bundle 590848 B） | 33071 | `syms_61258_fina.txt` | `syms_6138_fina.txt` |",
              "| fina | `ksu-template-fina.ko`（FinaSU 1.2.0 bundle 590848 B） | 33071 | `syms_61258_fina.txt` | `syms_6138_fina.txt` |")
if "## 31. 6.12.38 syms 计算" not in t:
    t = t.rstrip() + """

---

## 31. 6.12.38 syms 计算审计（2026-10-25 23:00）

按当前每个 6.12 模板的未定义符号集合，计算 6.12.38 所需 syms：

| flavor | 模板 | 所需符号 | 已解析 | 缺失 | syms 表行数 | 多余 |
|---|---|---:|---:|---:|---:|---:|
| kernelsu | `ksu-template.ko` | 226 | 226 | 0 | 226 | 0 |
| resukisu | `ksu-template-bakasu.ko` | 233 | 233 | 0 | 241 | 8 |
| next | `ksu-template-next.ko` | 227 | 227 | 0 | 227 | 0 |
| sukisu | `ksu-template-sukisu.ko` | 245 | 245 | 0 | 245 | 0 |
| fina | `ksu-template-fina.ko` | 232 | 232 | 0 | 232 | 0 |

- 所有所需符号在现有 `syms_6138*` 表中均能解析，`missing=0`；
- 6.12.38 关键 anchor 校验：
  `prepare_creds=0xffffffc080b8a21c`、`selinux_state=0xffffffc0826663c8` 均正确；
- 计算出的必需集合写入 `refs/kernel-audit/syms-6138-required/`；
- 完整报告：`docs/reference/syms-6138-audit.md`。

结论：FinaSU 1.2.0 模板的未定义符号集合与旧模板一致，6.12.38 不需要新增 syms；
resukisu 表有 8 个多余符号，保留以兼容历史模板，不影响解析。
"""
    p.write_text(t, encoding="utf-8", newline="\n")
    print("updated DEVICE-VERIFY 6138 table + §31")
else:
    p.write_text(t, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY table updated")
