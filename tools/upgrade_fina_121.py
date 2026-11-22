from pathlib import Path
import hashlib
import shutil

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
SRC = Path(r"<LOCAL_USER>user\Documents\<DSH>\<OLD_WORKSPACE>\refs\fina-v1.2.1\FinaSU_v1.2.1_kernel-bundle.zip")
TMP = WS / ".probe" / "fina121"
TMP.mkdir(parents=True, exist_ok=True)
ASSET = WS / "main" / "app" / "assets" / "ksu-template-fina.ko"

import zipfile
with zipfile.ZipFile(SRC) as z:
    new = z.read("arm64/android16-6.12_kernelsu.ko")
old = ASSET.read_bytes()
(TMP / "old-ksu-template-fina-1.2.0.ko").write_bytes(old)
ASSET.write_bytes(new)
print("template new", len(new), hashlib.sha256(new).hexdigest())

p = WS / "main" / "app" / "assets" / "kernel_profiles.sh"
t = p.read_text(encoding="utf-8")
t = t.replace("#        fina     = FinaSU 1.2.0             kernel 33071 / uapi 6",
              "#        fina     = FinaSU 1.2.1             kernel 33074 / uapi 6")
t = t.replace("        fina)     echo \"33071\" ;;", "        fina)     echo \"33074\" ;;")
p.write_text(t, encoding="utf-8", newline="\n")

p = WS / "main" / "app" / "assets" / "root_stage.sh"
t = p.read_text(encoding="utf-8")
t = t.replace("        EXPECT_KVER=33071; EXPECT_UAPI=6 ;;",
              "        EXPECT_KVER=33074; EXPECT_UAPI=6 ;;")
p.write_text(t, encoding="utf-8", newline="\n")

p = WS / "tools" / "verify_apk.py"
t = p.read_text(encoding="utf-8")
t = t.replace('("ksu-template-fina.ko", "31fdd7b03de9524d", "FinaSU 1.2.0 native 6.12 LKM (MultiSU bundle)")',
              '("ksu-template-fina.ko", "d1f8cedb14c5a62f", "FinaSU 1.2.1 native 6.12 LKM (MultiSU bundle)")')
p.write_text(t, encoding="utf-8", newline="\n")

p = WS / "docs" / "DEVICE-VERIFY.md"
t = p.read_text(encoding="utf-8")
t = t.replace("| fina | `ksu-template-fina.ko`（FinaSU 1.2.0 bundle 590848 B） | 33071 | `syms_61258_fina.txt` | `syms_6138_fina.txt` |",
              "| fina | `ksu-template-fina.ko`（FinaSU 1.2.1 bundle 590848 B） | 33074 | `syms_61258_fina.txt` | `syms_6138_fina.txt` |")
t = t.replace("- FinaSU 升级到 v1.2.0（33071），`ksud` 取自已安装管理器的 `libksud.so`\n  （`ksud 1.2.0 (uapi: 6)`）；内置 6.12 模板同步替换为 1.2.0 版本。",
              "- FinaSU 升级到 v1.2.1（33074），`ksud` 取自已安装管理器的 `libksud.so`\n  （`ksud 1.2.1 (uapi: 6)`）；内置 6.12 模板同步替换为 1.2.1 版本。")
if "## 35. FinaSU 1.2.1" not in t:
    t = t.rstrip() + f"""

---

## 35. FinaSU 1.2.1 模板升级（2026-10-25 23:12）

- 管理器：`v1.2.1` / versionCode 33074 / uapi 6；
- kernel bundle：`FinaSU_v1.2.1_kernel-bundle.zip`
  sha256 `15c64acb7e5782290020db61f2670a4871b73d9fda78e1ff4a3ba93bb3df3c69`；
- 内置 6.12 模板：`arm64/android16-6.12_kernelsu.ko`，590,848 B；
  sha256 `d1f8cedb14c5a62fb5f15861bd89ed2553525d33f31801bf3a795aa6a998bfeb`；
- 未定义符号集合仍为 232 个，与 1.2.0 完全一致；
  `syms_61258_fina.txt` / `syms_6138_fina.txt` 覆盖率仍为 232/232；
- 期望版本更新为 33074 / uapi 6
  （`kernel_profiles.sh`、`root_stage.sh`）。
"""
    p.write_text(t, encoding="utf-8", newline="\n")
    print("appended DEVICE-VERIFY §35")
