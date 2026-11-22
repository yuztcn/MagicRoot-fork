from pathlib import Path
import re

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
SIZE = "3,824,414 B"
SHA = "944621cdafefc1f1720e02511a7192c9a2c3790277318c8194ddbf67793f952c"

# update final build metadata in restored docs
for rel in ["docs/DEVICE-VERIFY.md",
            "docs/reference/kernel-adaptation-61258-61238.md",
            "docs/reference/reference-parameter-research.md"]:
    p = WS / rel
    if not p.exists():
        continue
    t = p.read_text(encoding="utf-8")
    t = re.sub(r"size = `[^`]+`", f"size = `{SIZE}`", t)
    t = re.sub(r"sha256 = `[0-9a-f]{64}`", f"sha256 = `{SHA}`", t)
    t = t.replace("3,824,410 B", SIZE)
    t = t.replace("f0b7082de4aab69d39a8680544d2ddd00eb56befa2dafc3fb4c1661e82b93450", SHA)
    p.write_text(t, encoding="utf-8", newline="\n")
    print("updated build hash", rel)

p = WS / "docs/DEVICE-VERIFY.md"
t = p.read_text(encoding="utf-8")
if "## 29. FinaSU 1.2.0" not in t:
    t = t.rstrip() + f"""

---

## 29. FinaSU 1.2.0 模板升级（2026-10-25 22:40）

- 管理器 APK：`v1.2.0` / versionCode 33071 / uapi 6；
- 内置 6.12 模板替换为 `FinaSU_v1.2.0_kernel-bundle.zip` 的
  `arm64/android16-6.12_kernelsu.ko`；
- 模板大小 590848 B，sha256
  `31fdd7b03de9524dd021c975e15780b69f3e64dea4b2a91877f95938d0913113`；
- 新旧模板 ELF 未定义符号集合完全一致（232 个）；
  `syms_61258_fina.txt` / `syms_6138_fina.txt` 覆盖率均为 232/232，missing=0；
- 期望版本表同步为 FinaSU 33071 / uapi 6
  （`kernel_profiles.sh`、`root_stage.sh`）。

构建：APK {SIZE}，sha256 `{SHA}`；`verify_apk` 通过。
"""
    p.write_text(t, encoding="utf-8", newline="\n")
    print("appended FinaSU §29")
