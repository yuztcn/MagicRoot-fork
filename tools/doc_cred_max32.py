from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
NEW_HASH = "928abcf78d7829c64933d7f6d837016f77399c20958602e1692a8d655cd8ed6b"

p = WS / "tools" / "check_612_binary_mapping.py"
t = p.read_text(encoding="utf-8")
t = t.replace('"t64560_cred": "16a3374aaff093dede490ce5d320757680bf3271ad43b88523dc68ee2d4039fc"',
              f'"t64560_cred": "{NEW_HASH}"')
p.write_text(t, encoding="utf-8", newline="\n")

p = WS / "docs/reference/reference-parameter-research.md"
t = p.read_text(encoding="utf-8")
t = t.replace("UI 可循环 16/24/32（cred 8/12/16/24）。",
              "UI 可循环 16/24/32（cred 8/12/16/24/32）。")
p.write_text(t, encoding="utf-8", newline="\n")

p = WS / "docs/DEVICE-VERIFY.md"
t = p.read_text(encoding="utf-8")
if "## 30. cred MAXVICTIM 32" not in t:
    t = t.rstrip() + f"""

---

## 30. cred MAXVICTIM 32（2026-10-25 22:50）

- `t64560_cred` 以 `-DMAXVICTIM=32` 重新编译，大小 76,304 B，
  sha256 `{NEW_HASH}`；
- run.sh 的 `VICTIMS_CRED` 允许 `8/12/16/24/32`；
- UI cred 档位循环改为 `8 → 12 → 16 → 24 → 32 → 8`，默认仍为 24；
- `t64560_cred.c` 默认值同步为 32，Makefile 的 cred 目标显式加
  `-DMAXVICTIM=32`；
- `verify_apk.py` 新增 cred 二进制的 hash 固定。
"""
    p.write_text(t, encoding="utf-8", newline="\n")
    print("appended DEVICE-VERIFY §30")
print("updated mapping/docs")
