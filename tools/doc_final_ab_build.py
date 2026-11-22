from pathlib import Path
import re

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
size = "3,823,666 B"
sha = "cca786d9fd7d83f03c7b5bac0fc3d50e892884ee2859520bd3adecc0b77f1ebf"

for rel in ["docs/reference/kernel-adaptation-61258-61238.md"]:
    p = WS / rel
    t = p.read_text(encoding="utf-8")
    t = re.sub(r"size = `[^`]+`", f"size = `{size}`", t)
    t = re.sub(r"sha256 = `[0-9a-f]{64}`", f"sha256 = `{sha}`", t)
    p.write_text(t, encoding="utf-8", newline="\n")
    print("updated", rel)

dv = WS / "docs/DEVICE-VERIFY.md"
dt = dv.read_text(encoding="utf-8")
dt = dt.rstrip() + f"""

最终构建（A/B 后）：APK {size}，sha256 `{sha}`；
`tools/verify_apk.py` 通过（versionCode 8 / versionName 1.0.3，39 个资产）。
"""
dv.write_text(dt, encoding="utf-8", newline="\n")
print("DEVICE-VERIFY final build appended")

# save a compact A/B summary for traceability
p = WS / ".probe/ab/summary.json"
p.write_text("""{
  "device": "<SERIAL>",
  "adb": "SDK 37 platform-tools 37.0.1-15733141",
  "mode": "permissive-only (MAGICROOT_PERMISSIVE_ONLY=1)",
  "trials": [
    {"preset": "current", "trial": 1, "outcome": "ok", "attempt": 35, "elapsed_s": 352.3},
    {"preset": "current", "trial": 2, "outcome": "ok", "attempt": 9, "elapsed_s": 107.1},
    {"preset": "reference", "trial": 1, "outcome": "ok", "attempt": 8, "elapsed_s": 139.3},
    {"preset": "reference", "trial": 2, "outcome": "kernel_reboot", "attempt": 13, "elapsed_s": 199.3}
  ],
  "conclusion": "current 2/2 success; reference 1/2 success + 1 kernel reboot; defaults unchanged"
}
""", encoding="utf-8")
print("saved", p)
