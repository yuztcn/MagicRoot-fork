from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
size = "3,822,818 B"
sha = "08c3f389f4db8a586a46fc43e4b9b2c339758a02ca9df06e739da9b353b5d08f"

doc = WS / "docs/reference/kernel-adaptation-61258-61238.md"
t = doc.read_text(encoding="utf-8")
t = t.replace("<APK_SIZE>", size).replace("<APK_HASH>", sha)
doc.write_text(t, encoding="utf-8", newline="\n")
print("adaptation doc hash updated")

dv = WS / "docs/DEVICE-VERIFY.md"
dt = dv.read_text(encoding="utf-8")
old = """按五项要求完成静态适配与构建："""
new = """按五项要求完成静态适配与构建（2026-10-25 19:40 更新：已拿到 6.12.38
`boot.img/init_boot.img/vendor_boot.img`，6.12.38 的 next/sukisu/fina syms
已从 6.12.38 vmlinux 生成并审计为 missing=0；vendor_boot 的 6.12.23 模块不可混用）："""
if old in dt and "6.12.38 的 next/sukisu/fina syms" not in dt:
    dt = dt.replace(old, new, 1)
    dv.write_text(dt, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §21 updated")
else:
    print("DEVICE-VERIFY unchanged")
