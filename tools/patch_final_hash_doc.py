from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
old = "69dc57bf0e556aa050e1ed03fd6d6c691956e1f39bce9f41393ec666f193c58e"
new = "e4b0ca0ba25ac0a6f08a7a376ebdf76beb8ee511a065d794df745be1573457b9"
size_old = "3,814,455 B"
size_new = "3,814,459 B"
for rel in ("docs/reference/kernel-adaptation-61258-61238.md",
            "docs/DEVICE-VERIFY.md"):
    p = WS / rel
    if not p.exists():
        continue
    t = p.read_text(encoding="utf-8")
    t2 = t.replace(old, new).replace(size_old, size_new)
    if t2 != t:
        p.write_text(t2, encoding="utf-8", newline="\n")
        print("updated", rel)
    else:
        print("no change", rel)
