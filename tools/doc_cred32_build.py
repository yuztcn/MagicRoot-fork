from pathlib import Path
import re

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
SIZE = "3,824,438 B"
SHA = "7703b11ea84a4d4d0e4c037aa212b2845409ec831a6c059355e2d2ea629683a2"

for rel in ["docs/DEVICE-VERIFY.md",
            "docs/reference/kernel-adaptation-61258-61238.md",
            "docs/reference/reference-parameter-research.md"]:
    p = WS / rel
    if not p.exists():
        continue
    t = p.read_text(encoding="utf-8")
    t = re.sub(r"size = `[^`]+`", f"size = `{SIZE}`", t)
    t = re.sub(r"sha256 = `[0-9a-f]{64}`", f"sha256 = `{SHA}`", t)
    t = t.replace("3,824,414 B", SIZE)
    t = t.replace("944621cdafefc1f1720e02511a7192c9a2c3790277318c8194ddbf67793f952c", SHA)
    p.write_text(t, encoding="utf-8", newline="\n")
    print("updated build metadata", rel)
