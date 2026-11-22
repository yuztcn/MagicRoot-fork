from pathlib import Path
import re

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
SIZE = "3,825,142 B"
SHA = "90ac0fcf1c299c900227fad97f0ce66465a9a3e91d12b6a6ea4bc44fac1fff2f"

for rel in ["docs/DEVICE-VERIFY.md",
            "docs/reference/kernel-adaptation-61258-61238.md",
            "docs/reference/reference-parameter-research.md"]:
    p = WS / rel
    if not p.exists():
        continue
    t = p.read_text(encoding="utf-8")
    t = re.sub(r"size = `[^`]+`", f"size = `{SIZE}`", t)
    t = re.sub(r"sha256 = `[0-9a-f]{64}`", f"sha256 = `{SHA}`", t)
    t = t.replace("3,825,158 B", SIZE)
    t = t.replace("79c45e68f1e9f59ef5de4bc7bbbee086004f174b8ad3f1ee06dbe5b56d7c4433", SHA)
    p.write_text(t, encoding="utf-8", newline="\n")
    print("updated", rel)
