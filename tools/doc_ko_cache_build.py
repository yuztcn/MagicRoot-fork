from pathlib import Path
import re

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
SIZE = "3,825,158 B"
SHA = "79c45e68f1e9f59ef5de4bc7bbbee086004f174b8ad3f1ee06dbe5b56d7c4433"

for rel in ["docs/DEVICE-VERIFY.md",
            "docs/reference/kernel-adaptation-61258-61238.md",
            "docs/reference/reference-parameter-research.md"]:
    p = WS / rel
    if not p.exists():
        continue
    t = p.read_text(encoding="utf-8")
    t = re.sub(r"size = `[^`]+`", f"size = `{SIZE}`", t)
    t = re.sub(r"sha256 = `[0-9a-f]{64}`", f"sha256 = `{SHA}`", t)
    t = t.replace("3,824,430 B", SIZE)
    t = t.replace("ec4fe4c377026b6226c5614556463bea6d704ee426dac9e72e45a986c382c610", SHA)
    p.write_text(t, encoding="utf-8", newline="\n")
    print("updated build metadata", rel)
