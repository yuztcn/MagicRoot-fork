import re
from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
for name in ["t64560_v36", "t64560_cred"]:
    p = WS / "main" / "app" / "assets" / name
    b = p.read_bytes()
    print("=====", name, len(b))
    for m in re.finditer(rb"(?i)(slab|leak|runaway|stale|posix_timers|SAFE_[A-Z_]+)", b):
        s = max(0, m.start() - 80)
        e = min(len(b), m.end() + 120)
        chunk = b[s:e]
        text = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print(m.start(), text)
