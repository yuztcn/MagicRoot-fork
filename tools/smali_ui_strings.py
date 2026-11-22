from __future__ import annotations
import re
from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
SM = WS / ".probe" / "ref273" / "smali"


def methods(path: Path, max_strings=120):
    s = path.read_text(encoding="utf-8", errors="replace")
    parts = re.split(r"(?=^\.method )", s, flags=re.M)
    for part in parts:
        m = re.match(r"\.method[^\n]*", part)
        if not m:
            continue
        sig = m.group(0).strip()
        vals = []
        for x in re.finditer(r'const-string(?:/jumbo)? v[0-9]+, "(.*?)"', part):
            v = x.group(1)
            if v and v not in vals:
                vals.append(v)
        if vals:
            print("\n###", sig)
            for v in vals[:max_strings]:
                print(" STR", v)


for name in [
    "com/pyb110/onekey/MainActivity.smali",
    "com/pyb110/onekey/JailbreakRunService.smali",
]:
    print("=" * 48, name)
    methods(SM / name)
