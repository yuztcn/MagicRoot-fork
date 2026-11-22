from __future__ import annotations
import re
from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
SM = WS / ".probe" / "ref273" / "smali"


def extract(path: Path, method_prefix: str):
    s = path.read_text(encoding="utf-8", errors="replace")
    parts = re.split(r"(?=^\.method )", s, flags=re.M)
    for part in parts:
        m = re.match(r"\.method[^\n]*", part)
        if not m:
            continue
        sig = m.group(0)
        if method_prefix not in sig:
            continue
        print("METHOD", sig)
        for x in re.finditer(r'const-string(?:/jumbo)? v[0-9]+, "(.*?)"', part):
            print("STR", x.group(1))
        for x in re.finditer(r"invoke-\w+(?:/range)? \{[^}]*\}, (L[^;]+;)->([^\(]+)", part):
            cls, meth = x.groups()
            if any(k in meth for k in ("zip", "Zip", "Entry", "entry", "File", "read", "Read",
                                       "sha", "getName", "getName", "open", "Open",
                                       "extract", "Extract", "native", "Native")):
                print("INV", cls, meth)
        return
    print("method not found")


extract(SM / "sv.smali", "N(Landroid/content/Context;")
