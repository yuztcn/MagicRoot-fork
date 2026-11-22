from __future__ import annotations
import re
from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
SM = WS / ".probe" / "ref273" / "smali"


def methods(path: Path):
    s = path.read_text(encoding="utf-8", errors="replace")
    parts = re.split(r"(?=^\.method )", s, flags=re.M)
    for part in parts:
        m = re.match(r"\.method[^\n]*", part)
        if not m:
            continue
        sig = m.group(0).strip()
        strs = [x.group(1) for x in re.finditer(r'const-string(?:/jumbo)? v[0-9]+, "(.*?)"', part)]
        invokes = [x.group(1) for x in re.finditer(r"invoke-\w+(?:/range)? \{[^}]*\}, (L[^;]+;|\[L[^;]+;)\.->([^\(]+)", part)]
        print("\n###", sig)
        for x in strs:
            print(" STR", x)
        for cls, meth in invokes:
            if any(k in meth for k in ("run", "exec", "shell", "start", "install", "Root", "root",
                                       "manager", "Manager", "su", "Su", "stage", "Stage",
                                       "load", "Load", "patch", "Patch", "module", "Module")):
                print(" INV", cls, meth)


for name in ["b61.smali"]:
    print("=" * 40, name)
    methods(SM / name)
