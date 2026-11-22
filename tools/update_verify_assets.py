#!/usr/bin/env python3
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
p = WS / "tools/verify_apk.py"
t = p.read_text(encoding="utf-8")
old = ('    ("ksu-template-next.ko", None, "KernelSU-Next 3.4.2 LKM fallback (6.18 KMI)"),\n'
       '    ("ksu-template-sukisu.ko", None, "SukiSU 4.2.1 LKM fallback (6.18 KMI)"),\n')
new = ('    ("ksu-template-next.ko", None, "KernelSU-Next 3.4.2 native 6.12 LKM (MultiSU)"),\n'
       '    ("ksu-template-sukisu.ko", None, "SukiSU 4.2.1-r2 native 6.12 LKM (MultiSU)"),\n'
       '    ("ksu-template-fina.ko", None, "FinaSU 1.0.10 native 6.12 LKM (MultiSU bundle)"),\n'
       '    ("syms_61258_next.txt", None, "6.12.58 next syms"),\n'
       '    ("syms_61258_sukisu.txt", None, "6.12.58 sukisu syms"),\n'
       '    ("syms_61258_fina.txt", None, "6.12.58 fina syms"),\n')
if old not in t:
    raise SystemExit("anchor missing")
p.write_text(t.replace(old, new), encoding="utf-8", newline="\n")
print("verify assets updated")
