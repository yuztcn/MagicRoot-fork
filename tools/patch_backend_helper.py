#!/usr/bin/env python3
from pathlib import Path

p = Path(__file__).resolve().parent / "device" / "fix_backend_host.py"
t = p.read_text(encoding="utf-8")
old = '''        for m in re.finditer(
                r'text="([^"]*·[^"]*)"[^>]*bounds="\\[(\\d+),(\\d+)\\]\\[(\\d+),(\\d+)\\]"', xml):
            x1, y1, x2, y2 = map(int, m.groups()[1:])
            labels.append((m.group(1), (x1 + x2) // 2, (y1 + y2) // 2))'''
new = '''        for m in re.finditer(
                r'text="((?:BakaSU|FinaSU|KernelSU-Next|KernelSU|SukiSU) · [a-z]+)"'
                r'[^>]*bounds="\\[(\\d+),(\\d+)\\]\\[(\\d+),(\\d+)\\]"', xml):
            x1, y1, x2, y2 = map(int, m.groups()[1:])
            labels.append((m.group(1), (x1 + x2) // 2, (y1 + y2) // 2))'''
if old not in t:
    raise SystemExit("anchor missing")
p.write_text(t.replace(old, new), encoding="utf-8", newline="\n")
print("patched backend label regex")
