#!/usr/bin/env python3
"""Build a name/address table from a CGA base plus extra symbol tables."""
import pathlib
import subprocess
import sys

base = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
extras = [pathlib.Path(value) for value in sys.argv[3:]]
lines = []
names = set()
text = subprocess.check_output(["readelf", "-sW", str(base)], text=True)
for line in text.splitlines():
    fields = line.split()
    if len(fields) < 8 or not fields[0].rstrip(":").isdigit():
        continue
    if fields[6] != "ABS":
        continue
    value = int(fields[1], 16)
    name = fields[7]
    if value >= 0xFFFFFFC000000000 and name not in names:
        names.add(name)
        lines.append(f"{name} 0x{value:x}")

for path in extras:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) < 2 or not fields[1].startswith("0x") or fields[0] in names:
            continue
        names.add(fields[0])
        lines.append(f"{fields[0]} {fields[1]}")

out.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"symbols={len(lines)} output={out}")
