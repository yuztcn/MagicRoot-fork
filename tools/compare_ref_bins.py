#!/usr/bin/env python3
"""Compare reference binaries with our assets and list app-level symbols."""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
WS = Path(__file__).resolve().parent.parent
REF = WS / "refs/oneplus-v270-zip/assets"
OUR = WS / "main/app/assets"
AN = WS / "refs/analysis"


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


ref_bins = []
for p in sorted(REF.rglob("*")):
    if p.is_file() and p.read_bytes()[:4] == b"\x7fELF" and "lib/" not in p.as_posix():
        ref_bins.append(p)
ours = {}
for p in sorted(OUR.iterdir()):
    if p.is_file():
        ours.setdefault(sha(p), []).append(p.name)
print("=== reference ELF hashes and whether we ship the same bytes ===")
for p in ref_bins:
    h = sha(p)
    rel = p.relative_to(REF).as_posix()
    print(f"{rel:44} {h[:16]} ours={ours.get(h, [])}")

print("\n=== app symbols (all non-libc-ish) per core binary ===")
for name in ("cred.bin", "patch.bin", "perm.bin", "resolve.bin", "writer.bin"):
    b = AN / ("assets_core_" + name.replace(".", ".") + ".symbols.txt")
    if not b.exists():
        b = AN / ("assets_core_" + name + ".symbols.txt")
    lines = b.read_text(encoding="utf-8", errors="replace").splitlines()
    app = []
    for line in lines:
        m = re.match(r"0x([0-9a-f]+)\s+(\d+)\s+(.*)", line)
        if not m:
            continue
        addr, size, sym = int(m.group(1), 16), int(m.group(2)), m.group(3)
        if size <= 0:
            continue
        if re.match(r"(__|_Z|_IO|_dl|_nl|_Unwind|_int_malloc|_start|malloc|free|mem|str|printf|scanf|fopen|fread|fwrite|fclose|vfprintf|abort|perror|btree|release_|init_|scudo|posix_timers|ptrace|raise|signal|sig|fork|exec|wait|kill|mmap|munmap|mprotect|open|read|write|close|ioctl|futex|pthread|sched_|clock|time|get|set|syscall|errno|dl|rtld|locale|wcs|mb|ctype|qsort|bsearch|rand|atexit|exit|longjmp|setjmp|fcntl|dup|pipe|stat|lstat|readlink|unlink|mkdir|chdir|access|chmod|chown|umask|utime|sysinfo|uname|times|alarm|sleep|nanosleep|sigaction|sigprocmask)", sym):
            continue
        app.append((addr, size, sym))
    print(f"\n--- assets/core/{name} ({len(app)} candidate app symbols)")
    for addr, size, sym in sorted(app, key=lambda x: -x[1])[:40]:
        print(f"  {addr:#08x} {size:6d} {sym}")
