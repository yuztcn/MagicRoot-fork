#!/usr/bin/env python3
"""Align stored ZIP entries like Android's zipalign.

Usage: zipalign.py [-f] [-p] <align> <input.apk> <output.apk>

Stored entries are padded with a 0xD935 "Android alignment" extra field so
their data starts on an <align>-byte boundary.  With -p, shared-library
entries (*.so) are aligned to 4096 bytes regardless of <align>.

Only compression type, names and entry order are preserved; deflated entries
are recompressed, so the output must be re-signed after this step.
"""
from __future__ import annotations

import os
import struct
import sys
import zipfile

EXTRA_ID = 0xD935


def aligned_extra(current: bytes, offset: int, name_len: int, align: int) -> bytes:
    """Return an extra field that makes the data offset a multiple of align."""
    base = offset + 30 + name_len
    # The alignment field itself is 4 bytes of header plus payload.
    pad = (-(base + 4)) % align
    return current + struct.pack("<HH", EXTRA_ID, pad) + b"\0" * pad


def main() -> None:
    args = [a for a in sys.argv[1:]]
    force = False
    page_align = False
    while args and args[0].startswith("-") and args[0] != "-":
        flag = args.pop(0)
        if flag == "-f":
            force = True
        elif flag == "-p":
            page_align = True
        else:
            raise SystemExit(f"unknown option {flag}")
    if len(args) != 3:
        raise SystemExit("usage: zipalign.py [-f] [-p] <align> <input.apk> <output.apk>")
    align = int(args[0])
    if align <= 0 or align & (align - 1):
        raise SystemExit("align must be a power of two")
    source, output = args[1], args[2]
    if not force and os.path.exists(output):
        raise SystemExit(f"{output} already exists (use -f)")

    with zipfile.ZipFile(source) as src, zipfile.ZipFile(output, "w", allowZip64=True) as dst:
        for item in src.infolist():
            name = item.filename.encode("utf-8")
            payload = src.read(item.filename)
            if item.compress_type == zipfile.ZIP_STORED:
                entry_align = 4096 if page_align and item.filename.endswith(".so") else align
                position = dst.fp.tell()
                item.extra = aligned_extra(item.extra, position, len(name), entry_align)
            dst.writestr(item, payload)

    # Verify: every stored entry must now start on its boundary.
    with zipfile.ZipFile(output) as check:
        raw = open(output, "rb").read()
        for item in check.infolist():
            if item.compress_type != zipfile.ZIP_STORED:
                continue
            name_len, extra_len = struct.unpack_from("<HH", raw, item.header_offset + 26)
            data = item.header_offset + 30 + name_len + extra_len
            expect = 4096 if page_align and item.filename.endswith(".so") else align
            if data % expect:
                raise SystemExit(f"unaligned {item.filename}: {data} % {expect}")
    print(f"ZIPALIGN_OK align={align} page={int(page_align)} output={output}")


if __name__ == "__main__":
    main()
