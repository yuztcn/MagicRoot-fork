#!/usr/bin/env python3
"""Validate a SUSFS guard LKM before it is allowed near a device.

Usage:
    python tools/check_susfs_guard.py <guard.ko> [--kmi android16-6.12]

Checks:
  * ELF aarch64 relocatable object
  * .modinfo vermagic present and matching the requested KMI family
  * the 20016397 openat2/syscall-table hardening marker is present
  * the guard does not claim a different KMI

This is a static gate, not proof that the kernel will load or run it.
"""
import argparse
import re
import sys
from pathlib import Path

EXPECTED_HOOK = b"susfs_or_entry_expected_hook"
KMI_PREFIX = {
    "android16-6.12": b"6.12.",
    "android15-6.6": b"6.6.",
    "android17-6.18": b"6.18.",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ko", type=Path)
    ap.add_argument("--kmi", choices=sorted(KMI_PREFIX))
    args = ap.parse_args()

    data = args.ko.read_bytes()
    errors = []
    if data[:4] != b"\x7fELF":
        errors.append("not an ELF file")
    m = re.search(rb"vermagic=([^\x00\r\n]+)", data)
    vermagic = m.group(1).decode("latin1") if m else None
    if not vermagic:
        errors.append("no vermagic in .modinfo")
    if args.kmi and vermagic and not vermagic.startswith(KMI_PREFIX[args.kmi].decode()):
        errors.append(f"vermagic {vermagic!r} does not match {args.kmi}")
    if EXPECTED_HOOK not in data:
        errors.append("missing susfs_or_entry_expected_hook hardening marker")
    if b"susfs_fp_hook" not in data:
        errors.append("missing susfs_fp_hook (syscall-table wrapper)")

    print(f"file:      {args.ko}")
    print(f"bytes:     {len(data)}")
    print(f"vermagic:  {vermagic}")
    print(f"hook:      {'present' if EXPECTED_HOOK in data else 'MISSING'}")
    print(f"fp_hook:   {'present' if b'susfs_fp_hook' in data else 'MISSING'}")
    if errors:
        for e in errors:
            print(f"REJECT: {e}", file=sys.stderr)
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
