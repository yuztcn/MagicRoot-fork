#!/usr/bin/env python3
"""Add init_cred only when another symbol table proves the same kernel.

A source table is accepted only when every overlapping symbol has the same
address (at least 40 shared names, or the complete target table).  No address
is guessed from a model name or a nearby kernel version.  Per-profile
SHA256SUMS.txt entries are updated for every modified file.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "main/app/assets"


def number(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        return int(text, 16)


def parse(path: Path) -> dict[str, int]:
    result = {}
    for line in path.read_bytes().decode("utf-8").splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0].startswith("#"):
            continue
        name, address = fields[0], fields[1]
        try:
            number(fields[0])
        except ValueError:
            pass
        else:
            # Legacy HOneClick/Honor maps are "address name".
            name, address = fields[1], fields[0]
        try:
            result[name] = number(address)
        except ValueError:
            continue
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = sorted(set(ASSETS.rglob("syms*.txt")) | set(ASSETS.rglob("*-syms.txt")))
    tables = {path: parse(path) for path in files}
    donors = {path: table for path, table in tables.items() if "init_cred" in table}
    changed = []
    unresolved = []

    for target, table in tables.items():
        if "init_cred" in table:
            continue
        matches = []
        for donor, values in donors.items():
            if donor == target:
                continue
            common = table.keys() & values.keys()
            if len(common) < 40 and len(common) != len(table):
                continue
            if all(table[name] == values[name] for name in common):
                matches.append((donor, values["init_cred"], len(common)))
        addresses = {address for _, address, _ in matches}
        if len(addresses) == 1:
            donor, address, overlap = matches[0]
            if not args.check:
                with target.open("ab") as out:
                    out.write(f"init_cred 0x{address:x}\n".encode("ascii"))
                changed.append((target, donor, address, overlap))
                table["init_cred"] = address
                donors[target] = table
            else:
                unresolved.append((target, "missing"))
            continue
        unresolved.append((target, "conflict" if len(addresses) > 1 else "no_proven_donor"))

    for target, donor, address, overlap in changed:
        manifest = target.parent / "SHA256SUMS.txt"
        if manifest.is_file():
            lines = []
            for line in manifest.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1] == target.name:
                    line = hashlib.sha256(target.read_bytes()).hexdigest() + " " + parts[1]
                lines.append(line)
            manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"ADD {target.relative_to(ROOT)} init_cred=0x{address:x} "
              f"source={donor.relative_to(ROOT)} overlap={overlap}")

    for target, reason in unresolved:
        print(f"UNRESOLVED {target.relative_to(ROOT)} reason={reason}")
    print(f"SUMMARY added={len(changed)} unresolved={len(unresolved)}")
    return 1 if args.check and unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main())
