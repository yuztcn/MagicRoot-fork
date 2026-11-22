#!/usr/bin/env python3
"""Complete official-KernelSU tables with symbols added by manager 32727.

KernelSU v3.3.1-47-gdbb73665 (versionCode 32727) added eleven kernel symbol
references.  The official tables in this repo predate that build, while the
bakasu/fina/sukisu tables for the same kernel already contain them because
those managers referenced them earlier.

A donor is accepted only when every symbol the target and donor share has the
same address (at least 40 shared names, or the complete target table).  All
donors that provide a missing symbol must agree on its address.  No address is
guessed from a model name or a nearby kernel version.

Targets are discovered with the same ksu_select_ko() the device uses, so a new
98260 profile cannot be silently skipped.  Per-profile SHA256SUMS.txt entries
are updated for every modified file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "main/app/assets"
SYMBOLS = (
    "__arm64_sys_unshare",
    "bsearch",
    "bpf_get_btf_vmlinux",
    "btf_find_by_name_kind",
    "btf_type_by_id",
    "btf_name_by_offset",
    "btf_type_skip_modifiers",
    "copy_from_kernel_nofault",
    "shmem_file_setup",
    "sort",
    "strndup_user",
)


def number(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        return int(text, 16)


def parse(path: Path) -> dict[str, int]:
    result = {}
    for line in path.read_bytes().decode("utf-8", "replace").splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0].startswith("#"):
            continue
        name, address = fields[0], fields[1]
        try:
            number(fields[0])
        except ValueError:
            pass
        else:
            # Legacy "address name" maps.
            name, address = fields[1], fields[0]
        try:
            result.setdefault(name, number(address))
        except ValueError:
            continue
    return result


def kernel_syms(profile: str) -> Path | None:
    """Return the official-KernelSU table selected for this profile."""
    script = (
        'D=$PWD; . ./kernel_profiles.sh >/dev/null 2>&1; '
        'KO_TEMPLATE=""; SYMS=""; FLAVOR_SYMS_MISSING=0; '
        f'ksu_select_ko "{profile}" kernelsu >/dev/null 2>&1; '
        'printf "%s" "$SYMS"'
    )
    out = subprocess.run(["bash", "-c", script], cwd=ASSETS, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         check=False).stdout.strip()
    return Path(out) if out else None


def profiles() -> list[str]:
    table = json.loads((ROOT / "tools/kernel_profiles.json").read_text())
    ids = [p["id"] for p in table["profiles_98260"]]
    # 61821/61821brm already carry the symbols; H1C has no kernelsu table.
    return [p for p in ids if p not in ("61821", "61821brm", "61821h1c")]


def update_manifest(path: Path) -> None:
    manifest = path.parent / "SHA256SUMS.txt"
    if not manifest.is_file():
        return
    lines = []
    for line in manifest.read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == path.name:
            line = hashlib.sha256(path.read_bytes()).hexdigest() + " " + parts[1]
        lines.append(line)
    manifest.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="fail instead of appending missing symbols")
    args = parser.parse_args()

    tables = {p: parse(p) for p in sorted(ASSETS.rglob("syms*.txt"))}
    targets = {}
    for profile in profiles():
        path = kernel_syms(profile)
        if path is None or not path.is_file():
            raise SystemExit(f"no kernelsu table for profile {profile}")
        targets[profile] = path

    changed = []
    unresolved = []
    for profile, target in targets.items():
        table = tables[target]
        missing = [s for s in SYMBOLS if s not in table]
        if not missing:
            continue
        added = []
        for symbol in missing:
            matches = []
            for donor, values in tables.items():
                if donor == target or symbol not in values:
                    continue
                common = table.keys() & values.keys()
                if len(common) < 40 and len(common) != len(table):
                    continue
                if all(table[name] == values[name] for name in common):
                    matches.append((donor, values[symbol], len(common)))
            addresses = {address for _, address, _ in matches}
            if len(addresses) != 1:
                unresolved.append((profile, symbol,
                                   "conflict" if addresses else "no_donor"))
                continue
            donor, address, overlap = matches[0]
            added.append((symbol, address, donor, overlap))
        if not added:
            continue
        if args.check:
            unresolved.extend((profile, symbol, "missing") for symbol, _, _, _ in added)
            continue
        text = target.read_bytes()
        if text and not text.endswith(b"\n"):
            text += b"\n"
        text += "".join(f"{name} 0x{address:x}\n"
                        for name, address, _, _ in sorted(added)).encode("ascii")
        target.write_bytes(text)
        update_manifest(target)
        changed.append((profile, target, added))

    for profile, target, added in changed:
        donor = added[0][2]
        print(f"ADD {profile} {target.relative_to(ROOT)} +{len(added)} "
              f"source={donor.relative_to(ROOT)}")
    for profile, symbol, reason in unresolved:
        print(f"UNRESOLVED {profile} {symbol} reason={reason}")
    print(f"SUMMARY profiles={len(targets)} changed={len(changed)} "
          f"unresolved={len(unresolved)}")
    return 1 if unresolved else 0


if __name__ == "__main__":
    raise SystemExit(main())
