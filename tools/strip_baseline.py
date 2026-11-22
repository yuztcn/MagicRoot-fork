#!/usr/bin/env python3
"""Strip baseline profiles, v1 signature files, and verified duplicate assets from APK.

Duplicate assets listed in tools/asset_dedup_map.json are removed ONLY when both
the duplicate entry and its canonical entry exist in the APK and match the
pinned SHA-256 digest.  At runtime MainActivity.openBundledAsset transparently
reads the canonical entry and writes the original relative path into the staged
deployment batch ZIP, keeping /data/local/tmp/magic 100% identical.
"""
import hashlib
import json
import sys
import zipfile
from pathlib import Path

BASELINE = {"assets/dexopt/baseline.prof", "assets/dexopt/baseline.profm"}
SIGNATURE_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC")
DEDUP_MAP_PATH = Path(__file__).resolve().parent / "asset_dedup_map.json"


def load_dedup_map() -> dict[str, dict]:
    if not DEDUP_MAP_PATH.is_file():
        return {}
    doc = json.loads(DEDUP_MAP_PATH.read_text(encoding="utf-8"))
    return doc.get("duplicates", {})


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: strip_baseline.py <input.apk> <output.apk>")
    source, output = map(Path, sys.argv[1:])
    dedup_map = load_dedup_map()
    removed = []
    deduped = []
    dedup_bytes_u = 0
    dedup_bytes_c = 0
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(output, "w", allowZip64=True) as dst:
        namelist = set(src.namelist())
        # Precompute canonical entry SHA-256 digests before dst.writestr(item, ...)
        # mutates item.header_offset in place.
        canonical_hashes: dict[str, str] = {}
        for meta in dedup_map.values():
            canon_entry = "assets/" + meta["canonical"]
            if canon_entry in namelist and canon_entry not in canonical_hashes:
                canonical_hashes[canon_entry] = sha256_hex(src.read(canon_entry))

        for item in src.infolist():
            name = item.filename
            if name in BASELINE or name == "META-INF/MANIFEST.MF" or (
                name.startswith("META-INF/") and name.endswith(SIGNATURE_SUFFIXES)
            ):
                removed.append(name)
                continue
            payload = src.read(name)
            if name.startswith("assets/"):
                rel = name[len("assets/"):]
                meta = dedup_map.get(rel)
                if meta:
                    canon_entry = "assets/" + meta["canonical"]
                    expected_sha = meta["sha256"]
                    if (
                        canonical_hashes.get(canon_entry) == expected_sha
                        and sha256_hex(payload) == expected_sha
                    ):
                        deduped.append(name)
                        dedup_bytes_u += item.file_size
                        dedup_bytes_c += item.compress_size
                        continue
            dst.writestr(item, payload)
    print(
        f"STRIPPED={len(removed)} DEDUPED={len(deduped)} "
        f"SAVED_UNCOMPRESSED={dedup_bytes_u} SAVED_COMPRESSED={dedup_bytes_c} output={output}"
    )
    for name in removed:
        print(f"REMOVED={name}")


if __name__ == "__main__":
    main()
