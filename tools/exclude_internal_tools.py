#!/usr/bin/env python3
"""Exclude the remaining internal development scripts from the shipped source
archive, then print the final artifact list."""
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
pr = WS / "tools/package_release.py"
t = pr.read_text(encoding="utf-8")

new_entries = [
    "tools/finish_integration.py",
    "tools/finalize_integration.py",
    "tools/final_ux_pass.py",
    "tools/about_and_names.py",
    "tools/fix_verify.py",
    "tools/survey_ko.py",
    "tools/inspect_managers.py",
    "tools/scan_embedded_ko.py",
    "tools/scan_embedded_elf.py",
    "tools/extract_embedded_ko.py",
    "tools/identify_lkm_versions.py",
    "tools/exclude_doc_tools.py",
]
anchor = '    "tools/exclude_patch2.py",\n'
add = anchor
for e in new_entries:
    if f'"{e}"' not in t:
        add += f'    "{e}",\n'
if add != anchor:
    t = t.replace(anchor, add, 1)
    pr.write_text(t, encoding="utf-8", newline="\n")
    print("excluded", len(new_entries), "internal tools")
else:
    print("nothing to exclude")
