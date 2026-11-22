#!/usr/bin/env python3
"""Regression checks for the 6.1.x CGA Termux su entry.

The g264-family CGA module has no kernel su_compat, so su is provided by
su_lkm through an overlay at /system_ext/bin/su.  Termux's su wrapper does not
search /system_ext/bin: it probes a fixed absolute-path list.  Without a patch
it reports "No su program found on this device." even when the overlay is up.

Checks:
1. Static: both su_optional.sh copies cover running Termux processes and call
   termux_su_patch() on every success path and on the no-target failure path.
2. Dynamic: extract the production termux_su_patch() into a shell harness,
   point TERMUX_SU at a temp copy of the upstream Termux su.in, and verify the
   rewritten `for p in` line, the backup, idempotency, custom targets and the
   non-Termux/missing cases.
3. The two su_optional.sh copies stay byte-identical.

Usage:
    python3 -I tools/test_termux_su_entry.py
"""
from __future__ import annotations

import filecmp
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SU_G264 = ROOT / "main/app/assets/su-g264/su_optional.sh"
SU_61157 = ROOT / "main/app/assets/61157/su-g264/su_optional.sh"
RUN_6157 = ROOT / "main/app/assets/98260/run6157_full.sh"
SETUP = ROOT / "main/app/assets/su-g264/setup_su_app.sh"

# Upstream termux-tools scripts/su.in (matches the message in the device
# screenshot).  Kept verbatim so the harness exercises the real line shape.
TERMUX_SU_IN = """#!/bin/sh

unset LD_LIBRARY_PATH LD_PRELOAD

for p in /debug_ramdisk/su /sbin/su /system/sbin/su /system/bin/su /system/xbin/su /su/bin/su /magisk/.core/bin/su
do
\tif [ -x "$p" ]; then
\t\tPATH=/debug_ramdisk:/sbin:/sbin/su:/su/bin:/su/xbin:/system/bin:/system/xbin \\
\t\t\texec "$p" "$@"
\tfi
done

echo "No su program found on this device. Termux"
exit 1
"""

problems: list[str] = []


def fail(msg: str) -> None:
    problems.append(msg)
    print("FAIL " + msg)


def static_checks() -> None:
    print("== static su_optional.sh contract ==")
    for path in (SU_G264, SU_61157):
        if not path.exists():
            fail(f"missing {path}")
            continue
        src = path.read_text()
        if 'TERMUX_SU=/data/data/com.termux/files/usr/bin/su' not in src:
            fail(f"{path}: missing TERMUX_SU")
        all_pids = src.split("all_pids() {", 1)
        if len(all_pids) != 2:
            fail(f"{path}: all_pids() not found")
        else:
            body = all_pids[1].split("\n}", 1)[0]
            if "pidof com.termux" not in body:
                fail(f"{path}: all_pids does not cover com.termux")
        if "termux_su_patch /system_ext/bin" not in src:
            fail(f"{path}: system_ext success path does not patch Termux")
        if "termux_su_patch \"$target\"" not in src:
            fail(f"{path}: fallback overlay success path does not patch Termux")
        no_target = src.split('echo "SU_OPTIONAL_FAIL=no_mountable_target"', 1)
        if len(no_target) != 2 or "termux_su_patch" not in no_target[0].split(
                'echo "SU_OPTIONAL_WARN=system_ext_bin_overlay_failed"', 1)[-1]:
            fail(f"{path}: no-mountable-target path does not patch Termux")
        if 'zygote_pids=' not in src or 'case " $zygote_pids "' not in src:
            fail(f"{path}: Termux pid can be mistaken for a zygote mount")

    if SU_G264.exists() and SU_61157.exists():
        if not filecmp.cmp(SU_G264, SU_61157, shallow=False):
            fail("su-g264 and 61157/su-g264 su_optional.sh diverged")

    setup = SETUP.read_text() if SETUP.exists() else ""
    if "sh \"$R/su_optional.sh\" enable" not in setup:
        fail("setup_su_app.sh no longer calls su_optional.sh enable")

    run = RUN_6157.read_text() if RUN_6157.exists() else ""
    if "sh $D/su-g264/setup_su_app.sh" not in run:
        fail("g264 branch no longer invokes setup_su_app.sh")
    if 'echo "98260_SU_SETUP_BEGIN ksud=$KSUD"' not in run:
        fail("g264 branch lost the 98260_SU_SETUP_BEGIN marker")
    if '98260_SU_ENTRY=skipped reason=g264_overlay_su' not in run:
        fail("g264 branch no longer documents the su_entry skip")


def extract_function(src: str) -> str:
    start = src.index("termux_su_patch() {")
    end = src.index("\nenable_one() {", start)
    return src[start:end].rstrip() + "\n"


def run_patch(script: str, su_path: Path, target: str = "/system_ext/bin") -> str:
    harness = script + '\ntermux_su_patch "$2"\n'
    with tempfile.TemporaryDirectory(prefix="magicroot-termux-su-") as td:
        hp = Path(td) / "harness.sh"
        hp.write_text(harness)
        cp = subprocess.run(
            ["sh", str(hp), str(su_path), target],
            text=True, capture_output=True,
        )
    if cp.returncode != 0:
        fail(f"harness failed rc={cp.returncode}: {cp.stdout}{cp.stderr}")
    return cp.stdout


def dynamic_checks() -> None:
    print("== dynamic termux_su_patch ==")
    func = extract_function(SU_G264.read_text())

    with tempfile.TemporaryDirectory(prefix="magicroot-termux-su-case-") as td:
        ts = Path(td) / "su"
        ts.write_text(TERMUX_SU_IN)
        ts.chmod(0o755)
        before = ts.stat()

        out = run_patch("TERMUX_SU=\"$1\"\n" + func, ts)
        print(out.rstrip())
        if "SU_OPTIONAL_TERMUX=patched" not in out:
            fail("first patch did not report patched")

        expected = (
            "for p in /system_ext/bin/su /data/adb/ksu/bin/su "
            "/data/local/tmp/magic/su /debug_ramdisk/su /sbin/su "
            "/system/sbin/su /system/bin/su /system/xbin/su /su/bin/su "
            "/magisk/.core/bin/su"
        )
        lines = ts.read_text().splitlines()
        loops = [ln for ln in lines if ln.startswith("for p in ")]
        if loops != [expected]:
            fail(f"unexpected search line: {loops!r}")

        bak = Path(str(ts) + ".magicroot.bak")
        if not bak.exists() or bak.read_text() != TERMUX_SU_IN:
            fail("backup missing or not the original wrapper")

        after = ts.stat()
        if stat.S_IMODE(after.st_mode) != stat.S_IMODE(before.st_mode):
            fail("wrapper mode changed")
        if after.st_uid != before.st_uid:
            fail("wrapper owner changed (cat must rewrite the inode)")

        out = run_patch("TERMUX_SU=\"$1\"\n" + func, ts)
        if "SU_OPTIONAL_TERMUX=already" not in out:
            fail("second patch is not idempotent: " + out.strip())
        if Path(str(ts) + ".magicroot.tmp").exists():
            fail("temp file left behind")

        out = run_patch("TERMUX_SU=\"$1\"\n" + func, ts, "/system/xbin")
        if "SU_OPTIONAL_TERMUX=patched" not in out:
            fail("custom target was not patched")
        first = [ln for ln in ts.read_text().splitlines() if ln.startswith("for p in ")][0]
        if not first.startswith("for p in /system/xbin/su /system_ext/bin/su "):
            fail("custom target not first: " + first)

        plain = Path(td) / "plain"
        plain.write_text("#!/bin/sh\nexec /system/bin/su \"$@\"\n")
        out = run_patch("TERMUX_SU=\"$1\"\n" + func, plain)
        if "SU_OPTIONAL_TERMUX=unsupported" not in out:
            fail("non-Termux wrapper was modified or not reported: " + out.strip())

        out = run_patch("TERMUX_SU=\"$1\"\n" + func, Path(td) / "missing")
        if "SU_OPTIONAL_TERMUX=absent" not in out:
            fail("missing Termux wrapper not reported as absent")


def main() -> int:
    static_checks()
    dynamic_checks()
    if problems:
        print(f"\nfailures={len(problems)}")
        return 1
    print("\nfailures=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
