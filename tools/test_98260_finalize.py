#!/usr/bin/env python3
"""Regression checks for the 98260 SuSFS-off finalization path.

Two independent checks:

1. Compile and run tools/tests/RunProgressTest.java against the production
   RunProgress classifier. This exercises the actual Java logic without needing
   Android or Gradle.
2. Statically walk run.sh and enforce the shell contract:
   * every 98260 success path calls finalize_98260();
   * finalize_98260 emits explicit begin/end markers around SuSFS + cleanup;
   * rootd cleanup su calls use `timeout -k` (TERM alone can be ignored).

Usage:
    python3 tools/test_98260_finalize.py
"""
from __future__ import annotations

import re
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUN_SH = ROOT / "main/app/assets/run.sh"
JAVA_DIR = ROOT / "main/compose-app/app/src/main/java/com/aoki/magicroot"
TEST_JAVA = ROOT / "tools/tests/RunProgressTest.java"

problems: list[str] = []


def fail(msg: str) -> None:
    problems.append(msg)
    print("FAIL " + msg)


def run_junit_style() -> None:
    print("== Java RunProgress classifier ==")
    run_progress = JAVA_DIR / "RunProgress.java"
    if not run_progress.exists():
        fail(f"missing {run_progress}")
        return
    with tempfile.TemporaryDirectory(prefix="magicroot-runprogress-") as td:
        cp = subprocess.run(
            ["javac", "-encoding", "UTF-8", "-d", td, str(run_progress), str(TEST_JAVA)],
            text=True, capture_output=True,
        )
        if cp.returncode != 0:
            fail("javac failed:\n" + cp.stdout + cp.stderr)
            return
        cp = subprocess.run(
            ["java", "-cp", td, "com.aoki.magicroot.RunProgressTest"],
            text=True, capture_output=True,
        )
        print(cp.stdout.rstrip())
        if cp.stderr.strip():
            print(cp.stderr.rstrip())
        if cp.returncode != 0:
            fail("RunProgressTest failed")


def function_body(text: str, name: str) -> str:
    marker = name + "() {"
    start = text.find(marker)
    if start < 0:
        return ""
    opening = text.find("{", start)
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return ""


def check_shell() -> None:
    print("\n== run.sh finalization contract ==")
    text = RUN_SH.read_text(encoding="utf-8", errors="replace")

    body = function_body(text, "finalize_98260")
    if not body:
        fail("run.sh has no finalize_98260() function")
        return

    order = [
        "98260_FINALIZE_BEGIN",
        "susfs_load",
        "soft_reboot_repair",
        "cleanup_98260_rootd_listener",
        "cleanup_stale_98260_rootd",
        "98260_FINALIZE_END",
    ]
    positions = [body.find(item) for item in order]
    if any(p < 0 for p in positions):
        fail("finalize_98260 is missing one of: " + ", ".join(order))
    elif positions != sorted(positions):
        fail("finalize_98260 steps are out of order: " + repr(list(zip(order, positions))))

    # Both non-preflight 98260 success branches must use the shared finalizer.
    markers = list(re.finditer(r'echo "CHAIN_98260_DONE"', text))
    if len(markers) < 2:
        fail(f"expected at least two CHAIN_98260_DONE branches, found {len(markers)}")
    for i, m in enumerate(markers):
        tail = text[m.end():m.end() + 500]
        if "finalize_98260" not in tail:
            fail(f"CHAIN_98260_DONE branch #{i + 1} does not call finalize_98260()")

    # Rootd cleanup must not wait forever if su ignores SIGTERM.
    for fname in ("cleanup_98260_rootd_listener", "cleanup_stale_98260_rootd"):
        fbody = function_body(text, fname)
        if not fbody:
            fail(f"run.sh has no {fname}() function")
            continue
        for lineno, line in enumerate(fbody.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if re.search(r'"?\$_(?:ksu_)?su"?\s+-c', line) and "timeout -k" not in line:
                fail(f"{fname} line {lineno} invokes su without timeout -k: {stripped}")

    # The helper must outlive a stuck su session instead of holding finalization.
    cleanup = function_body(text, "cleanup_98260_rootd_listener")
    for needle in ("setsid", "< /dev/null &", "ROOTD_CLEAN_LAUNCH_RC",
                   "ROOTD_CLEAN_WAIT_MS"):
        if needle not in cleanup:
            fail(f"rootd cleanup lacks detached completion mechanism: {needle}")
    # A process whose comm can no longer be read (it vanished mid-scan) must be
    # skipped quietly, not abort the helper.  Accept either path spelling.
    quiet_skip = ('if ! { read -r _comm < "/proc/$pid/comm"; }' in cleanup
                  or 'if ! { read -r _comm < "$p/comm"; }' in cleanup)
    if not quiet_skip:
        fail("rootd helper does not quietly skip a vanished candidate comm")

    # Exercise the extracted function with stubs to prove the branches and
    # ordering, not just the presence of strings.
    harness = f"""#!/bin/sh
set -u
SUSFS_ENABLE=0
MAGICROOT_KEEP_ROOTD=0
susfs_load() {{ echo "STUB susfs_load"; }}
soft_reboot_repair() {{ echo "STUB soft_reboot_repair"; }}
cleanup_98260_rootd_listener() {{ echo "STUB cleanup_listener"; }}
cleanup_stale_98260_rootd() {{ echo "STUB cleanup_stale"; }}
{body}
echo "--- normal ---"
finalize_98260
echo "--- no-susfs ---"
finalize_98260 0
"""
    with tempfile.TemporaryDirectory(prefix="magicroot-finalize-") as td:
        script = Path(td) / "finalize.sh"
        script.write_text(harness, encoding="utf-8")
        cp = subprocess.run(["sh", str(script)], text=True, capture_output=True)
        out = cp.stdout
        print(out.rstrip())
        if cp.returncode != 0:
            fail("finalize_98260 shell harness failed:\n" + cp.stdout + cp.stderr)
            return
        normal, _, no_susfs = out.partition("--- no-susfs ---")
        for needle in ("STUB susfs_load", "STUB soft_reboot_repair",
                       "STUB cleanup_listener", "STUB cleanup_stale",
                       "98260_FINALIZE_BEGIN", "98260_FINALIZE_END"):
            if needle not in normal:
                fail(f"normal finalize_98260 output missing {needle!r}")
        for needle in ("STUB cleanup_listener", "STUB cleanup_stale",
                       "98260_FINALIZE_BEGIN", "98260_FINALIZE_END"):
            if needle not in no_susfs:
                fail(f"no-susfs finalize_98260 output missing {needle!r}")
        if "STUB susfs_load" in no_susfs:
            fail("finalize_98260 0 unexpectedly called susfs_load")


def check_detached_launch() -> None:
    """Demonstrate why redirecting output alone does not detach root work."""
    print("\n== rootd helper detached-launch harness ==")
    with tempfile.TemporaryDirectory(prefix="magicroot-detach-") as td:
        base = Path(td)
        helper = base / "helper.sh"
        output = base / "helper.out"
        fake_su = base / "fake-su"
        helper.write_text(
            "#!/bin/sh\n"
            f"printf 'ROOTD_KILL_RC=0\\n' > '{output}'\n"
            "sleep 5\n",
            encoding="utf-8",
        )
        fake_su.write_text(
            "#!/bin/sh\n"
            "[ \"$1\" = -c ] || exit 64\n"
            "exec /bin/sh -c \"$2\"\n",
            encoding="utf-8",
        )
        helper.chmod(0o755)
        fake_su.chmod(0o755)
        synchronous = f"sh '{helper}' > '{output}' 2>&1"
        detached = f"setsid sh '{helper}' > '{output}' 2>&1 < /dev/null &"
        old = subprocess.run(
            ["timeout", "-k", "1", "1", str(fake_su), "-c", synchronous],
            text=True, capture_output=True, timeout=8,
        )
        if old.returncode == 0:
            fail("synchronous helper unexpectedly escaped the stuck-su harness")
        output.unlink(missing_ok=True)
        started = time.monotonic()
        new = subprocess.run(
            ["timeout", "-k", "1", "2", str(fake_su), "-c", detached],
            text=True, capture_output=True, timeout=8,
        )
        elapsed_ms = round((time.monotonic() - started) * 1000)
        print(f"synchronous_rc={old.returncode} detached_rc={new.returncode} detached_ms={elapsed_ms}")
        if new.returncode != 0 or elapsed_ms >= 1500:
            fail("detached helper still waits for its root child")
            return
        deadline = time.monotonic() + 2
        published = False
        while time.monotonic() < deadline:
            if output.exists() and "ROOTD_KILL_RC=0" in output.read_text():
                published = True
                break
            time.sleep(0.02)
        if not published:
            fail("detached helper did not publish its result")


def check_production_cleanup_harness() -> None:
    """Run the production cleanup with only the root helper replaced by a stub."""
    print("\n== production rootd cleanup harness ==")
    body = function_body(RUN_SH.read_text(encoding="utf-8"), "cleanup_98260_rootd_listener")
    with tempfile.TemporaryDirectory(prefix="magicroot-production-cleanup-") as td:
        base = Path(td)
        fake_bin = base / "bin"
        fake_bin.mkdir()
        fake_helper = base / "fake-helper.sh"
        fake_helper.write_text(
            "#!/bin/sh\n"
            "printf 'ROOTD_PID=24251 PPID=24243 COMM=exploit-android\\n'\n"
            "printf 'ROOTD_KILL_RC=0\\n'\n"
            "sleep 5\n",
            encoding="utf-8",
        )
        fake_helper.chmod(0o755)
        fake_su = fake_bin / "su"
        fake_su.write_text(
            "#!/bin/sh\n"
            "if [ \"${2-}\" = 'id -u' ]; then printf '0\\n'; exit 0; fi\n"
            "cmd=${2-}\n"
            "case \"$cmd\" in\n"
            "  *rootd-cleanup*)\n"
            "    cmd=$(printf '%s' \"$cmd\" | sed \"s#sh '[^']*'#sh '$FAKE_HELPER'#\")\n"
            "    exec /bin/sh -c \"$cmd\"\n"
            "    ;;\n"
            "esac\n"
            "exit 64\n",
            encoding="utf-8",
        )
        fake_su.chmod(0o755)
        script = base / "run-cleanup.sh"
        script.write_text(
            "#!/bin/sh\n"
            f"D='{base}'\n"
            "MAGICROOT_ROOTD_CLEANUP_TIMEOUT=1\n"
            "MAGICROOT_ROOTD_CLEANUP_WAIT_MS=2000\n"
            f"{body}\n"
            "cleanup_98260_rootd_listener\n",
            encoding="utf-8",
        )
        env = dict(os.environ)
        env["PATH"] = str(fake_bin) + ":" + env.get("PATH", "")
        env["FAKE_HELPER"] = str(fake_helper)
        started = time.monotonic()
        result = subprocess.run(
            ["sh", str(script)], text=True, capture_output=True,
            env=env, timeout=8,
        )
        elapsed_ms = round((time.monotonic() - started) * 1000)
        print(result.stdout.rstrip())
        print(f"production_cleanup_ms={elapsed_ms} rc={result.returncode}")
        if result.returncode != 0:
            fail("production cleanup harness failed: " + result.stderr)
        if elapsed_ms >= 2000:
            fail(f"production cleanup still waits for root child: {elapsed_ms} ms")
        for needle in ("ROOTD_CLEAN_LAUNCH_RC=0", "ROOTD_KILL_RC=0",
                       "98260_ROOTD_CLEANUP=ok"):
            if needle not in result.stdout:
                fail(f"production cleanup output missing {needle}")


def main() -> int:
    run_junit_style()
    check_shell()
    check_detached_launch()
    check_production_cleanup_harness()
    print("\n== RESULT ==")
    if problems:
        print(f"problems={len(problems)}")
        return 1
    print("all 98260 finalization checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
