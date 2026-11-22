#!/usr/bin/env python3
"""Static and functional regression for runtime kallsyms symbol completion.

Covers:
  * ko_patch prints MISSING_SYM and accepts an optional kallsyms dump;
  * exact-name fallback uses the runtime address unchanged (no slide math);
  * zero/hidden kallsyms addresses are refused, leaving the symbol missing;
  * run98260.sh retries through the rootd client only when symbols are missing,
    and still fails closed when no root kallsyms can be obtained.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KO_PATCH = os.environ.get("KO_PATCH", str(ROOT / "main/app/assets/ko_patch"))
RUNNER = ROOT / "main/app/assets/98260/run98260.sh"
SLIDE = 0x232c400000
KERNEL = "6.12.58-android16-6-g142ddad31e60-abogki576095858-4k"
TEMPLATE = ROOT / "main/app/assets/ksu-template.ko"
SYMS = ROOT / "main/app/assets/syms_61258.txt"
PICK = ("_printk", "prepare_creds", "commit_creds")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def read_table(path: Path) -> dict[str, int]:
    table = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] in PICK:
            table[fields[0]] = int(fields[1], 16)
    return table


def run(args: list[str]) -> str:
    proc = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=120, check=False)
    require(proc.returncode == 0, f"command failed {args}: {proc.stdout}")
    return proc.stdout


def abs_values(ko: Path) -> dict[str, int]:
    out = subprocess.check_output(["readelf", "-sW", str(ko)], text=True)
    values = {}
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[6] == "ABS" and fields[7] in PICK:
            values[fields[7]] = int(fields[1], 16)
    return values


def functional(tmp: Path) -> None:
    picked = read_table(SYMS)
    require(len(picked) == len(PICK), f"missing anchors in {SYMS}: {picked}")
    truncated = tmp / "truncated.syms"
    truncated.write_text("\n".join(
        line for line in SYMS.read_text().splitlines()
        if line.split() and line.split()[0] not in PICK) + "\n")
    kallsyms = tmp / "runtime.kallsyms"
    kallsyms.write_text("\n".join(
        f"0x{picked[name] + SLIDE:x} t {name}" for name in PICK) + "\n")
    zeroed = tmp / "zero.kallsyms"
    zeroed.write_text("\n".join(
        f"0000000000000000 t {name}" for name in PICK) + "\n")

    without = tmp / "without.ko"
    out = run([KO_PATCH, str(TEMPLATE), str(without), str(truncated),
               hex(SLIDE), KERNEL])
    require("MISSING=3" in out and out.count("MISSING_SYM=") >= 3,
            f"missing names are not reported: {out}")

    with_dump = tmp / "with.ko"
    out = run([KO_PATCH, str(TEMPLATE), str(with_dump), str(truncated),
               hex(SLIDE), KERNEL, str(kallsyms)])
    require("MISSING=0" in out, f"runtime resolver did not complete: {out}")
    for name in PICK:
        require(f"KALLSYMS_FALLBACK={name}=" in out,
                f"no fallback line for {name}: {out}")
    values = abs_values(with_dump)
    for name in PICK:
        require(values.get(name) == picked[name] + SLIDE,
                f"{name}: ABS {values.get(name):#x} != runtime {picked[name] + SLIDE:#x}")

    hidden = tmp / "hidden.ko"
    out = run([KO_PATCH, str(TEMPLATE), str(hidden), str(truncated),
               hex(SLIDE), KERNEL, str(zeroed)])
    require("MISSING=3" in out and "KALLSYMS_FALLBACK=" not in out,
            f"zero addresses were accepted: {out}")


def shell_retry(tmp: Path) -> None:
    text = RUNNER.read_text()
    require("runtime_symbols_retry()" in text, "runner lacks runtime_symbols_retry")
    require('grep -q \'^MISSING_SYM=\' "$KSU_LOG"' in text,
            "runner does not gate the retry on MISSING_SYM")
    require('"$KOPATCH_BIN" "$_rs_tmpl" "$_rs_out" "$_rs_syms" "$SLIDE" "$KERNEL" "$_rs_dump"' in text,
            "runner does not pass the kallsyms dump to ko_patch")

    fn = tmp / "fn.sh"
    start = text.index("runtime_symbols_retry() {")
    end = text.index("\n}\n", start) + 3
    fn.write_text(text[start:end])
    (tmp / "98260").mkdir()
    mocked = tmp / "mock-su"
    mocked.write_text(
        "#!/bin/sh\n"
        "cmd=\"\"\n"
        "while [ $# -gt 0 ]; do if [ \"$1\" = \"-c\" ]; then shift; cmd=$1; fi; shift; done\n"
        "dump=$(printf '%s' \"$cmd\" | sed -n \"s/.*'\\([^']*\\)'[[:space:]]*$/\\1/p\")\n"
        "[ -n \"$dump\" ] || exit 1\n"
        "if [ \"${FAKE_MODE:-ok}\" = \"ok\" ]; then cp \"$FAKE_KALLSYMS\" \"$dump\"; else : > \"$dump\"; fi\n"
        "chmod 644 \"$dump\"\n")
    mocked.chmod(0o755)
    picked = read_table(SYMS)
    kallsyms = tmp / "runtime.kallsyms"
    kallsyms.write_text("\n".join(
        f"0x{picked[name] + SLIDE:x} t {name}" for name in PICK) + "\n")
    truncated = tmp / "truncated.syms"
    truncated.write_text("\n".join(
        line for line in SYMS.read_text().splitlines()
        if line.split() and line.split()[0] not in PICK) + "\n")

    script = (
        "set -u\n"
        "D=$1; KSU_LOG=$D/ksu.log; LOG=$D/native.log; EXEC_PID=$$\n"
        "SLIDE=%s; KERNEL=%s; KOPATCH_BIN=$2; SU=$3; FAKE_KALLSYMS=$4; export FAKE_KALLSYMS\n"
        "num_or() { case \"$1\" in ''|*[!0-9]*) echo \"$2\" ;; *) echo \"$1\" ;; esac; }\n"
        ". \"$5\"\nMAGICROOT_98260_SYM_WAIT_S=2\n"
        ": > \"$KSU_LOG\"; : > \"$LOG\"\n"
        "if runtime_symbols_retry \"$6\" \"$D/out.ko\" \"$7\" \"$KSU_LOG\"; then echo RETRY_OK; else echo RETRY_FAIL; fi\n"
    ) % (hex(SLIDE), KERNEL)
    args = ["bash", "-c", script, "bash", str(tmp), KO_PATCH, str(mocked),
            str(kallsyms), str(fn), str(TEMPLATE), str(truncated)]
    out = run(args)
    require("RETRY_OK" in out and "98260_KSU_PATCH_RETRY=0 missing=0" in out,
            f"shell retry failed: {out}")
    require("98260_SYMS_RUNTIME=dump" in out, f"no dump evidence: {out}")

    env = dict(os.environ, FAKE_MODE="empty")
    proc = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=120, check=False,
                          env=env)
    require(proc.returncode == 0, proc.stdout)
    require("RETRY_FAIL" in proc.stdout and
            "98260_SYMS_RUNTIME=unavailable reason=no_root_kallsyms" in proc.stdout,
            f"no-root case did not fail closed: {proc.stdout}")


def main() -> None:
    require(Path(KO_PATCH).is_file(), f"missing ko_patch {KO_PATCH}")
    with tempfile.TemporaryDirectory(prefix="runtime-syms-test-") as tmp:
        work = Path(tmp)
        functional(work)
        shell_retry(work)
    print("PASS runtime symbols: MISSING_SYM report, exact kallsyms fallback, "
          "zero-address refusal, rootd retry, fail-closed")


if __name__ == "__main__":
    main()
