#!/usr/bin/env python3
"""Deterministic regression test for the g142 six-anchor KASLR helper.

This uses a synthetic capture, not a live trace or a root operation.  The
expected slide/votes/anchors and derived addresses are calculated independently
from the helper implementation.
"""
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "main/app/assets/kaslr_slide_aph136g142"
ANCHORS = [
    ("worker_thread", 0xFFFFFFC080207BC8),
    ("rcu_gp_fqs_loop", 0xFFFFFFC08018DBFC),
    ("rcu_gp_kthread", 0xFFFFFFC08018D6F4),
    ("folio_wait_bit_common", 0xFFFFFFC0802E798C),
    ("ufshcd_issue_dev_cmd", 0xFFFFFFC080E55658),
    ("icc_set_bw", 0xFFFFFFC08037A2B8),
]
SLIDE = 0x20B5600000


def run(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(HELPER), str(path)], text=True,
                          capture_output=True, timeout=10, check=False)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="g142-kaslr-test-") as td:
        root = Path(td)
        valid = root / "valid"
        invalid = root / "invalid"
        valid.mkdir()
        invalid.mkdir()
        valid.joinpath("bl_text.txt").write_text(
            "".join(f"event caller={name}+0x0\n" for name, _ in ANCHORS),
            encoding="ascii")
        with valid.joinpath("bl_0.bin").open("wb") as out:
            for _ in range(3):
                for _, address in ANCHORS:
                    out.write(struct.pack("<Q", address + SLIDE))
        invalid.joinpath("bl_text.txt").write_text(
            "event caller=unknown+0x0\n", encoding="ascii")
        invalid.joinpath("bl_0.bin").write_bytes(b"")

        expected = (
            f"KASLR_SLIDE={SLIDE:#x}\n"
            "KASLR_VOTES=18\n"
            "KASLR_SECOND=0\n"
            "KASLR_ANCHORS=6\n"
            "KASLR_BYTES=144\n"
            f"SELINUX_ARG={0xFFFFFFC0827E7A60 + SLIDE - 7:#x}\n"
            f"PREPARE={0xFFFFFFC0801935B8 + SLIDE:#x}\n"
        )
        result = run(valid)
        assert result.returncode == 0, result
        assert result.stdout == expected, (result.stdout, expected)
        assert result.stderr == "", result.stderr

        result = run(invalid)
        assert result.returncode == 2, result
        assert result.stdout == "KASLR_ERROR=no_anchor\n", result.stdout
        assert result.stderr == "", result.stderr

    print("PASS g142 KASLR synthetic capture (valid + no-anchor)")


if __name__ == "__main__":
    main()
