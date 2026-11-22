#!/usr/bin/env python3
"""Regression contract for dangerous-cleanup result reporting."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent
TEXT = (ROOT / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java").read_text()


def method(name: str) -> str:
    start = TEXT.index(f"public void {name}()")
    opening = TEXT.index("{", start)
    depth = 0
    for i in range(opening, len(TEXT)):
        if TEXT[i] == "{": depth += 1
        elif TEXT[i] == "}":
            depth -= 1
            if depth == 0: return TEXT[start:i + 1]
    raise AssertionError(name)


class CleanupContractTest(unittest.TestCase):
    def test_tmp_cleanup_does_not_depend_on_deleted_ksu_su(self) -> None:
        body = method("doCleanTmp")
        self.assertIn("cleanupShell(", body)
        self.assertNotIn('runStatusCommand("rm -rf /data/local/tmp', body)
        self.assertIn("CLEAN_TMP_GUARD_CLEAR", body)
        self.assertIn("CLEAN_TMP_GUARD_FOUND", body)

    def test_tmp_cleanup_reports_failure_instead_of_null(self) -> None:
        body = method("doCleanTmp")
        self.assertIn("CLEAN_SHELL_FAILED", body)
        self.assertIn("需要 Shizuku 或可用 root", body)
        self.assertNotIn('String.valueOf(out)', body)

    def test_tmp_cleanup_includes_dotfiles(self) -> None:
        body = method("doCleanTmp")
        self.assertIn("/data/local/tmp/.[!.]*", body)
        self.assertIn("/data/local/tmp/..?*", body)

    def test_adb_cleanup_remains_separate(self) -> None:
        body = method("doCleanAdb")
        self.assertIn("CLEAN_ADB_DONE", body)
        self.assertNotIn("doCleanTmp()", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
