#!/usr/bin/env python3
"""Device test: verify that the Compose tab page survives process death.

This test is intentionally non-destructive apart from stopping/starting the
app. It does NOT install an APK and does NOT need root.

Requirements:
    - adb available in PATH, via ADB env var, or the default SDK path;
    - the release app already installed:
          package com.aoki.magicroot

Usage:
    python release/tools/page_persistence_test.py
    python release/tools/page_persistence_test.py --package com.aoki.magicroot
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

DEFAULT_ADB = Path(r"<LOCAL_USER>user\Downloads\<TOOLCHAIN>\sdk\platform-tools\adb.exe")
TAB_TEXT = "关于"
REOPEN_MARKER = "关于 MagicRoot"  # AboutPage title, not the Home hero text.


def find_adb() -> str:
    env = os.environ.get("ADB")
    if env and Path(env).is_file():
        return env
    found = shutil.which("adb")
    if found:
        return found
    if DEFAULT_ADB.is_file():
        return str(DEFAULT_ADB)
    raise SystemExit("adb not found; set ADB=... or PATH")


def run(adb: str, *args: str, check: bool = True) -> str:
    proc = subprocess.run([adb, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if check and proc.returncode != 0:
        raise SystemExit(f"adb {' '.join(args)} failed:\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout


def launch(adb: str, package: str) -> None:
    run(adb, "shell", "am", "force-stop", package, check=False)
    time.sleep(0.4)
    run(adb, "shell", "monkey", "-p", package, "-c",
        "android.intent.category.LAUNCHER", "1")
    time.sleep(2.0)


def dump(adb: str) -> ET.Element:
    run(adb, "shell", "uiautomator", "dump", "/sdcard/magicroot_window.xml")
    xml = run(adb, "exec-out", "cat", "/sdcard/magicroot_window.xml")
    try:
        return ET.fromstring(xml)
    except ET.ParseError as exc:
        raise SystemExit(f"cannot parse uiautomator dump: {exc}\n{xml[:500]}")


def find_node(root: ET.Element, text: str) -> ET.Element | None:
    for node in root.iter("node"):
        if node.get("text", "") == text:
            return node
    return None


def center(node: ET.Element) -> tuple[int, int]:
    bounds = node.get("bounds", "")
    # [x1,y1][x2,y2]
    try:
        left_top, right_bottom = bounds.split("][")
        x1, y1 = (int(v) for v in left_top.strip("[").split(","))
        x2, y2 = (int(v) for v in right_bottom.strip("]").split(","))
        return (x1 + x2) // 2, (y1 + y2) // 2
    except Exception as exc:
        raise SystemExit(f"bad bounds {bounds!r}: {exc}")


def has_marker(root: ET.Element) -> bool:
    for node in root.iter("node"):
        if REOPEN_MARKER in node.get("text", ""):
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", default="com.aoki.magicroot")
    args = parser.parse_args()
    adb = find_adb()
    package = args.package

    print(f"adb: {adb}")
    print(f"package: {package}")
    print("1. launch app")
    launch(adb, package)
    root = dump(adb)
    tab = find_node(root, TAB_TEXT)
    if tab is None:
        raise SystemExit(f"tab {TAB_TEXT!r} not found in UI dump; is the app in the foreground?")
    x, y = center(tab)
    print(f"2. tap {TAB_TEXT!r} at ({x},{y})")
    run(adb, "shell", "input", "tap", str(x), str(y))
    time.sleep(1.2)
    root = dump(adb)
    if not has_marker(root):
        raise SystemExit("AboutPage marker not found after tapping the tab; test aborted")
    print("3. AboutPage marker present; killing process with am force-stop")
    run(adb, "shell", "am", "force-stop", package)
    time.sleep(0.5)
    print("4. relaunch app")
    run(adb, "shell", "monkey", "-p", package, "-c",
        "android.intent.category.LAUNCHER", "1")
    time.sleep(2.0)
    root = dump(adb)
    if has_marker(root):
        print("PASS: page 1 restored after process death")
        return 0
    print("FAIL: app returned to HomePage after process death")
    return 1


if __name__ == "__main__":
    sys.exit(main())
