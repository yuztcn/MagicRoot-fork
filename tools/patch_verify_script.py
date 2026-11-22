#!/usr/bin/env python3
"""Make the success-page automation resilient to a leftover success/about page."""
from pathlib import Path

p = Path(__file__).resolve().parent / "device" / "verify_success_page.py"
t = p.read_text(encoding="utf-8")
old = """    adb("shell", "monkey", "-p", PKG, "-c",
        "android.intent.category.LAUNCHER", "1")
    time.sleep(4)
"""
new = """    adb("shell", "monkey", "-p", PKG, "-c",
        "android.intent.category.LAUNCHER", "1")
    time.sleep(4)
    # leave a leftover success/about overlay first
    for _ in range(3):
        nodes = dump_nodes()
        if find(nodes, "返回主页"):
            adb("shell", "input", "tap", str(find(nodes, "返回主页")[1]),
                str(find(nodes, "返回主页")[2]))
            time.sleep(1)
            continue
        if find(nodes, "关闭"):
            adb("shell", "input", "tap", str(find(nodes, "关闭")[1]),
                str(find(nodes, "关闭")[2]))
            time.sleep(1)
            continue
        break
"""
if old not in t:
    raise SystemExit("anchor missing")
p.write_text(t.replace(old, new), encoding="utf-8", newline="\n")
print("automation patched")
