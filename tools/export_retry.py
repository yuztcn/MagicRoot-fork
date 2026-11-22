#!/usr/bin/env python3
"""Retry the stale-log auto-export after app launch until the shell is ready,
and report whether it succeeded."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
J = WS / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java"
t = J.read_text(encoding="utf-8")

old = '''        // If the previous run was interrupted (e.g. the device restarted during
        // the race), export its run.log once the shell is available so the user
        // can read/share it.
        mainHandler.postDelayed(() -> new Thread(() -> {
            try {
                exportStaleRunLog("launch");
            } catch (Throwable ignored) {
            }
        }).start(), 4000);
    }

    /**
     * Copy a leftover run.log (previous interrupted/rebooted run) to
     * /sdcard/Download/MagicRoot and rename it away so it is exported once.
     */
    private void exportStaleRunLog(String tag) {
        try {
            String size = shellNoThrow("wc -c < " + WORK + "/run.log 2>/dev/null");
            int n = 0;
            try {
                n = Integer.parseInt(String.valueOf(size).trim());
            } catch (Throwable ignored) {
            }
            if (n <= 0)
                return;
            String dir = "/sdcard/Download/MagicRoot";
            String dst = dir + "/prev-run-" + System.currentTimeMillis() + ".txt";
            shell("mkdir -p " + dir
                    + " && { cat " + WORK + "/run.log; echo; "
                    + "echo '=== PERMISSIVE_STARTED ==='; "
                    + "cat " + WORK + "/marks/PERMISSIVE_STARTED 2>/dev/null; } > '" + dst + "'"
                    + " && chmod 644 '" + dst + "'"
                    + " && mv -f " + WORK + "/run.log " + WORK + "/run.log.exported 2>/dev/null; true");
            log("已导出上次运行日志(" + tag + "): " + dst);
            if ("launch".equals(tag)) {
                log("提示：如上次是设备重启中断，开机后先静置 1-2 分钟再执行；"
                        + "链路会自动等待系统稳定（PREFLIGHT_WAIT）");
            }
        } catch (Throwable ignored) {
        }
    }'''

new = '''        // If the previous run was interrupted (e.g. the app was closed or the
        // device restarted during the race), export its run.log once the shell
        // is available so the user can read/share it.  The shell binder may
        // still be connecting at launch, so retry a few times.
        for (int[] plan : new int[][]{{4000, 0}, {12000, 1}, {25000, 2}, {40000, 3}}) {
            final int attempt = plan[1];
            mainHandler.postDelayed(() -> new Thread(() -> {
                boolean ok = false;
                try {
                    ok = exportStaleRunLog("launch");
                } catch (Throwable ignored) {
                }
                if (!ok && attempt == 3) {
                    log("未发现可导出的上次运行日志（或 run.log 不存在）");
                }
            }).start(), plan[0]);
        }
    }

    /**
     * Copy a leftover run.log (previous interrupted/rebooted run) to
     * /sdcard/Download/MagicRoot and rename it away so it is exported once.
     * Returns true when a log was found and exported.
     */
    private boolean exportStaleRunLog(String tag) {
        try {
            String size = shellNoThrow("wc -c < " + WORK + "/run.log 2>/dev/null");
            int n = 0;
            try {
                n = Integer.parseInt(String.valueOf(size).trim());
            } catch (Throwable ignored) {
            }
            if (n <= 0)
                return false;
            String dir = "/sdcard/Download/MagicRoot";
            String dst = dir + "/prev-run-" + System.currentTimeMillis() + ".txt";
            shell("mkdir -p " + dir
                    + " && { cat " + WORK + "/run.log; echo; "
                    + "echo '=== PERMISSIVE_STARTED ==='; "
                    + "cat " + WORK + "/marks/PERMISSIVE_STARTED 2>/dev/null; } > '" + dst + "'"
                    + " && chmod 644 '" + dst + "'"
                    + " && mv -f " + WORK + "/run.log " + WORK + "/run.log.exported 2>/dev/null; true");
            String check = shellNoThrow("test -s '" + dst + "' && echo OK || echo FAIL");
            if (check == null || !check.contains("OK"))
                return false;
            log("已导出上次运行日志(" + tag + "): " + dst);
            if ("launch".equals(tag)) {
                log("提示：如上次是设备重启/关闭 App 中断，开机后先静置 1-2 分钟再执行；"
                        + "链路会自动等待系统稳定（PREFLIGHT_WAIT）");
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }'''

if old not in t:
    raise SystemExit("export anchor missing")
t = t.replace(old, new, 1)
J.write_text(t, encoding="utf-8", newline="\n")
print("patched export retries")
