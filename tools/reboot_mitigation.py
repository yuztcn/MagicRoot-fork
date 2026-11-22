#!/usr/bin/env python3
"""Reboot-mitigation + log-preservation pass:

- preflight thresholds tuned for real device behaviour (uptime>=120s, load<=20,
  <=240s wait) so a freshly booted, busy device waits instead of crashing;
- kill leftover grab/forker spray processes and add a short settle delay before
  the SELinux permissive race;
- auto-export a previous interrupted run.log (e.g. after a reboot) to
  /sdcard/Download/MagicRoot, before the next run deletes it.
"""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent


def patch(path: Path, pairs):
    p = Path(path)
    t = p.read_text(encoding="utf-8", errors="replace")
    for old, new in pairs:
        if old not in t:
            raise SystemExit(f"anchor missing in {p.name}: {old[:80]}")
        t = t.replace(old, new, 1)
    p.write_text(t, encoding="utf-8", newline="\n")
    print("patched", p.relative_to(WS))


# ------------------------------------------------------------------ run.sh ---
R = WS / "main/app/assets/run.sh"
patch(R, [
    ('PREFLIGHT_SETTLE=${MAGICROOT_BOOT_SETTLE_SEC:-90}',
     'PREFLIGHT_SETTLE=${MAGICROOT_BOOT_SETTLE_SEC:-120}'),
    ('PREFLIGHT_MAX_LOAD=${MAGICROOT_PREFLIGHT_MAX_LOAD:-10}',
     'PREFLIGHT_MAX_LOAD=${MAGICROOT_PREFLIGHT_MAX_LOAD:-20}'),
    ('PREFLIGHT_MAX_WAIT=${MAGICROOT_PREFLIGHT_MAX_WAIT:-240}',
     'PREFLIGHT_MAX_WAIT=${MAGICROOT_PREFLIGHT_MAX_WAIT:-240}'),
    ('case "$PREFLIGHT_SETTLE" in \'\'|*[!0-9]*) PREFLIGHT_SETTLE=90 ;; esac',
     'case "$PREFLIGHT_SETTLE" in \'\'|*[!0-9]*) PREFLIGHT_SETTLE=120 ;; esac'),
    ('case "$PREFLIGHT_MAX_LOAD" in \'\'|*[!0-9]*) PREFLIGHT_MAX_LOAD=10 ;; esac',
     'case "$PREFLIGHT_MAX_LOAD" in \'\'|*[!0-9]*) PREFLIGHT_MAX_LOAD=20 ;; esac'),
    # cleanup leftover spray processes + short settle before the race
    ('''echo "== 3. SELinux permissive =="''',
     '''# Kill any leftover grab/forker spray processes and let the kernel settle
# briefly before the dangerous permissive race (fresh-boot runs used to panic
# while these were still winding down).
pkill -9 -f '[f]orker' 2>/dev/null
pkill -9 -f '[g]rab\\.sh' 2>/dev/null
pkill -9 -f '[t]race_pipe_raw' 2>/dev/null
sleep 1
echo "PERMISSIVE_CLEANUP=done"
echo "== 3. SELinux permissive =="'''),
])

# ------------------------------------------------------------- MainActivity --
J = WS / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java"
patch(J, [
    # auto-export stale log at app launch (after shell becomes available)
    ('''        // Do not poll run.log with a shell every 2 s.  The run loop consumes the
        // child process stdout as a blocking stream instead (Enhanced requirement:
        // no host-side polling while the cred stage is racing).
    }''',
     '''        // If the previous run was interrupted (e.g. the device restarted during
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
    }'''),
    # export before the new run overwrites run.log
    ('''            shell("rm -f " + WORK + "/run.log");
            String stale = shellNoThrow("cat " + WORK + "/marks/PERMISSIVE_STARTED 2>/dev/null");''',
     '''            exportStaleRunLog("before-run");
            shell("rm -f " + WORK + "/run.log");
            String stale = shellNoThrow("cat " + WORK + "/marks/PERMISSIVE_STARTED 2>/dev/null");'''),
])
print("done")
