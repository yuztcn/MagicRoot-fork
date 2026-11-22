#!/usr/bin/env python3
"""App log streaming/watchdog + boot-settle preflight defaults/UI stages.

- run.sh stdout now goes through a shell read loop (line-buffered) instead of
  tee, so the app receives log lines immediately;
- a watchdog falls back to polling run.log if the stream stalls for >8s;
- preflight waits for a settled boot before the race (defaults raised);
- UI progress shows preflight/waiting/previous-crash states.
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


# -------------------------------------------------------------- MainActivity
J = WS / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java"
patch(J, [
    # replace tee with a line-buffered pump; add stale-crash warning + watchdog
    ('''            shell("rm -f " + WORK + "/run.log");
            log("开始执行 run.sh（日志同时写入 " + WORK + "/run.log）...");''',
     '''            shell("rm -f " + WORK + "/run.log");
            String stale = shellNoThrow("cat " + WORK + "/marks/PERMISSIVE_STARTED 2>/dev/null");
            if (stale != null && !stale.trim().isEmpty()) {
                log("PREVIOUS_RUN_INCOMPLETE 上次链路在 permissive 阶段中断（可能重启）: "
                        + stale.trim());
                log("WARN 已启用开机稳定等待，请让设备静置片刻再重试");
            }
            log("开始执行 run.sh（日志同时写入 " + WORK + "/run.log）...");'''),
    ('''            Process p = shellProcess("cd " + WORK + " && " + env
                    + "sh run.sh 2>&1 | tee -a " + WORK + "/run.log");

            // Enhanced requirement: do not poll the host with a new shell while
            // cred/phase work is racing.  Consume the existing child stdout as a
            // blocking stream; tee still persists the full run.log.
            final StringBuilder runLog = new StringBuilder(64 * 1024);
            final AtomicBoolean sawDone = new AtomicBoolean(false);
            final AtomicBoolean sawFail = new AtomicBoolean(false);
            Thread reader = new Thread(() -> {
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(p.getInputStream(), "UTF-8"))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        final String s = line;''',
     '''            // Line-buffered pump: `tee` may block-buffer its stdout, which made
            // the in-app log look frozen while run.log kept growing.  The shell
            // read loop prints each line immediately and appends it to run.log.
            Process p = shellProcess("cd " + WORK + " && " + env
                    + "sh run.sh 2>&1 | while IFS= read -r __ml; do "
                    + "printf '%s\\\\n' \\"$__ml\\"; "
                    + "printf '%s\\\\n' \\"$__ml\\" >> " + WORK + "/run.log; done");

            // Consume the existing child stdout as a blocking stream.  A
            // watchdog re-reads run.log if the stream stalls (Stellar/Shizuku
            // pipes can stall while the kernel race is running).
            final StringBuilder runLog = new StringBuilder(64 * 1024);
            final AtomicBoolean sawDone = new AtomicBoolean(false);
            final AtomicBoolean sawFail = new AtomicBoolean(false);
            final long[] lastStreamAt = {System.currentTimeMillis()};
            Thread reader = new Thread(() -> {
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(p.getInputStream(), "UTF-8"))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        lastStreamAt[0] = System.currentTimeMillis();
                        final String s = line;'''),
    ('''                        mainHandler.post(() -> {
                            if (!isDestroyed())
                                ui.appendLog(s);
                        });
                    }
                } catch (Throwable ignored) {
                }
            }, "magicroot-stdout");
            reader.setDaemon(true);
            reader.start();
''',
     '''                        mainHandler.post(() -> {
                            if (!isDestroyed())
                                ui.appendLog(s);
                        });
                    }
                } catch (Throwable e) {
                    log("日志读取线程结束: " + e);
                }
            }, "magicroot-stdout");
            reader.setDaemon(true);
            reader.start();

            Thread watchdog = new Thread(() -> {
                boolean warned = false;
                while (p.isAlive()) {
                    try {
                        Thread.sleep(3000);
                    } catch (InterruptedException e) {
                        return;
                    }
                    if (!p.isAlive())
                        return;
                    if (System.currentTimeMillis() - lastStreamAt[0] < 8000) {
                        warned = false;
                        continue;
                    }
                    String tail = shellNoThrow("tail -c 20000 " + WORK + "/run.log 2>/dev/null");
                    if (tail != null && !tail.isEmpty()) {
                        mainHandler.post(() -> {
                            if (!isDestroyed())
                                ui.replaceLog(tail);
                        });
                        if (!warned) {
                            warned = true;
                            log("[watchdog] 日志流停滞，改用 run.log 轮询");
                        }
                    }
                }
            }, "magicroot-logwatch");
            watchdog.setDaemon(true);
            watchdog.start();
'''),
    # progress mapping for preflight/stall states
    ('''        if (line.startsWith("== 1.")) {''',
     '''        } else if (line.startsWith("PREFLIGHT_WAIT")) {
            progress = 3;
            stage = "等待系统稳定（刚开机/系统繁忙）";
        } else if (line.startsWith("PREFLIGHT_OK")) {
            progress = 5;
            stage = "系统稳定，准备链路";
        } else if (line.startsWith("PREFLIGHT_SKIP")) {
            progress = 4;
            stage = "已跳过开机等待";
        } else if (line.startsWith("PREVIOUS_RUN_INCOMPLETE")) {
            progress = 4;
            stage = "上次运行中断（检测到重启）";
        } else if (line.startsWith("== 1.")) {'''),
])

# ------------------------------------------------------------------ run.sh --
R = WS / "main/app/assets/run.sh"
patch(R, [
    ('PREFLIGHT_SETTLE=${MAGICROOT_BOOT_SETTLE_SEC:-60}',
     'PREFLIGHT_SETTLE=${MAGICROOT_BOOT_SETTLE_SEC:-90}'),
    ('PREFLIGHT_MAX_LOAD=${MAGICROOT_PREFLIGHT_MAX_LOAD:-12}',
     'PREFLIGHT_MAX_LOAD=${MAGICROOT_PREFLIGHT_MAX_LOAD:-10}'),
    ('PREFLIGHT_MIN_MEM_KB=${MAGICROOT_PREFLIGHT_MIN_MEM_KB:-819200}',
     'PREFLIGHT_MIN_MEM_KB=${MAGICROOT_PREFLIGHT_MIN_MEM_KB:-1048576}'),
    ('PREFLIGHT_MAX_WAIT=${MAGICROOT_PREFLIGHT_MAX_WAIT:-180}',
     'PREFLIGHT_MAX_WAIT=${MAGICROOT_PREFLIGHT_MAX_WAIT:-240}'),
    ('case "$PREFLIGHT_SETTLE" in \'\'|*[!0-9]*) PREFLIGHT_SETTLE=60 ;; esac',
     'case "$PREFLIGHT_SETTLE" in \'\'|*[!0-9]*) PREFLIGHT_SETTLE=90 ;; esac'),
    ('case "$PREFLIGHT_MAX_LOAD" in \'\'|*[!0-9]*) PREFLIGHT_MAX_LOAD=12 ;; esac',
     'case "$PREFLIGHT_MAX_LOAD" in \'\'|*[!0-9]*) PREFLIGHT_MAX_LOAD=10 ;; esac'),
    ('case "$PREFLIGHT_MIN_MEM_KB" in \'\'|*[!0-9]*) PREFLIGHT_MIN_MEM_KB=819200 ;; esac',
     'case "$PREFLIGHT_MIN_MEM_KB" in \'\'|*[!0-9]*) PREFLIGHT_MIN_MEM_KB=1048576 ;; esac'),
    ('case "$PREFLIGHT_MAX_WAIT" in \'\'|*[!0-9]*) PREFLIGHT_MAX_WAIT=180 ;; esac',
     'case "$PREFLIGHT_MAX_WAIT" in \'\'|*[!0-9]*) PREFLIGHT_MAX_WAIT=240 ;; esac'),
])
print("done")
