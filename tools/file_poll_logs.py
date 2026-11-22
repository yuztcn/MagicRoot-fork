#!/usr/bin/env python3
"""Make in-app progress authoritative from run.log polling instead of the
Stellar/Shizuku child stdout pipe (which can stall while the kernel race runs,
leaving the app stuck at '开始执行 run.sh')."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
J = WS / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java"
t = J.read_text(encoding="utf-8")

old = '''            // Consume the existing child stdout as a blocking stream.  A
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
                        final String s = line;
                        if (s.isEmpty())
                            continue;
                        synchronized (runLog) {
                            runLog.append(s).append('\\n');
                            if (runLog.length() > 200_000)
                                runLog.delete(0, runLog.length() - 200_000);
                        }
                        String t = s.trim();
                        if (t.equals("DONE"))
                            sawDone.set(true);
                        if (t.startsWith("FAIL="))
                            sawFail.set(true);
                        updateProgressFromLine(s);
                        mainHandler.post(() -> {
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

            try {
                p.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            try {
                reader.join(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            log("run.sh 已退出");'''

new = '''            // The child stdout pipe from Stellar/Shizuku can stall while the
            // kernel race is spraying, which used to leave the app stuck at
            // "开始执行 run.sh" even though run.log kept growing.  The pipe is
            // only drained here; UI progress is read from run.log (authoritative
            // and always complete).
            final StringBuilder runLog = new StringBuilder(64 * 1024);
            final AtomicBoolean sawDone = new AtomicBoolean(false);
            final AtomicBoolean sawFail = new AtomicBoolean(false);
            final AtomicBoolean processFinished = new AtomicBoolean(false);
            final int[] knownLines = {0};
            Thread drainer = new Thread(() -> {
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(p.getInputStream(), "UTF-8"))) {
                    while (r.readLine() != null) {
                        // discard: run.log polling below feeds the UI
                    }
                } catch (Throwable e) {
                    log("stdout 管道读取结束: " + e);
                }
            }, "magicroot-stdout-drain");
            drainer.setDaemon(true);
            drainer.start();
            log("[log] 界面进度改为轮询 run.log（每 1.5s）");

            Thread logPoller = new Thread(() -> {
                while (!processFinished.get()) {
                    knownLines[0] = pollRunLog(knownLines[0], runLog, sawDone, sawFail);
                    try {
                        Thread.sleep(1500);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
                // final pass after the process exits
                knownLines[0] = pollRunLog(knownLines[0], runLog, sawDone, sawFail);
            }, "magicroot-logpoll");
            logPoller.setDaemon(true);
            logPoller.start();

            try {
                p.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            processFinished.set(true);
            try {
                logPoller.join(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            drainer.interrupt();
            log("run.sh 已退出");'''

if old not in t:
    raise SystemExit("reader/watchdog anchor missing")
t = t.replace(old, new, 1)

# add the pollRunLog helper before updateProgressFromLine
anchor = "    private void updateProgressFromLine(String line) {"
helper = '''    /**
     * Read newly appended lines from run.log and feed the in-app log/progress.
     * Returns the new known line count.  Safe to call from a background thread.
     */
    private int pollRunLog(int knownLines, StringBuilder runLog,
                           AtomicBoolean sawDone, AtomicBoolean sawFail) {
        try {
            String cnt = shellNoThrow("wc -l < " + WORK + "/run.log 2>/dev/null");
            int total = -1;
            try {
                total = Integer.parseInt(String.valueOf(cnt).trim());
            } catch (Throwable ignored) {
            }
            if (total >= 0 && total <= knownLines)
                return knownLines;
            String chunk = shellNoThrow("tail -n +" + (knownLines + 1) + " "
                    + WORK + "/run.log 2>/dev/null");
            if (chunk == null || chunk.isEmpty())
                return knownLines;
            int added = 0;
            for (String s : chunk.split("\\n")) {
                if (s.isEmpty())
                    continue;
                added++;
                synchronized (runLog) {
                    runLog.append(s).append('\\n');
                    if (runLog.length() > 200_000)
                        runLog.delete(0, runLog.length() - 200_000);
                }
                String tr = s.trim();
                if (tr.equals("DONE"))
                    sawDone.set(true);
                if (tr.startsWith("FAIL="))
                    sawFail.set(true);
                updateProgressFromLine(s);
                final String line = s;
                mainHandler.post(() -> {
                    if (!isDestroyed())
                        ui.appendLog(line);
                });
            }
            return knownLines + added;
        } catch (Throwable t) {
            return knownLines;
        }
    }

'''
if anchor not in t:
    raise SystemExit("updateProgressFromLine anchor missing")
t = t.replace(anchor, helper + anchor, 1)
J.write_text(t, encoding="utf-8", newline="\n")
print("patched MainActivity log polling")
