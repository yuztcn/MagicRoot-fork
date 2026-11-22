from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\compose-app\app\src\main\java\com\aoki\magicroot\MainActivity.java")
t = p.read_text(encoding="utf-8")

old = '''            mainHandler.postDelayed(() -> new Thread(() -> {
                boolean ok = false;
                try {
                    ok = exportStaleRunLog("launch");
                } catch (Throwable ignored) {
                }'''
new = '''            mainHandler.postDelayed(() -> new Thread(() -> {
                // Never export while a chain is running: during PREFLIGHT_WAIT /
                // the exploit stages run.log is the *current* log, not a stale
                // interrupted one, and renaming it mid-run would corrupt log
                // polling.  The one-shot "before-run" export is handled inside
                // runChain before the process starts.
                if (runInProgress)
                    return;
                boolean ok = false;
                try {
                    ok = exportStaleRunLog("launch");
                } catch (Throwable ignored) {
                }'''
if old not in t:
    raise SystemExit("launch export anchor missing")
t = t.replace(old, new, 1)

old2 = '''    private boolean exportStaleRunLog(String tag) {
        try {
            String size = shellNoThrow("wc -c < " + WORK + "/run.log 2>/dev/null");'''
new2 = '''    private boolean exportStaleRunLog(String tag) {
        // "launch" exports stale logs only; while a run is active run.log is
        // live (PREFLIGHT_WAIT etc.) and must not be renamed/exported again.
        if ("launch".equals(tag) && runInProgress)
            return false;
        try {
            String size = shellNoThrow("wc -c < " + WORK + "/run.log 2>/dev/null");'''
if old2 not in t:
    raise SystemExit("export guard anchor missing")
t = t.replace(old2, new2, 1)
p.write_text(t, encoding="utf-8", newline="\n")
print("patched launch-export guard")
