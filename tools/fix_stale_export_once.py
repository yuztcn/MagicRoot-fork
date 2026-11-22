from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\compose-app\app\src\main\java\com\aoki\magicroot\MainActivity.java")
t = p.read_text(encoding="utf-8")

if "private volatile boolean staleExportDone" not in t:
    t = t.replace(
        "    private volatile boolean runInProgress = false;",
        "    private volatile boolean runInProgress = false;\n"
        "    private volatile boolean staleExportDone = false;", 1)

t = t.replace(
'''                if (runInProgress)
                    return;
                boolean ok = false;
                try {
                    ok = exportStaleRunLog("launch");''',
'''                if (runInProgress || staleExportDone)
                    return;
                boolean ok = false;
                try {
                    ok = exportStaleRunLog("launch");''', 1)

t = t.replace(
'''            log("已导出上次运行日志(" + tag + "): " + dst);''',
'''            staleExportDone = true;
            log("已导出上次运行日志(" + tag + "): " + dst);''', 1)

p.write_text(t, encoding="utf-8", newline="\n")
print("patched staleExportDone guard")
