#!/usr/bin/env python3
"""Log export feedback, compact About button/status placement, success-page
layout fix, and shell binder retry (fixes the 'Stellar/Shizuku 均不可用' log
entries seen in error.txt)."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
M = WS / "main/compose-app/app/src/main/kotlin/com/aoki/magicroot/MiuixHost.kt"
U = WS / "main/compose-app/app/src/main/kotlin/com/aoki/magicroot/UiState.kt"
J = WS / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java"


def patch(path: Path, pairs, required=True):
    p = Path(path)
    t = p.read_text(encoding="utf-8", errors="replace")
    for old, new in pairs:
        if old not in t:
            if required:
                print("WARN missing in", p.name, ":", old[:60])
            continue
        t = t.replace(old, new, 1)
    p.write_text(t, encoding="utf-8", newline="\n")
    print("patched", p.relative_to(WS))


# ---------------------------------------------------------------- UiState ---
patch(U, [
    ("""    var showSuccess by mutableStateOf(false)""",
     """    var showSuccess by mutableStateOf(false)
    /** Success-page log export feedback ("正在导出…", "日志已导出：…", …). */
    var exportResult by mutableStateOf("")
    var exportOk by mutableStateOf(false)

    fun setExportResult(text: String, ok: Boolean) {
        exportResult = text
        exportOk = ok
    }"""),
])

# ------------------------------------------------------------ MiuixHost -----
# Success page: real export feedback + fixed kernel-version layout
patch(M, [
    ("""                Spacer(Modifier.height(6.dp))
                Row(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = "内核版本",
                        fontSize = 12.sp,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        text = state.kernelVersion,
                        fontSize = 10.sp,
                        maxLines = 1,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                }""",
     """                Spacer(Modifier.height(6.dp))
                Text(
                    text = "内核版本",
                    fontSize = 12.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
                Text(
                    text = state.kernelVersion,
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = MiuixTheme.colorScheme.onSurface,
                )"""),
    ("""                Button(
                    onClick = { activity.exportSuccessLog() },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("导出日志", fontSize = 14.sp) }
                Spacer(Modifier.height(8.dp))""",
     """                Button(
                    onClick = { activity.exportSuccessLog() },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("导出日志", fontSize = 14.sp) }
                if (state.exportResult.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text(
                        text = state.exportResult,
                        fontSize = 10.sp,
                        lineHeight = 14.sp,
                        color = if (state.exportOk) MiuixTheme.colorScheme.primary
                        else MiuixTheme.colorScheme.error,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                Spacer(Modifier.height(8.dp))"""),
    ("""    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MiuixTheme.colorScheme.background)
            .padding(horizontal = 20.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.weight(1f))
        Card(
            colors = CardDefaults.defaultColors(color = MiuixTheme.colorScheme.surfaceContainerHighest),
            insideMargin = PaddingValues(0.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 18.dp, vertical = 18.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                StatusPill("提权成功", MiuixTheme.colorScheme.primaryContainer)""",
     """    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MiuixTheme.colorScheme.background)
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(horizontal = 20.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.weight(1f))
        Card(
            colors = CardDefaults.defaultColors(color = MiuixTheme.colorScheme.surfaceContainerHighest),
            insideMargin = PaddingValues(0.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 18.dp, vertical = 18.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                StatusPill("提权成功", MiuixTheme.colorScheme.primaryContainer)"""),
])

# Header: compact "关于" pill at the bottom-right, status pill back to top-right
patch(M, [
    ("""            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "MagicRoot",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        color = MiuixTheme.colorScheme.primary,
                    )
                    Text(
                        text = "零特权提权链路",
                        fontSize = 21.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                }
                Column(horizontalAlignment = Alignment.End) {
                    StatusPill(
                        text = when {
                            state.running -> "运行中"
                            state.busy -> "处理中"
                            else -> "就绪"
                        },
                        color = when {
                            state.running -> MiuixTheme.colorScheme.primaryContainer
                            state.busy -> MiuixTheme.colorScheme.secondaryContainer
                            else -> MiuixTheme.colorScheme.tertiaryContainer
                        },
                    )
                    TextButton(
                        text = "关于",
                        onClick = { state.showAbout = true },
                    )
                }
            }
            Text(
                text = "CVE-2026-64560 · ${state.ksuManagerLabel} LKM · ${state.status}",
                fontSize = 11.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(3.dp))
            Text(
                text = "内核 ${state.kernelVersion}",
                fontSize = 9.5.sp,
                lineHeight = 13.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )""",
     """            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "MagicRoot",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        color = MiuixTheme.colorScheme.primary,
                    )
                    Text(
                        text = "零特权提权链路",
                        fontSize = 21.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                }
                StatusPill(
                    text = when {
                        state.running -> "运行中"
                        state.busy -> "处理中"
                        else -> "就绪"
                    },
                    color = when {
                        state.running -> MiuixTheme.colorScheme.primaryContainer
                        state.busy -> MiuixTheme.colorScheme.secondaryContainer
                        else -> MiuixTheme.colorScheme.tertiaryContainer
                    },
                )
            }
            Text(
                text = "CVE-2026-64560 · ${state.ksuManagerLabel} LKM · ${state.status}",
                fontSize = 11.sp,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            Spacer(Modifier.height(3.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "内核 ${state.kernelVersion}",
                    fontSize = 9.5.sp,
                    lineHeight = 13.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    modifier = Modifier.weight(1f),
                )
                Box(
                    modifier = Modifier
                        .background(
                            color = MiuixTheme.colorScheme.surfaceContainerHigh,
                            shape = RoundedCornerShape(12.dp),
                        )
                        .clickable { state.showAbout = true }
                        .padding(horizontal = 10.dp, vertical = 4.dp),
                ) {
                    Text(
                        text = "关于",
                        fontSize = 10.sp,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                }
            }"""),
])

# ----------------------------------------------------------- MainActivity ----
# shell binder retry (error.txt: "清理失败: Stellar/Shizuku 均不可用")
patch(J, [
    ("    private Process shellProcess(String cmd) throws Exception {",
     """    private Process shellProcess(String cmd) throws Exception {
        Exception last = null;
        for (int attempt = 0; attempt < 5; attempt++) {
            try {
                return shellProcessOnce(cmd);
            } catch (IllegalStateException e) {
                String msg = String.valueOf(e.getMessage());
                if (!msg.contains("均不可用"))
                    throw e;
                last = e;
                try {
                    Thread.sleep(600);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        if (last != null)
            throw last;
        throw new IllegalStateException("Stellar/Shizuku 均不可用");
    }

    private Process shellProcessOnce(String cmd) throws Exception {"""),
])

# keep the in-memory run log for export fallback
patch(J, [
    ("    private volatile boolean runInProgress = false;",
     "    private volatile boolean runInProgress = false;\n    private volatile String lastRunLogText = \"\";"),
    ("""                ui.setStatus("提权完成");
                // Export the success log before cleaning the work directory so
                // the success page's 导出日志 button still has a source file.""",
     """                ui.setStatus("提权完成");
                // Keep the full run log in memory so 导出日志 still works after
                // the work directory has been cleaned.
                lastRunLogText = fullLog;
                // Export the success log before cleaning the work directory so
                // the success page's 导出日志 button still has a source file."""),
])

# real export implementation with explicit success/failure feedback
old_export = """    /** Success-page action: export the retained run log to Download/MagicRoot. */
    public void exportSuccessLog() {
        final String src = ui.getSuccessLogPath();
        new Thread(() -> {
            try {
                String dir = "/sdcard/Download/MagicRoot";
                String dst = dir + "/magicroot-success-" + System.currentTimeMillis() + ".log";
                String cmd = "mkdir -p " + dir + " && { "
                        + "if [ -f \\"" + src + "\\" ]; then cp \\"" + src + "\\" \\"" + dst + "\\"; "
                        + "elif [ -f " + WORK + "/run.log ]; then cp " + WORK + "/run.log \\"" + dst + "\\"; "
                        + "else echo NO_LOG > \\"" + dst + "\\"; fi; } "
                        + "2>/dev/null; chmod 644 \\"" + dst + "\\" 2>/dev/null; echo OK";
                String out = shell(cmd);
                log("成功日志已导出: " + dst + " " + (out == null ? "" : out.trim()));
                feedback("日志已导出", dst, 1);
            } catch (Throwable t) {
                feedback("导出失败", t.toString(), 2);
            }
        }).start();
    }"""
new_export = """    /**
     * Success-page action: export the retained run log to Download/MagicRoot
     * (same destination convention as the failure log) and report an explicit
     * success/failure message on the success page.
     */
    public void exportSuccessLog() {
        final String snap = ui.getSuccessLogPath();
        final String mem = lastRunLogText;
        ui.setExportResult("正在导出…", true);
        new Thread(() -> {
            String dir = "/sdcard/Download/MagicRoot";
            String dst = dir + "/magicroot-success-" + System.currentTimeMillis() + ".txt";
            String cachePath = "";
            String err = "";
            boolean ok = false;
            try {
                // fallback: persist the in-memory log into app files first
                if (mem != null && !mem.isEmpty()) {
                    File base = getExternalFilesDir(null);
                    if (base == null)
                        base = getFilesDir();
                    File cache = new File(base, "last-run.log");
                    try (FileOutputStream out = new FileOutputStream(cache)) {
                        out.write(mem.getBytes("UTF-8"));
                        out.flush();
                        out.getFD().sync();
                    }
                    cachePath = cache.getAbsolutePath();
                }
                String cmd = "mkdir -p " + dir + "; "
                        + "if [ -s '" + (snap == null ? "" : snap) + "' ]; then "
                        + "cp -f '" + (snap == null ? "" : snap) + "' '" + dst + "'; "
                        + "elif [ -s " + WORK + "/run.log ]; then cp -f " + WORK + "/run.log '" + dst + "'; "
                        + "elif [ -n '" + cachePath + "' ] && [ -s '" + cachePath + "' ]; then "
                        + "cp -f '" + cachePath + "' '" + dst + "'; "
                        + "else echo NO_LOG > '" + dst + "'; fi; "
                        + "chmod 644 '" + dst + "' 2>/dev/null; "
                        + "if [ -s '" + dst + "' ]; then "
                        + "echo \\"EXPORT_OK=$(wc -c < '" + dst + "')\\"; "
                        + "else echo EXPORT_FAIL; fi";
                String out = shell(cmd);
                if (out != null && out.contains("EXPORT_OK=")) {
                    ok = true;
                    String size = out.replaceAll("(?s).*EXPORT_OK=([0-9]+).*", "$1").trim();
                    final String msg = "日志已导出: " + dst + " (" + size + " B)";
                    log(msg);
                    runOnUiThread(() -> {
                        ui.setExportResult(msg, true);
                        feedback("日志已导出", dst, 1);
                    });
                } else {
                    err = (out == null ? "no shell output" : out.trim());
                }
            } catch (Throwable t) {
                err = t.toString();
            }
            if (!ok) {
                final String msg = "导出失败: " + (err.isEmpty() ? "日志文件为空或不可写" : err);
                log(msg);
                runOnUiThread(() -> {
                    ui.setExportResult(msg, false);
                    feedback("日志导出失败", msg, 2);
                });
            }
        }).start();
    }"""
patch(J, [(old_export, new_export)])

# clear export status when leaving the success page
patch(J, [
    ("""    public void returnHome() {
        ui.closeSuccess();
        ui.clearFeedback();
    }""",
     """    public void returnHome() {
        ui.closeSuccess();
        ui.setExportResult("", true);
        ui.clearFeedback();
    }"""),
])

# friendlier manager-extraction messages
patch(J, [
    ('return "no usable payload in " + pkg + " " + bundled;',
     'return "管理器里没有可用 ksud，使用内置兜底 " + bundled;'),
    ('return "manager-not-installed(" + pkg + ") " + bundled;',
     'return "管理器未安装（" + pkg + "），使用内置兜底 " + bundled;'),
    ('return "unavailable(" + pkg + ": " + t + ")";',
     'return "管理器未安装或签名不可读（" + pkg + "），root_stage 将回退 get-sign";'),
])

print("done")
