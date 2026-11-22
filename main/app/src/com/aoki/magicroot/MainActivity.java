package com.aoki.magicroot;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import moe.shizuku.server.IRemoteProcess;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.Shizuku;
import rikka.shizuku.ShizukuBinderWrapper;
import roro.stellar.Stellar;

public class MainActivity extends Activity {
    private static final int REQ_SHIZUKU = 1001;
    private static final int REQ_STELLAR = 1002;
    private static final String STELLAR_PKG = "roro.stellar.manager";
    private static final String WORK = "/data/local/tmp/magic";
    private static final String[] ASSETS = {
            "kaslr_slide_61258", "kaslr_slide_6138", "kaslr_slide_6123", "kaslr_slide_6138y", 
            "syms_61258.txt", "syms_6138.txt", "syms_6123.txt", "syms_6138y.txt", "kernel_profiles.sh", "ko_patch", "addrcalc",
            "syms_6138_next.txt", "syms_6123_next.txt", "syms_6138y_next.txt", "syms_6138_sukisu.txt", "syms_6123_sukisu.txt", "syms_6138y_sukisu.txt", "syms_6138_fina.txt", "syms_6123_fina.txt", "syms_6138y_fina.txt",
            "t64560_v36", "cred_target", "t64560_cred",
            "ksu_grant", "ksu-template.ko", "forker", "grab.sh", "grab_legacy.sh", "lib.sh", "run.sh", "root_stage.sh", "clean.sh", "pc98260-su", "libadbroot.so", "ksu-template-66118.ko", "ksu-template-66118-kernelsu.ko", "ksu-template-66118-next.ko", "ksu-template-66118-sukisu.ko", "ksu-template-66118-fina.ko", "ksu-template-66118-bakasu.ko",
             "su_entry.sh"
    };

    /**
     * CVE-2026-98260 experimental second-chain assets (Honor 6.12.58 / 6.12.38,
     * per-kernel directories; opt-in and requires explicit confirmation).
     * This legacy activity is a build-only fallback; the Compose activity is the
     * shipped UI.  Chain selection here is a minimal opt-in checkbox so the
     * fallback build can still exercise the 98260 chain if needed.
     */
    private static final String[] ASSETS_98260 = {
            "98260-g554/exploit-android-key-ptr", "98260-g554/syms_66118.txt", "98260-g554/syms_66118_next.txt", "98260-g554/syms_66118_sukisu.txt", "98260-g554/syms_66118_fina.txt", "98260-g554/syms_66118_bakasu.txt", "98260-g554/syms_66118_kernelsu.txt", "98260-g554/target.sh",
            "98260-f171/exploit-android-key-ptr", "98260-f171/syms_66118.txt", "98260-f171/syms_66118_next.txt", "98260-f171/syms_66118_sukisu.txt", "98260-f171/syms_66118_fina.txt", "98260-f171/syms_66118_bakasu.txt", "98260-f171/syms_66118_kernelsu.txt", "98260-f171/target.sh",
            "98260/exploit-android-perf", "98260/exploit-android-perf-chain",
            "98260/exploit-android-key-ptr", "98260/pc98260-su",
            "98260/run98260.sh", "98260/target.sh", "98260/SHA256SUMS.txt",
            "98260-6138/exploit-android-perf", "98260-6138/exploit-android-perf-chain",
            "98260-6138/exploit-android-key-ptr", "98260-6138/pc98260-su",
            "98260-6138/target.sh", "98260-6138/SHA256SUMS.txt",
            "98260-6123/exploit-android-perf", "98260-6123/exploit-android-perf-chain",
            "98260-6123/exploit-android-key-ptr", "98260-6123/pc98260-su",
            "98260-6123/run98260.sh", "98260-6123/target.sh", "98260-6123/SHA256SUMS.txt",
            "98260-6138y/exploit-android-perf", "98260-6138y/exploit-android-perf-chain",
            "98260-6138y/exploit-android-key-ptr", "98260-6138y/pc98260-su",
            "98260-6138y/run98260.sh", "98260-6138y/target.sh", "98260-6138y/SHA256SUMS.txt"
    };

    private TextView logView;
    private ScrollView scrollView;
    private Button runButton;
    private Button stageButton;
    private Button cleanButton;
    private Button grantButton;
    private CheckBox suOptional;
    private CheckBox chain98260Check;
    private CheckBox preflight98260Check;
    private CheckBox skipPreflightCheck;
    private Button flavorButton;
    private String ksuFlavor = "kernelsu";
    private static final String[] FLAVOR_KEYS = {"kernelsu", "resukisu", "next", "sukisu", "fina"};
    private static final String[] FLAVOR_LABELS = {"KernelSU", "BakaSU", "KernelSU-Next", "SukiSU", "FinaSU"};
    private CheckBox skipFsuidCheck;
    private SharedPreferences victimPrefs;
    private Button victimPermButton;
    private Button victimFsuidButton;
    private Button victimCredButton;
    private int victimPerm = 32;
    private int victimFsuid = 32;
    private int victimCred = 24;
    private volatile boolean runInProgress = false;
    private final AtomicBoolean actionBusy = new AtomicBoolean(false);
    private PowerManager.WakeLock wakeLock;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(Color.BLACK);
        getWindow().setNavigationBarColor(Color.BLACK);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.BLACK);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
            v.setPadding(bars.left + dp(4), bars.top + dp(4),
                    bars.right + dp(4), bars.bottom + dp(4));
            return insets;
        });

        Button grant = new Button(this);
        grant.setText("1. 授权 Stellar / Shizuku");
        grantButton = grant;
        Button stage = new Button(this);
        stage.setText("2. 部署资产");
        stageButton = stage;
        Button run = new Button(this);
        run.setText("3. 开始提权");
        runButton = run;
        Button clean = new Button(this);
        clean.setText("4. 清理临时文件");
        cleanButton = clean;
        styleButton(grant);
        styleButton(stage);
        styleButton(run);
        styleButton(clean);

        logView = new TextView(this);
        logView.setTextSize(12f);
        logView.setTextColor(0xFFD6E2F0);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextIsSelectable(true);
        logView.setPadding(dp(10), dp(10), dp(10), dp(10));
        logView.setBackgroundColor(Color.BLACK);

        scrollView = new ScrollView(this);
        scrollView.setBackgroundColor(Color.BLACK);
        scrollView.addView(logView);

        // 2×2 按钮网格，缩小按钮占用高度，给日志留更多空间。
        LinearLayout row1 = new LinearLayout(this);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        // The first label wraps to two lines. Baseline alignment would push
        // that button downward, so align both buttons by their top edge.
        row1.setBaselineAligned(false);
        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        row2.setBaselineAligned(false);
        row1.addView(grant, buttonParams(false));
        row1.addView(stage, buttonParams(true));
        row2.addView(run, buttonParams(false));
        row2.addView(clean, buttonParams(true));
        root.addView(row1, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(row2, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // 三档 victim 控制：SELinux / fsuid 可选 16/24/32，cred 可选 8/12/16/24。
        // 默认 32 / 32 / 24；点击按钮循环切换并持久化。
        victimPrefs = getSharedPreferences("magicroot_victims", MODE_PRIVATE);
        victimPerm = validVictim(victimPrefs.getInt("permissive", 32), 32);
        victimFsuid = validVictim(victimPrefs.getInt("fsuid", 32), 32);
        victimCred = validCredVictim(victimPrefs.getInt("cred_24", 24), 24);

        TextView victimLabel = new TextView(this);
        victimLabel.setText("Victim 档位（SELinux/fsuid: 16/24/32，cred: 8/12/16/24/32）");
        victimLabel.setTextColor(0xFF9FB3C8);
        victimLabel.setTextSize(11f);
        LinearLayout.LayoutParams victimLabelLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        victimLabelLp.setMargins(dp(8), dp(6), dp(8), dp(2));
        root.addView(victimLabel, victimLabelLp);

        LinearLayout victimRow = new LinearLayout(this);
        victimRow.setOrientation(LinearLayout.HORIZONTAL);
        victimRow.setBaselineAligned(false);
        victimPermButton = makeVictimButton("SELinux", victimPerm);
        victimFsuidButton = makeVictimButton("fsuid", victimFsuid);
        victimCredButton = makeVictimButton("cred", victimCred);
        victimRow.addView(victimPermButton, victimButtonParams(0));
        victimRow.addView(victimFsuidButton, victimButtonParams(1));
        victimRow.addView(victimCredButton, victimButtonParams(2));
        root.addView(victimRow, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        victimPermButton.setOnClickListener(v -> {
            victimPerm = cycleVictim(victimPerm);
            victimPermButton.setText("SELinux " + victimPerm);
            victimPrefs.edit().putInt("permissive", victimPerm).apply();
        });
        victimFsuidButton.setOnClickListener(v -> {
            victimFsuid = cycleVictim(victimFsuid);
            victimFsuidButton.setText("fsuid " + victimFsuid);
            victimPrefs.edit().putInt("fsuid", victimFsuid).apply();
        });
        victimCredButton.setOnClickListener(v -> {
            victimCred = cycleCredVictim(victimCred);
            victimCredButton.setText("cred " + victimCred);
            victimPrefs.edit().putInt("cred", victimCred).apply();
        });

        // 可选项：默认关闭，不改变 KernelSU 的 su_compat 状态。
        final SharedPreferences suPrefs = getSharedPreferences("magicroot_su", MODE_PRIVATE);
        suOptional = new CheckBox(this);
        suOptional.setText("可选：su_compat + su 搜索入口（默认关）");
        suOptional.setTextColor(0xFFD6E2F0);
        suOptional.setTextSize(12f);
        suOptional.setButtonTintList(ColorStateList.valueOf(0xFF4FC3F7));
        suOptional.setChecked(suPrefs.getBoolean("enabled", false));
        suOptional.setOnCheckedChangeListener((buttonView, isChecked) ->
                suPrefs.edit().putBoolean("enabled", isChecked).apply());
        LinearLayout.LayoutParams suLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        suLp.setMargins(dp(8), 0, dp(8), dp(2));
        root.addView(suOptional, suLp);

        // 98260 为默认链路；不再要求二次确认。
        final SharedPreferences chainPrefs = getSharedPreferences("magicroot_chain", MODE_PRIVATE);
        chain98260Check = new CheckBox(this);
        chain98260Check.setText("98260（默认，6.12.x 已验证 / 6.6.118 g554/f171 profile）");
        chain98260Check.setTextColor(0xFFD6E2F0);
        chain98260Check.setTextSize(12f);
        chain98260Check.setButtonTintList(ColorStateList.valueOf(0xFFFF8A65));
        chain98260Check.setChecked("98260".equals(chainPrefs.getString("chain", "98260")));
        chain98260Check.setOnCheckedChangeListener((buttonView, isChecked) ->
                chainPrefs.edit()
                        .putString("chain", isChecked ? "98260" : "64560")
                        .putBoolean("ack_98260", true)
                        .apply());
        LinearLayout.LayoutParams chainLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        chainLp.setMargins(dp(8), 0, dp(8), 0);
        root.addView(chain98260Check, chainLp);

        preflight98260Check = new CheckBox(this);
        preflight98260Check.setText("98260 预检模式（只读，不执行提权；建议先跑）");
        preflight98260Check.setTextColor(0xFFD6E2F0);
        preflight98260Check.setTextSize(12f);
        preflight98260Check.setButtonTintList(ColorStateList.valueOf(0xFF4FC3F7));
        preflight98260Check.setChecked(chainPrefs.getBoolean("preflight_98260", false));
        preflight98260Check.setOnCheckedChangeListener((buttonView, isChecked) ->
                chainPrefs.edit().putBoolean("preflight_98260", isChecked).apply());
        LinearLayout.LayoutParams preflightLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        preflightLp.setMargins(dp(8), 0, dp(8), dp(2));
        root.addView(preflight98260Check, preflightLp);

        final SharedPreferences skipPreflightPrefs = getSharedPreferences("magicroot_preflight_skip", MODE_PRIVATE);
        skipPreflightCheck = new CheckBox(this);
        skipPreflightCheck.setText("跳过 PREFLIGHT（默认关 · 显式跳过开机稳定等待，不推荐）");
        skipPreflightCheck.setTextColor(0xFFD6E2F0);
        skipPreflightCheck.setTextSize(12f);
        skipPreflightCheck.setButtonTintList(ColorStateList.valueOf(0xFFE57373));
        skipPreflightCheck.setChecked(skipPreflightPrefs.getBoolean("enabled", false));
        skipPreflightCheck.setOnCheckedChangeListener((buttonView, isChecked) ->
                skipPreflightPrefs.edit().putBoolean("enabled", isChecked).apply());
        LinearLayout.LayoutParams skipPreflightLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        skipPreflightLp.setMargins(dp(8), 0, dp(8), dp(2));
        root.addView(skipPreflightCheck, skipPreflightLp);

        final SharedPreferences backendPrefs = getSharedPreferences("magicroot_backend", MODE_PRIVATE);
        ksuFlavor = normalizeFlavor(backendPrefs.getString("flavor", "kernelsu"));
        flavorButton = new Button(this);
        flavorButton.setTextSize(12f);
        flavorButton.setTextColor(0xFFD6E2F0);
        flavorButton.setAllCaps(false);
        updateFlavorButton();
        flavorButton.setOnClickListener(v -> {
            int idx = 0;
            for (int i = 0; i < FLAVOR_KEYS.length; i++) {
                if (FLAVOR_KEYS[i].equals(ksuFlavor)) { idx = i; break; }
            }
            ksuFlavor = FLAVOR_KEYS[(idx + 1) % FLAVOR_KEYS.length];
            backendPrefs.edit().putString("flavor", ksuFlavor).apply();
            updateFlavorButton();
        });
        LinearLayout.LayoutParams flavorLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        flavorLp.setMargins(dp(8), 0, dp(8), dp(2));
        root.addView(flavorButton, flavorLp);
        updateVictimControlsEnabled();

        root.addView(scrollView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);
        // getWindow().getInsetsController() 在部分 Android 17 上 DecorView 尚未建立会 NPE。
        // 必须在 setContentView 之后通过 DecorView 获取，并保留 null 保护。
        WindowInsetsController controller = getWindow().getDecorView().getWindowInsetsController();
        if (controller != null) {
            controller.setSystemBarsAppearance(0,
                    WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                            | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS);
        }
        if (savedInstanceState != null) {
            CharSequence saved = savedInstanceState.getCharSequence("log", "");
            if (saved != null && saved.length() > 0)
                logView.setText(saved);
        }

        Shizuku.addRequestPermissionResultListener((request, result) -> {
            log("Shizuku permission result=" + result);
        });

        grant.setOnClickListener(v -> {
            if (!beginAction())
                return;
            try {
                if (isPackageInstalled(STELLAR_PKG)) {
                    try {
                        if (!Stellar.INSTANCE.pingBinder()) {
                            Intent i = getPackageManager().getLaunchIntentForPackage(STELLAR_PKG);
                            if (i != null)
                                startActivity(i);
                            log("Stellar 未连接：请先启动 Stellar 并完成 ADB 授权");
                        } else if (Stellar.INSTANCE.checkSelfPermission("stellar")) {
                            log("Stellar 已授权，uid=" + Stellar.INSTANCE.getUid());
                            return;
                        } else {
                            Stellar.INSTANCE.requestPermission("stellar", REQ_STELLAR);
                            log("已请求 Stellar 授权，请在 Stellar 弹窗允许后重试");
                            return;
                        }
                    } catch (Throwable t) {
                        log("Stellar 授权检查失败: " + t);
                    }
                }
                if (!Shizuku.pingBinder()) {
                    log("Stellar/Shizuku 均未运行：先启动 Stellar 或 Shizuku");
                    return;
                }
                if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                    log("Shizuku 已授权");
                } else {
                    Shizuku.requestPermission(REQ_SHIZUKU);
                }
            } finally {
                endAction();
            }
        });

        stage.setOnClickListener(v -> {
            if (!beginAction())
                return;
            new Thread(() -> {
                try {
                    log("部署资产到 " + WORK + " ...");
                    ensureWorkDirWritable();
                    boolean chain98260 = chain98260Check != null && chain98260Check.isChecked();
                    for (String name : ASSETS) {
                        stageAsset(name);
                        log("  ok " + name);
                    }
                    if (chain98260) {
                        for (String name : ASSETS_98260) {
                            int slash = name.indexOf('/');
                            if (slash <= 0) {
                                throw new java.io.IOException("unexpected_asset_path: " + name);
                            }
                            String dir = name.substring(0, slash);
                            if (!dir.startsWith("98260")) {
                                throw new java.io.IOException("unexpected_asset_dir: " + dir);
                            }
                            ensureStageDirWritable(WORK + "/" + dir);
                            stageAssetAs(name, name.substring(slash + 1), WORK + "/" + dir);
                            log("  ok " + name);
                        }
                    }
                    log("部署完成 chain=" + (chain98260 ? "98260" : "64560"));
                } catch (Throwable t) {
                    log("部署失败: " + t);
                } finally {
                    endAction();
                }
            }).start();
        });

        run.setOnClickListener(v -> startRun());
        clean.setOnClickListener(v -> {
            if (!beginAction())
                return;
            new Thread(() -> {
                try {
                    log("清理中...");
                    String cmd = "if [ -f " + WORK + "/clean.sh ]; then sh " + WORK + "/clean.sh; "
                            + "else rm -rf " + WORK
                            + " /data/local/tmp/honor /data/local/tmp/root_stage.sh"
                            + " /data/local/tmp/.magicroot-exec /data/local/tmp/bl_*.bin"
                            + " /data/local/tmp/bl_text.txt /storage/emulated/0/Download/MagicRoot"
                            + " /storage/emulated/0/Android/data/com.aoki.magicroot/files/stage"
                            + " /data/local/tmp/ksu-patched.ko /data/local/tmp/ksu.ko"
                            + " /data/local/tmp/self.ready /data/local/tmp/self.cred"
                            + " /data/local/tmp/KSU_RESULT /data/local/tmp/ROOTED"
                            + " /data/local/tmp/CMD /data/local/tmp/CMD.run"
                            + " /data/local/tmp/NOLOAD /data/local/tmp/DOLOAD"
                            + " /data/local/tmp/rsh.out /data/local/tmp/cand_*.pid; "
                            + "echo CLEAN_OK; fi";
                    log(shell(cmd));
                    clearStageCache();
                } catch (Throwable t) {
                    log("清理失败: " + t);
                } finally {
                    endAction();
                }
            }).start();
        });
        startLogPoller();
    }

    private static String normalizeFlavor(String flavor) {
        if (flavor == null) return "kernelsu";
        if ("official".equals(flavor) || "bakasu".equals(flavor)) return "resukisu";
        for (String f : FLAVOR_KEYS) {
            if (f.equals(flavor)) return f;
        }
        return "kernelsu";
    }

    private void updateFlavorButton() {
        if (flavorButton == null) return;
        String label = "KernelSU";
        for (int i = 0; i < FLAVOR_KEYS.length; i++) {
            if (FLAVOR_KEYS[i].equals(ksuFlavor)) { label = FLAVOR_LABELS[i]; break; }
        }
        flavorButton.setText("KernelSU 后端: " + label + "（点击切换）");
    }

    private void setControlsEnabled(boolean enabled) {
        if (grantButton != null) grantButton.setEnabled(enabled);
        if (runButton != null) runButton.setEnabled(enabled);
        if (stageButton != null) stageButton.setEnabled(enabled);
        if (cleanButton != null) cleanButton.setEnabled(enabled);
        if (skipFsuidCheck != null) skipFsuidCheck.setEnabled(enabled);
        if (chain98260Check != null) chain98260Check.setEnabled(enabled);
        if (preflight98260Check != null) {
            boolean chain = chain98260Check != null && chain98260Check.isChecked();
            preflight98260Check.setEnabled(enabled && chain);
        }
        updateVictimControlsEnabled();
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private void styleButton(Button button) {
        button.setTextColor(Color.WHITE);
        button.setBackgroundTintList(ColorStateList.valueOf(0xFF20242B));
        button.setAllCaps(false);
    }

    private LinearLayout.LayoutParams buttonParams(boolean rightColumn) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                0, dp(52), 1f);
        // Symmetric outer margins and an 8dp centre gutter keep both columns
        // aligned with the 8dp checkbox gutter on every row.
        int left = rightColumn ? dp(4) : dp(8);
        int right = rightColumn ? dp(8) : dp(4);
        lp.setMargins(left, dp(4), right, dp(4));
        return lp;
    }

    private Button makeVictimButton(String label, int value) {
        Button b = new Button(this);
        b.setText(label + " " + value);
        b.setTextSize(12f);
        b.setSingleLine(true);
        b.setMinHeight(0);
        b.setMinimumHeight(0);
        b.setPadding(dp(2), 0, dp(2), 0);
        styleButton(b);
        return b;
    }

    private LinearLayout.LayoutParams victimButtonParams(int index) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                0, dp(40), 1f);
        int left = index == 0 ? dp(8) : dp(2);
        int right = index == 2 ? dp(8) : dp(2);
        lp.setMargins(left, dp(2), right, dp(2));
        return lp;
    }

    private int cycleVictim(int value) {
        if (value == 16) return 24;
        if (value == 24) return 32;
        return 16;
    }

    private int validVictim(int value, int fallback) {
        return (value == 16 || value == 24 || value == 32) ? value : fallback;
    }

    private int cycleCredVictim(int value) {
        if (value == 8) return 12;
        if (value == 12) return 16;
        if (value == 16) return 24;
        if (value == 24) return 32;
        return 8;
    }

    private int validCredVictim(int value, int fallback) {
        return (value == 8 || value == 12 || value == 16 || value == 24 || value == 32) ? value : fallback;
    }

    private void updateVictimControlsEnabled() {
        boolean busy = runInProgress || actionBusy.get();
        boolean chain98260 = chain98260Check != null && chain98260Check.isChecked();
        boolean enabled = !busy && !chain98260;
        if (victimPermButton != null) victimPermButton.setEnabled(enabled);
        boolean skipFsuid = skipFsuidCheck != null && skipFsuidCheck.isChecked();
        if (victimFsuidButton != null) victimFsuidButton.setEnabled(enabled && !skipFsuid);
        if (victimCredButton != null) victimCredButton.setEnabled(enabled);
        if (victimFsuidButton != null)
            victimFsuidButton.setAlpha(skipFsuid ? 0.45f : 1f);
        if (skipFsuidCheck != null) skipFsuidCheck.setEnabled(!busy && !chain98260);
        if (flavorButton != null) flavorButton.setEnabled(!busy);
        if (preflight98260Check != null) {
            preflight98260Check.setEnabled(!busy && chain98260);
            preflight98260Check.setAlpha(chain98260 ? 1f : 0.45f);
        }
        if (skipPreflightCheck != null) skipPreflightCheck.setEnabled(!busy);
        if (chain98260Check != null) chain98260Check.setEnabled(!busy);
    }

    private boolean beginAction() {
        if (!actionBusy.compareAndSet(false, true)) {
            return false;
        }
        runOnUiThread(() -> {
            if (!isDestroyed())
                setControlsEnabled(false);
        });
        return true;
    }

    private void endAction() {
        actionBusy.set(false);
        runOnUiThread(() -> {
            if (!isDestroyed())
                setControlsEnabled(true);
        });
    }

    private void startRun() {
        if (!beginAction())
            return;
        runInProgress = true;
        final boolean skipFsuid = skipFsuidCheck != null && skipFsuidCheck.isChecked();
        final SharedPreferences chainPrefs = getSharedPreferences("magicroot_chain", MODE_PRIVATE);
        final boolean chain98260 = "98260".equals(chainPrefs.getString("chain", "98260"));
        final boolean preflight98260 = chain98260 && chainPrefs.getBoolean("preflight_98260", false);
        final boolean skipPreflight = getSharedPreferences("magicroot_preflight_skip", MODE_PRIVATE)
                .getBoolean("enabled", false);
        final int vPerm = victimPerm;
        final int vFsuid = victimFsuid;
        final int vCred = victimCred;
        log("提权任务已启动：部署/开始/清理按钮已禁用，等待 DONE / FAIL 标志...");
        log("链路: " + (chain98260 ? "98260（默认 · 6.12.x 已验证 / 6.6.118 g554/f171 profile · rootd 后端）" : "64560"));
        log("victims: SELinux=" + vPerm + " fsuid=" + vFsuid + " cred=" + vCred);
        log("fsuid 阶段: " + (skipFsuid ? "跳过（实验）" : "执行"));
                if (preflight98260) log("98260 预检模式：只读，不执行提权阶段");
        if (skipPreflight) log("PREFLIGHT_SKIP=1（显式开关）: 跳过开机稳定等待");
        new Thread(() -> runChain(skipFsuid, vPerm, vFsuid, vCred, chain98260, preflight98260, skipPreflight)).start();
    }

    /** 返回 1=DONE，2=FAIL=，0=未完成；只认行首，避免 PHASE2_DONE / LAYOUT_DONE 误判。 */
    private int finishKind(String tail) {
        for (String line : tail.split("\n")) {
            String s = line.trim();
            if (s.equals("DONE"))
                return 1;
            if (s.startsWith("FAIL="))
                return 2;
        }
        return 0;
    }

    private void runChain(boolean skipFsuid, int vPerm, int vFsuid, int vCred,
                          boolean chain98260, boolean preflight98260, boolean skipPreflight) {
        try {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "magic9:root");
            wakeLock.acquire(2 * 60 * 60 * 1000L);
            String check = shell("test -f " + WORK + "/run.sh && echo OK || echo MISSING");
            if (!check.contains("OK")) {
                log("工作目录已在上次成功后清理，请先点「2. 部署资产」");
                return;
            }
                        if (skipPreflight)
                shell("touch " + WORK + "/skip-preflight");
            else
                shell("rm -f " + WORK + "/skip-preflight");
            shell("rm -f " + WORK + "/run.log");
            log("开始执行 run.sh（日志同时写入 " + WORK + "/run.log）...");
            final SharedPreferences rt60 = getSharedPreferences("magicroot_98260_runtime", MODE_PRIVATE);
            final int rt60Attempts = rt60.getInt("attempts", 12);
            final int rt60Rounds = rt60.getInt("churn_rounds", 8);
            final int rt60PerCpu = rt60.getInt("churn_per_cpu", 32);
            final int rt60Wait = rt60.getInt("wait_cap", 8);
            final boolean rt60CustomEnabled = rt60.getBoolean("custom_ko_enabled", false);
            final String rt60CustomPath = rt60.getString("custom_ko_path", "");
            String env = "MAGICROOT_VICTIMS_PERMISSIVE=" + vPerm
                    + " MAGICROOT_VICTIMS_FSUID=" + vFsuid
                    + " MAGICROOT_VICTIMS_CRED=" + vCred
                    + " MAGICROOT_KSU_FLAVOR=" + ksuFlavor
                    + " MAGICROOT_CHAIN=" + (chain98260 ? "98260" : "64560")
                    + " MAGICROOT_ENABLE_98260=" + (chain98260 ? "1" : "0")
                    + " MAGICROOT_98260_PREFLIGHT=" + (preflight98260 ? "1" : "0")
                    + " MAGICROOT_98260_KSU=1 "
                    + " MAGICROOT_98260_ATTEMPTS=" + rt60Attempts
                    + " MAGICROOT_98260_CHURN_ROUNDS=" + rt60Rounds
                    + " MAGICROOT_98260_CHURN_PER_CPU=" + rt60PerCpu
                    + " MAGICROOT_98260_WAIT_CAP=" + rt60Wait
                    + " MAGICROOT_98260_CUSTOM_KO=" + (rt60CustomEnabled ? rt60CustomPath : "")
                    + " MAGICROOT_CUSTOM_KO=" + (rt60CustomEnabled ? rt60CustomPath : "")
                    + " MAGICROOT_SKIP_PREFLIGHT=" + (skipPreflight ? "1" : "0");

            Process p = shellProcess("cd " + WORK + " && " + env
                    + "sh run.sh 2>&1 | tee -a " + WORK + "/run.log");

            final AtomicBoolean exited = new AtomicBoolean(false);
            Thread waiter = new Thread(() -> {
                try {
                    p.waitFor();
                } catch (Throwable ignored) {
                }
                exited.set(true);
            });
            waiter.setDaemon(true);
            waiter.start();

            boolean success = false;
            while (!exited.get()) {
                String tail = "";
                try {
                    tail = shell("tail -n 10 " + WORK + "/run.log 2>/dev/null");
                } catch (Throwable ignored) {
                }
                int kind = finishKind(tail);
                if (kind != 0) {
                    success = (kind == 1);
                    log(success ? "检测到 DONE，提权流程完成" : "检测到 FAIL，保留现场日志");
                    break;
                }
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    break;
                }
            }
            log("run.sh 已退出");

            // 进程可能在 watcher 两次读取之间就退出；再补读一次日志确认 DONE。
            if (!success) {
                try {
                    String tail = shell("tail -n 50 " + WORK + "/run.log 2>/dev/null");
                    success = (finishKind(tail) == 1);
                    if (success)
                        log("检测到 DONE（进程已退出），准备清理");
                } catch (Throwable ignored) {
                }
            }

            if (preflight98260) {
                // Read-only 98260 preflight; never show the root success page.
                String tailAll = shell("tail -n 400 " + WORK + "/run.log 2>/dev/null");
                if (tailAll != null && tailAll.contains("CHAIN_98260_PREFLIGHT_OK=1")) {
                    log("98260 预检通过（只读，未执行任何提权阶段）");
                } else {
                    log("98260 预检未通过（详见日志 PREFLIGHT_OK=0）");
                }
                return;
            }
            if (success) {
                try {
                    p.waitFor(5, TimeUnit.SECONDS);
                } catch (Throwable ignored) {
                }
                if (chain98260) {
                    log("98260 链成功：请查看内核后端状态与 rootd 日志");
                    log("清理按钮仅移除临时文件与失败日志");
                } else {
                    log("开始清理工作目录...");
                    shell("rm -rf " + WORK +
                            " /data/local/tmp/.magicroot-exec" +
                            " /data/local/tmp/honor" +
                            " /data/local/tmp/root_stage.sh" +
                            " /data/local/tmp/bl_*.bin" +
                            " /data/local/tmp/bl_text.txt" +
                            " /storage/emulated/0/Download/MagicRoot");
                    log("提权完成，工作目录已清理（下次运行请重新部署资产）");
                }
            }
        } catch (Throwable t) {
            log("执行失败: " + t);
        } finally {
            runInProgress = false;
            endAction();
            if (wakeLock != null && wakeLock.isHeld())
                wakeLock.release();
        }
    }

    /** Activity 被重建时也能从 run.log 恢复显示；tee 写在 Shizuku 侧，App 被杀也不影响链路。 */
    private void startLogPoller() {
        Thread t = new Thread(() -> {
            String last = "";
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    String text = shell("tail -n 400 " + WORK + "/run.log 2>/dev/null");
                    if (!text.isEmpty() && !text.equals(last)) {
                        last = text;
                        String finalText = text;
                        runOnUiThread(() -> {
                            if (!isDestroyed()) {
                                logView.setText(finalText);
                                scrollToBottom();
                            }
                        });
                    }
                } catch (Throwable ignored) {
                }
                try { Thread.sleep(2000); } catch (InterruptedException e) { return; }
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private static void deleteTree(File f) {
        if (f == null || !f.exists())
            return;
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) {
                for (File child : children)
                    deleteTree(child);
            }
        }
        f.delete();
    }

    private void ensureWorkDirWritable() throws Exception {
        String state = shellNoThrow("test -w '" + WORK + "' && echo WRITABLE || echo READONLY");
        if (state != null && state.contains("WRITABLE")) {
            return;
        }
        String stamp = String.valueOf(System.currentTimeMillis());
        String oldDir = WORK + ".old." + stamp;
        log("WORKDIR_READONLY=1 rotate=" + oldDir);
        shellNoThrow("mv '" + WORK + "' '" + oldDir + "' 2>/dev/null || rm -rf '" + WORK + "' 2>/dev/null; "
                + "mkdir -p '" + WORK + "'; chmod 771 '" + WORK + "'");
        String state2 = shellNoThrow("test -w '" + WORK + "' && echo WRITABLE || echo READONLY");
        if (state2 == null || !state2.contains("WRITABLE")) {
            throw new java.io.IOException("workdir_readonly: " + WORK);
        }
    }

    private void ensureStageDirWritable(String dir) throws Exception {
        String state = shellNoThrow("if [ -d '" + dir + "' ] && [ ! -w '" + dir
                + "' ]; then echo READONLY; else echo WRITABLE; fi");
        if (state != null && state.contains("WRITABLE")) {
            return;
        }
        String stamp = String.valueOf(System.currentTimeMillis());
        String oldDir = dir + ".old." + stamp;
        log("STAGE_DIR_READONLY=1 dir=" + dir + " rotate=" + oldDir);
        shellNoThrow("mv '" + dir + "' '" + oldDir + "' 2>/dev/null || rm -rf '" + dir
                + "' 2>/dev/null; mkdir -p '" + dir + "'; chmod 771 '" + dir + "'");
        String state2 = shellNoThrow("if [ -d '" + dir + "' ] && [ ! -w '" + dir
                + "' ]; then echo READONLY; else echo WRITABLE; fi");
        if (state2 == null || !state2.contains("WRITABLE")) {
            throw new java.io.IOException("stage_dir_readonly: " + dir);
        }
    }

    private void clearStageCache() {
        try {
            File external = getExternalFilesDir(null);
            if (external != null)
                deleteTree(new File(external, "stage"));
            deleteTree(new File(getFilesDir(), "stage"));
        } catch (Throwable ignored) {
        }
    }

    private void stageAsset(String name) throws Exception {
        stageAssetAs(name, name, WORK);
    }

    private void stageAsset(String name, String targetDir) throws Exception {
        stageAssetAs(name, name, targetDir);
    }

    /** Stage assetName from the APK as destName inside targetDir (subdir-safe). */
    private void stageAssetAs(String assetName, String destName, String targetDir) throws Exception {
        String destPath = targetDir + "/" + destName;
        String tmpPath = destPath + ".new";
        shellNoThrow("rm -f '" + tmpPath + "' '" + destPath + "' 2>/dev/null || true");
        shell("mkdir -p '" + targetDir + "'");

        File baseDir = getExternalFilesDir(null);
        if (baseDir == null) {
            baseDir = getFilesDir();
        }
        File stageDir = new File(baseDir, "stage");
        if (!stageDir.exists()) {
            stageDir.mkdirs();
        }
        if (!stageDir.isDirectory() || !stageDir.canWrite()) {
            // A root adb shell can chown the external stage dir.  Fall back to
            // the app-private files dir so redeploy never depends on root fs
            // ownership.
            stageDir = new File(getFilesDir(), "stage");
            stageDir.mkdirs();
        }
        stageDir.setReadable(true, false);
        stageDir.setWritable(true, false);
        stageDir.setExecutable(true, false);

        File localFile = new File(stageDir, destName.replace('/', '_') + ".stage");
        try (InputStream in = getAssets().open(assetName);
             FileOutputStream out = new FileOutputStream(localFile)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            out.flush();
            out.getFD().sync();
        }
        localFile.setReadable(true, false);
        localFile.setWritable(true, false);
        localFile.setExecutable(true, false);

        // Write to a sibling .new file and rename atomically, so a failed or
        // interrupted copy never leaves a truncated executable in WORK.
        String localPath = localFile.getAbsolutePath();
        shell("mkdir -p '" + targetDir + "' && cp -f '" + localPath + "' '" + tmpPath
                + "' && chmod 755 '" + tmpPath
                + "' && mv -f '" + tmpPath + "' '" + destPath + "'");
        try {
            localFile.delete();
        } catch (Throwable ignored) {
        }

        String check = shellNoThrow("test -f '" + destPath + "' && echo OK || echo FAIL");
        if (check == null || !check.contains("OK")) {
            throw new IllegalStateException(assetName + " staging verify failed (" + destPath + ")");
        }
    }

    private String shell(String cmd) throws Exception {
        Process p = shellProcess(cmd);
        StringBuilder sb = new StringBuilder();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
        String line;
        while ((line = r.readLine()) != null)
            sb.append(line).append('\n');
        p.waitFor();
        return sb.toString();
    }

    private String shellNoThrow(String cmd) {
        try {
            return shell(cmd);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private Process shellProcess(String cmd) throws Exception {
        if (isPackageInstalled(STELLAR_PKG)) {
            try {
                if (Stellar.INSTANCE.pingBinder()) {
                    if (!Stellar.INSTANCE.checkSelfPermission("stellar")) {
                        runOnUiThread(() -> Stellar.INSTANCE.requestPermission("stellar", REQ_STELLAR));
                        throw new IllegalStateException("Stellar 未授权");
                    }
                    Process p = Stellar.INSTANCE.newProcess(
                            new String[]{"sh", "-c", cmd},
                            new String[]{"PATH=/system/bin:/system/xbin:/data/adb/ksu/bin",
                                    "HOME=/data/local/tmp", "TMPDIR=/data/local/tmp"},
                            "/data/local/tmp");
                    if (p != null)
                        return p;
                }
            } catch (Throwable t) {
                log("Stellar shell 不可用，尝试 Shizuku: " + t);
            }
        }

        IBinder binder = Shizuku.getBinder();
        if (binder == null || !binder.pingBinder())
            throw new IllegalStateException("Stellar/Shizuku 均不可用");
        IShizukuService service = IShizukuService.Stub.asInterface(new ShizukuBinderWrapper(binder));
        IRemoteProcess remote = service.newProcess(
                new String[]{"sh", "-c", cmd},
                new String[]{"PATH=/system/bin:/system/xbin:/data/adb/ksu/bin",
                        "HOME=/data/local/tmp", "TMPDIR=/data/local/tmp"},
                "/data/local/tmp");
        if (remote == null)
            throw new IllegalStateException("Shizuku 拒绝启动 shell");
        return new RemoteProcess(remote);
    }

    private boolean isPackageInstalled(String pkg) {
        try {
            getPackageManager().getPackageInfo(pkg, 0);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private void log(String s) {
        runOnUiThread(() -> {
            logView.append(s + "\n");
            scrollToBottom();
        });
    }

    private void scrollToBottom() {
        if (scrollView != null) {
            scrollView.post(() -> scrollView.fullScroll(ScrollView.FOCUS_DOWN));
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        CharSequence text = logView.getText();
        if (text.length() > 20000)
            text = text.subSequence(text.length() - 20000, text.length());
        outState.putCharSequence("log", text);
    }

    private static final class RemoteProcess extends Process {
        private final IRemoteProcess remote;
        private OutputStream stdin;
        private InputStream stdout;
        private Integer exitCode;

        RemoteProcess(IRemoteProcess remote) { this.remote = remote; }

        @Override public synchronized OutputStream getOutputStream() {
            if (stdin == null) {
                try {
                    stdin = new ParcelFileDescriptor.AutoCloseOutputStream(remote.getOutputStream());
                } catch (Throwable t) { throw new RuntimeException("stdin", t); }
            }
            return stdin;
        }

        @Override public synchronized InputStream getInputStream() {
            if (stdout == null) {
                try {
                    stdout = new ParcelFileDescriptor.AutoCloseInputStream(remote.getInputStream());
                } catch (Throwable t) { throw new RuntimeException("stdout", t); }
            }
            return stdout;
        }

        @Override public synchronized InputStream getErrorStream() {
            try {
                return new ParcelFileDescriptor.AutoCloseInputStream(remote.getErrorStream());
            } catch (Throwable t) { throw new RuntimeException("stderr", t); }
        }

        @Override public synchronized int waitFor() throws InterruptedException {
            try {
                exitCode = remote.waitFor();
                return exitCode;
            } catch (Throwable t) { throw new RuntimeException("waitFor", t); }
        }

        @Override public synchronized boolean waitFor(long timeout, TimeUnit unit)
                throws InterruptedException {
            try {
                boolean exited = remote.waitForTimeout(timeout, unit.toString());
                if (exited) exitCode = remote.exitValue();
                return exited;
            } catch (Throwable t) { throw new RuntimeException("waitForTimeout", t); }
        }

        @Override public synchronized int exitValue() {
            try {
                if (exitCode == null) exitCode = remote.exitValue();
                return exitCode;
            } catch (Throwable t) { throw new RuntimeException("exitValue", t); }
        }

        @Override public void destroy() {
            try { remote.destroy(); } catch (Throwable ignored) { }
        }
    }
}
