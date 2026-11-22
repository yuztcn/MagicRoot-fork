package com.aoki.magicroot;

import android.content.Context;
import android.database.Cursor;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;

import androidx.activity.ComponentActivity;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import android.os.Build;
import android.widget.Toast;
import java.io.FileInputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import java.util.LinkedHashSet;
import java.io.BufferedOutputStream;
import java.util.zip.ZipFile;

import moe.shizuku.server.IRemoteProcess;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.Shizuku;

/**
 * Controller-only activity. All layout is Compose/Miuix in MiuixHost.kt.
 * The shell/Shizuku code is kept in Java to preserve the tested chain.
 */
public class MainActivity extends ComponentActivity {
    private static final int REQ_SHIZUKU = 1001;
    private static final String WORK = "/data/local/tmp/magic";
    private static final String SUSFS_RELEASE_API =
            "https://api.github.com/repos/inforcqb/susfs4ksu-lkm/releases/latest";
    private static final String SUSFS_UPDATED_WORK_NAME = "susfs_guard_lkm.updated.ko";
    private static final long SUSFS_MAX_DOWNLOAD = 32L * 1024L * 1024L;
    private final AtomicBoolean susfsUpdateRunning = new AtomicBoolean(false);
    private final AtomicBoolean managerKoCheckRunning = new AtomicBoolean(false);
    private final AtomicBoolean deviceStatusRefreshing = new AtomicBoolean(false);
    private static final String[] ASSETS = {
            "kaslr_slide_61258", "kaslr_slide_61258b", "kaslr_slide_6138", "kaslr_slide_6123", "kaslr_slide_6138y",
            "kaslr_slide_aph112", "kaslr_slide_aph136g142",
            "kaslr-98937/poc98937", "kaslr-98937/slide98937",
            "kaslr-98937/run98937.sh", "kaslr-98937/targets.conf",
            "kaslr-98937/README.md", "kaslr-98937/slide98937.c",
            "98260-g142/syms_g142_kernelsu.txt", "98260-g142/syms_g142_bakasu.txt",
            "98260-g142/syms_g142_fina.txt", "98260-g142/syms_g142_next.txt",
            "98260-g142/syms_g142_sukisu.txt", "98260-g142/syms_g142_nova.txt",
            "syms_61258.txt", "syms_6138.txt", "syms_6123.txt", "syms_6138y.txt", "syms_aph112.txt",
            "syms_g856.txt", "syms_g856_bakasu.txt", "syms_g856_next.txt", "syms_g856_sukisu.txt", "syms_g856_fina.txt",
            "syms_61258_bakasu.txt", "syms_6138_bakasu.txt", "syms_6123_bakasu.txt", "syms_6138y_bakasu.txt",
            "syms_6138_next.txt", "syms_6123_next.txt", "syms_6138y_next.txt", "syms_6138_sukisu.txt", "syms_6123_sukisu.txt", "syms_6138y_sukisu.txt", "syms_6138_fina.txt", "syms_6123_fina.txt", "syms_6138y_fina.txt",
            "syms_61258_next.txt", "syms_61258_sukisu.txt", "syms_61258_fina.txt",
            "syms_61258b.txt", "syms_61258b_bakasu.txt", "syms_61258b_next.txt", "syms_61258b_sukisu.txt", "syms_61258b_fina.txt",
            "syms_61258c.txt", "syms_61258c_resukisu.txt", "syms_61258c_next.txt", "syms_61258c_sukisu.txt", "syms_61258c_fina.txt",
            "syms_61258_nova.txt", "syms_61258c_nova.txt", "syms_g856_nova.txt", "syms_6138_nova.txt",
            "syms_g4b36.txt", "syms_g4b36_bakasu.txt", "syms_g4b36_fina.txt", "syms_g4b36_next.txt", "syms_g4b36_sukisu.txt", "syms_g4b36_nova.txt",
            "syms_g52d15.txt", "syms_g52d15_bakasu.txt", "syms_g52d15_fina.txt", "syms_g52d15_next.txt", "syms_g52d15_sukisu.txt", "syms_g52d15_nova.txt",
            "kernel_profiles.sh", "ko_patch", "addrcalc",
            "t64560_v36", "cred_target", "t64560_cred",
            "ksu_grant", "ksu_flavor",
            "ksu-template.ko", "ksu-template-bakasu.ko", "ksu-template-fina.ko",
            "ksu-template-next.ko", "ksu-template-sukisu.ko",
            "ksu-template-61821-next.ko",
            "ksu-template-61821-sukisu.ko", "ksu-template-61821-fina.ko",
            "ksu-template-61821-bakasu.ko",
            "forker", "grab.sh", "grab_legacy.sh", "lib.sh", "run.sh", "lsposed-hotfix.sh", "soft-reboot-root.sh", "root_stage.sh", "clean.sh", "rootd_stop.sh", "su_surface_clean.sh", "pc98260-su", "libadbroot.so", "ksu-template-66118.ko", "ksu-template-66118-next.ko", "ksu-template-66118-sukisu.ko", "ksu-template-66118-fina.ko", "ksu-template-66118-bakasu.ko",
            
            "su_entry.sh", "wait_helper",
            "61157/brm_plant", "61157/brm_plant_magicpad", "61157/brm_plant_g264", "61157/pc98260_su",
            "61157/kernelsu-honor.ko", "61157/ksu-loader", "61157/ksu-loader-g264", "61157/ksud",
            "61157/kernelsu-magicpad.ko", "61157/ksu-loader-magicpad",
            "61157/syms_elp_an00.txt", "61157/syms_magicpad3.txt", "61157/syms_g264.txt",
            "61157/g264/ksm-g264-base.ko", "61157/g264/ko_slide_patch",
            "61157/su-g264/su_lkm", "61157/su-g264/su_overlay_helper",
            "61157/su-g264/su_optional.sh", "61157/su-g264/setup_su_app.sh",
            "61157/run61157.sh", "61157/check.sh", "61157/verify.sh",
            "98260-6157/exploit-android-key-ptr", "98260-6157/pc98260-su",
            "98260-6157/target.sh",
            "98260/run6157_full.sh", "6157-integrity.tsv",
            "64560-61821/run64560_61821.sh", "64560-61821/t64560_v36", "64560-61821/t64560_v42",
            "64560-61821/perf_cred_honor", "64560-61821/kaslr_slide", "64560-61821/forker",
            "64560-61821/grab.sh", "64560-61821/ksu-template.ko", "64560-61821/syms.txt",
            "64560-61821/root_stage.sh", "64560-61821/ksu_grant.sh", "64560-61821/ksud",
            "ksu6157/ksu_prepare", "ksu6157/ksu-loader", "ksu6157/ksu-loader-generic",
            "ksu6157/ksu-syms.txt", "ksu6157/sigparam",
            "stpclear", "susfs_insmod", "susfs_guard_lkm-6.12.ko", "susfs_guard_lkm-6.6.ko", "susfs_guard_lkm-6.18.ko", "su_forward", 
            
            "98260-g264/exploit-android-key-ptr", "98260-g264/pc98260-su", "98260-g264/target.sh",
            "98260-gaaa/exploit-android-key-ptr", "98260-gaaa/pc98260-su", "98260-gaaa/target.sh",
            "98260-g3306/exploit-android-key-ptr", "98260-g3306/pc98260-su", "98260-g3306/target.sh",
            "98260-g84/exploit-android-key-ptr", "98260-g84/pc98260-su", "98260-g84/target.sh",
            "98260-g77f/exploit-android-key-ptr", "98260-g77f/pc98260-su", "98260-g77f/target.sh",
            "98260-gce849/exploit-android-key-ptr", "98260-gce849/pc98260-su", "98260-gce849/target.sh",
            "98260-g5859/exploit-android-key-ptr", "98260-g5859/pc98260-su", "98260-g5859/target.sh",
            "98260-g54d/exploit-android-key-ptr", "98260-g54d/pc98260-su", "98260-g54d/target.sh",
            "98260-g40b1/exploit-android-key-ptr", "98260-g40b1/pc98260-su", "98260-g40b1/target.sh",
            "98260-g8a496/exploit-android-key-ptr", "98260-g8a496/pc98260-su", "98260-g8a496/target.sh",
            "98260-g2e1f/exploit-android-key-ptr", "98260-g2e1f/pc98260-su", "98260-g2e1f/target.sh",
            "98260-ge9da/exploit-android-key-ptr", "98260-ge9da/pc98260-su", "98260-ge9da/target.sh",
            "98260-g8d6/exploit-android-key-ptr", "98260-g8d6/pc98260-su", "98260-g8d6/target.sh",
            "g264/ko_slide_patch", "g264/ksm-g264-base.ko", "g264/ksm-gaaa-base.ko",
            "g264/ksm-g3306-base.ko", "g264/ksm-g84-base.ko", "g264/ksm-g77f-base.ko",
            "g264/ksm-g7d-base.ko", "g264/ksm-gce849-base.ko", "g264/ksm-g5859-base.ko",
            "g264/ksm-g54d-base.ko", "g264/ksm-g40b1-base.ko", "g264/ksm-ge9da-base.ko",
            "g264/ksm-g8a496-base.ko", "g264/ksm-g2e1f-base.ko", "g264/ksm-g8d6-base.ko",
            "g264/syms-g264.txt", "g264/syms-gaaa.txt", "g264/syms-g3306.txt",
            "g264/syms-g84.txt", "g264/syms-g77f.txt", "g264/syms-g7d.txt",
            "g264/syms-gce849.txt", "g264/syms-g5859.txt", "g264/syms-g54d.txt",
            "g264/syms-g40b1.txt", "g264/syms-g8a496.txt", "g264/syms-g2e1f.txt",
            "g264/syms-ge9da.txt", "g264/syms-g8d6.txt",
            "ksu6157/kernelsu-honor.ko", "ksu6157/ksud",
            "ksu6157-g264/kernelsu-honor.ko", "ksu6157-g264/ksu_prepare", "ksu6157-g264/ksud",
            "ksu6157-g264/ksu-loader", "ksu6157-g264/ksu-syms.txt", "ksu6157-g264/sigparam",
            "su-g264/setup_su_app.sh", "su-g264/su_lkm", "su-g264/su_optional.sh", "su-g264/su_overlay_helper",
            "ksu6157-m6/bundled_ko.md5", "ksu6157-m6/kernelsu-os9-selx11.ko",
            "ksu6157-m6/kernelsu_ksu331.ko", "ksu6157-m6/kernelsu_success.ko",
            "ksu6157-m6/ko_patch2", "ksu6157-m6/ksu_loader.sh", "ksu6157-m6/ksu_probe.sh",
            "ksu6157-m6/ksu_rules", "ksu6157-m6/ksud_resukisu", "ksu6157-m6/ksud_success",
            "ksu6157-m6/load_ko", "ksu6157-m6/magiskpolicy", "ksu6157-m6/next_sym_addr.txt",
            "ksu6157-m6/next_sym_addr_uapi5.txt", "ksu6157-m6/poison_trap.sh",
            "ksu6157-m6/post_root.sh", "ksu6157-m6/su_forward", "ksu6157-m6/su_optional.sh",
            "ksu6157-m6/su_overlay_helper"
    };

    /**
     * CVE-2026-98260 experimental second-chain assets (Honor 6.12.58 /
     * 6.12.38, opt-in, requires explicit confirmation).  Staged under
     * $WORK/98260/ or $WORK/98260-6138/ and never used by the default
     * CVE-2026-64560 pipeline.
     */
    private static final String[] ASSETS_98260 = {
            "kaslr-98937/poc98937", "kaslr-98937/slide98937",
            "kaslr-98937/run98937.sh", "kaslr-98937/targets.conf",
            "kaslr-98937/README.md", "kaslr-98937/slide98937.c",
            "98260-g554/exploit-android-key-ptr", "98260-g554/syms_66118.txt", "98260-g554/syms_66118_next.txt", "98260-g554/syms_66118_sukisu.txt", "98260-g554/syms_66118_fina.txt", "98260-g554/syms_66118_bakasu.txt", "98260-g554/syms_66118_kernelsu.txt", "98260-g554/syms_66118_nova.txt", "98260-g554/target.sh",
            "98260-f171/exploit-android-key-ptr", "98260-f171/syms_66118.txt", "98260-f171/syms_66118_next.txt", "98260-f171/syms_66118_sukisu.txt", "98260-f171/syms_66118_fina.txt", "98260-f171/syms_66118_bakasu.txt", "98260-f171/syms_66118_kernelsu.txt", "98260-f171/syms_66118_nova.txt", "98260-f171/target.sh",
            "98260-6658/exploit-android-key-ptr", "98260-6658/pc98260-su", "98260-6658/target.sh",
            "98260-6658/syms_6658_kernelsu.txt", "98260-6658/syms_6658_bakasu.txt", "98260-6658/syms_6658_fina.txt", "98260-6658/syms_6658_next.txt", "98260-6658/syms_6658_sukisu.txt", "98260-6658/syms_6658_nova.txt",
            "98260-6689/exploit-android-key-ptr", "98260-6689/pc98260-su", "98260-6689/target.sh",
            "98260-6689/syms_6689_kernelsu.txt", "98260-6689/syms_6689_bakasu.txt", "98260-6689/syms_6689_fina.txt", "98260-6689/syms_6689_next.txt", "98260-6689/syms_6689_sukisu.txt", "98260-6689/syms_6689_nova.txt",
            "98260-g142/exploit-android-key-ptr", "98260-g142/pc98260-su", "98260-g142/target.sh", "98260-g142/SHA256SUMS.txt",
            "98260-g142/syms_g142_kernelsu.txt", "98260-g142/syms_g142_bakasu.txt", "98260-g142/syms_g142_fina.txt", "98260-g142/syms_g142_next.txt", "98260-g142/syms_g142_sukisu.txt", "98260-g142/syms_g142_nova.txt",
            "98260-ga812/exploit-android-key-ptr", "98260-ga812/pc98260-su", "98260-ga812/target.sh",
            "98260-ga812/syms_ga812_kernelsu.txt", "98260-ga812/syms_ga812_bakasu.txt", "98260-ga812/syms_ga812_fina.txt", "98260-ga812/syms_ga812_next.txt", "98260-ga812/syms_ga812_sukisu.txt", "98260-ga812/syms_ga812_nova.txt",
            "98260-g893/exploit-android-key-ptr", "98260-g893/pc98260-su", "98260-g893/target.sh",
            "98260-g893/syms_g893_kernelsu.txt", "98260-g893/syms_g893_bakasu.txt", "98260-g893/syms_g893_fina.txt", "98260-g893/syms_g893_next.txt", "98260-g893/syms_g893_sukisu.txt", "98260-g893/syms_g893_nova.txt",
            "98260-61258b/exploit-android-key-ptr", "98260-61258b/target.sh",
            "98260-61258c/exploit-android-key-ptr", "98260-61258c/target.sh",
            "98260-61821/exploit-android-key-ptr", "98260-61821/syms_61821_kernelsu.txt", "98260-61821/ksu-template.ko", "98260-61821/target.sh",
            "98260-61821/ksu-template-61821-bakasu.ko", "98260-61821/ksu-template-61821-fina.ko", "98260-61821/ksu-template-61821-next.ko", "98260-61821/ksu-template-61821-sukisu.ko",
            "98260-61821/slide_probe", "98260-61821/kaslr_slide",
            "98260-61821/forker_618", "98260-61821/grab_honor.sh",
            "98260-61821/grab_slide_618.sh",
            "98260-61821-brm/exploit-android-key-ptr", "98260-61821-brm/slide_probe", "98260-61821-brm/target.sh",
            "98260-61821-brm/syms_61821_brm.txt", "98260-61821-brm/ksu-template.ko", "98260-61821-brm/ksu-template-61821-kernelsu.ko",
            "98260-61821-brm/ksu-template-61821-bakasu.ko", "98260-61821-brm/ksu-template-61821-fina.ko", "98260-61821-brm/ksu-template-61821-next.ko", "98260-61821-brm/ksu-template-61821-sukisu.ko",
            "98260-61821-117/target.sh", "98260-61821-117/syms_117.txt",
            "98260-61821-117/ksu-template-117-kernelsu.ko", "98260-61821-117/ksu-template-117-bakasu.ko",
            "98260-61821-117/ksu-template-117-fina.ko", "98260-61821-117/ksu-template-117-next.ko",
            "98260-61821-117/ksu-template-117-sukisu.ko",
            "98260-h1c/cve98260_plant", "98260-h1c/cve98260_slide", "98260-h1c/cve98260_su",
            "98260-h1c/cve98260_module", "98260-h1c/addrcalc", "98260-h1c/root_stage.sh",
            "98260-h1c/ksu-template-115.ko",
            "98260-h1c/run_h1c.sh",
            "98260/exploit-android-perf", "98260/exploit-android-perf-chain",
            "98260/exploit-android-key-ptr",
            "98260/run98260.sh", "98260/target.sh", "98260/SHA256SUMS.txt",
            "98260-6138/exploit-android-perf", "98260-6138/exploit-android-perf-chain",
            "98260-6138/exploit-android-key-ptr",
            "98260-6138/target.sh", "98260-6138/SHA256SUMS.txt",
            "98260-6123/exploit-android-perf", "98260-6123/exploit-android-perf-chain",
            "98260-6123/exploit-android-key-ptr",
            "98260-6123/run98260.sh", "98260-6123/target.sh", "98260-6123/SHA256SUMS.txt",
            "98260-g856/exploit-android-key-ptr", "98260-g856/target.sh", "98260-g856/SHA256SUMS.txt",
            "98260-6138y/exploit-android-perf", "98260-6138y/exploit-android-perf-chain",
            "98260-6138y/exploit-android-key-ptr",
            "98260-6138y/run98260.sh", "98260-6138y/target.sh", "98260-6138y/SHA256SUMS.txt",
            "98260-g4b36/exploit-android-key-ptr", "98260-g4b36/target.sh",
            "98260-g4b36/SHA256SUMS.txt",
            "98260-g52d15/exploit-android-key-ptr", "98260-g52d15/target.sh",
            "98260-g52d15/SHA256SUMS.txt",
            "98260-aph112/exploit-android-perf", "98260-aph112/exploit-android-perf-chain",
            "98260-aph112/exploit-android-key-ptr", "98260-aph112/pc98260-su",
            "98260-aph112/target.sh", "98260-aph112/SHA256SUMS.txt"
    };

    private UiState ui;
    private volatile boolean runInProgress = false;
    /** Highest progress emitted for the current run; keeps the bar monotonic. */
    private volatile int runProgressValue = 0;
    private volatile boolean staleExportDone = false;
    private volatile String lastRunLogText = "";
    private volatile java.io.File cachedRootSu;
    private volatile long lastRootSuProbe;
    private final AtomicBoolean actionBusy = new AtomicBoolean(false);
    private final AtomicBoolean softRebootFixRunning = new AtomicBoolean(false);
    private final AtomicBoolean oneClickWait = new AtomicBoolean(false);
    private PowerManager.WakeLock wakeLock;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private static final java.util.concurrent.ExecutorService WORKER_POOL =
            java.util.concurrent.Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "magicroot-worker");
                t.setDaemon(true);
                return t;
            });
    private final java.util.concurrent.ExecutorService liveLogWriter =
            java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "magicroot-live-log");
                t.setDaemon(true);
                return t;
            });
    private LiveLogStore liveLogStore;

    private static void runAsync(Runnable task) {
        runAsync(task, "magicroot-worker");
    }

    private static void runAsync(Runnable task, String name) {
        WORKER_POOL.execute(() -> {
            Thread current = Thread.currentThread();
            String prev = current.getName();
            if (name != null && !name.isEmpty()) {
                current.setName(name);
            }
            try {
                task.run();
            } finally {
                current.setName(prev);
            }
        });
    }
    private ActivityResultLauncher<String[]> customKoPicker;
    private ActivityResultLauncher<String[]> susfsLkmPicker;
    private ActivityResultLauncher<String[]> bootImagePicker;
    private final AtomicBoolean adaptiveProfileBusy = new AtomicBoolean(false);
    private Shizuku.OnBinderReceivedListener shizukuBinderReceivedListener;
    private Shizuku.OnBinderDeadListener shizukuBinderDeadListener;
    private Shizuku.OnRequestPermissionResultListener shizukuPermissionListener;

    /** Called from the Miuix 98260 advanced options card. */
    public void pickCustomKo() {
        if (customKoPicker != null) {
            customKoPicker.launch(new String[]{"*/*"});
        }
    }

    /** Pick a local SuSFS guard .ko; it is validated for KMI and staged into WORK. */
    /** Pick a boot image and generate a local HOneClick-style 6.18 profile. */
    public void pickAdaptiveBoot() {
        if (bootImagePicker != null) {
            bootImagePicker.launch(new String[]{"application/octet-stream", "*/*"});
        }
    }

    private void importAdaptiveBoot(Uri uri) {
        if (!adaptiveProfileBusy.compareAndSet(false, true)) return;
        runAsync(() -> {
            try {
                log("ADAPTIVE_BEGIN uri=" + uri);
                byte[] boot = readUriBytes(uri, 512L * 1024 * 1024);
                byte[] kernel = KernelProfileGenerator.extractKernel(boot);
                String release = KernelProfileGenerator.peekKernelRelease(kernel);
                final String kernelText;
                final String id;
                final long symsBytes;
                if (release.startsWith("6.12.") || release.startsWith("6.6.")) {
                    // 6.12/6.6 are standard GKI builds: kallsyms is exported
                    // normally, so a local dump is already a complete
                    // "name 0xADDR" table for ko_patch — no BTF/vulnerability
                    // check needed (that is 6.18.21-specific plumbing).
                    KernelProfileGenerator.KallsymsResult result =
                            KernelProfileGenerator.generateKallsyms(kernel);
                    File root = new File(getFilesDir(), "profiles");
                    File dir = new File(root, result.safeId());
                    if (!dir.exists() && !dir.mkdirs())
                        throw new IllegalStateException("无法创建自适应配置目录");
                    writeFileBytes(new File(dir, "syms.txt"),
                            symbolTableText(result.symbols).getBytes("UTF-8"));
                    JSONObject profile = new JSONObject();
                    profile.put("id", result.id);
                    profile.put("kernel", result.kernel);
                    profile.put("audit_kallsyms", result.kallsymsCount);
                    profile.put("vulnerable", false);
                    writeFileBytes(new File(dir, "profile.json"),
                            profile.toString(2).getBytes("UTF-8"));
                    kernelText = result.kernel;
                    id = result.id;
                    symsBytes = new File(dir, "syms.txt").length();
                } else {
                    // 6.18.x keeps the full validated pipeline (BTF struct
                    // layout + vulnerability call-order check).  Anything
                    // else (incl. 6.1.x) is rejected inside generate().
                    KernelProfileGenerator.Result result = KernelProfileGenerator.generate(kernel);
                    File root = new File(getFilesDir(), "profiles");
                    File dir = new File(root, result.safeId());
                    if (!dir.exists() && !dir.mkdirs())
                        throw new IllegalStateException("无法创建自适应配置目录");
                    // Our ko_patch consumes "name 0xADDR" tables, while the
                    // HOneClick generator emits "ADDR type name".  Convert here
                    // instead of shipping a second incompatible format.
                    writeFileBytes(new File(dir, "syms.txt"),
                            symbolTableText(result.symbols).getBytes("UTF-8"));
                    JSONObject profile = new JSONObject();
                    profile.put("id", result.id);
                    profile.put("kernel", result.kernel);
                    profile.put("timer_link", hexLong(result.timerLink));
                    profile.put("cred_link", hexLong(result.credLink));
                    profile.put("slide_site_low", hexLong(result.slideSiteLow));
                    profile.put("selinux_link", hexLong(result.selinuxLink));
                    profile.put("user_ns", hexLong(result.userNs));
                    profile.put("root_user", hexLong(result.rootUser));
                    profile.put("groups", hexLong(result.groups));
                    profile.put("ucounts", hexLong(result.ucounts));
                    profile.put("kitimer_size", result.kitimerSize);
                    profile.put("kitimer_node", result.kitimerNode);
                    profile.put("task_cred", result.taskCred);
                    profile.put("cred_size", result.credSize);
                    profile.put("slab_objects", 21);
                    profile.put("slab_pages", 2);
                    profile.put("vulnerable", true);
                    profile.put("audit_btf_base", hexLong(result.btfBase));
                    profile.put("audit_kallsyms", result.kallsymsCount);
                    writeFileBytes(new File(dir, "profile.json"),
                            profile.toString(2).getBytes("UTF-8"));
                    kernelText = result.kernel;
                    id = result.id;
                    symsBytes = new File(dir, "syms.txt").length();
                }
                runOnUiThread(() -> {
                    ui.updateAdaptiveProfile(kernelText, id, "已生成 · " + kernelText);
                    feedback("自适应配置已生成", id, 1);
                });
                log("ADAPTIVE_OK kernel=" + kernelText + " id=" + id + " syms=" + symsBytes);
            } catch (Throwable t) {
                log("ADAPTIVE_FAILED=" + t);
                runOnUiThread(() -> {
                    ui.updateAdaptiveProfile("", "", "导入失败：" + t.getMessage());
                    feedback("boot.img 导入失败", String.valueOf(t.getMessage()), 2);
                });
            } finally {
                adaptiveProfileBusy.set(false);
            }
        }, "magicroot-adaptive-profile");
    }

    private static String hexLong(long value) {
        return String.format(Locale.ROOT, "0x%016x", value);
    }

    /** ko_patch consumes "name 0xADDR" tables; both generator paths share this. */
    private static String symbolTableText(List<KernelProfileGenerator.Symbol> symbols) {
        StringBuilder out = new StringBuilder(symbols.size() * 48);
        for (KernelProfileGenerator.Symbol symbol : symbols) {
            out.append(symbol.name)
                    .append(" 0x")
                    .append(String.format(Locale.ROOT, "%x", symbol.address))
                    .append('\n');
        }
        return out.toString();
    }

    private void writeFileBytes(File file, byte[] bytes) throws Exception {
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(bytes);
        }
    }

    private byte[] readUriBytes(Uri uri, long limit) throws Exception {
        try (InputStream in = getContentResolver().openInputStream(uri)) {
            if (in == null) throw new IllegalStateException("无法打开所选文件");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[65536];
            long total = 0;
            int n;
            while ((n = in.read(buffer)) > 0) {
                total += n;
                if (total > limit) throw new IllegalStateException("文件超过大小限制");
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }
    }

    /** Locate a generated profile whose kernel exactly matches the running one. */
    private JSONObject findAdaptiveProfile(String kernel) {
        File root = new File(getFilesDir(), "profiles");
        File[] dirs = root.listFiles();
        if (dirs == null) return null;
        for (File dir : dirs) {
            File json = new File(dir, "profile.json");
            if (!json.isFile()) continue;
            try {
                JSONObject p = new JSONObject(new String(readFileBytes(json), "UTF-8"));
                if (kernel.equals(p.optString("kernel", "")))
                    return p;
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    private byte[] readFileBytes(File file) throws Exception {
        try (InputStream in = new FileInputStream(file)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[65536];
            int n;
            while ((n = in.read(buffer)) > 0) out.write(buffer, 0, n);
            return out.toByteArray();
        }
    }

    private void loadAdaptiveProfile() {
        try {
            // Must be scoped to the currently running kernel (same exact-match
            // rule findAdaptiveProfile() already uses for real 98260 dispatch):
            // getFilesDir()/profiles/ can hold profiles generated for several
            // different boot.img imports over time (e.g. earlier adaptive-
            // generator validation plus a later real import for a different
            // kernel). Blindly taking File.listFiles()[0] picked an arbitrary
            // one — filesystem order isn't stable — so the status card could
            // keep showing a stale/unrelated kernel's "已生成 · ..." line on
            // every app relaunch even after importing a fresh matching
            // boot.img, since the next onCreate() re-ran this and could land
            // on the old directory again.
            String kernel = ui.getKernelVersion();
            if (kernel == null || kernel.isEmpty() || "unknown".equals(kernel)) return;
            JSONObject p = findAdaptiveProfile(kernel);
            if (p != null) {
                ui.updateAdaptiveProfile(p.optString("kernel", ""), p.optString("id", ""),
                        "已生成 · " + p.optString("kernel", ""));
            } else {
                ui.updateAdaptiveProfile("", "", "未找到匹配当前内核的自适应配置");
            }
        } catch (Throwable ignored) {
        }
    }

    /** Write generated symbol table through the Shizuku shell before run.sh starts. */
    private boolean stageAdaptiveSymbols(JSONObject profile) {
        try {
            File dir = null;
            File root = new File(getFilesDir(), "profiles");
            File[] dirs = root.listFiles();
            if (dirs != null) {
                for (File d : dirs) {
                    File json = new File(d, "profile.json");
                    if (json.isFile() && profile.optString("kernel", "").equals(
                            new JSONObject(new String(readFileBytes(json), "UTF-8"))
                                    .optString("kernel", ""))) {
                        dir = d;
                        break;
                    }
                }
            }
            if (dir == null) return false;
            byte[] syms = readFileBytes(new File(dir, "syms.txt"));
            Process p = shellProcess("cat > '" + WORK + "/syms_adaptive.txt'");
            try (OutputStream out = p.getOutputStream()) {
                out.write(syms);
            }
            p.getOutputStream().close();
            byte[] buffer = new byte[8192];
            try (InputStream in = p.getInputStream()) {
                while (in.read(buffer) > 0) { }
            }
            p.waitFor(30, TimeUnit.SECONDS);
            String check = shellNoThrow("wc -c < '" + WORK + "/syms_adaptive.txt' 2>/dev/null");
            log("ADAPTIVE_STAGE_SYMS bytes=" + String.valueOf(check).trim()
                    + " expected=" + syms.length);
            return check != null && String.valueOf(check).trim().equals(String.valueOf(syms.length));
        } catch (Throwable t) {
            log("ADAPTIVE_STAGE_SYMS_FAILED=" + t);
            return false;
        }
    }

    public void pickSusfsLkm() {
        if (susfsLkmPicker != null) {
            susfsLkmPicker.launch(new String[]{"application/octet-stream", "*/*"});
        }
    }

    private void stageCustomKo(Uri uri) {
        feedback("自定义 KO", "正在通过 SAF 导入…", 0);
        runAsync(() -> {
            Process process = null;
            try {
                try {
                    getContentResolver().takePersistableUriPermission(
                            uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                } catch (Throwable ignored) {
                    // Some providers do not support persistable grants.
                }
                String name = null;
                try (Cursor c = getContentResolver().query(uri, null, null, null, null)) {
                    if (c != null && c.moveToFirst()) {
                        int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                        if (idx >= 0) name = c.getString(idx);
                    }
                } catch (Throwable ignored) {
                }
                String dest = "/data/local/tmp/magic/custom.ko";
                shell("mkdir -p /data/local/tmp/magic");
                process = shellProcess("cat > " + dest);
                long copied = 0;
                try (InputStream in = getContentResolver().openInputStream(uri);
                     OutputStream out = process.getOutputStream()) {
                    if (in == null) throw new IllegalStateException("openInputStream returned null");
                    byte[] buf = new byte[64 * 1024];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        out.write(buf, 0, n);
                        copied += n;
                    }
                }
                // Remote Process implementations can report "process hasn't exited"
                // even after stdin EOF; verify the staged file size instead of
                // relying on exitValue().
                try {
                    process.waitFor(10, TimeUnit.SECONDS);
                } catch (Throwable ignored) {
                }
                long actual = -1;
                for (int i = 0; i < 20; i++) {
                    String sizeText = shellNoThrow("wc -c < '" + dest + "' 2>/dev/null");
                    if (sizeText != null) {
                        try {
                            actual = Long.parseLong(sizeText.trim());
                        } catch (Throwable ignored) {
                        }
                    }
                    if (actual == copied && copied > 0) break;
                    Thread.sleep(200);
                }
                if (copied <= 0 || actual != copied) {
                    throw new IllegalStateException(
                            "shell copy incomplete expected=" + copied + " actual=" + actual);
                }
                shell("chmod 644 " + dest);
                final String finalName = name;
                runOnUiThread(() -> {
                    ui.updateCustomKoPath(dest);
                    ui.updateCustomKoEnabled(true);
                    log("CUSTOM_KO_IMPORTED=" + dest + " name=" + finalName);
                    feedback("自定义 KO 已导入", (finalName == null ? "custom.ko" : finalName) + " -> " + dest, 1);
                });
            } catch (Throwable t) {
                runOnUiThread(() -> feedback("自定义 KO 导入失败", String.valueOf(t), 2));
            } finally {
                if (process != null) try { process.destroy(); } catch (Throwable ignored) {}
            }
        }, "magicroot-saf-ko");
    }

    private void stageCustomSusfs(Uri uri) {
        feedback("本地 SuSFS", "正在导入并校验模块…", 0);
        runAsync(() -> {
            try {
                try {
                    getContentResolver().takePersistableUriPermission(
                            uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                } catch (Throwable ignored) {
                }
                String name = "susfs_guard_lkm.custom.ko";
                try (Cursor c = getContentResolver().query(uri, null, null, null, null)) {
                    if (c != null && c.moveToFirst()) {
                        int idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                        if (idx >= 0 && c.getString(idx) != null) name = c.getString(idx);
                    }
                } catch (Throwable ignored) {
                }
                File dir = new File(getFilesDir(), "susfs");
                if (!dir.exists() && !dir.mkdirs())
                    throw new java.io.IOException("无法创建 SuSFS 私有目录");
                File tmp = new File(dir, "susfs_guard_lkm.import");
                long copied = 0;
                try (InputStream in = getContentResolver().openInputStream(uri);
                     FileOutputStream out = new FileOutputStream(tmp)) {
                    if (in == null) throw new java.io.IOException("无法读取所选文件");
                    byte[] buf = new byte[65536];
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        out.write(buf, 0, n);
                        copied += n;
                        if (copied > SUSFS_MAX_DOWNLOAD)
                            throw new java.io.IOException("模块过大");
                    }
                    out.getFD().sync();
                }
                if (copied <= 0) throw new java.io.IOException("所选文件为空");
                String kmi = kmiOf(kernelReleaseForSusfs());
                validateSusfsKo(tmp, kmi);
                File saved = new File(dir, "susfs_guard_lkm-custom-" + kmi + ".ko");
                if (!tmp.renameTo(saved)) {
                    copyFile(tmp, saved);
                    tmp.delete();
                }
                boolean staged = stageSusfsUpdated(saved);
                ui.updateSusfsLocalModule(saved.getName(), kmi, "本地导入");
                final String finalName = name;
                final String finalKmi = kmi;
                runOnUiThread(() -> {
                    ui.setSusfsUpdateBusy(false);
                    ui.setSusfsUpdateStatus(
                            "本地 SuSFS 已导入" + (staged ? "并暂存" : "（暂存失败）")
                                    + " · " + finalName + " · KMI " + finalKmi);
                    log("SUSFS_LOCAL_IMPORT=ok name=" + finalName
                            + " kmi=" + finalKmi + " staged=" + staged
                            + " path=" + saved.getAbsolutePath());
                    if (staged && ui.getSusfsSupported()) {
                        ui.updateSusfs(true);
                    }
                    feedback("本地 SuSFS 已导入",
                            staged ? "模块已暂存，开启 SuSFS 后生效" : "文件已保存，但暂存 WORK 失败",
                            staged ? 1 : 2);
                });
            } catch (Throwable t) {
                log("SUSFS_LOCAL_IMPORT=failed " + t);
                runOnUiThread(() -> {
                    ui.setSusfsUpdateBusy(false);
                    ui.setSusfsUpdateStatus("本地 SuSFS 导入失败: " + t);
                    feedback("本地 SuSFS 导入失败", String.valueOf(t), 2);
                });
            }
        }, "magicroot-susfs-import");
    }

    @SuppressWarnings("deprecation") // color APIs only used below API 35
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        androidx.core.view.WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        if (Build.VERSION.SDK_INT < 35) {
            getWindow().setStatusBarColor(android.graphics.Color.TRANSPARENT);
            getWindow().setNavigationBarColor(android.graphics.Color.TRANSPARENT);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                getWindow().setNavigationBarContrastEnforced(false);
                getWindow().setStatusBarContrastEnforced(false);
            }
        }
        customKoPicker = registerForActivityResult(
                new ActivityResultContracts.OpenDocument(), uri -> {
                    if (uri != null) stageCustomKo(uri);
                });
        susfsLkmPicker = registerForActivityResult(
                new ActivityResultContracts.OpenDocument(), uri -> {
                    if (uri != null) stageCustomSusfs(uri);
                });
        bootImagePicker = registerForActivityResult(
                new ActivityResultContracts.OpenDocument(), uri -> {
                    if (uri != null) importAdaptiveBoot(uri);
                });
        ui = new UiState(this);
        File externalFiles = getExternalFilesDir(null);
        liveLogStore = new LiveLogStore(new File(
                externalFiles != null ? externalFiles : getFilesDir(), "magicroot-live.log"));
        try {
            // Migrate the original internal log so the next authorized shell can
            // read panic/soft-reboot evidence without run-as or root.
            String previous = liveLogStore.readTail(400);
            if (previous.isEmpty() && externalFiles != null) {
                LiveLogStore legacy = new LiveLogStore(new File(getFilesDir(), "magicroot-live.log"));
                previous = legacy.readTail(400);
                if (!previous.isEmpty())
                    liveLogStore.reset(previous);
            }
            if (!previous.isEmpty()) {
                ui.replaceLog(previous + "\n—— 以上为上次运行记录（可能被软重启/panic 中断）——");
            }
        } catch (Throwable ignored) {
        }
        MiuixHost.install(this);
        loadAdaptiveProfile();
        refreshInstalledApps();
        refreshInstalledManagers();

        // Shizuku: official README uses sticky binder + dead + permission
        // result listeners. The provider itself is registered in the manifest.
        shizukuBinderReceivedListener = () -> {
            log("Shizuku binder 已连接");
            updateChannelAuth();
            syncLocalDeploymentState();
        };
        shizukuBinderDeadListener = () -> {
            log("Shizuku binder 已断开");
            updateChannelAuth();
        };
        shizukuPermissionListener = (requestCode, result) -> {
            log("Shizuku permission result=" + result);
            if (requestCode == REQ_SHIZUKU) {
                boolean granted = result == PackageManager.PERMISSION_GRANTED;
                updateChannelAuth();
                feedback(
                        granted ? "Shizuku 已授权" : "Shizuku 未授权",
                        granted ? "可以部署资产" : "请在 Shizuku 中允许后重试",
                        granted ? 1 : 2);
            }
        };
        Shizuku.addBinderReceivedListenerSticky(shizukuBinderReceivedListener);
        Shizuku.addBinderDeadListener(shizukuBinderDeadListener);
        Shizuku.addRequestPermissionResultListener(shizukuPermissionListener);
        updateChannelAuth();

        // If the previous run was interrupted (e.g. the app was closed or the
        // device restarted during the race), export its run.log once the shell
        // is available so the user can read/share it.  The shell binder may
        // still be connecting at launch, so retry a few times.
        for (int[] plan : new int[][]{{4000, 0}, {12000, 1}, {25000, 2}, {40000, 3}}) {
            final int attempt = plan[1];
            mainHandler.postDelayed(() -> runAsync(() -> {
                // Never export while a chain is running: during PREFLIGHT_WAIT /
                // the exploit stages run.log is the *current* log, not a stale
                // interrupted one, and renaming it mid-run would corrupt log
                // polling.  The one-shot "before-run" export is handled inside
                // runChain before the process starts.
                if (runInProgress || staleExportDone)
                    return;
                boolean ok = false;
                try {
                    ok = exportStaleRunLog("launch");
                } catch (Throwable ignored) {
                }
                if (!ok && attempt == 3) {
                    log("未发现可导出的上次运行日志（或 run.log 不存在）");
                }
            }), plan[0]);
        }
    }

    /** Append only the current run's complete native/diagnostic logs. */
    private static String diagnosticLogLoop() {
        return "_meta=" + WORK + "/run.log; "
                + "[ -f \"$_meta\" ] || _meta=" + WORK + "/run.log.exported; "
                // A guard-only run has no 98260_LOG marker; do not attach the
                // previous run's native log in that case.
                + "if grep -q '^98260_LOG=" + WORK + "/98260.log$' \"$_meta\" 2>/dev/null; then "
                + "if [ -s " + WORK + "/98260.log ]; then "
                + "printf '\\n=== %s ===\\n' '98260.log'; cat " + WORK + "/98260.log; "
                + "fi; fi; "
                // H1C early failures must not inherit plant/root-stage logs
                // from an older run that never produced H1C_BEGIN this time.
                + "if grep -q '^98260_H1C_BEGIN ' \"$_meta\" 2>/dev/null; then "
                + "for f in 98260-h1c.log 98260-h1c-ko-patch.log "
                + "98260-h1c-plant.log 98260-h1c-root-stage.log; do "
                + "if [ -s " + WORK + "/$f ]; then "
                + "printf '\\n=== %s ===\\n' \"$f\"; cat " + WORK + "/$f; "
                + "fi; done; fi";
    }

    /**
     * Copy the payload logs (98260.log plus the O_SYNC mirror) to Download
     * before the next deployment truncates them.  After a panic the work dir
     * used to hold only NULs; the mirror is written with O_SYNC so the last
     * plant/reap lines survive, and this export keeps them across the next
     * run's deploy.
     */
    private void exportStale98260Logs(String tag) {
        try {
            String dir = "/sdcard/Download/MagicRoot";
            long ts = System.currentTimeMillis();
            String dst1 = dir + "/prev-98260-" + ts + ".log";
            String dst2 = dir + "/prev-98260-sync-" + ts + ".log";
            String cmd = "mkdir -p " + dir + " 2>/dev/null; n=0; "
                    + "if [ -s " + WORK + "/98260.log ]; then "
                    + "cat " + WORK + "/98260.log > '" + dst1 + "' && n=$((n+1)); fi; "
                    + "if [ -s " + WORK + "/98260.log.sync ]; then "
                    + "cat " + WORK + "/98260.log.sync > '" + dst2 + "' && n=$((n+1)); fi; "
                    + "chmod 644 '" + dst1 + "' '" + dst2 + "' 2>/dev/null; "
                    + "echo EXPORTED=$n";
            String out = shellNoThrow(cmd);
            if (out != null && out.contains("EXPORTED=0"))
                return;
            log("已导出上次 payload 日志(" + tag + "): " + dst1);
        } catch (Throwable ignored) {
        }
    }

    /**
     * Copy a leftover run.log (previous interrupted/rebooted run) to
     * /sdcard/Download/MagicRoot and rename it away so it is exported once.
     * Returns true when a log was found and exported.
     */
    private synchronized boolean exportStaleRunLog(String tag) {
        // "launch" exports stale logs only; while a run is active run.log is
        // live (PREFLIGHT_WAIT etc.) and must not be renamed/exported again.
        if ("launch".equals(tag) && runInProgress)
            return false;
        exportStale98260Logs(tag);
        try {
            // Manual export may run after the launch/failure path already
            // renamed run.log.  Fall back to the retained exported copy.
            String src = WORK + "/run.log";
            String size = shellNoThrow("wc -c < " + src + " 2>/dev/null");
            int n = 0;
            try {
                n = Integer.parseInt(String.valueOf(size).trim());
            } catch (Throwable ignored) {
            }
            boolean renameAfter = true;
            if (n <= 0) {
                src = WORK + "/run.log.exported";
                size = shellNoThrow("wc -c < " + src + " 2>/dev/null");
                try {
                    n = Integer.parseInt(String.valueOf(size).trim());
                } catch (Throwable ignored) {
                }
                renameAfter = false;
            }
            if (n <= 0)
                return false;
            String dir = "/sdcard/Download/MagicRoot";
            String dst = dir + "/prev-run-" + System.currentTimeMillis() + ".txt";
            String rename = renameAfter
                    ? " && mv -f " + WORK + "/run.log " + WORK + "/run.log.exported"
                    : "";
            shell("mkdir -p " + dir
                    + " && { cat '" + src + "'; echo; "
                    + "echo '=== PERMISSIVE_STARTED ==='; "
                    + "cat " + WORK + "/marks/PERMISSIVE_STARTED 2>/dev/null; "
                    + diagnosticLogLoop() + "; true; } > '" + dst + "'"
                    + " && chmod 644 '" + dst + "'" + rename + " 2>/dev/null; true");
            String check = shellNoThrow("test -s '" + dst + "' && echo OK || echo FAIL");
            if (check == null || !check.contains("OK"))
                return false;
            staleExportDone = true;
            log("已导出上次运行日志(" + tag + "): " + dst);
            if ("launch".equals(tag)) {
                log("提示：如上次是设备重启/关闭 App 中断，开机后等待系统完成启动即可；"
                        + "链路会自动等待系统稳定（PREFLIGHT_WAIT）");
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshInstalledApps();
        if (ui != null) {
            refreshLocalSusfsState();
            syncLocalDeploymentState();
        }
        refreshInstalledManagers();
    }

    @Override
    protected void onDestroy() {
        try {
            if (shizukuBinderReceivedListener != null)
                Shizuku.removeBinderReceivedListener(shizukuBinderReceivedListener);
            if (shizukuBinderDeadListener != null)
                Shizuku.removeBinderDeadListener(shizukuBinderDeadListener);
            if (shizukuPermissionListener != null)
                Shizuku.removeRequestPermissionResultListener(shizukuPermissionListener);
        } catch (Throwable ignored) {
        }
        mainHandler.removeCallbacksAndMessages(null);
        liveLogWriter.shutdown();
        super.onDestroy();
    }

    public UiState getUi() {
        return ui;
    }

    /** Open the selected KSU manager from the success card. */
    public void openKsuManager() {
        String pkg = ui == null ? "" : ui.getKsuManagerPkg();
        String[] candidates = {
                pkg,
                "com.resukisu.resukisu",
                "com.sukisu.ultra",
                "me.weishu.kernelsu",
                "me.yuki.fina",
                "com.rifsxd.ksunext",
                "com.sukisu.nova",
                "dev.maplesu.manager",
        };
        for (String candidate : candidates) {
            if (candidate == null || candidate.isEmpty()) continue;
            try {
                Intent i = getPackageManager().getLaunchIntentForPackage(candidate);
                if (i != null) {
                    startActivity(i);
                    return;
                }
            } catch (Throwable ignored) {
            }
        }
        feedback("未找到管理器", "请先安装对应的 KernelSU 管理器", 2);
    }

    public void doGrant() {
        if (!beginAction())
            return;
        feedback("检查授权", "正在检查 Shizuku…", 0);
        try {
            if (!Shizuku.pingBinder()) {
                log("Shizuku 未运行：请先启动 Shizuku");
                feedback("授权不可用", "先启动 Shizuku", 2);
                return;
            }
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                log("Shizuku 已授权");
                updateChannelAuth();
                feedback("Shizuku 已授权", "可以部署资产", 1);
            } else {
                Shizuku.requestPermission(REQ_SHIZUKU);
                feedback("已请求 Shizuku 授权", "允许后再次点击授权", 0);
            }
        } finally {
            endAction();
        }
    }

    public void doStage() {
        if (!beginAction())
            return;
        feedback("正在部署资产", "传输运行文件到 " + WORK, 0);
        runAsync(() -> {
            try {
                ui.setStatus("部署中");
                log("部署资产到 " + WORK + " ...");
                final String chain = ui.getChain();
                stageAllRuntimeAssets(chain);
                // Manager extraction is required for both chains: 98260's
                // ksud handoff must use the currently selected Flavor's
                // installed manager, not a stale /data/adb/ksud.
                final String flavor = ui.getKsuFlavor();
                shell("echo '" + flavor + "' > " + WORK + "/ksu_flavor; chmod 644 " + WORK + "/ksu_flavor");
                try {
                    log("管理器文件提取（" + ui.getKsuManagerLabel() + "）: " + extractManagerKsud(flavor));
                } catch (Throwable t) {
                    log("管理器 ksud 提取失败，使用内置兜底: " + t);
                }
                try {
                    log("MANAGER_LKM=" + extractManagerLkm(flavor));
                } catch (Throwable t) {
                    log("MANAGER_LKM_FAIL=" + t);
                }
                try {
                    log("管理器签名提取: " + stageManagerSignature(flavor));
                } catch (Throwable t) {
                    log("管理器签名提取失败，root_stage 可用 get-sign: " + t);
                }
                log("部署完成");
                ui.markSetupReady();
                refreshLocalSusfsState();
                ui.setStatus("资产已部署");
                ui.markAssetsDeployed(true);
                writeDeploymentStamp();
                feedback("资产已部署", "可以开始提权", 1);
            } catch (Throwable t) {
                log("部署失败: " + t);
                ui.setStatus("部署失败");
                ui.markAssetsDeployed(false);
                String msg = t.toString();
                if (msg.contains("Shizuku 不可用") || msg.contains("Shizuku")) {
                    feedback("授权不可用", "请先启动 Shizuku，再重新部署", 2);
                } else {
                    feedback("部署失败", msg, 2);
                }
            } finally {
                endAction();
            }
        });
    }

    /**
     * Direct KernelSU root execution.
     *
     * /system/bin/su is the normal su_compat entry, but it can be absent after a
     * cold boot until the chain has re-loaded KernelSU, or when a different
     * KernelSU user-space manager exposes su under another path.  Probe the
     * known entries instead of hard-failing on /system/bin/su.
     */
    private java.io.File findSuEntry() {
        // Prefer the real KSU userspace entry.  /system/bin/su can be a
        // su_compat shim whose ksud target was removed; /product/bin/su is a
        // rootd wrapper that dies once the rootd socket is cleaned.  Probe each
        // candidate instead of trusting canExecute().
        for (String path : new String[]{
                "/data/adb/ksu/bin/su",
                "/system/bin/su",
                "/product/bin/su",
                "/debug_ramdisk/su",
                "/system_ext/bin/su",
                "/system/xbin/su",
                "/vendor/bin/su",
                "/system/sbin/su",
                WORK + "/pc98260-su"}) {
            java.io.File f = new java.io.File(path);
            if (f.canExecute() && suEntryWorks(f))
                return f;
        }
        return null;
    }

    private boolean suEntryWorks(java.io.File su) {
        try {
            Process p = new ProcessBuilder(su.getAbsolutePath(), "-c", "id -u")
                    .redirectErrorStream(true).start();
            p.getOutputStream().close();
            StringBuilder sb = new StringBuilder();
            try (java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(p.getInputStream(), "UTF-8"))) {
                String line;
                while ((line = r.readLine()) != null)
                    sb.append(line).append('\n');
            }
            if (!p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return false;
            }
            return p.exitValue() == 0 && sb.toString().trim().equals("0");
        } catch (Throwable t) {
            return false;
        }
    }

    private String ksuRootExec(String cmd) throws Exception {
        java.io.File su = findSuEntry();
        if (su == null)
            throw new IllegalStateException("KSU_SU_MISSING");
        Process p = new ProcessBuilder(su.getAbsolutePath(), "-c", cmd)
                .redirectErrorStream(true).start();
        p.getOutputStream().close();
        StringBuilder sb = new StringBuilder();
        try (java.io.BufferedReader r = new java.io.BufferedReader(
                new java.io.InputStreamReader(p.getInputStream(), "UTF-8"))) {
            String line;
            while ((line = r.readLine()) != null)
                sb.append(line).append('\n');
        }
        if (!p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IllegalStateException("KSU_TIMEOUT");
        }
        int rc = p.exitValue();
        if (rc != 0 && sb.length() == 0)
            throw new IllegalStateException("KSU_RC=" + rc);
        return sb.toString();
    }

    private String readProcess(Process p, long timeoutMs) throws Exception {
        p.getOutputStream().close();
        StringBuilder sb = new StringBuilder();
        try (java.io.BufferedReader r = new java.io.BufferedReader(
                new java.io.InputStreamReader(p.getInputStream(), "UTF-8"))) {
            String line;
            while ((line = r.readLine()) != null)
                sb.append(line).append('\n');
        }
        if (!p.waitFor(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)) {
            p.destroyForcibly();
            throw new IllegalStateException("TIMEOUT");
        }
        if (p.exitValue() != 0 && sb.length() == 0)
            throw new IllegalStateException("RC=" + p.exitValue());
        return sb.toString();
    }

    /**
     * Rootd-first execution for Parallel Space repair.
     *
     * stpclear (libstp StpClearStatus) is only reliable from the full-capability
     * rootd context; KSU su is the fallback.  The rootd client uses a leading
     * '!' to request direct exec of the binary.
     */
    private String parallelRootExec(String cmd, boolean directExec) throws Exception {
        java.io.File pc = new java.io.File(WORK, "98260/pc98260-su");
        if (!pc.canExecute()) pc = new java.io.File(WORK, "pc98260-su");
        final String pcPath = pc.getAbsolutePath();
        final String wire = directExec ? "!" + cmd : cmd;
        Exception rootdError = null;
        // Rootd socket is root:shell 0660; the app uid cannot connect.  Run
        // the client through the Shizuku shell (uid 2000) so it joins the
        // shell group and the leading '!' direct-exec keeps full caps.
        try {
            String probe = shellNoThrow("test -x '" + pcPath
                    + "' && test -S /data/local/tmp/pc98260-root.sock && echo ROOTD_OK");
            if (probe != null && probe.contains("ROOTD_OK")) {
                String quoted = "'" + wire.replace("'", "'\\''") + "'";
                String out = shell("/system/bin/timeout 60 " + pcPath + " -c " + quoted);
                if (out != null && !out.contains("connect root daemon")) {
                    return out;
                }
                rootdError = new IllegalStateException(
                        out == null ? "rootd no output" : out);
            }
        } catch (Exception e) {
            rootdError = e;
        }
        // Legacy app-uid path, kept for environments where the socket is
        // world-accessible.
        if (pc.canExecute()) {
            try {
                Process p = Runtime.getRuntime().exec(
                        new String[]{pcPath, "-c", wire});
                return readProcess(p, 20000);
            } catch (Exception e) {
                if (rootdError == null) rootdError = e;
            }
        }
        try {
            return ksuRootExec(cmd);
        } catch (Exception suError) {
            if (rootdError != null)
                throw new IllegalStateException("ROOTD=" + rootdError + " KSU=" + suError);
            throw suError;
        }
    }

    /**
     * Honor's Parallel Space user id is not universally 100 (the MLY-AN00
     * test device uses 103).  Parse pm list users through root first, then fall
     * back to UserManager.  Never issue stop/start for a guessed 100.
     */
    private int findParallelUserId() {
        try {
            String out = parallelRootExec("/system/bin/pm list users", false);
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("UserInfo\\{(\\d+):([^:}]+)")
                    .matcher(out == null ? "" : out);
            while (m.find()) {
                int id = Integer.parseInt(m.group(1));
                String name = m.group(2).toLowerCase(java.util.Locale.ROOT);
                if (name.contains("平行") || name.contains("parallel"))
                    return id;
            }
            log("PARALLEL_USERID_UNKNOWN output=" + (out == null ? "" : out.trim()));
        } catch (Throwable t) {
            log("PARALLEL_USERID_ROOT_WARN=" + t);
        }
        // Never guess 100: on MLY-AN00 the profile is 103, and stopping or
        // launching the wrong user gives RUNNING_LOCKED / 程序准备中.
        return -1;
    }

    /**
     * Stop the Parallel Space user, clear Honor STP/hisecd root verdict, then
     * launch Parallel Space.  Do not stop-user: on MLY-AN00 the profile is
     * user 103, and stopping it leaves it RUNNING_LOCKED, which makes every
     * cloned app show "程序准备中".  Only stpclear + launch are safe here.
     */
    public void fixParallelSpace() {
        if (!beginAction())
            return;
        feedback("正在修复平行空间", "stop-user → 清理 STP → 重新打开", 0);
        runAsync(() -> {
            try {
                ui.setStatus("修复平行空间");
                int parallelUser = findParallelUserId();
                log("PARALLEL_FIX_BEGIN user=" + parallelUser);
                if (parallelUser <= 0) {
                    ui.setStatus("未识别平行空间用户");
                    feedback("平行空间修复失败", "未识别到平行空间用户，请先在设置中创建平行空间", 2);
                    return;
                }
                // 1) stop-user first.  start-user leaves the profile RUNNING_LOCKED
                // on this ROM; force-stop is the path that actually clears it.
                // 2) clear STP.
                // 3) launch Parallel Space, which starts the profile normally.
                log("PARALLEL_FIX_ORDER=stop_user_then_clear_then_launch");
                try {
                    String stopForce = "/system/bin/am stop-user -f " + parallelUser;
                    String stopOut = parallelRootExec(stopForce, false).trim();
                    log("PARALLEL_STOP_USER_FORCE=" + stopOut);
                    if (stopOut.contains("Switch failed") || stopOut.contains("Can't stop")
                            || stopOut.contains("Exception") || stopOut.contains("SecurityException")) {
                        String stopRetry = "/system/bin/am stop-user " + parallelUser;
                        String retryOut = parallelRootExec(stopRetry, false).trim();
                        log("PARALLEL_STOP_USER_RETRY=" + retryOut);
                    }
                } catch (Throwable t) {
                    log("PARALLEL_STOP_USER_WARN=" + t);
                }

                boolean stpOk = ensureStpclearRoot();
                if (stpOk) {
                    try {
                        String out = runStpclearRoot();
                        stpOk = out != null && !out.contains("STP_MISSING");
                        log("STP_CLEAR_RC=" + (stpOk ? "0 " : "fail ") + out);
                    } catch (Throwable t) {
                        stpOk = false;
                        log("STP_CLEAR_WARN=" + t);
                    }
                } else {
                    log("STP_CLEAR=missing");
                }

                String start = "/system/bin/am start -n com.hihonor.parallelspace/.launcher.InitActivity --user 0";
                log("PARALLEL_REOPEN=" + parallelRootExec(start, false).trim());
                if (stpOk) {
                    ui.setStatus("平行空间已修复");
                    feedback("平行空间修复完成", "已识别 User " + parallelUser + "、清理 STP 并打开平行空间", 1);
                } else {
                    ui.setStatus("STP 清理失败");
                    feedback("平行空间未完全修复", "STP 清理失败；已尝试打开，但仍可能被拦截", 2);
                }
            } catch (Throwable t) {
                log("PARALLEL_FIX_FAILED=" + t);
                ui.setStatus("平行空间修复失败");
                feedback("平行空间修复失败", t.toString(), 2);
            } finally {
                endAction();
            }
        });
    }

    /** Identity of the installed APK; an update must invalidate staged assets. */
    private String installedApkStamp() {
        try {
            android.content.pm.PackageInfo pi = getPackageManager()
                    .getPackageInfo(getPackageName(), 0);
            return pi.lastUpdateTime + ":" + pi.getLongVersionCode();
        } catch (Throwable ignored) {
            return "";
        }
    }

    private void writeDeploymentStamp() {
        try {
            String data = "app=1.0.6-13\napk=" + installedApkStamp()
                    + "\nchain=" + ui.getChain()
                    + "\nflavor=" + ui.getKsuFlavor()
                    + "\nmanager=" + ui.getKsuManagerPkg() + "\n";
            shellNoThrow("printf '%s' '" + data.replace("'", "")
                    + "' > '" + WORK + "/.magicroot_assets_ready'");
            log("ASSET_STAMP=ok apk=" + installedApkStamp()
                    + " chain=" + ui.getChain() + " flavor=" + ui.getKsuFlavor());
        } catch (Throwable ignored) {
        }
    }

    /** Check whether a complete deployment already exists on disk. */
    private boolean localDeploymentReady() {
        try {
            String files = shellNoThrow("test -f '" + WORK + "/run.sh' && test -f '"
                    + WORK + "/kernel_profiles.sh' && { test -f '" + WORK
                    + "/98260/run98260.sh' || test -f '" + WORK
                    + "/98260/run6157_full.sh' || test -f '" + WORK
                    + "/61157/run61157.sh'; } && echo OK");
            if (files == null || !files.contains("OK"))
                return false;
            String stamp = shellNoThrow("cat '" + WORK + "/.magicroot_assets_ready' 2>/dev/null");
            if (stamp == null || stamp.trim().isEmpty()) return false;
            // A legacy stamp without the APK identity cannot prove that the
            // staged run.sh/kernel_profiles.sh match this APK update.  Force a
            // fresh deployment instead of running stale scripts.
            String apkStamp = installedApkStamp();
            if (apkStamp.isEmpty() || !stamp.contains("apk=" + apkStamp)) return false;
            return stamp.contains("chain=" + ui.getChain())
                    && stamp.contains("flavor=" + ui.getKsuFlavor())
                    && stamp.contains("manager=" + ui.getKsuManagerPkg());
        } catch (Throwable t) {
            return false;
        }
    }

    private void syncLocalDeploymentState() {
        if (ui == null) return;
        runAsync(() -> {
            if (localDeploymentReady()) {
                runOnUiThread(() -> ui.markAssetsDeployed(true));
            }
        }, "magicroot-local-assets");
    }

    /** One-click shortcut: reuse saved setup, auto-deploy if needed, then run. */
    public void oneClickRoot() {
        if (ui == null || ui.getBusy() || ui.getRunning())
            return;
        if (!Shizuku.pingBinder()
                || Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
            doGrant();
            return;
        }
        if (ui.getAssetsDeployed()) {
            startRun();
            return;
        }
        if (!oneClickWait.compareAndSet(false, true))
            return;
        runAsync(() -> {
            try {
                // A previous boot may have left a complete deployment in
                // /data/local/tmp/magic.  Reuse it instead of wiping/re-staging
                // the whole asset set again.
                if (localDeploymentReady()) {
                    log("ONE_CLICK=reuse_local_deployment chain=" + ui.getChain()
                            + " manager=" + ui.getKsuManagerPkg());
                    oneClickWait.set(false);
                    runOnUiThread(() -> {
                        ui.markAssetsDeployed(true);
                        startRun();
                    });
                    return;
                }
                log("ONE_CLICK=deploy_then_run chain=" + ui.getChain()
                        + " manager=" + ui.getKsuManagerPkg());
                runOnUiThread(() -> feedback("一键提权",
                        "正在按上次设置自动部署，然后开始提权…", 0));
                doStage();
                for (int i = 0; i < 240; i++) {
                    Thread.sleep(500);
                    if (ui.getAssetsDeployed() && !ui.getBusy() && !ui.getRunning()) {
                        oneClickWait.set(false);
                        runOnUiThread(this::startRun);
                        return;
                    }
                    if (!ui.getBusy() && i > 4 && !ui.getAssetsDeployed()) {
                        break;
                    }
                }
                oneClickWait.set(false);
                runOnUiThread(() -> feedback("一键提权失败",
                        "自动部署未完成，请查看运行日志后重试", 2));
            } catch (Throwable t) {
                oneClickWait.set(false);
                log("ONE_CLICK_FAILED=" + t);
                runOnUiThread(() -> feedback("一键提权失败", String.valueOf(t), 2));
            }
        }, "magicroot-one-click");
    }

    public void startRun() {
        if (!beginAction())
            return;
        resetLiveLog();
        if (ui != null) ui.markSetupReady();
        runInProgress = true;
        runProgressValue = 0;
        ui.setRunning(true);
        final boolean chainNow98260 = "98260".equals(ui.getChain());
        ui.startRunProgress();
        ui.setStatus(chainNow98260 ? "98260 准备中" : "提权中");
        // The run page owns progress/status now; do not leave a transient
        // "正在准备" banner over the bottom action bar.
        ui.clearFeedback();;
        final boolean suCompat = ui.getSuCompat();
                final boolean suEntry = ui.getSuEntry();
        final boolean allowShell = ui.getAllowShell();
        final boolean adbRoot = ui.getAdbRoot();
        final boolean kernelUmount = ui.getKernelUmount();
        final boolean selinuxHide = ui.getSelinuxHide();
        final String ksuFlavor = ui.getKsuFlavor();
        final String credMode = ui.getCredMode();
        // The old manager-grant/module-load soft-reboot switches are removed.
        // They issued ksud soft-reboot, which becomes a hard reset on these
        // late-load kernels.  The Tools page now runs lsposed-hotfix.sh only.
        final boolean repairModule = false;
        final boolean repairManager = false;
        // Mutually exclusive debug mode: does not write fsuid=0, therefore
        // must not be combined with the KernelSU su path.
        final boolean skipFsuid = false;
        final int vPerm = ui.getVictimPerm();
        final int vFsuid = ui.getVictimFsuid();
        final int vCred = ui.getVictimCred();
        final String chain = ui.getChain();
        final boolean chain98260 = "98260".equals(chain);
        final boolean preflight98260 = chain98260 && ui.getChain98260Preflight();
        final boolean skipPreflight = ui.getSkipPreflight();
        log("提权任务已启动：等待 DONE / FAIL 标志...");
        log("链路: " + (chain98260 ? "98260（默认 · 6.12.58/58b 已验证 / 6.6.118 profile）" : "64560（备用）"));
        log("内核后端: " + (chain98260
                ? ("98260-rootd + " + (ui.getChain98260Ksu() ? "KernelSU 自动加载" : "仅 rootd（KSU 关闭）"))
                : ui.getKsuManagerLabel() + " (flavor=" + ksuFlavor + ", " + ui.getKsuManagerPkg() + ")"));
        if (chain98260)
            log("cred 分支: " + ("real".equals(credMode)
                    ? "real-cred（独立 cap + direct-finit + 管理器 late-load 用户态）"
                    : "fake-cred（rootd + 管理器 late-load）"));
        log("victims: SELinux=" + vPerm + " fsuid=" + vFsuid + " cred=" + vCred);
        log("fsuid 阶段: " + (skipFsuid ? "跳过（实验）" : "执行"));
        log("su_compat: " + (suCompat ? "开启" : "关闭"));
        log("su entry: " + (suEntry ? "开启（Termux patch + /data/adb/ksud 回退，不依赖 su_compat）" : "关闭"));
        log("keep rootd/socket: " + (ui.getKeepRootdForStp() ? "开启（STP 清理用）" : "关闭"));
                log("allow shell: " + (allowShell ? "开启（默认，模块加载期参数）" : "关闭"));
        log("adb_root: " + (adbRoot ? "开启（KernelSU feature）" : "关闭（源码默认）"));
        log("kernel_umount: " + (kernelUmount ? "开启（默认）" : "关闭"));
        log("selinux_hide: " + (selinuxHide ? "开启（默认）" : "关闭"));
        log("SELinux: 提权结束后默认恢复 Enforcing");
        if (preflight98260) {
            log("98260 预检模式：只做只读检查，不执行 UAF/cred/rootd 阶段");
        }
        if (skipPreflight) {
            log("PREFLIGHT_SKIP=1（显式开关）: 跳过开机稳定等待");
        }
        runAsync(() -> runChain(suCompat, suEntry, allowShell, adbRoot,
                kernelUmount, selinuxHide, ksuFlavor, repairModule, repairManager, skipFsuid, vPerm, vFsuid, vCred,
                chain, preflight98260, skipPreflight), "magicroot-chain");
    }

    /** Public entry used by the UI when the SuSFS step becomes visible. */
    public void refreshLocalSusfsState() {
        runAsync(this::restoreLocalSusfsState, "magicroot-susfs-scan");
    }

    private String readVermagic(File f) {
        try (FileInputStream in = new FileInputStream(f);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > SUSFS_MAX_DOWNLOAD)
                    return null;
            }
            String text = new String(out.toByteArray(), "ISO-8859-1");
            int i = text.indexOf("vermagic=");
            if (i < 0) return null;
            int end = i + "vermagic=".length();
            while (end < text.length() && text.charAt(end) != 0
                    && text.charAt(end) != ' ' && text.charAt(end) != '\n'
                    && text.charAt(end) != '\r')
                end++;
            return text.substring(i + "vermagic=".length(), end);
        } catch (Throwable t) {
            return null;
        }
    }

    /** Discover the newest cached/imported SuSFS guard that matches this KMI. */
    private void restoreLocalSusfsState() {
        try {
            File dir = new File(getFilesDir(), "susfs");
            File[] files = dir.listFiles();
            File newest = null;
            if (files != null) {
                for (File f : files) {
                    if (!f.isFile() || !f.getName().endsWith(".ko")) continue;
                    if (newest == null || f.lastModified() > newest.lastModified()) newest = f;
                }
            }
            if (newest == null) {
                ui.clearSusfsLocalModule();
                return;
            }
            String release = kernelReleaseForSusfs();
            String currentKmi = kmiOf(release);
            if (currentKmi == null) currentKmi = kmiOf(ui.getKernelVersion());
            String actualKmi = kmiOf(String.valueOf(readVermagic(newest)));
            if (currentKmi != null && actualKmi != null && currentKmi.equals(actualKmi)) {
                ui.updateSusfsLocalModule(newest.getName(), actualKmi, "本地缓存");
            } else {
                ui.clearSusfsLocalModule();
            }
        } catch (Throwable t) {
            ui.clearSusfsLocalModule();
            log("SUSFS_LOCAL_SCAN_FAILED=" + t);
        }
    }

    /**
     * Removed: the app no longer downloads or bundles a cross-KMI SuSFS guard.
     * A guard is only valid when its vermagic matches the running kernel and
     * it contains the upstream openat2/syscall-table hardening.  Exact guards
     * must be built per kernel release; accepting a GitHub release here would
     * reintroduce the mismatched-module reboot risk.
     */
    public void updateSusfsLkm() {
        if (!susfsUpdateRunning.compareAndSet(false, true))
            return;
        setSusfsUpdateStatus("正在检查 SuSFS LKM 在线更新…", true);
        runAsync(() -> {
            try {
                String release = kernelReleaseForSusfs();
                String kmi = kmiOf(release);
                if (kmi == null)
                    throw new IllegalStateException("无法确定内核 KMI: " + release);
                String android = regexGroup(release, "android(\\d+)");
                if (android == null)
                    android = androidTokenForSdk();

                JSONObject root = fetchJson(SUSFS_RELEASE_API);
                String tag = root.optString("tag_name", "latest");
                JSONArray assets = root.optJSONArray("assets");
                if (assets == null)
                    throw new IllegalStateException("release 中没有 assets");
                JSONObject exact = null;
                JSONObject fallback = null;
                String exactSuffix = "-" + android + "-" + kmi + ".ko";
                String kmiSuffix = "-" + kmi + ".ko";
                for (int i = 0; i < assets.length(); i++) {
                    JSONObject a = assets.optJSONObject(i);
                    if (a == null)
                        continue;
                    String name = a.optString("name", "");
                    if (!name.endsWith(".ko") || !name.startsWith("susfs_guard_lkm"))
                        continue;
                    if (android != null && name.contains(exactSuffix)) {
                        exact = a;
                    } else if (name.contains(kmiSuffix) && fallback == null) {
                        fallback = a;
                    }
                }
                JSONObject chosen = exact != null ? exact : fallback;
                if (chosen == null)
                    throw new IllegalStateException(
                            "没有找到 KMI=" + kmi + " android=" + android + " 的 .ko");
                String name = chosen.optString("name", "susfs_guard_lkm.ko");
                String url = chosen.optString("browser_download_url", "");
                if (url.isEmpty())
                    throw new IllegalStateException("asset 没有下载地址");
                long expectedSize = chosen.optLong("size", 0L);
                String expectedDigest = chosen.optString("digest", "");

                File dir = new File(getFilesDir(), "susfs");
                if (!dir.exists() && !dir.mkdirs())
                    throw new IllegalStateException("无法创建私有 SuSFS 目录");
                File tmp = new File(dir, "susfs_guard_lkm.download");
                String actualSha = downloadHttp(url, tmp, expectedSize);
                if (expectedDigest.startsWith("sha256:")) {
                    if (!expectedDigest.substring(7).equalsIgnoreCase(actualSha)) {
                        tmp.delete();
                        throw new IllegalStateException("SHA-256 校验失败");
                    }
                } else {
                    log("SUSFS_DIGEST_ABSENT=1 asset=" + name + " sha256=" + actualSha
                            + " size=" + expectedSize);
                }
                validateSusfsKo(tmp, kmi);
                String safeTag = tag.replaceAll("[^A-Za-z0-9._-]", "_");
                File saved = new File(dir, "susfs_guard_lkm-" + safeTag + "-" + kmi + ".ko");
                if (!tmp.renameTo(saved)) {
                    copyFile(tmp, saved);
                    tmp.delete();
                }
                writeSusfsMeta(dir, tag, name, actualSha, kmi, android);
                ui.updateSusfsLocalModule(saved.getName(), kmi, "在线下载");
                boolean staged = stageSusfsUpdated(saved);
                String msg = "已下载 " + tag + " / " + name
                        + (staged ? "；提权时优先加载新版模块"
                        : "；私有目录已保存，但暂存 workdir 失败，提权前请保持 Shizuku 可用");
                setSusfsUpdateStatus(msg, false);
                log("SUSFS_UPDATE=ok tag=" + tag + " asset=" + name
                        + " kmi=" + kmi + " android=" + android
                        + " sha256=" + actualSha + " staged=" + staged
                        + " path=" + saved.getAbsolutePath());
                showToast(msg);
            } catch (Throwable t) {
                String msg = "SuSFS LKM 更新失败: " + t;
                setSusfsUpdateStatus(msg, false);
                log("SUSFS_UPDATE=failed " + t);
                showToast(msg);
            } finally {
                susfsUpdateRunning.set(false);
            }
        }, "magicroot-susfs-update");
    }

    private void setSusfsUpdateStatus(String text, boolean busy) {
        runOnUiThread(() -> {
            ui.setSusfsUpdateBusy(busy);
            ui.setSusfsUpdateStatus(text);
        });
    }

    private void showToast(String text) {
        runOnUiThread(() -> Toast.makeText(this, text, Toast.LENGTH_LONG).show());
    }

    private String kernelReleaseForSusfs() {
        String v = System.getProperty("os.version");
        if (v != null && !v.trim().isEmpty())
            return v.trim();
        v = shellNoThrow("uname -r");
        if (v != null && !v.trim().isEmpty())
            return v.trim();
        v = shellNoThrow("cat /proc/version 2>/dev/null");
        return v == null ? "" : v.trim();
    }

    private String regexGroup(String value, String regex) {
        if (value == null)
            return null;
        Matcher m = Pattern.compile(regex).matcher(value);
        return m.find() ? m.group(1) : null;
    }

    private String kmiOf(String value) {
        if (value == null)
            return null;
        Matcher m = Pattern.compile("(\\d+)\\.(\\d+)").matcher(value);
        return m.find() ? m.group(1) + "." + m.group(2) : null;
    }

    private String androidTokenForSdk() {
        int major = Build.VERSION.SDK_INT - 20;
        return major >= 12 ? "android" + major : null;
    }

    private JSONObject fetchJson(String url) throws Exception {
        HttpURLConnection c = openHttp(url);
        c.setRequestProperty("Accept", "application/vnd.github+json");
        int code = c.getResponseCode();
        if (code != 200)
            throw new IllegalStateException("GitHub API HTTP " + code);
        try (InputStream in = c.getInputStream();
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > 2 * 1024 * 1024)
                    throw new IllegalStateException("GitHub API 响应过大");
            }
            return new JSONObject(out.toString("UTF-8"));
        } finally {
            c.disconnect();
        }
    }

    private HttpURLConnection openHttp(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(15000);
        c.setReadTimeout(45000);
        c.setInstanceFollowRedirects(true);
        c.setRequestProperty("User-Agent", "MagicRoot/1.0.6");
        return c;
    }

    private String downloadHttp(String url, File dst, long expectedSize) throws Exception {
        HttpURLConnection c = openHttp(url);
        c.setRequestProperty("Accept", "application/octet-stream");
        int code = c.getResponseCode();
        if (code != 200)
            throw new IllegalStateException("下载 HTTP " + code);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        long total = 0;
        try (InputStream in = c.getInputStream();
             FileOutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                total += n;
                if (total > SUSFS_MAX_DOWNLOAD)
                    throw new IllegalStateException("下载文件超过上限");
                out.write(buf, 0, n);
                md.update(buf, 0, n);
            }
            out.getFD().sync();
        } finally {
            c.disconnect();
        }
        if (total <= 0)
            throw new IllegalStateException("下载为空");
        if (expectedSize > 0 && total != expectedSize)
            throw new IllegalStateException("大小不匹配 expected=" + expectedSize + " actual=" + total);
        StringBuilder hex = new StringBuilder();
        for (byte b : md.digest())
            hex.append(String.format("%02x", b & 0xff));
        return hex.toString();
    }

    private void validateSusfsKo(File f, String kmi) throws Exception {
        try (FileInputStream in = new FileInputStream(f);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                if (out.size() > SUSFS_MAX_DOWNLOAD)
                    throw new IllegalStateException("模块过大");
            }
            byte[] data = out.toByteArray();
            if (data.length < 4 || data[0] != 0x7f || data[1] != 'E'
                    || data[2] != 'L' || data[3] != 'F')
                throw new IllegalStateException("不是 ELF 模块");
            String text = new String(data, "ISO-8859-1");
            int i = text.indexOf("vermagic=");
            if (i < 0)
                throw new IllegalStateException("没有 vermagic");
            int end = i + "vermagic=".length();
            while (end < text.length() && text.charAt(end) != 0
                    && text.charAt(end) != ' ' && text.charAt(end) != '\n'
                    && text.charAt(end) != '\r')
                end++;
            String vermagic = text.substring(i + "vermagic=".length(), end);
            String actualKmi = kmiOf(vermagic);
            if (!kmi.equals(actualKmi))
                throw new IllegalStateException("vermagic KMI 不匹配: " + vermagic);
            if (!text.contains("susfs_or_entry_expected_hook")) {
                // Upstream may not expose this marker in release builds.  The
                // authoritative gate is the KMI match above; a missing marker
                // is diagnostic only, never a reason to reject the module.
                log("SUSFS_HARDENING=absent kmi=" + actualKmi);
            }
        }
    }

    /** WORK can be rotated when root owns it; the downloaded guard lives in
     *  app-private files/susfs, so re-stage the newest one before every run. */
    private void restageLatestSusfsUpdated() {
        try {
            File dir = new File(getFilesDir(), "susfs");
            File[] files = dir.listFiles();
            if (files == null) return;
            File newest = null;
            for (File f : files) {
                if (!f.isFile() || !f.getName().endsWith(".ko")) continue;
                if (newest == null || f.lastModified() > newest.lastModified()) newest = f;
            }
            if (newest == null) return;
            boolean ok = stageSusfsUpdated(newest);
            log("SUSFS_RESTAGE=" + (ok ? "ok" : "failed")
                    + " file=" + newest.getName() + " bytes=" + newest.length());
        } catch (Throwable t) {
            log("SUSFS_RESTAGE_FAILED=" + t);
        }
    }

    private boolean stageSusfsUpdated(File src) {        try {
            String dest = WORK + "/" + SUSFS_UPDATED_WORK_NAME;
            shell("mkdir -p '" + WORK + "'");
            Process p = shellProcess("cat > '" + dest + "'");
            try (InputStream in = new FileInputStream(src);
                 OutputStream out = p.getOutputStream()) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0)
                    out.write(buf, 0, n);
            }
            try {
                p.waitFor(30, TimeUnit.SECONDS);
            } catch (Throwable ignored) {
            }
            String size = shellNoThrow("wc -c < '" + dest + "'");
            if (size == null || !size.trim().equals(String.valueOf(src.length())))
                return false;
            shellNoThrow("chmod 644 '" + dest + "'");
            return true;
        } catch (Throwable t) {
            log("SUSFS_STAGE_FAILED=" + t);
            return false;
        }
    }

    private void writeSusfsMeta(File dir, String tag, String asset, String sha,
                                String kmi, String android) throws Exception {
        File meta = new File(dir, "latest.txt");
        String text = "tag=" + tag + "\nasset=" + asset + "\nsha256=" + sha
                + "\nkmi=" + kmi + "\nandroid=" + android + "\n";
        try (FileOutputStream out = new FileOutputStream(meta)) {
            out.write(text.getBytes("UTF-8"));
            out.getFD().sync();
        }
    }

    private void copyFile(File src, File dst) throws Exception {
        try (InputStream in = new FileInputStream(src);
             FileOutputStream out = new FileOutputStream(dst)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0)
                out.write(buf, 0, n);
            out.getFD().sync();
        }
    }

    public void doClean() {
        if (!beginAction())
            return;
        feedback("正在清理", "删除本项目工作目录与外部 stage 缓存…", 0);
        runAsync(() -> {
            try {
                runOnUiThread(() -> ui.setStatus("清理中"));
                log("清理中...");
                String cmd = "if [ -f " + WORK + "/clean.sh ]; then sh " + WORK + "/clean.sh; "
                        + "else rm -rf " + WORK
                        + " /storage/emulated/0/Android/data/com.aoki.magicroot/files/stage; "
                        + "fi; echo CLEAN_OK";
                String cleanOut = cleanupShell(cmd);
                log("CLEAN_SHELL=" + cleanOut);
                boolean ok = cleanOut != null && cleanOut.contains("CLEAN_OK")
                        && !cleanOut.toLowerCase(Locale.ROOT).contains("denied")
                        && !cleanOut.toLowerCase(Locale.ROOT).contains("read-only");
                if (!ok) {
                    runOnUiThread(() -> ui.setStatus("清理失败"));
                    feedback("清理失败", "清理脚本未完成，临时文件可能仍在", 2);
                    return;
                }
                clearStageCache();
                runOnUiThread(() -> {
                    ui.markAssetsDeployed(false);
                    ui.setStatus("已清理");
                });
                feedback("清理完成", "已恢复部署前的临时状态", 1);
            } catch (Throwable t) {
                log("清理失败: " + t);
                runOnUiThread(() -> ui.setStatus("清理失败"));
                feedback("清理失败", t.toString(), 2);
            } finally {
                endAction();
            }
        });
    }

    /**
     * Re-stage every APK asset before a run.  The work dir is intentionally
     * persistent (logs/ko cache), so an APK update alone does not update
     * /data/local/tmp/magic.  Without this sync, an old run.sh or t64560_*
     * binary can remain deployed after an update and still enforce an old
     * slab/stale limit.  Always overwrite from the current APK.
     */
    private void ensureWorkDirWritable() throws Exception {
        String state;
        try {
            state = shell("test -w '" + WORK + "' && echo WRITABLE || echo READONLY");
        } catch (Throwable t) {
            log("SHELL_PROBE_ERROR=" + t);
            throw new java.io.IOException("shizuku_shell_error: " + t);
        }
        if (state == null || state.trim().isEmpty()) {
            // Do not misreport a failed Shizuku remote shell as a read-only
            // directory; this used to trigger a pointless rotation loop.
            throw new java.io.IOException("shizuku_shell_unavailable: " + WORK);
        }
        if (state.contains("WRITABLE")) {
            return;
        }
        // A previous root-stage/exploit run can leave /data/local/tmp/magic
        // owned by root.  The app shell (uid 2000) then cannot overwrite it;
        // rotate the whole old dir aside (parent /data/local/tmp is writable)
        // and create a fresh shell-owned work dir.
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

    /** Rotate a root-owned staging subdirectory so uid 2000 can redeploy. */
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

    /**
     * Normalize permissions after every deployment.  stageAssetFrom already
     * chmods the individual file before mv, but this also covers directories,
     * assets restored from older workdirs, and the on-demand stpclear path.
     */
    private void normalizeDeploymentPermissions() {
        shellNoThrow("chmod 755 '" + WORK + "' 2>/dev/null || true");
        shellNoThrow("chmod 755 '" + WORK + "'/*.sh '" + WORK + "'/stpclear '"
                + WORK + "'/pc98260-su '" + WORK + "'/susfs_insmod '" + WORK
                + "'/su_forward '" + WORK + "'/ko_patch '" + WORK
                + "'/kaslr_slide_61258b '" + WORK
                + "'/kaslr_slide_aph112 '" + WORK
                + "'/kaslr_slide_aph136g142 '" + WORK
                + "'/ksu_grant 2>/dev/null || true");
        shellNoThrow("chmod 755 '" + WORK + "'/kaslr-98937 '" + WORK
                + "'/kaslr-98937/poc98937 '" + WORK
                + "'/kaslr-98937/slide98937 '" + WORK
                + "'/kaslr-98937/run98937.sh' 2>/dev/null || true");
        shellNoThrow("chmod 755 '" + WORK + "'/98260 '" + WORK + "'/98260-61258b '"
                + WORK + "'/98260-61258c '"
                + WORK + "'/98260-6138 '"
                + WORK + "'/98260-6123 '" + WORK + "'/98260-g856 '" + WORK + "'/98260-6138y '" + WORK + "'/98260-g4b36 '"
                + WORK + "'/98260-g554 '" + WORK + "'/98260-f171 '" + WORK + "'/98260-61821 '" + WORK + "'/98260-61821-brm '" + WORK + "'/98260-aph112 '" + WORK + "'/98260-h1c '" + WORK + "'/98260-g142 2>/dev/null || true");
        shellNoThrow("chmod 755 '" + WORK + "'/98260/*.sh '" + WORK
                + "'/98260/stpclear '" + WORK + "'/98260/pc98260-su '" + WORK
                + "'/98260-61258b/exploit-android-key-ptr '" + WORK
                + "'/98260-61258c/exploit-android-key-ptr '" + WORK
                + "'/98260-aph112/exploit-android-key-ptr '" + WORK
                + "'/98260-aph112/pc98260-su 2>/dev/null || true");
        shellNoThrow("chmod 755 '" + WORK + "'/98260-61258b/target.sh '" + WORK
                + "'/98260-61258c/target.sh '" + WORK
                + "'/98260-g554/target.sh '" + WORK
                + "'/98260-f171/target.sh '" + WORK
                + "'/98260-aph112/target.sh 2>/dev/null || true");
        shellNoThrow("chmod 755 '" + WORK + "'/98260-6157/* '" + WORK
                + "'/98260-g264/* '" + WORK + "'/98260-gaaa/* '" + WORK + "'/98260-g3306/* '" + WORK
                + "'/98260-g84/* '" + WORK + "'/98260-g77f/* '" + WORK
                + "'/98260-gce849/* '" + WORK + "'/98260-g5859/* '" + WORK
                + "'/98260-g54d/* '" + WORK + "'/98260-g40b1/* '" + WORK
                + "'/98260-g8a496/* '" + WORK + "'/98260-g2e1f/* '" + WORK
                + "'/98260-ge9da/* '" + WORK + "'/98260-g8d6/* '" + WORK
                + "'/g264/* '" + WORK
                + "'/su-g264/* '" + WORK + "'/ksu6157/* '" + WORK
                + "'/ksu6157-g264/* '" + WORK + "'/ksu6157-m6/* "
                + "2>/dev/null || true");
        shellNoThrow("chmod 644 '" + WORK + "'/*.ko '" + WORK + "'/*.so '"
                + WORK + "'/*.txt '" + WORK + "'/98260-*/syms_*.txt 2>/dev/null || true");
        shellNoThrow("chmod -R a+rwX '" + WORK + "' 2>/dev/null || true");
        log("ASSET_CHMOD=ok scripts=755 ko=644");
    }

    /**
     * g928 98260 does not use the legacy CVE-2026-64560 payload/KASLR assets.
     * Keep them in the APK for the 6.12/6.6 legacy chain, but do not deploy
     * them on 6.18.21 where they are dead weight and a stale-state risk.
     */
    private boolean shouldStageLegacyAsset(String name, String release) {
        if (release != null && release.startsWith("6.1.")) {
            return KernelLogHelper.shouldStage6157Asset(name, release);
        }
        boolean r66 = release != null
                && (release.contains("6.6.118-") || release.contains("6.6.89-"));
        boolean r612 = release != null && release.startsWith("6.12.");
        boolean r618 = release != null && release.startsWith("6.18.21-android17-5-");
        boolean rG856 = release != null
                && release.startsWith("6.12.23-android16-5-gcd85666d7884");
        boolean rG142 = release != null
                && release.startsWith("6.12.58-android16-6-g142ddad31e60");
        // 6.12 never dispatches to run6157/run61157.  Do not copy the complete
        // 6.1 CGA/M6 suites into every 6.12 work dir (about 144 MiB of dead data).
        if (r612 && KernelLogHelper.is6157OnlyAsset(name)) return false;
        // g142's 64560 route needs both its dedicated KASLR helper and the
        // per-flavor g142 symbol tables.  Never stage them on another build.
        if (name.equals("kaslr_slide_aph136g142")) return rG142;
        if (name.startsWith("98260-g142/")) return rG142;
        if (name.startsWith("98260-g856/")) return rG856;
        if (name.startsWith("syms_g856")) return rG856;
        if (name.startsWith("syms_g4b36")) {
            return release != null
                    && release.startsWith("6.12.38-android16-5-g4b3671e1f5b7");
        }
        if (name.startsWith("syms_g52d15")) {
            return release != null
                    && release.startsWith("6.12.81-android16-6-g52d15df5db87");
        }
        // SukiSU Nova tables are profile-exact; never stage another 6.12
        // build's table (its addresses would silently mis-patch the LKM).
        if (name.equals("syms_61258_nova.txt")) {
            return release != null
                    && release.startsWith("6.12.58-android16-6-g3a7ac1674240");
        }
        if (name.equals("syms_61258c_nova.txt")) {
            return release != null
                    && release.startsWith("6.12.58-android16-6-g42fcf008ff5c");
        }
        if (name.equals("syms_6138_nova.txt")) {
            return release != null && release.startsWith("6.12.38-android16-5-gfde");
        }
        if (name.startsWith("64560-61821/")) {
            return r618;
        }
        if (name.startsWith("98260-h1c/")) {
            return r618;
        }
        // Only deploy the LKM templates that belong to this KMI.  The manager
        // can still override them with its embedded/carved KO.
        if (name.startsWith("ksu-template")) {
            if (r66) return name.contains("66118");
            if (r618) return name.contains("61821");
            if (r612) return !name.contains("66118") && !name.contains("61821");
        }
        // Keep the bundled ksud fallback on the stable branch.  Manager-apk
        // extraction still runs first; this is only used when extraction fails.
        if (name.startsWith("ksud_")) {
            String flavor = ui == null ? "kernelsu" : ui.getKsuFlavor();
            String selected = "resukisu".equals(flavor) ? "ksud_bakasu" : "ksud_" + flavor;
            return name.equals(selected);
        }
        if (r618) {
            if (name.equals("addrcalc") || name.equals("forker")
                    || name.equals("grab.sh") || name.equals("grab_legacy.sh")
                    || name.equals("root_stage.sh")
                    || name.equals("wait_helper") || name.equals("cred_target")
                    || name.equals("t64560_v36") || name.equals("t64560_cred")
                    || name.equals("ksu_grant")
                    || name.startsWith("kaslr_slide_")
                    || (name.startsWith("syms_") && name.endsWith(".txt")))
                return false;
        }
        if (r66) {
            if (name.startsWith("kaslr_slide_")
                    || (name.startsWith("syms_") && name.endsWith(".txt")))
                return false;
        }
        if (r612 && !r618) {
            if (name.contains("66118") || name.contains("61821"))
                return false;
        }
        return true;
    }

    /** Reclaim 6.1-only directories left by older 6.12 deployments. */
    private void pruneUnused6157AssetsOn612(String release) {
        if (release == null || !release.startsWith("6.12.")) return;
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        paths.add("61157");
        paths.add("g264");
        paths.add("su-g264");
        paths.add("ksu6157");
        paths.add("ksu6157-g264");
        paths.add("ksu6157-m6");
        paths.add("98260/run6157_full.sh");
        paths.add("6157-integrity.tsv");
        for (KernelLogHelper.Profile6157 p : KernelLogHelper.PROFILES_6157)
            paths.add(p.payloadDir);
        StringBuilder cmd = new StringBuilder("rm -rf");
        for (String path : paths)
            cmd.append(" '").append(WORK).append('/').append(path).append('\'');
        cmd.append(" && echo ASSET_PRUNE_612_OK");
        String out = shellNoThrow(cmd.toString());
        log(out != null && out.contains("ASSET_PRUNE_612_OK")
                ? "ASSET_PRUNE_612=ok removed=" + paths.size()
                : "ASSET_PRUNE_612=failed (non-fatal; current deployment remains fail-closed)");
    }

    private void stageAllRuntimeAssets(String chain) throws Exception {
        ensureWorkDirWritable();
        String legacyRelease = kernelReleaseForSusfs();
        pruneUnused6157AssetsOn612(legacyRelease);
        List<String> plan = buildStagePlan(chain, legacyRelease);
        log("ASSET_PLAN count=" + plan.size() + " chain=" + chain
                + " kernel=" + legacyRelease);

        // Fast path: one ZIP upload + one unzip call.  The previous per-asset
        // path made 5-7 Shizuku round trips per file (hundreds of processes).
        if (stagePlanBatch(plan)) {
            normalizeBatchPermissions();
            requireCriticalAssets(chain, legacyRelease);
            log("ASSET_SYNC=ok count=" + plan.size() + " chain=" + chain + " mode=batch");
            return;
        }

        // Fallback: the old per-file path, for devices without unzip or when
        // the Shizuku ZIP pipe is unavailable.
        log("ASSET_BATCH_FALLBACK=1");
        int count = 0;
        for (String name : plan) {
            try {
                stageAsset(name);
            } catch (java.io.FileNotFoundException missing) {
                log("ASSET_MISSING=" + name);
                continue;
            }
            count++;
        }
        normalizeDeploymentPermissions();
        requireCriticalAssets(chain, legacyRelease);
        log("ASSET_SYNC=ok count=" + count + " chain=" + chain + " mode=per-file");
    }

    private static String payloadDirFor6157(String release) {
        return KernelLogHelper.payloadDirFor6157(release);
    }

    private static String cgaBaseFor6157(String release) {
        return KernelLogHelper.cgaBaseFor6157(release);
    }

    private static void appendRequiredFile(StringBuilder cmd, String path) {
        cmd.append(" && test -f '").append(WORK).append("/").append(path).append("'");
    }

    /** Fail deployment instead of stamping a work dir that cannot run. */
    private void requireCriticalAssets(String chain, String release) throws Exception {
        StringBuilder cmd = new StringBuilder();
        cmd.append("test -f '").append(WORK).append("/run.sh' && ")
           .append("test -f '").append(WORK).append("/lib.sh' && ")
           .append("test -f '").append(WORK).append("/kernel_profiles.sh' && ")
           .append("test -f '").append(WORK).append("/ko_patch'");
        if ("98260".equals(chain)) {
            cmd.append(" && { test -f '").append(WORK).append("/98260/run98260.sh'")
               .append(" || test -f '").append(WORK).append("/98260/run6157_full.sh'; }");
            if (release != null && release.startsWith("6.1.")) {
                if (release.startsWith("6.1.157-android14-11-g19a495a97bff")) {
                    // g19a runs run61157.sh with TARGET61157=magicpad, which calls
                    // ksu_handoff_61157() -> kernelsu-magicpad.ko / syms_magicpad3.txt /
                    // ksu-loader-magicpad / 61157/ksud (see ksu_handoff_61157() in
                    // run61157.sh). ksu6157/ksu_prepare, ksu6157/ksu-loader-generic and
                    // ksu6157/ksu-syms.txt belong to ksu_handoff_myuse(), which is only
                    // reachable for TARGET61157=elp (g7d) and g7d is routed to
                    // run6157_full.sh instead, so checking those here never caught a
                    // missing magicpad asset.
                    cmd.append(" && test -f '").append(WORK)
                       .append("/61157/run61157.sh'")
                       .append(" && test -f '").append(WORK)
                       .append("/61157/kernelsu-magicpad.ko'")
                       .append(" && test -f '").append(WORK)
                       .append("/61157/syms_magicpad3.txt'")
                       .append(" && test -f '").append(WORK)
                       .append("/61157/ksu-loader-magicpad'")
                       .append(" && test -f '").append(WORK)
                       .append("/61157/ksud'");
                } else {
                    cmd.append(" && test -f '").append(WORK)
                       .append("/98260/run6157_full.sh'");
                    appendRequiredFile(cmd, "6157-integrity.tsv");
                    String dir = payloadDirFor6157(release);
                    if (release.startsWith("6.1.157-android14-11-g7d3922fade43")) {
                        appendRequiredFile(cmd, "98260-6157/exploit-android-key-ptr");
                        appendRequiredFile(cmd, "98260-6157/pc98260-su");
                        appendRequiredFile(cmd, "ksu6157/sigparam");
                        appendRequiredFile(cmd, "ksu6157-m6/ksu_loader.sh");
                        appendRequiredFile(cmd, "ksu6157-m6/load_ko");
                        appendRequiredFile(cmd, "ksu6157-m6/ko_patch2");
                        appendRequiredFile(cmd, "ksu6157-m6/kernelsu-os9-selx11.ko");
                        appendRequiredFile(cmd, "ksu6157-m6/next_sym_addr.txt");
                        appendRequiredFile(cmd, "ksu6157-m6/ksu_rules");
                        appendRequiredFile(cmd, "ksu6157-m6/post_root.sh");
                    } else {
                        String base = cgaBaseFor6157(release);
                        if (dir == null || base == null) {
                            cmd.append(" && false");
                        } else {
                            appendRequiredFile(cmd, dir + "/exploit-android-key-ptr");
                            appendRequiredFile(cmd, dir + "/pc98260-su");
                            appendRequiredFile(cmd, "g264/ko_slide_patch");
                            appendRequiredFile(cmd, base);
                            appendRequiredFile(cmd, "ksu6157-g264/ksud");
                            appendRequiredFile(cmd, "ksu6157-g264/sigparam");
                            appendRequiredFile(cmd, "su-g264/setup_su_app.sh");
                            appendRequiredFile(cmd, "su-g264/su_lkm");
                            appendRequiredFile(cmd, "su-g264/su_optional.sh");
                            appendRequiredFile(cmd, "su-g264/su_overlay_helper");
                            if (release.startsWith("6.1.157-android14-11-g2646292297b1")) {
                                appendRequiredFile(cmd, "ksu6157-g264/ksu_prepare");
                                appendRequiredFile(cmd, "ksu6157-g264/ksu-loader");
                                appendRequiredFile(cmd, "ksu6157-g264/ksu-syms.txt");
                            }
                        }
                    }
                }
                appendRequiredFile(cmd, "pc98260-su");
                appendRequiredFile(cmd, "root_stage.sh");
                appendRequiredFile(cmd, "libadbroot.so");
                appendRequiredFile(cmd, "su_entry.sh");
            }
            if (release != null
                    && release.startsWith("6.12.23-android16-5-gcd85666d7884")) {
                cmd.append(" && test -f '").append(WORK)
                   .append("/98260-g856/exploit-android-key-ptr'");
            }
            if (release != null
                    && release.startsWith("6.12.58-android16-6-g142ddad31e60")) {
                appendRequiredFile(cmd, "98260-g142/exploit-android-key-ptr");
                appendRequiredFile(cmd, "98260-g142/pc98260-su");
                appendRequiredFile(cmd, "98260-g142/target.sh");
                appendRequiredFile(cmd, "98260-g142/SHA256SUMS.txt");
                appendRequiredFile(cmd, "98260-g142/syms_g142_kernelsu.txt");
                appendRequiredFile(cmd, "98260-g142/syms_g142_bakasu.txt");
                appendRequiredFile(cmd, "98260-g142/syms_g142_next.txt");
                appendRequiredFile(cmd, "98260-g142/syms_g142_sukisu.txt");
                appendRequiredFile(cmd, "98260-g142/syms_g142_fina.txt");
            }
        } else if ("64560".equals(chain) && release != null
                && release.startsWith("6.12.58-android16-6-g142ddad31e60")) {
            appendRequiredFile(cmd, "kaslr_slide_aph136g142");
            appendRequiredFile(cmd, "98260-g142/syms_g142_kernelsu.txt");
            appendRequiredFile(cmd, "98260-g142/syms_g142_bakasu.txt");
            appendRequiredFile(cmd, "98260-g142/syms_g142_next.txt");
            appendRequiredFile(cmd, "98260-g142/syms_g142_sukisu.txt");
            appendRequiredFile(cmd, "98260-g142/syms_g142_fina.txt");
        }
        cmd.append(" && echo ASSET_CRITICAL_OK");
        String out = shell(cmd.toString());
        if (out == null || !out.contains("ASSET_CRITICAL_OK")) {
            String missing = shellNoThrow("for f in run.sh kernel_profiles.sh ko_patch "
                    + "98260/run98260.sh 98260/run6157_full.sh 61157/run61157.sh; do "
                    + "[ -f '" + WORK + "/'$f ] || echo $f; done");
            log("ASSET_CRITICAL_MISSING=" + String.valueOf(missing).trim());
            throw new java.io.IOException("关键运行资产缺失: "
                    + String.valueOf(missing).trim());
        }
    }

    private List<String> buildStagePlan(String chain, String release) {
        LinkedHashSet<String> plan = new LinkedHashSet<>();
        for (String name : ASSETS) {
            if (name == null || name.isEmpty()) continue;
            if (shouldStageLegacyAsset(name, release)) plan.add(name);
        }
        // 6.1.x uses run6157_full.sh/run61157.sh, but run.sh's 98260 entry
        // guard and the shared 98260 directory still need the dispatcher.
        if ("98260".equals(chain) && release != null && release.startsWith("6.1.")) {
            plan.add("98260/run98260.sh");
        }
        if ("98260".equals(chain)
                && release != null
                && !release.startsWith("6.1.157-android14-11-")) {
            log("ASSET_KERNEL_MATCH=" + release);
            for (String name : ASSETS_98260) {
                int slash = name.indexOf('/');
                if (slash <= 0) continue;
                String dir = name.substring(0, slash);
                if (!shouldStage98260Asset(name, dir, release)) continue;
                plan.add(name);
            }
        }
        return new ArrayList<>(plan);
    }

    private boolean stagePlanBatch(List<String> plan) {
        String zip = WORK + "/.assets-batch.zip";
        File localZip = null;
        try {
            shellNoThrow("rm -f '" + zip + "'");
            // One traversal instead of one Shizuku process per profile dir.
            shellNoThrow("chmod -R 777 '" + WORK + "' 2>/dev/null || true");

            File baseDir = getExternalFilesDir(null);
            if (baseDir == null) baseDir = getFilesDir();
            File stageDir = new File(baseDir, "stage");
            if (!stageDir.exists()) stageDir.mkdirs();
            if (!stageDir.isDirectory() || !stageDir.canWrite()) {
                stageDir = new File(getFilesDir(), "stage");
                stageDir.mkdirs();
            }
            stageDir.setReadable(true, false);
            stageDir.setWritable(true, false);
            stageDir.setExecutable(true, false);
            localZip = new File(stageDir, ".asset-batch.zip");
            if (localZip.exists()) localZip.delete();

            long tZip = android.os.SystemClock.elapsedRealtime();
            int entries = 0;
            int missingCount = 0;
            try (ZipOutputStream zos = new ZipOutputStream(
                    new BufferedOutputStream(new FileOutputStream(localZip), 1 << 20))) {
                byte[] buf = new byte[1 << 16];
                for (String name : plan) {
                    InputStream input;
                    try {
                        input = openBundledAsset(name);
                    } catch (java.io.FileNotFoundException missing) {
                        log("ASSET_MISSING=" + name);
                        missingCount++;
                        continue;
                    }
                    try (InputStream in = input) {
                        zos.putNextEntry(new ZipEntry(name));
                        if (name.endsWith(".sh")) {
                            ByteArrayOutputStream normalized = new ByteArrayOutputStream();
                            int n;
                            while ((n = in.read(buf)) > 0) {
                                for (int i = 0; i < n; i++) {
                                    if (buf[i] != '\r') normalized.write(buf[i]);
                                }
                            }
                            byte[] data = normalized.toByteArray();
                            zos.write(data, 0, data.length);
                        } else {
                            int n;
                            while ((n = in.read(buf)) > 0) zos.write(buf, 0, n);
                        }
                        zos.closeEntry();
                        entries++;
                    }
                }
            }
            if (entries <= 0) {
                log("ASSET_BATCH_EMPTY=1 missing=" + missingCount);
                return false;
            }
            localZip.setReadable(true, false);
            long tZipDone = android.os.SystemClock.elapsedRealtime();

            String cp = shell("mkdir -p '" + WORK + "' && cp -f '"
                    + localZip.getAbsolutePath() + "' '" + zip
                    + "' && chmod 644 '" + zip + "' && echo BATCH_CP_OK");
            long tCpDone = android.os.SystemClock.elapsedRealtime();
            if (cp == null || !cp.contains("BATCH_CP_OK")) {
                log("ASSET_BATCH_COPY=failed " + String.valueOf(cp).trim());
                shellNoThrow("rm -f '" + zip + "'");
                return false;
            }
            String out = shell("cd '" + WORK + "' && unzip -o -q '.assets-batch.zip' "
                    + "&& echo BATCH_UNZIP_OK; rm -f '.assets-batch.zip'");
            if (out == null || !out.contains("BATCH_UNZIP_OK")) {
                log("ASSET_BATCH_UNZIP=failed " + String.valueOf(out).trim());
                return false;
            }
            long tUnzipDone = android.os.SystemClock.elapsedRealtime();
            log("ASSET_BATCH=ok entries=" + entries
                    + (missingCount > 0 ? " missing=" + missingCount : "")
                    + " zip_bytes=" + localZip.length()
                    + " zip_ms=" + (tZipDone - tZip)
                    + " cp_ms=" + (tCpDone - tZipDone)
                    + " unzip_ms=" + (tUnzipDone - tCpDone));
            return true;
        } catch (Throwable t) {
            log("ASSET_BATCH_FAILED=" + t);
            shellNoThrow("rm -f '" + zip + "'");
            return false;
        } finally {
            if (localZip != null) {
                try { localZip.delete(); } catch (Throwable ignored) { }
            }
        }
    }

    private void normalizeBatchPermissions() {
        long t0 = android.os.SystemClock.elapsedRealtime();
        // 777 is intentional for /data/local/tmp/magic: the deployment shell may
        // be root-owned while run.sh runs as uid=2000.  It is a temporary dir.
        shellNoThrow("chmod -R 777 '" + WORK + "' 2>/dev/null || true");
        log("ASSET_CHMOD=ok mode=batch ms="
                + (android.os.SystemClock.elapsedRealtime() - t0));
    }

    private boolean shouldStage98260Asset(String name, String dir, String release) {
        return KernelLogHelper.shouldStage98260Asset(name, dir, release, Build.MODEL);
    }

    private void runChain(boolean suCompat, boolean suEntry,
                           boolean allowShell, boolean adbRoot, boolean kernelUmount, boolean selinuxHide,
                           String ksuFlavor, boolean repairModule, boolean repairManager,
                           boolean skipFsuid,
                           int vPerm, int vFsuid, int vCred,
                           String chain, boolean preflight98260, boolean skipPreflight) {
        final boolean chain98260 = "98260".equals(chain);
        final boolean keepRootd = ui.getKeepRootdForStp();
        try {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "magic9:root");
            wakeLock.acquire(6 * 60 * 60 * 1000L);
            // Always sync current APK assets first.  A persistent work dir
            // otherwise keeps an old run.sh/t64560_* after an APK update,
            // which is exactly how a removed slab/stale gate can still exit.
            try {
                log("同步 APK 运行资产到 " + WORK + " ...");
                stageAllRuntimeAssets(chain);
            } catch (Throwable syncError) {
                log("ASSET_SYNC_FAIL=" + syncError);
                ui.setStatus("资产同步失败");
                ui.finishRunProgress(false);
                feedback("资产同步失败", "请重新部署资产后再试", 2);
                return;
            }
            // A rotated WORK dir loses the previously downloaded SuSFS guard;
            // restore the newest private copy after asset staging.
            restageLatestSusfsUpdated();
            // A stale app process can keep serving the previous APK's assets
            // even after an install.  For 6.18, refuse to launch with an old
            // kernel_profiles.sh instead of reporting a misleading
            // kernel_unsupported.
            String deployedRelease = kernelReleaseForSusfs();
            if ("98260".equals(chain) && deployedRelease != null
                    && deployedRelease.startsWith("6.18.")) {
                String probe = shellNoThrow("grep -q 'CHAIN_98260_KERNEL_61821' '"
                        + WORK + "/kernel_profiles.sh' 2>/dev/null && echo OK || echo MISSING");
                if (probe == null || !"OK".equals(probe.trim())) {
                    log("FAIL=asset_stale_618 deployed=" + WORK
                            + "/kernel_profiles.sh expected=CHAIN_98260_KERNEL_61821");
                    ui.setStatus("部署资产未更新");
                    ui.finishRunProgress(false);
                    feedback("部署资产未更新",
                            "请强制停止 MagicRoot 后重新打开，再点「部署资产」后重试", 2);
                    return;
                }
            }
            String check = shell("test -f " + WORK + "/run.sh && echo OK || echo MISSING");
            if (!check.contains("OK")) {
                log("工作目录已在上次成功后清理，请先点「部署资产」");
                ui.setStatus("未部署资产");
                ui.finishRunProgress(false);
                feedback("未部署资产", "请先点击「部署资产」", 2);
                return;
            }
            shell("echo " + (suCompat ? "1" : "0") + " > " + WORK + "/su_compat");
            final boolean susfsOn = ui.getSusfsEnabled();
            if (susfsOn)
                shellNoThrow("echo 1 > " + WORK + "/susfs; chmod 644 " + WORK + "/susfs");
            else
                shellNoThrow("rm -f " + WORK + "/susfs");
            String susfsMarker = shellNoThrow("cat " + WORK + "/susfs 2>/dev/null || echo absent");
            log("SUSFS_SWITCH=" + (susfsOn ? "1" : "0")
                    + " marker=" + (susfsMarker == null ? "absent" : susfsMarker.trim()));
                                    // KernelSU-family backend selection: one of the five managers.
            shell("echo " + ksuFlavor + " > " + WORK + "/ksu_flavor");
            ui.updateRunProgress(6, "提取管理器 KO");
            String managerKsud = "";
            String managerKo = "";
            try {
                String r = extractManagerKsud(ksuFlavor);
                log("管理器文件提取（" + ui.getKsuManagerLabel() + "）: " + r);
                String ksudPath = WORK + "/ksud_" + ksuFlavor + ".manager";
                if (r != null && r.startsWith("manager-apk:")
                        && "OK".equals(String.valueOf(shellNoThrow(
                        "test -x '" + ksudPath + "' && echo OK")).trim())) {
                    managerKsud = ksudPath;
                }
                log("管理器签名提取: " + stageManagerSignature(ksuFlavor));
            } catch (Throwable t) {
                log("MANAGER_EXTRACT_FAIL=" + t);
            }
            try {
                String r = extractManagerLkm(ksuFlavor);
                log("MANAGER_LKM=" + r);
                String koPath = WORK + "/ko-" + ksuFlavor + ".ko";
                if (r != null && !r.contains("source=bundled:")
                        && "OK".equals(String.valueOf(shellNoThrow(
                        "test -f '" + koPath + "' && echo OK")).trim())) {
                    managerKo = koPath;
                }
            } catch (Throwable t) {
                log("MANAGER_LKM_FAIL=" + t);
            }
            log("MANAGER_PREFER_KSUD=" + (managerKsud.isEmpty() ? "missing" : managerKsud));
            log("MANAGER_PREFER_KO=" + (managerKo.isEmpty() ? "missing" : managerKo));
            if (chain98260 && !preflight98260
                    && (managerKsud.isEmpty() || managerKo.isEmpty())) {
                // Never mix a manager's ksud with a bundled/other-manager LKM.
                // The device runner repeats this check before any UAF is armed.
                log("FAIL=manager_pair_missing ksud=" + (managerKsud.isEmpty() ? "missing" : "ok")
                        + " lkm=" + (managerKo.isEmpty() ? "missing" : "ok"));
                ui.setStatus("管理器 ksud/LKM 配对失败");
                ui.finishRunProgress(false);
                feedback("管理器文件不完整",
                        "请确认当前管理器已安装且包含匹配 ksud/LKM；已禁止内置或其他版本回退", 2);
                return;
            }
            // Remove legacy soft-reboot markers.  The manager-grant and
            // module-load soft-reboot options were removed; only the explicit
            // Tools > soft reboot fix may restart zygote/lspd.
            shell("rm -f " + WORK + "/soft_reboot_module " + WORK
                    + "/soft_reboot_manager " + WORK + "/soft_reboot_repair");
            if (skipPreflight)
                shell("touch " + WORK + "/skip-preflight");
            else
                shell("rm -f " + WORK + "/skip-preflight");
            exportStaleRunLog("before-run");
            shell("rm -f " + WORK + "/run.log");
            String stale = shellNoThrow("cat " + WORK + "/marks/PERMISSIVE_STARTED 2>/dev/null");
            if (stale != null && !stale.trim().isEmpty()) {
                log("PREVIOUS_RUN_INCOMPLETE 上次链路在 permissive 阶段中断（可能重启）: "
                        + stale.trim());
                log("WARN 已启用开机稳定等待，请稍候片刻再重试");
            }
            log("开始执行 run.sh（日志同时写入 " + WORK + "/run.log）...");
            // 6.18 must use the HOneClick plant: the legacy BRM timer slab
            // reclaim misses on these builds (page_freed=0), and the H1C
            // engine owns the correct preflight/slide/rootd handoff.
            final String kernelVersion = ui.getKernelVersion();
            // 6.18.21 is H1C-only; the legacy BRM engine was removed.
            final String engine98260 = "h1c";
            // The timer_link/cred_link env vars below are BRM/H1C-specific
            // (6.18.21 only); a 6.12.x/6.6.x boot.img import now produces a
            // plain-kallsyms profile.json with no timer_link field at all
            // (see importAdaptiveBoot), so this lookup must stay scoped to
            // 6.18.x or optString("timer_link") would come back "" and blow
            // up Long.parseUnsignedLong below for every 6.12/6.6 run.
            JSONObject adaptiveProfile = (chain98260 && kernelVersion != null
                    && kernelVersion.startsWith("6.18."))
                    ? findAdaptiveProfile(kernelVersion) : null;
            boolean adaptiveReady = false;
            if (adaptiveProfile != null && adaptiveProfile.optBoolean("vulnerable", false)) {
                adaptiveReady = stageAdaptiveSymbols(adaptiveProfile);
                log("ADAPTIVE_PROFILE=" + adaptiveProfile.optString("id", "")
                        + " ready=" + adaptiveReady);
            }
            String adaptiveEnv = "";
            if (adaptiveReady) {
                long timer = Long.parseUnsignedLong(
                        adaptiveProfile.optString("timer_link").replaceFirst("^0x", ""), 16);
                long negTimer = -timer;
                adaptiveEnv = " MAGICROOT_98260_ADAPTIVE=1"
                        + " MAGICROOT_98260_ADAPTIVE_ID=" + adaptiveProfile.optString("id", "")
                        + " MAGICROOT_98260_ADAPTIVE_SYMS=" + WORK + "/syms_adaptive.txt"
                        + " MAGICROOT_98260_TIMER_LINK=" + adaptiveProfile.optString("timer_link")
                        + " MAGICROOT_98260_NEG_TIMER=" + hexLong(negTimer)
                        + " MAGICROOT_98260_CRED_LINK=" + adaptiveProfile.optString("cred_link")
                        + " MAGICROOT_98260_SELINUX_LINK=" + adaptiveProfile.optString("selinux_link")
                        + " MAGICROOT_98260_USER_NS=" + adaptiveProfile.optString("user_ns")
                        + " MAGICROOT_98260_ROOT_USER=" + adaptiveProfile.optString("root_user")
                        + " MAGICROOT_98260_GROUPS=" + adaptiveProfile.optString("groups")
                        + " MAGICROOT_98260_UCOUNTS=" + adaptiveProfile.optString("ucounts")
                        + " MAGICROOT_98260_SITE_LOW=" + adaptiveProfile.optString("slide_site_low")
                        + " MAGICROOT_98260_KITIMER_SIZE=" + adaptiveProfile.optInt("kitimer_size")
                        + " MAGICROOT_98260_KITIMER_NODE=" + adaptiveProfile.optInt("kitimer_node")
                        + " MAGICROOT_98260_TASK_CRED=" + adaptiveProfile.optInt("task_cred")
                        + " MAGICROOT_98260_CRED_SIZE=" + adaptiveProfile.optInt("cred_size")
                        + " MAGICROOT_98260_SLAB_OBJECTS=" + adaptiveProfile.optInt("slab_objects")
                        + " MAGICROOT_98260_SLAB_PAGES=" + adaptiveProfile.optInt("slab_pages");
            }
            // 6.1.x uses run6157_full.sh's own retry profile (6 attempts /
            // 32 churn per CPU / 8s wait cap).  The 98260 UI tuning targets
            // the 6.12/6.6/6.18 chain; exporting 12/256 here would make the
            // 6.1 route burn 8x more empty retries.  Values match the
            // HyperBreak integration's tested 6.1 profile.
            final boolean is6157Chain = KernelLogHelper.findProfile6157(kernelVersion) != null;
            final int tuneAttempts = is6157Chain ? 6 : ui.getChain98260Attempts();
            final int tuneChurnPerCpu = is6157Chain ? 32 : ui.getChain98260ChurnPerCpu();
            final int tuneWaitCap = is6157Chain ? 8 : ui.getChain98260WaitCap();
            log("98260_TUNE family=" + (is6157Chain ? "6.1" : "98260")
                    + " attempts=" + tuneAttempts
                    + " churnPerCpu=" + tuneChurnPerCpu
                    + " waitCap=" + tuneWaitCap);
            String env = "MAGICROOT_VICTIMS_PERMISSIVE=" + vPerm
                    + " MAGICROOT_VICTIMS_FSUID=" + vFsuid
                    + " MAGICROOT_VICTIMS_CRED=" + vCred
                    + " MAGICROOT_SU_COMPAT=" + (suCompat ? "1" : "0")
                    
                    + " MAGICROOT_SU_ENTRY=" + (suEntry ? "1" : "0")
                    + " MAGICROOT_KEEP_ROOTD=" + (keepRootd ? "1" : "0")
                    + " MAGICROOT_STP_COMPAT=" + ((!suCompat && !suEntry && keepRootd) ? "1" : "0")
                    + " MAGICROOT_ALLOW_SHELL=" + (allowShell ? "1" : "0")
                    + " MAGICROOT_ADB_ROOT=" + (adbRoot ? "1" : "0")
                    + " MAGICROOT_KERNEL_UMOUNT=" + (kernelUmount ? "1" : "0")
                    + " MAGICROOT_SELINUX_HIDE=" + (selinuxHide ? "1" : "0")
                    + " MAGICROOT_SUSFS=" + (susfsOn ? "1" : "0")
                    + " MAGICROOT_SUSFS_PROTECT=" + (ui.getSusfsProtectMode() ? "1" : "0")
                    + " MAGICROOT_SUSFS_ALLOW_UNHARDENED=" + (ui.getSusfsAllowUnhardened() ? "1" : "0")
                    + " MAGICROOT_KSU_FLAVOR=" + ksuFlavor
                    + " MAGICROOT_KSUD=" + managerKsud
                    + " MAGICROOT_MANAGER_KO=" + managerKo
                    + " MAGICROOT_KSU_PKG=" + ui.getKsuManagerPkg()
                    + " MAGICROOT_KSU_MANAGER_VERSION=" + managerVersionCode(ksuFlavor)
                    + " MAGICROOT_CHAIN=" + chain
                    + " MAGICROOT_ENABLE_98260=" + (chain98260 ? "1" : "0")
                    + " MAGICROOT_98260_CRED_MODE=" + ui.getCredMode()
                    + " MAGICROOT_98260_PREFLIGHT=" + (preflight98260 ? "1" : "0")
                    + " MAGICROOT_98260_ENGINE=" + engine98260
+ " MAGICROOT_98260_KSU=" + ((chain98260 && ui.getChain98260Ksu()) ? "1" : "0")
                    + " MAGICROOT_98260_ATTEMPTS=" + tuneAttempts
                    + " MAGICROOT_98260_CHURN_ROUNDS=" + ui.getChain98260ChurnRounds()
                    + " MAGICROOT_98260_CHURN_PER_CPU=" + tuneChurnPerCpu
                    + " MAGICROOT_98260_WAIT_CAP=" + tuneWaitCap
                    + " MAGICROOT_98260_CUSTOM_KO=" + (ui.getCustomKoEnabled() ? ui.getCustomKoPath() : "")
                    + " MAGICROOT_CUSTOM_KO=" + (ui.getCustomKoEnabled() ? ui.getCustomKoPath() : "")
                    + " MAGICROOT_REPAIR=" + ((repairModule || repairManager) ? "1" : "0")
                    + " MAGICROOT_SKIP_PREFLIGHT=" + (skipPreflight ? "1" : "0")
                    + adaptiveEnv;
            // Line-buffered pump: `tee` may block-buffer its stdout, which made
            // the in-app log look frozen while run.log kept growing.  The shell
            // read loop prints each line immediately and appends it to run.log.
            // Keep the separator here, not at the end of the env string: a
            // missing/trimmed trailing space would turn the last assignment
            // into "...=0sh run.sh" (sh: run.sh inaccessible or not found).
            shellNoThrow((keepRootd ? ": > " : "rm -f ") + WORK + "/.keep-rootd-user");
            // A previous DONE in run.log must never be mistaken for this run.
            shellNoThrow(": > " + WORK + "/run.log");
            Process p = shellProcess("cd " + WORK + " && " + env
                    + " sh run.sh < /dev/null 2>&1 | while IFS= read -r __ml; do "
                    + "printf '%s\\n' \"$__ml\"; "
                    + "printf '%s\\n' \"$__ml\" >> " + WORK + "/run.log; done");

            // The child stdout pipe from Shizuku can stall while the
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
                    String line;
                    while ((line = r.readLine()) != null) {
                        // run.log polling feeds the UI, but detect the final
                        // markers here too: if the Shizuku poller is busy or
                        // stalled, the tail-exit thread must still see DONE.
                        String tr = line.trim();
                        if (tr.equals("DONE"))
                            sawDone.set(true);
                        if (tr.startsWith("FAIL="))
                            sawFail.set(true);
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

            final AtomicBoolean watchdogTimedOut = new AtomicBoolean(false);
            Thread watchdog = new Thread(() -> {
                try {
                    Thread.sleep(1800000L);
                } catch (InterruptedException e) {
                    return;
                }
                if (!processFinished.get()) {
                    watchdogTimedOut.set(true);
                    sawFail.set(true);
                    log("FAIL=run_timeout 1800s；强制结束 run.sh，避免界面无限等待");
                    log("HINT=若设备仍异常请重启手机后再试");
                    try {
                        p.destroyForcibly();
                    } catch (Throwable ignored) {
                    }
                }
            }, "magicroot-run-watchdog");
            watchdog.setDaemon(true);
            watchdog.start();

            // If run.sh has already printed DONE/FAIL but a background child
            // inherited the stdout pipe, the wrapper shell can stay alive and
            // p.waitFor() would block until the 900s watchdog.  Bound that tail
            // wait to 10s so the UI cannot sit at 100% indefinitely.
            Thread tailExit = new Thread(() -> {
                while (!processFinished.get()) {
                    if (sawDone.get() || sawFail.get()) {
                        try {
                            Thread.sleep(10000L);
                        } catch (InterruptedException e) {
                            return;
                        }
                        if (!processFinished.get()) {
                            log("run.sh 已输出完成标志但进程未退出，强制结束管道");
                            try {
                                p.destroyForcibly();
                            } catch (Throwable ignored) {
                            }
                        }
                        return;
                    }
                    try {
                        Thread.sleep(500L);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }, "magicroot-tail-exit");
            tailExit.setDaemon(true);
            tailExit.start();
            try {
                // Do not call Process.waitFor(timeout): Shizuku's
                // waitForTimeout throws a Java "process not end" exception even
                // though timeout is a normal condition.  Blocking waitFor plus
                // our own watchdog is reliable.
                p.waitFor();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Throwable t) {
                log("WARN waitFor exception: " + t);
            }
            processFinished.set(true);
            watchdog.interrupt();
            tailExit.interrupt();
            if (watchdogTimedOut.get()) {
                log("run.sh 已因 watchdog 结束");
            }
            try {
                logPoller.join(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            drainer.interrupt();
            log("run.sh 已退出");

            String fullLog;
            synchronized (runLog) {
                fullLog = runLog.toString();
            }
            int finalKind = finishKind(fullLog);
            boolean success = sawDone.get() && !sawFail.get() && finalKind != 2;
            if (sawDone.get() && !sawFail.get())
                log("检测到 DONE（流式），提权流程完成");
            else if (sawFail.get())
                log("检测到 FAIL，保留现场日志");

            if (!success) {
                String tail = tailLines(fullLog, 50);
                if (!tail.isEmpty()) {
                    success = (finishKind(tail) == 1);
                    if (success)
                        log("检测到 DONE（进程已退出），准备清理");
                }
            }

            if (preflight98260) {
                if (fullLog.contains("CHAIN_98260_PREFLIGHT_OK=1")) {
                    log("98260 预检通过（只读，未执行任何提权阶段）");
                    ui.setStatus("98260 预检通过");
                    ui.finishPreflight(true);
                    feedback("98260 预检通过", "只读检查完成，未执行任何提权阶段；详情见日志", 1);
                } else {
                    log("98260 预检未通过（详见日志 PREFLIGHT_OK=0）");
                    ui.setStatus("98260 预检未通过");
                    ui.finishPreflight(false);
                    feedback("98260 预检未通过", "只读检查未通过，未执行任何提权阶段，详见日志", 2);
                }
                return;
            }

            if (success) {
                final boolean softRebootUnsafe = fullLog.contains("98260_SOFT_REBOOT_SAFE=0");
                if (softRebootUnsafe)
                    log("98260 仍有未证明 armed victim：管理器软重启/zygote 全场收尸可能触发内核 panic（已允许执行，风险自担）");
                try {
                    p.waitFor(5, TimeUnit.SECONDS);
                } catch (Throwable ignored) {
                }
                ui.setStatus(softRebootUnsafe ? "提权完成 · 软重启有风险" : "提权完成");
                // Keep the full run log in memory so 导出日志 still works after
                // the work directory has been cleaned.
                lastRunLogText = fullLog;
                // Export the success log before cleaning the work directory so
                // the success page's 导出日志 button still has a source file.
                String successLogPath = "";
                try {
                    String dir = "/sdcard/Download/MagicRoot";
                    successLogPath = dir + "/magicroot-success-" + System.currentTimeMillis() + ".log";
                    shell("mkdir -p " + dir + " && cp " + WORK + "/run.log " + successLogPath
                            + " && { " + diagnosticLogLoop() + "; true; } >> " + successLogPath
                            + " 2>/dev/null; chmod 644 " + successLogPath + " 2>/dev/null; true");
                } catch (Throwable ignored) {
                }
                final String cleanCmd = "if [ -f " + WORK + "/clean.sh ]; then sh " + WORK
                        + "/clean.sh; else rm -rf " + WORK + "; fi";
                final boolean autoCleanTemp = ui.getAutoCleanTemp();
                if (chain98260) {
                    if (keepRootd) {
                        log("98260 链成功：已按设置保留 rootd/socket（STP 清理用），跳过自动清理");
                    } else {
                    boolean ksuLoaded = fullLog.contains("98260_KSU=loaded");
                    boolean ksuFailed = fullLog.contains("98260_KSU=failed");
                    // "loaded" only proves the LKM is resident.  Without a
                    // working su the manager is not registered and cleanup
                    // would delete the only fallback (rootd client), making
                    // the Tools > su entry repair impossible.
                    boolean ksuSuReady = fullLog.contains("98260_KSU_SU_WAIT=1")
                            // The real-cred path reuses the proof it already
                            // made instead of re-probing for 60 s.
                            || fullLog.contains("98260_KSU_SU_WAIT=reuse")
                            || fullLog.contains("98260_SU_PROVIDER_EARLY=")
                            || fullLog.contains("98260_SU_PROVIDER_POST=")
                            // run98260 shut the listener down after a proven su;
                            // the generic finalize must not contradict it.
                            || fullLog.contains("98260_CLEANUP=ok reason=ksu_loaded")
                            || fullLog.contains("98260_ROOTD_CLEANUP=handled")
                            // 6.1.x manager-KO / CGA paths report this form.
                            || fullLog.contains("98260_SU_PROVIDER=ready");
                    if (ksuLoaded && !ksuSuReady) {
                        log("98260 链成功：KernelSU 模块已加载，但 su 未就绪；保留工作目录与 rootd，可在本次 boot 内重试 su entry");
                    } else if (ksuLoaded) {
                        if (softRebootUnsafe) {
                            // unproven armed victims must stay owned by the live
                            // watcher.  Cleaning the workdir used to hide this
                            // state and made a later parent exit look harmless;
                            // last_kmsg 01:12 shows init reaping such a zombie.
                            log("98260 仍有 unproven victim：保留工作目录与 plant 看护进程，重启后再清理");
                        } else if (autoCleanTemp) {
                            log("98260 链成功：KernelSU 已加载，按默认设置清理临时文件与 rootd socket");
                            cleanupShell(cleanCmd);
                            clearStageCache();
                            ui.markAssetsDeployed(false);
                            log("临时文件已清理；rootd 进程仅作为本次 boot 的兜底保留");
                        } else {
                            log("98260 链成功：KernelSU 已加载，已关闭自动清理，保留临时文件");
                        }
                    } else if (ksuFailed) {
                        log("98260 链成功：仅 rootd 提权，KernelSU 未加载");
                        log("为保留 root 兜底，跳过自动清理；重启前不要强制结束 plant");
                    } else {
                        log("98260 链成功：rootd 通道保留在当前 boot，跳过自动清理");
                    }
                    }
                } else {
                    if (autoCleanTemp) {
                        log("开始清理工作目录...");
                        cleanupShell(cleanCmd);
                        clearStageCache();
                        ui.markAssetsDeployed(false);
                        log("提权完成，工作目录已清理（下次运行请重新部署资产）");
                    } else {
                        log("已关闭自动清理，保留工作目录");
                    }
                }
                ui.finishRunProgress(true);
                int elapsed = ui.getRunElapsedSec();
                ui.openSuccess(elapsed, successLogPath);
                ui.setStatus(softRebootUnsafe ? "提权完成 · 软重启有风险" : "提权完成");
                if (softRebootUnsafe) {
                    feedback("提权完成，但软重启有风险",
                            "仍有未证明的 timer-UAF victim；FinaSU 等 Flavor 的管理器软重启可能触发内核 panic 或硬重启，已允许执行", 2);
                } else {
                    feedback("提权完成", "耗时 " + elapsed + "s，可从成功页导出日志", 1);
                }
            } else {
                // Keep the failed run's log too: its victim ledger summary
                // (unproven=N) is what the soft-reboot guard reads to avoid a
                // panic on the next zygote restart.
                lastRunLogText = fullLog;
                try {
                    String failDir = "/sdcard/Download/MagicRoot";
                    String failPath = failDir + "/fail_log_" + System.currentTimeMillis() + ".txt";
                    shell("mkdir -p " + failDir + " && cp " + WORK + "/run.log " + failPath
                            + " && { " + diagnosticLogLoop() + "; true; } >> " + failPath
                            + " && chmod 644 " + failPath + " 2>/dev/null || true");
                    log("失败日志已导出: " + failPath);
                } catch (Throwable ignored) {
                }
                ui.setStatus("失败，日志已保留");
                ui.finishRunProgress(false);
                if (chain98260) {
                    boolean mustRestart = fullLog.contains("98260_PARKED=1")
                            || fullLog.contains("98260_H1C_PLANT_STARTED=1")
                            || fullLog.contains("98260_plant_alive_same_boot")
                            || fullLog.contains("98260_h1c_plant_already_running")
                            || fullLog.contains("stage_already_started")
                            || fullLog.contains("98260_BOOT_CHANGED");
                    if (mustRestart) {
                        feedback("98260 失败（需重启）",
                                "本次 boot 已启动或停放 98260 plant：请重启后再试，勿重复触发 UAF 或 kill 父进程", 2);
                    } else {
                        feedback("98260 失败", "日志已导出到 Download/MagicRoot；请发我完整日志", 2);
                    }
                } else {
                    feedback("提权失败", "下一步：日志已导出到 Download/MagicRoot，请发我完整日志", 2);
                }
            }
        } catch (Throwable t) {
            log("执行失败: " + t);
            ui.setStatus("执行失败");
            ui.finishRunProgress(false);
            feedback("执行失败", t.toString(), 2);
        } finally {
            runInProgress = false;
            ui.setRunning(false);
            endAction();
            if (wakeLock != null && wakeLock.isHeld())
                wakeLock.release();
        }
    }

    /** 1=DONE, 2=FAIL=, 0=unfinished; only line starts match. */
    private int finishKind(String tail) {
        return KernelLogHelper.finishKind(tail);
    }

    /**
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
            for (String s : chunk.split("\n")) {
                if (s.isEmpty())
                    continue;
                added++;
                synchronized (runLog) {
                    runLog.append(s).append('\n');
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
                persistLiveLog(line);
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

    private void updateProgressFromLine(String line) {
        RunProgress.Step step = RunProgress.classify(line, runProgressValue);
        if (step == null)
            return;
        if (step.percent > runProgressValue)
            runProgressValue = step.percent;
        final int progress = step.percent;
        final String stage = step.stage;
        mainHandler.post(() -> {
            if (!isDestroyed()) {
                ui.updateRunProgress(progress, stage);
                if (stage.startsWith("98260：") || "98260 准备中".equals(ui.getStatus())
                        || stage.startsWith("SuSFS")) {
                    ui.setStatus(stage);
                }
            }
        });
    }

    private static String tailLines(String text, int count) {
        return KernelLogHelper.tailLines(text, count);
    }

    private boolean beginAction() {
        if (!actionBusy.compareAndSet(false, true))
            return false;
        ui.setBusy(true);
        return true;
    }

    private void endAction() {
        actionBusy.set(false);
        ui.setBusy(false);
    }

    /**
     * Tools action: manually export the last run.log (or the previous exported
     * copy) without waiting for the next app launch.
     */
    public void exportLastRunLog() {
        feedback("导出上次日志", "正在读取 run.log…", 0);
        runAsync(() -> {
            try {
                boolean ok = exportStaleRunLog("manual");
                if (ok) {
                    feedback("日志已导出", "Download/MagicRoot", 1);
                } else if (lastRunLogText != null && !lastRunLogText.isEmpty()) {
                    // The file may have been cleaned; the retained in-memory
                    // log is still exportable.
                    exportCurrentLog();
                } else {
                    feedback("没有可导出的日志", "run.log 不存在或正在运行", 2);
                }
            } catch (Throwable t) {
                feedback("日志导出失败", t.toString(), 2);
            }
        }, "magicroot-export-last-log");
    }

    /**
     * Success-page action: export the retained run log to Download/MagicRoot
     * (same destination convention as the failure log) and report an explicit
     * success/failure message on the success page.
     */
    public void exportSuccessLog() {
        final String snap = ui.getSuccessLogPath();
        final String mem = lastRunLogText;
        ui.setExportResult("正在导出…", true);
        runAsync(() -> {
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
                        + "echo \"EXPORT_OK=$(wc -c < '" + dst + "')\"; "
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
        });
    }

    /** Export the in-memory UI log to Download/MagicRoot without clipboard. */
    public void exportCurrentLog() {
        final String mem = ui == null ? "" : ui.getLogText();
        if (mem == null || mem.isEmpty()) {
            feedback("没有可导出的日志", "当前日志为空", 2);
            return;
        }
        feedback("导出日志", "正在写入 Download/MagicRoot…", 0);
        runAsync(() -> {
            String dir = "/sdcard/Download/MagicRoot";
            String dst = dir + "/magicroot-log-" + System.currentTimeMillis() + ".txt";
            String cachePath = "";
            try {
                File base = getExternalFilesDir(null);
                if (base == null) base = getFilesDir();
                File cache = new File(base, "export-current.log");
                try (FileOutputStream out = new FileOutputStream(cache)) {
                    out.write(mem.getBytes("UTF-8"));
                    out.flush();
                    out.getFD().sync();
                }
                cachePath = cache.getAbsolutePath();
                String cmd = "mkdir -p '" + dir + "'; "
                        + "cp -f '" + cachePath + "' '" + dst + "' 2>/dev/null; "
                        + "chmod 644 '" + dst + "' 2>/dev/null; "
                        + "if [ -s '" + dst + "' ]; then "
                        + "echo EXPORT_OK=$(wc -c < '" + dst + "'); "
                        + "else echo EXPORT_FAIL; fi";
                String out = shell(cmd);
                if (out != null && out.contains("EXPORT_OK=")) {
                    String size = out.replaceAll("(?s).*EXPORT_OK=([0-9]+).*", "$1").trim();
                    final String msg = "日志已导出: " + dst + " (" + size + " B)";
                    log(msg);
                    runOnUiThread(() -> feedback("日志已导出", dst, 1));
                } else {
                    final String msg = "日志导出失败: " + (out == null ? "no shell output" : out.trim());
                    log(msg);
                    runOnUiThread(() -> feedback("日志导出失败", msg, 2));
                }
            } catch (Throwable t) {
                log("LOG_EXPORT_FAILED=" + t);
                runOnUiThread(() -> feedback("日志导出失败", String.valueOf(t), 2));
            }
        }, "magicroot-export-current-log");
    }

    /** Success-page action: close the success page and go back to the home page. */
    public void returnHome() {
        ui.closeSuccess();
        ui.setExportResult("", true);
        ui.clearFeedback();
    }

    // ------------------------------------------------------------------
    // Installed-manager payload extraction
    // ------------------------------------------------------------------
    private static final String[] FLAVOR_ORDER = {"kernelsu", "resukisu", "next", "sukisu", "fina", "nova", "maplesu"};

    private String managerPkgOf(String flavor) {
        if (ui != null) {
            String override = ui.getManagerPkgOverride();
            if (override != null && !override.trim().isEmpty()
                    && isPackageInstalled(override.trim())) {
                return override.trim();
            }
        }
        String resolved = findInstalledManagerPkg(flavor);
        if (isPackageInstalled(resolved)) return resolved;
        switch (flavor) {
            case "fina": return "me.yuki.fina";
            case "kernelsu": return "me.weishu.kernelsu";
            case "sukisu": return "com.sukisu.ultra";
            case "next": return "com.rifsxd.ksunext";
            case "nova": return "com.sukisu.nova";
            case "maplesu": return "dev.maplesu.manager";
            default: return "com.resukisu.resukisu";
        }
    }

    private String managerVersionCode(String flavor) {
        try {
            PackageInfo pi = getPackageManager().getPackageInfo(managerPkgOf(flavor), 0);
            return String.valueOf(pi.getLongVersionCode());
        } catch (Throwable ignored) {
            return "";
        }
    }

    private byte[] readZipEntry(ZipFile zf, ZipEntry entry) throws Exception {
        try (InputStream in = zf.getInputStream(entry);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0)
                bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    /** Write the extracted ksud to the work dir and verify it with `-V`. */
    private String stageExtractedKsud(byte[] data, String flavor) {
        try {
            File base = getExternalFilesDir(null);
            if (base == null)
                base = getFilesDir();
            File stageDir = new File(base, "stage");
            if (!stageDir.exists() && !stageDir.mkdirs()) {
                stageDir = new File(getFilesDir(), "stage");
                stageDir.mkdirs();
            }
            stageDir.setReadable(true, false);
            stageDir.setWritable(true, false);
            stageDir.setExecutable(true, false);
            File local = new File(stageDir, "ksud_" + flavor + ".extract");
            try (FileOutputStream out = new FileOutputStream(local)) {
                out.write(data);
                out.flush();
                out.getFD().sync();
            }
            local.setReadable(true, false);
            local.setExecutable(true, false);
            String dest = WORK + "/ksud_" + flavor + ".manager";
            shell("cp -f '" + local.getAbsolutePath() + "' '" + dest
                    + "' && chmod 755 '" + dest + "'");
            String ver = shellNoThrow(dest + " -V 2>&1 | head -1");
            local.delete();
            if (ver != null && ver.contains("ksud"))
                return ver.trim();
            shellNoThrow("rm -f '" + dest + "'");
            return null;
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * Extract the userspace ksud from the installed manager APK (same approach
     * as the reference pipeline: the payload lives in the APK's native libs;
     * newer forks rename libksud.so, so the other arm64 .so candidates are
     * probed until one answers `-V`).
     */
    private String extractManagerKsud(String flavor) {
        String pkg = managerPkgOf(flavor);
        try {
            ApplicationInfo ai = getPackageManager().getApplicationInfo(pkg, 0);
            try (ZipFile zf = new ZipFile(new File(ai.sourceDir))) {
                String[] prefer = {
                        "lib/arm64-v8a/libksud.so",
                        "assets/ksud",
                        "lib/arm64-v8a/libksud",
                };
                for (String cand : prefer) {
                    ZipEntry e = zf.getEntry(cand);
                    if (e == null)
                        continue;
                    String ver = stageExtractedKsud(readZipEntry(zf, e), flavor);
                    if (ver != null)
                        return "manager-apk:" + cand + " " + ver;
                }
                ZipEntry best = null;
                java.util.Enumeration<? extends ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    String n = e.getName();
                    if (!n.startsWith("lib/arm64-v8a/") || !n.endsWith(".so"))
                        continue;
                    if (n.contains("libadbroot") || n.contains("libkernelsu")
                            || n.contains("libandroidx") || n.contains("libdatastore"))
                        continue;
                    if (best == null || e.getSize() > best.getSize())
                        best = e;
                }
                if (best != null) {
                    String ver = stageExtractedKsud(readZipEntry(zf, best), flavor);
                    if (ver != null)
                        return "manager-apk:" + best.getName() + " " + ver;
                }
            }
            return "管理器里没有可用 ksud（" + pkg + "），请安装或更新对应管理器后重试";
        } catch (Throwable t) {
            return "管理器未安装（" + pkg + "），请先安装该管理器";
        }
    }

    /**
     * KMI .ko adaptive extraction from the installed manager APK.
     *
     * KernelSU-family managers (official/Next/SukiSU/FinaSU/KowSU) embed
     * prebuilt KMI modules as raw-deflate streams inside lib/arm64-v8a/
     * libksud.so (not as .ko zip entries).  The reference 2.12.19 APK carves
     * 0xED-prefixed raw-deflate streams, checks the ELF header, reads the
     * .modinfo vermagic and selects the module matching the device KMI; it
     * then patches vermagic to uname -r and feeds the module to the loader.
     *
     * Here we carve and select the matching KMI, write WORK/ko-<flavor>.ko,
     * and leave vermagic/symbol rewriting to ko_patch (same strategy as the
     * existing 6.12.76 templates).  If the manager has no embedded module,
     * fall back to a real .ko zip entry, then to the bundled template.
     */
    private String extractManagerLkm(String flavor) {
        String pkg = managerPkgOf(flavor);
        String dest = WORK + "/ko-" + flavor + ".ko";
        // A stale manager LKM from an earlier extraction must never survive a
        // failed or mismatched selection.
        shellNoThrow("rm -f '" + dest + "'");
        try {
            ApplicationInfo ai = getPackageManager().getApplicationInfo(pkg, 0);
            // Use the app-visible kernel release first.  uname(2) can be
            // sanitized/spoofed by KernelSU/SuSFS modules and has produced the
            // wrong KMI (6.6.127) on a 6.12.58 kernel before.
            String osver = System.getProperty("os.version");
            String uname = shellNoThrow("uname -r");
            String procver = shellNoThrow("cat /proc/version 2>/dev/null");
            String kernel = firstKernelRelease(osver, uname, procver);
            String kver = kmiOfKernel(kernel);
            String patch = patchOfKernel(kernel);
            if (kver.isEmpty()) {
                return "MANAGER_LKM=none package=" + pkg
                        + " reason=unknown_kmi os.version=" + osver
                        + " uname=" + uname;
            }
            java.util.ArrayList<String> apks = new java.util.ArrayList<>();
            if (ai.sourceDir != null) apks.add(ai.sourceDir);
            if (ai.splitSourceDirs != null) {
                for (String split : ai.splitSourceDirs)
                    if (split != null && !apks.contains(split)) apks.add(split);
            }
            byte[] carved = null;
            String source = "";
            String vermagic = "";

            // 1) Embedded raw-deflate KMI modules in the manager native lib.
            for (String apk : apks) {
                try (ZipFile zf = new ZipFile(new File(apk))) {
                    java.util.ArrayList<String> libs = new java.util.ArrayList<>();
                    java.util.Enumeration<? extends ZipEntry> en = zf.entries();
                    while (en.hasMoreElements()) {
                        ZipEntry e = en.nextElement();
                        String n = e.getName();
                        if (n.equals("lib/arm64-v8a/libksud.so")) {
                            libs.add(0, n);
                        } else if (n.startsWith("lib/arm64-v8a/") && n.endsWith(".so")
                                && !n.contains("libkernelsu") && !n.contains("libadbroot")
                                && !n.contains("libandroidx") && !n.contains("libdatastore")) {
                            libs.add(n);
                        }
                    }
                    for (String lib : libs) {
                        byte[] data = readZipEntry(zf, zf.getEntry(lib));
                        byte[] ko = carveKmiKo(data, kver, patch);
                        if (ko != null) {
                            carved = ko;
                            source = apk + "!" + lib;
                            vermagic = modinfoVermagic(ko);
                            break;
                        }
                    }
                } catch (Throwable ignored) {
                }
                if (carved != null) break;
            }

            // 2) Some managers ship a plain .ko zip entry instead.  It must
            // still pass the same KMI check.
            if (carved == null) {
                for (String apk : apks) {
                    try (ZipFile zf = new ZipFile(new File(apk))) {
                        java.util.Enumeration<? extends ZipEntry> en = zf.entries();
                        while (en.hasMoreElements()) {
                            ZipEntry e = en.nextElement();
                            String n = e.getName();
                            String ln = n.toLowerCase();
                            if (!ln.endsWith(".ko") || ln.contains("susfs")) continue;
                            byte[] data = readZipEntry(zf, e);
                            if (data.length <= 4 || data[0] != 0x7f || data[1] != 'E'
                                    || data[2] != 'L' || data[3] != 'F') continue;
                            String vm = modinfoVermagic(data);
                            if (!kver.equals(kmiOfVermagic(vm))) continue;
                            carved = data;
                            source = apk + "!" + n;
                            vermagic = vm;
                            break;
                        }
                    } catch (Throwable ignored) {
                    }
                    if (carved != null) break;
                }
            }

            // 2.5) Some managers pack the KMI modules in a container our
            // raw-deflate carver does not understand (FinaSU 1.6.3).  Their
            // own ksud can dump the exact KMI asset; use it before the
            // bundled-template fallback so the manager LKM/ksud pair stays
            // consistent.
            if (carved == null && ("fina".equals(flavor) || "nova".equals(flavor) || "maplesu".equals(flavor))) {
                String viaKsud = tryKsudExtractManagerLkm(flavor, pkg, kver, dest);
                if (viaKsud != null) return viaKsud;
            }

            // 3) Bundled template fallback, accepted only for the same KMI.
            if (carved == null) {
                byte[] template = readBundledTemplate(flavor, kver);
                if (template != null) {
                    String vm = modinfoVermagic(template);
                    if (kver.equals(kmiOfVermagic(vm))) {
                        carved = template;
                        source = "bundled:" + flavor;
                        vermagic = vm;
                    }
                }
            }

            if (carved == null) {
                shellNoThrow("rm -f '" + dest + "'");
                return "MANAGER_LKM=none package=" + pkg
                        + " reason=no_matching_kmi target=" + kver
                        + " patch=" + patch + " os.version=" + osver
                        + " uname=" + uname;
            }
            String selectedKmi = kmiOfVermagic(vermagic);
            if (!kver.equals(selectedKmi)) {
                shellNoThrow("rm -f '" + dest + "'");
                return "MANAGER_LKM=none package=" + pkg
                        + " reason=vermagic_mismatch target=" + kver
                        + " selected=" + selectedKmi + " vermagic=" + vermagic;
            }

            File base = getExternalFilesDir(null);
            if (base == null) base = getFilesDir();
            File stageDir = new File(base, "stage");
            if (!stageDir.exists() && !stageDir.mkdirs())
                stageDir = new File(getFilesDir(), "stage");
            if (!stageDir.exists()) stageDir.mkdirs();
            stageDir.setReadable(true, false);
            stageDir.setWritable(true, false);
            File local = new File(stageDir, "manager_kmi_" + flavor + ".ko");
            try (FileOutputStream out = new FileOutputStream(local)) {
                out.write(carved);
                out.flush();
                out.getFD().sync();
            }
            local.setReadable(true, false);
            shellNoThrow("rm -f '" + dest + "'");
            shell("cp -f '" + local.getAbsolutePath() + "' '" + dest
                    + "' && chmod 644 '" + dest + "'");
            local.delete();
            // Auto late-load patch for manager-carved KOs: apply the structural
            // input-hook no-op to the freshly carved KO so no per-kernel
            // pre-patched template is needed.  Only SukiSU's prologue (TBNZ that
            // falls through to the uninitialized cleanup) needs it; other
            // flavors already early-return via TBZ and return null here (safe
            // no-op).  Produces ko-<flavor>-lateload.ko next to the raw KO;
            // run98260.sh prefers it for the late-load path.
            {
                String patchedDest = WORK + "/ko-" + flavor + "-lateload.ko";
                shellNoThrow("rm -f '" + patchedDest + "'");
                try {
                    byte[] patched = SukisuLateLoadPatch.patch(carved);
                    if (patched != null) {
                        File pf = new File(stageDir, "ko-" + flavor + "-lateload.ko");
                        try (FileOutputStream out = new FileOutputStream(pf)) {
                            out.write(patched);
                            out.flush();
                            out.getFD().sync();
                        }
                        pf.setReadable(true, false);
                        shell("cp -f '" + pf.getAbsolutePath() + "' '" + patchedDest
                                + "' && chmod 644 '" + patchedDest + "'");
                        pf.delete();
                        log("MANAGER_LATELOAD_AUTOPATCH=ok flavor=" + flavor
                                + " path=" + patchedDest);
                    } else {
                        log("MANAGER_LATELOAD_AUTOPATCH=skip flavor=" + flavor
                                + " reason=no_matching_prologue");
                    }
                } catch (Throwable t) {
                    log("MANAGER_LATELOAD_AUTOPATCH=failed flavor=" + flavor
                            + " reason=" + t);
                }
            }
            return "MANAGER_LKM=" + dest + " source=" + source
                    + " bytes=" + carved.length + " kernel=" + kver
                    + " patch=" + patch + " vermagic=" + vermagic;
        } catch (Throwable t) {
            shellNoThrow("rm -f '" + dest + "'");
            return "MANAGER_LKM=none package=" + pkg + " reason=" + t;
        }
    }

    /**
     * Ask the installed manager's own ksud to dump its embedded KMI module.
     *
     * <p>FinaSU 1.6.3 keeps the KMI LKMs in a container the raw-deflate carver
     * above does not recognize.  Its ksud exposes them through
     * {@code debug extract-binary android<kmi>_kernelsu.ko <path>}.  The
     * staged ksud is executed through the Shizuku shell (the app cannot
     * traverse /data/local/tmp), the result is checked for ELF magic and a
     * matching vermagic KMI, and only then moved to {@code ko-<flavor>.ko}.
     * Any failure leaves the existing bundled-template fallback untouched.</p>
     */
    private String tryKsudExtractManagerLkm(
            String flavor, String pkg, String kver, String dest) {
        String asset;
        switch (kver) {
            case "6.1": asset = "android14-6.1_kernelsu.ko"; break;
            case "6.6": asset = "android15-6.6_kernelsu.ko"; break;
            case "6.12": asset = "android16-6.12_kernelsu.ko"; break;
            case "6.18": asset = "android17-6.18_kernelsu.ko"; break;
            default: return null;
        }
        String ksud = WORK + "/ksud_" + flavor + ".manager";
        String probe = shellNoThrow("[ -x '" + ksud + "' ] && echo ok");
        if (probe == null || !probe.contains("ok")) return null;
        String tmp = WORK + "/ko-" + flavor + ".ksud-extract.ko";
        shellNoThrow("rm -f '" + tmp + "'");
        String out = shellNoThrow("export LD_LIBRARY_PATH='" + WORK
                + "'; '" + ksud + "' debug extract-binary '" + asset
                + "' '" + tmp + "' 2>&1 | tail -3");
        String magic = shellNoThrow("od -An -tx1 -N4 '" + tmp
                + "' 2>/dev/null | tr -d ' \\n'");
        String vm = shellNoThrow("grep -a -o 'vermagic=[^ ]*' '" + tmp
                + "' 2>/dev/null | head -1");
        String size = shellNoThrow("wc -c < '" + tmp + "' 2>/dev/null | tr -d ' \\n'");
        long bytes = -1L;
        try {
            bytes = Long.parseLong(size == null ? "" : size.trim());
        } catch (Throwable ignored) {
        }
        boolean ok = magic != null && magic.trim().equals("7f454c46")
                && vm != null && vm.contains(kver + ".") && bytes > 65536L;
        if (ok) {
            shellNoThrow("mv -f '" + tmp + "' '" + dest + "' && chmod 644 '" + dest + "'");
            return "MANAGER_LKM=" + dest + " source=ksud-extract flavor=" + flavor
                    + " package=" + pkg + " asset=" + asset
                    + " bytes=" + bytes
                    + " vermagic=" + vm.trim();
        }
        shellNoThrow("rm -f '" + tmp + "'");
        log("MANAGER_LKM_KSUD_EXTRACT=skip flavor=" + flavor
                + " asset=" + asset
                + " magic=" + (magic == null ? "?" : magic.trim())
                + " vermagic=" + (vm == null ? "?" : vm.trim())
                + " out=" + (out == null ? "" : out.trim()));
        return null;
    }

    /** Pick the first (os.version, uname -r, /proc/version) with a KMI. */
    private String firstKernelRelease(String... values) {
        return KernelLogHelper.firstKernelRelease(values);
    }

    /** major.minor of a kernel release string, e.g. 6.12.58 -> 6.12. */
    private String kmiOfKernel(String value) {
        return KernelLogHelper.kmiOfKernel(value);
    }

    /** major.minor of an ELF vermagic, e.g. 6.12.76-4k -> 6.12. */
    private String kmiOfVermagic(String value) {
        return KernelLogHelper.kmiOfVermagic(value);
    }

    /** major.minor.patch of a release, e.g. 6.12.58-android -> 6.12.58. */
    private String patchOfKernel(String value) {
        return KernelLogHelper.patchOfKernel(value);
    }

    /** Release part (before first space) of a vermagic. */
    private String releaseOfVermagic(String value) {
        return KernelLogHelper.releaseOfVermagic(value);
    }

    private byte[] readBundledTemplate(String flavor, String kver) {
        String[] candidates;
        if (kver != null && kver.startsWith("6.6")) {
            candidates = new String[] {
                    "ksu-template-66118-" + flavor + ".ko",
                    "ksu-template-66118.ko",
                    "ksu-template-" + flavor + ".ko",
                    "ksu-template.ko",
            };
        } else {
            candidates = new String[] {
                    "ksu-template-" + flavor + ".ko",
                    "ksu-template.ko",
            };
        }
        for (String name : candidates) {
            try (java.io.InputStream in = openBundledAsset(name)) {
                java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
                byte[] data = bos.toByteArray();
                if (data.length > 4 && data[0] == 0x7f && data[1] == 'E'
                        && data[2] == 'L' && data[3] == 'F')
                    return data;
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    /**
     * Carve the first embedded KMI .ko from a manager native library.
     * The reference app scans for raw-deflate 0xED blocks, probes Inflater,
     * validates the ELF header, and filters on .modinfo vermagic.
     */
    private byte[] carveKmiKo(byte[] data, String kver, String targetPatch) {
        long deadline = System.currentTimeMillis() + 60000L;
        byte[] kmiFallback = null;
        for (int off = 0; off + 4 < data.length; off++) {
            if (System.currentTimeMillis() > deadline) return kmiFallback;
            if ((data[off] & 0xff) != 0xED) continue;
            java.util.zip.Inflater inf = new java.util.zip.Inflater(true);
            try {
                inf.setInput(data, off, data.length - off);
                byte[] head = new byte[4];
                int hn = inf.inflate(head);
                if (hn != 4 || head[0] != 0x7f || head[1] != 'E'
                        || head[2] != 'L' || head[3] != 'F')
                    continue;
                java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream(1 << 20);
                bos.write(head);
                byte[] buf = new byte[65536];
                while (!inf.finished()) {
                    int n = inf.inflate(buf);
                    if (n <= 0) {
                        if (inf.needsInput() || inf.needsDictionary()) break;
                        continue;
                    }
                    bos.write(buf, 0, n);
                    if (bos.size() > 900000) break;
                }
                byte[] ko = bos.toByteArray();
                if (ko.length < 65536 || ko.length > 900000 || !inf.finished())
                    continue;
                String vm = modinfoVermagic(ko);
                if (vm == null || vm.isEmpty()) continue;
                if (kver == null || kver.isEmpty())
                    continue;
                // Strict KMI: 6.6.127 must never satisfy a 6.12 target.
                if (!kver.equals(kmiOfVermagic(vm))) continue;
                // Prefer the exact patch (6.12.58) when the manager ships it;
                // otherwise the same KMI (6.12.76) is the only safe choice and
                // is later vermagic-rewritten by ko_patch.
                String rel = releaseOfVermagic(vm);
                String relPatch = patchOfKernel(rel);
                if (targetPatch != null && !targetPatch.isEmpty()
                        && targetPatch.equals(relPatch)) {
                    return ko;
                }
                if (kmiFallback == null) kmiFallback = ko;
            } catch (Throwable ignored) {
            } finally {
                inf.end();
            }
        }
        return kmiFallback;
    }

    /** Read the NUL-terminated vermagic string from a carved .ko .modinfo. */
    private String modinfoVermagic(byte[] ko) {
        return KernelLogHelper.modinfoVermagic(ko);
    }

    /**
     * Compute the manager signing tuple (DER cert size + SHA-256 hex) from the
     * installed package and write it as "<flavor> <size> <hash>" to
     * WORK/manager_sig.  This removes the dependency on `ksud debug get-sign`
     * and works on a cold boot before the KernelSU fd exists.
     */
    private String stageManagerSignature(String flavor) {
        String pkg = managerPkgOf(flavor);
        try {
            PackageInfo pi = getPackageManager().getPackageInfo(
                    pkg, PackageManager.GET_SIGNING_CERTIFICATES);
            Signature[] certs;
            if (pi.signingInfo != null && pi.signingInfo.hasMultipleSigners())
                certs = pi.signingInfo.getApkContentsSigners();
            else if (pi.signingInfo != null)
                certs = pi.signingInfo.getSigningCertificateHistory();
            else
                certs = null;
            if (certs == null || certs.length == 0)
                return "no-signature(pkg=" + pkg + ")";
            byte[] der = certs[0].toByteArray();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(der);
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash)
                hex.append(String.format("%02x", b & 0xff));
            String line = flavor + " " + pkg + " " + der.length + " " + hex;
            shell("printf '%s\\n' '" + line + "' > " + WORK
                    + "/manager_sig && chmod 644 " + WORK + "/manager_sig");
            return "size=" + der.length + " sha256=" + hex.substring(0, 16) + "…";
        } catch (Throwable t) {
            return "管理器未安装或签名不可读（" + pkg + "），root_stage 将回退 get-sign";
        }
    }

    private void resetLiveLog() {
        final LiveLogStore store = liveLogStore;
        if (store == null)
            return;
        try {
            liveLogWriter.execute(() -> {
                try {
                    store.reset("=== MagicRoot current run ===");
                } catch (Throwable ignored) {
                }
            });
        } catch (Throwable ignored) {
        }
    }

    private void persistLiveLog(String line) {
        final LiveLogStore store = liveLogStore;
        if (store == null)
            return;
        try {
            liveLogWriter.execute(() -> {
                try {
                    store.append(line);
                } catch (Throwable ignored) {
                }
            });
        } catch (Throwable ignored) {
        }
    }

    private void log(String s) {
        final String line = s == null ? "(null)" : s;
        persistLiveLog(line);
        runOnUiThread(() -> {
            if (!isDestroyed())
                ui.appendLog(line);
        });
    }

    private void feedback(String title, String detail, int tone) {
        runOnUiThread(() -> {
            if (!isDestroyed())
                ui.showFeedback(title, detail, tone);
        });
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

    private void clearStageCache() {
        try {
            File external = getExternalFilesDir(null);
            if (external != null)
                deleteTree(new File(external, "stage"));
            deleteTree(new File(getFilesDir(), "stage"));
        } catch (Throwable ignored) {
        }
    }

    /**
     * Copy an APK asset into public Download/MagicRoot via MediaStore, then
     * return the filesystem path root can cp.  This does not require Shizuku,
     * Shizuku, MANAGE_EXTERNAL_STORAGE, or an app-private directory.
     */
    private String copyAssetToPublicDownload(String assetName, String destName) throws Exception {
        android.content.ContentResolver resolver = getContentResolver();
        String rel = android.os.Environment.DIRECTORY_DOWNLOADS + "/MagicRoot/";
        try {
            resolver.delete(
                    android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                    android.provider.MediaStore.MediaColumns.DISPLAY_NAME + "=? AND "
                            + android.provider.MediaStore.MediaColumns.RELATIVE_PATH + "=?",
                    new String[]{destName, rel});
        } catch (Throwable ignored) {
        }
        android.content.ContentValues values = new android.content.ContentValues();
        values.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, destName);
        values.put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "application/octet-stream");
        values.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, rel);
        values.put(android.provider.MediaStore.MediaColumns.IS_PENDING, 1);
        android.net.Uri uri = resolver.insert(
                android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
        if (uri == null) throw new java.io.IOException("MediaStore insert failed");
        try (java.io.InputStream in = openBundledAsset(assetName);
             java.io.OutputStream out = resolver.openOutputStream(uri)) {
            if (out == null) throw new java.io.IOException("MediaStore output failed");
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            out.flush();
        }
        android.content.ContentValues done = new android.content.ContentValues();
        done.put(android.provider.MediaStore.MediaColumns.IS_PENDING, 0);
        resolver.update(uri, done, null, null);
        return android.os.Environment.getExternalStorageDirectory().getAbsolutePath()
                + "/Download/MagicRoot/" + destName;
    }

    /**
     * Stage and execute stpclear through the root backend.  The app process
     * frequently cannot see or canExecute() files under $WORK (root-owned
     * directory, SELinux app-data restrictions), so Java-side File checks are
     * not a valid proof that root cannot run it.
     */
    private boolean ensureStpclearRoot() {
        String apk = getPackageCodePath();
        String stage = "mkdir -p '" + WORK + "' 2>/dev/null; "
                + "if [ ! -x '" + WORK + "/stpclear' ]; then "
                + "  (unzip -p '" + apk + "' assets/stpclear > '" + WORK + "/stpclear') 2>/dev/null || true; "
                + "  chmod 755 '" + WORK + "/stpclear' 2>/dev/null || true; "
                + "fi; "
                + "if [ -x '" + WORK + "/stpclear' ]; then echo STP_STAGE_OK; "
                + "else echo STP_MISSING; fi";
        try {
            String out = parallelRootExec(stage, false);
            if (out != null && out.contains("STP_STAGE_OK")) {
                log("STP_CLEAR_STAGE=root-apk");
                return true;
            }
            log("STP_CLEAR_STAGE=root-apk failed out=" + out);
        } catch (Throwable t) {
            log("STP_CLEAR_STAGE_APK_FAILED=" + t);
        }
        // App-private copy fallback: root still performs the copy/test.
        try {
            installStpclearFromPrivate();
            String out = parallelRootExec(
                    "test -x '" + WORK + "/stpclear' && echo STP_STAGE_OK", false);
            if (out != null && out.contains("STP_STAGE_OK")) {
                log("STP_CLEAR_STAGE=root-private");
                return true;
            }
        } catch (Throwable t) {
            log("STP_CLEAR_STAGE_PRIVATE_FAILED=" + t);
        }
        return false;
    }

    private String runStpclearRoot() throws Exception {
        // Direct-exec the binary through rootd (leading '!' in
        // parallelRootExec) so libstp/hisecd sees the full-capability
        // context.  Wrapping it in a shell would drop caps and make
        // StpClearStatus fail silently.
        String bin = WORK + "/stpclear";
        String out = parallelRootExec(bin, true);
        if (out == null || !out.contains("StpClearStatus=0"))
            throw new IllegalStateException("stpclear failed: " + out);
        return out;
    }

    /**
     * Copy stpclear to app cache, then let the root backend copy it into WORK.
     * Works after a cleanup removed the staged WORK copy.
     */
    private boolean installStpclearFromPrivate() {
        try {
            java.io.File priv = new java.io.File(getCacheDir(), "stpclear.stage");
            copyAssetToFile("stpclear", priv);
            priv.setExecutable(true, false);
            String dst = WORK + "/stpclear";
            String out = parallelRootExec(
                    "mkdir -p '" + WORK + "' && cp -f '" + priv.getAbsolutePath()
                            + "' '" + dst + "' && chmod 755 '" + dst
                            + "' && test -x '" + dst + "' && echo STP_STAGE_OK", false);
            if (out != null && out.contains("STP_STAGE_OK")) {
                log("STP_CLEAR_STAGE=private-copy");
                return true;
            }
            log("STP_CLEAR_STAGE=private-copy failed out=" + out);
        } catch (Throwable t) {
            log("STP_CLEAR_STAGE_PRIVATE_FAILED=" + t);
        }
        return false;
    }

    private InputStream openBundledAsset(String name) throws java.io.IOException {
        try {
            return getAssets().open(name);
        } catch (java.io.FileNotFoundException e) {
            String canonical = KernelLogHelper.resolveCanonicalAsset(name);
            if (canonical != null && !canonical.equals(name)) {
                return getAssets().open(canonical);
            }
            throw e;
        }
    }

    private void copyAssetToFile(String name, java.io.File dst) throws Exception {
        try (java.io.InputStream in = openBundledAsset(name);
             java.io.FileOutputStream out = new java.io.FileOutputStream(dst)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            out.flush();
            out.getFD().sync();
        }
        dst.setReadable(true, false);
        dst.setWritable(true, false);
        dst.setExecutable(true, false);
    }

    private void stageAsset(String name) throws Exception {
        stageAssetFrom(name, name, WORK);
    }

    private void stageAssetFrom(String assetName, String destName, String root) throws Exception {
        String destPath = root + "/" + destName;
        shell("mkdir -p '" + root + "'");
        int destSlash = destName.lastIndexOf('/');
        if (destSlash > 0) {
            shell("mkdir -p '" + root + "/" + destName.substring(0, destSlash) + "'");
        }
        String tmpPath = destPath + ".new";
        shellNoThrow("rm -f '" + tmpPath + "' '" + destPath + "' 2>/dev/null || true");
        // Always overwrite.  The old size-only skip kept a same-size but stale
                // have exactly the same byte size while using a different SELinux
        // label), which silently defeated the fix.

        File baseDir = getExternalFilesDir(null);
        if (baseDir == null)
            baseDir = getFilesDir();
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
        long copied = 0;
        try (InputStream in = openBundledAsset(assetName);
             FileOutputStream out = new FileOutputStream(localFile)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
                copied += n;
            }
            out.flush();
            out.getFD().sync();
        }
        localFile.setReadable(true, false);
        localFile.setWritable(true, false);
        localFile.setExecutable(true, false);

        // A previous deployment/staging path could leave CR characters in the
        // shell scripts (observed as run98260.sh[10]: : not found and
        // "set: -: unknown option").  Normalize every deployed shell script.
        if (destName.endsWith(".sh")) {
            byte[] raw = java.nio.file.Files.readAllBytes(localFile.toPath());
            java.io.ByteArrayOutputStream clean = new java.io.ByteArrayOutputStream(raw.length);
            for (byte value : raw) {
                if (value != '\r') clean.write(value);
            }
            byte[] normalized = clean.toByteArray();
            java.nio.file.Files.write(localFile.toPath(), normalized);
            copied = normalized.length;
        }

        String localPath = localFile.getAbsolutePath();
        shell("cp -f '" + localPath + "' '" + tmpPath
                + "' && chmod 755 '" + tmpPath
                + "' && mv -f '" + tmpPath + "' '" + destPath + "'");
        try {
            localFile.delete();
        } catch (Throwable ignored) {
        }

        String sizeText = shellNoThrow("wc -c < '" + destPath + "' 2>/dev/null");
        String expected = String.valueOf(copied);
        if (sizeText == null || !sizeText.trim().equals(expected)) {
            throw new java.io.IOException("asset_size_mismatch: " + destName
                    + " expected=" + expected + " actual="
                    + (sizeText == null ? "none" : sizeText.trim()));
        }
        String check = shellNoThrow("test -f '" + destPath + "' && echo OK || echo FAIL");
        if (check == null || !check.contains("OK")) {
            throw new IllegalStateException(destName + " staging verify failed (" + destPath + ")");
        }
    }

    private String rootShellExec(java.io.File su, String cmd) throws Exception {
        Process p = new ProcessBuilder(su.getAbsolutePath(), "-c",
                "export PATH=/system/bin:/system/xbin:/data/adb/ksu/bin; cd "
                        + WORK + " 2>/dev/null; " + cmd)
                .redirectErrorStream(true).start();
        try { p.getOutputStream().close(); } catch (Throwable ignored) { }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(p.getInputStream(), "UTF-8"))) {
            String line;
            while ((line = r.readLine()) != null)
                sb.append(line).append('\n');
        }
        if (!p.waitFor(30, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IllegalStateException("root shell timeout");
        }
        if (p.exitValue() != 0 && sb.length() == 0)
            throw new IllegalStateException("root shell rc=" + p.exitValue());
        return sb.toString();
    }

    private java.io.File rootShellSu() {
        java.io.File cached = cachedRootSu;
        if (cached != null && cached.canExecute())
            return cached;
        long now = android.os.SystemClock.elapsedRealtime();
        if (now - lastRootSuProbe < 15_000L)
            return null;
        lastRootSuProbe = now;
        java.io.File su = findSuEntry();
        if (su != null)
            cachedRootSu = su;
        return su;
    }

    private String shell(String cmd) throws Exception {
        // After a successful Root grant the app must not keep using Shizuku:
        // closing USB debugging kills the adb/Shizuku shell.  Prefer the Root
        // authorization for all subsequent shell work.
        java.io.File rootSu = rootShellSu();
        if (rootSu != null)
            return rootShellExec(rootSu, cmd);
        Process p = shellProcess(cmd);
        // Close stdin before reading.  The fork's remote process returns a real
        // pipe; a command must see EOF or it can wait forever on some builds.
        try { p.getOutputStream().close(); } catch (Throwable ignored) { }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(p.getInputStream(), "UTF-8"))) {
            String line;
            while ((line = r.readLine()) != null)
                sb.append(line).append('\n');
        }
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

    /** Run a command as the uid=2000 Shizuku shell, not the KSU root shell.
     *  /data/local/tmp/pc98260-root.sock is shell_data_file; uid=2000 may
     *  unlink it while u:r:ksu:s0 root can be denied by SELinux. */
    private String shellShizuku(String cmd) throws Exception {
        Process p = shellProcess(cmd);
        try { p.getOutputStream().close(); } catch (Throwable ignored) { }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(p.getInputStream(), "UTF-8"))) {
            String line;
            while ((line = r.readLine()) != null)
                sb.append(line).append('\n');
        }
        if (!p.waitFor(30, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IllegalStateException("shizuku shell timeout");
        }
        return sb.toString();
    }

    private String cleanupShell(String cmd) {
        try {
            return shellShizuku(cmd);
        } catch (Throwable t) {
            log("CLEAN_SHELL_SHIZUKU_FAILED=" + t);
            String fallback = shellNoThrow(cmd);
            return fallback == null ? "CLEAN_SHELL_FAILED" : fallback;
        }
    }

    /** Extract the selected manager's KMI-matched LKM without starting the root
     *  chain, so the user can verify the exact KO route before deploying. */
    public void checkManagerKo() {
        if (ui == null || !managerKoCheckRunning.compareAndSet(false, true))
            return;
        final String flavor = ui.getKsuFlavor();
        final String pkg = ui.getKsuManagerPkg();
        final String ver = managerVersionCode(flavor);
        feedback("管理器 KO 提取", "正在从 " + pkg + " 提取…", 0);
        log("MANAGER_KO_CHECK_BEGIN flavor=" + flavor + " pkg=" + pkg + " version=" + ver);
        runAsync(() -> {
            try {
                String result = extractManagerLkm(flavor);
                String expected = WORK + "/ko-" + flavor + ".ko";
                boolean ok = result.startsWith("MANAGER_LKM=" + expected + " ");
                log("MANAGER_KO_CHECK=" + result);
                runOnUiThread(() -> feedback(
                        ok ? "管理器 KO 提取成功" : "将回退内置模板",
                        result,
                        ok ? 1 : 2));
            } catch (Throwable t) {
                log("MANAGER_KO_CHECK_FAILED=" + t);
                runOnUiThread(() -> feedback("管理器 KO 提取失败", String.valueOf(t), 2));
            } finally {
                managerKoCheckRunning.set(false);
            }
        }, "magicroot-manager-ko");
    }

    /** hisecd/libhonordetect-style SU judgement.
     *  Mirrors the 21 prefix probes recovered from the vendor libraries and the
     *  ro.secure / ro.build.tags build-integrity checks. */
    public void checkSu() {
        feedback("SU 判定检查", "正在按 hisecd 路径表检查…", 0);
        runAsync(() -> {
            try {
                String[] prefixes = {
                        "/sbin", "/vendor/bin", "/system/sbin", "/system/bin",
                        "/system/xbin", "/system/bin/.ext", "/system/sd/xbin",
                        "/system/usr/we-need-root", "/cache", "/data", "/dev",
                        "/system/vendor/bin", "/vendor/xbin", "/system/vendor/xbin",
                        "/product/bin", "/product/xbin", "/data/local/tmp",
                        "/data/local/bin", "/data/local/xbin", "/data/local",
                        "/system/bin/failsafe",
                };
                StringBuilder loops = new StringBuilder();
                loops.append("echo __PROP__; getprop ro.secure; getprop ro.build.tags; ")
                        .append("getprop persist.sys.root.status; echo __HITS__; ");
                for (String p : prefixes) {
                    loops.append("[ -e '").append(p).append("/su' ] && echo 'SU:")
                            .append(p).append("/su'; ")
                            .append("[ -e '").append(p).append("/magisk' ] && echo 'MAGISK:")
                            .append(p).append("/magisk'; ");
                }
                String out = shell(loops.toString());
                if (out == null) out = "";
                log("SU_JUDGE=\n" + out);
                String propBlock = out;
                String hitBlock = "";
                int hitMarker = out.indexOf("__HITS__");
                if (hitMarker >= 0) {
                    propBlock = out.substring(0, hitMarker);
                    hitBlock = out.substring(hitMarker + "__HITS__".length());
                }
                String[] propLines = propBlock.split("\\r?\\n");
                String secure = "";
                for (String line : propLines) {
                    String t = line.trim();
                    if (t.isEmpty() || t.equals("__PROP__")) continue;
                    if (secure.isEmpty()) {
                        secure = t;
                        break;
                    }
                }
                boolean secureZero = "0".equals(secure);
                boolean testKeys = propBlock.contains("test-keys");
                int hits = 0;
                for (String line : hitBlock.split("\\r?\\n")) {
                    String t = line.trim();
                    if (t.startsWith("SU:") || t.startsWith("MAGISK:")) hits++;
                }
                boolean bad = hits > 0 || secureZero || testKeys;
                final String summary = bad
                        ? ("命中 " + hits + " 个 su/magisk 路径"
                            + (secureZero ? " · ro.secure=0" : "")
                            + (testKeys ? " · test-keys" : ""))
                        : "未发现 su/magisk 路径，构建属性正常";
                runOnUiThread(() -> feedback(
                        bad ? "SU 判定异常" : "SU 判定通过",
                        summary,
                        bad ? 2 : 1));
            } catch (Throwable t) {
                log("SU_JUDGE_FAILED=" + t);
                runOnUiThread(() -> feedback("SU 判定失败", t.toString(), 2));
            }
        }, "magicroot-su-judge");
    }

    /** Clear the STP root judgement that hisecd derives from the SU probes. */
    public void repairSuDetection() {
        feedback("SU 判定修复", "正在清除 STP root 判定…", 0);
        runAsync(() -> {
            try {
                if (!ensureStpclearRoot())
                    throw new IllegalStateException("stpclear missing");
                String out = runStpclearRoot();
                log("SU_JUDGE_REPAIR=" + out);
                if (out == null || out.contains("STP_MISSING"))
                    throw new IllegalStateException("stpclear missing at runtime");
                String status = shell("setprop persist.sys.root.status 0; "
                        + "getprop persist.sys.root.status");
                log("SU_JUDGE_REPAIR_STATUS=" + status);
                runOnUiThread(() -> feedback(
                        "SU 判定修复完成",
                        "STP root 状态已清除",
                        1));
            } catch (Throwable t) {
                log("SU_JUDGE_REPAIR_FAILED=" + t);
                runOnUiThread(() -> feedback("SU 判定修复失败", t.toString(), 2));
            }
        }, "magicroot-su-judge-repair");
    }

    /** Post-load su_entry repair.  Tries the KSU sucompat hook first, then
     *  the still-live pc98260 rootd (when auto-KSU cleanup kept it). */
    public void repairSuEntryAfterLoad() {
        feedback("su entry", "正在修复加载后的 su…", 0);
        runAsync(() -> {
            String script = "/data/local/tmp/magic/su_entry.sh";
            String[] attempts = {
                    "su -c \"sh " + script + "\" 2>&1",
                    "/system/bin/su -c \"sh " + script + "\" 2>&1",
                    "/data/local/tmp/magic/pc98260-su -c \"sh " + script + "\" 2>&1",
                    "/data/local/tmp/magic/98260-g264/pc98260-su -c \"sh " + script + "\" 2>&1",
            };
            String last = "";
            for (String cmd : attempts) {
                try {
                    String out = shell(cmd);
                    last = out == null ? "" : out;
                    log("SU_REPAIR=" + cmd + "\n" + last);
                    if (last.contains("SU_ENTRY=")) {
                        final String result = last;
                        runOnUiThread(() -> feedback("su entry 修复完成",
                                result.contains("SU_ENTRY=kernel_sucompat") ? "sucompat 可用" : "请查看日志", 1));
                        return;
                    }
                } catch (Throwable t) {
                    last = String.valueOf(t);
                }
            }
            final String result = last;
            runOnUiThread(() -> feedback("su entry 修复失败", result, 2));
        }, "magicroot-su-repair");
    }

    /**
     * Tools > soft reboot fix.  This is the ONLY remaining userspace restart
     * path: it runs lsposed-hotfix.sh, which runs the KSU module lifecycle and
     * restarts zygote, then waits for lspd/Zygisk.  It never calls ksud
     * soft-reboot.
     */
    /**
     * Number of unresolved armed-victim zombies recorded by the most recent
     * 98260 run's ledger summary ("[victim] summary ... unproven=N"), or -1
     * when no summary is present (older payload / non-98260 chain).
     *
     * An unproven zombie is a latent kernel-panic bomb: any later teardown
     * that reaps it through init (zygote restart in lsposed-hotfix.sh, or a
     * userspace soft-reboot) walks foreign rb_node contents and panics.  The
     * 2026-11-07 13:11/13:15 panics both followed a zygote hotfix run after a
     * session that had left unresolved victims.  Gate the hotfix on this.
     */
    private int unprovenVictimCount() {
        String logText = lastRunLogText;
        if (logText == null || logText.isEmpty())
            return -1;
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("\\[victim\\] summary[^\\n]*unproven=(\\d+)")
                .matcher(logText);
        int last = -1;
        while (m.find()) {
            try {
                last = Integer.parseInt(m.group(1));
            } catch (NumberFormatException ignored) {
            }
        }
        return last;
    }

    public void runSoftRebootRepair() {
        int unproven = unprovenVictimCount();
        if (unproven > 0) {
            // The unproven zombie can panic if init reaps it during a zygote
            // teardown.  This is reported, but no longer blocks the user's
            // explicit action.
            log("SOFT_REBOOT_FIX_WARN=unproven_victims count=" + unproven
                    + " note=zygote_teardown_may_panic");
            feedback("软重启修复", "注意：上次遗留 " + unproven
                    + " 个未证明 victim，zygote 重启可能触发内核 panic", 0);
        }
        if (!softRebootFixRunning.compareAndSet(false, true)) {
            feedback("软重启修复", "已在进行中，请稍候", 0);
            return;
        }
        feedback("软重启修复", "正在启动 lspd/zygote 热重启…", 0);
        runAsync(() -> {
            final String script = WORK + "/lsposed-hotfix.sh";
            final String logPath = WORK + "/lsposed-hotfix-tool.log";
            final String flavor = ui.getKsuFlavor();
            try {
                // Minimal path: write the hotfix into app cache and execute it
                // through the app's own su, without requiring a separate shell app.
                File cacheHotfix = new File(getCacheDir(), "lsposed-hotfix.sh");
                try (InputStream in = openBundledAsset("lsposed-hotfix.sh");
                     FileOutputStream out = new FileOutputStream(cacheHotfix)) {
                    byte[] buf = new byte[16 * 1024];
                    int n;
                    while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                }
                File cacheWrapper = new File(getCacheDir(), "soft-reboot-root.sh");
                String wrapper = "#!/system/bin/sh\n"
                        + "KSUD='" + WORK + "/ksud_" + flavor + "'\n"
                        + "export KSUD\n"
                        + "mkdir -p /data/local/tmp/magic\n"
                        + "exec sh '" + cacheHotfix.getAbsolutePath() + "'\n";
                try (FileOutputStream out = new FileOutputStream(cacheWrapper)) {
                    out.write(wrapper.getBytes("UTF-8"));
                }
                // Run the repair itself under the app's granted Root
                // authorization.  The LSPosed repair needs /data/adb/modules;
                // routing this through the Shizuku shell (uid 2000) cannot
                // reliably touch the module tree on temporary Root.
                File su = findSuEntry();
                if (su != null) {
                    // Auto-clean may have removed WORK.  Create it before the
                    // shell opens logPath; otherwise the redirect fails and the
                    // entire repair script is never executed.
                    String inner = "mkdir -p '" + WORK + "' && setsid sh '"
                            + cacheWrapper.getAbsolutePath()
                            + "' > '" + logPath + "' 2>&1 < /dev/null &";
                    Process p = new ProcessBuilder(su.getAbsolutePath(), "-c", inner)
                            .redirectErrorStream(true).start();
                    p.getOutputStream().close();
                    StringBuilder out = new StringBuilder();
                    try (java.io.BufferedReader r = new java.io.BufferedReader(
                            new java.io.InputStreamReader(p.getInputStream(), "UTF-8"))) {
                        String line;
                        while ((line = r.readLine()) != null) out.append(line).append('\n');
                    }
                    boolean finished = p.waitFor(8, TimeUnit.SECONDS);
                    log("SOFT_REBOOT_FIX_ROOT_SU=" + su.getAbsolutePath()
                            + " finished=" + finished
                            + " rc=" + (finished ? p.exitValue() : -1)
                            + " out=" + out.toString().trim());
                    boolean logStarted = false;
                    for (int i = 0; i < 10 && !logStarted; i++) {
                        String logCheck = shellNoThrow("test -s '" + logPath
                                + "' && head -1 '" + logPath + "' 2>/dev/null");
                        if (logCheck != null && logCheck.contains("=== BEGIN")) {
                            logStarted = true;
                            break;
                        }
                        Thread.sleep(300);
                    }
                    log("SOFT_REBOOT_FIX_LOG_STARTED=" + logStarted);
                    if (finished && p.exitValue() == 0 && logStarted) {
                        mainHandler.postDelayed(() -> softRebootFixRunning.set(false), 10_000);
                        runOnUiThread(() -> feedback("软重启修复已开始",
                                "已通过 Root 授权启动；界面会在几十秒内重启", 1));
                        return;
                    }
                    if (!finished) p.destroyForcibly();
                }
                log("SOFT_REBOOT_FIX_ROOT_SU=unavailable fallback=shizuku");
            } catch (Throwable directError) {
                log("SOFT_REBOOT_FIX_DIRECT_SU_FAILED=" + directError);
            }
            try {
                // Self-contained scripts: release only the two shell files.
                // ksud is never copied/released here; the existing chain or
                // /data/adb/ksud must already provide it.
                try {
                    stageAsset("lsposed-hotfix.sh");
                    stageAsset("soft-reboot-root.sh");
                } catch (Throwable stageError) {
                    log("SOFT_REBOOT_FIX_STAGE_FAILED=" + stageError);
                    final String stageMsg = String.valueOf(stageError);
                    runOnUiThread(() -> feedback("软重启修复不可用", stageMsg, 2));
                    return;
                }
                shellNoThrow("chmod 755 '" + script + "' '" + WORK + "/soft-reboot-root.sh'");
                String check = shellNoThrow("test -f '" + script + "' && echo OK || echo MISSING");
                if (check == null || !check.contains("OK")) {
                    runOnUiThread(() -> feedback("软重启修复不可用",
                            "内置脚本释放失败：" + script, 2));
                    return;
                }
                final String rootScript = WORK + "/soft-reboot-root.sh";
                String checkRoot = shellNoThrow("test -f '" + rootScript + "' && echo OK || echo MISSING");
                if (checkRoot == null || !checkRoot.contains("OK")) {
                    runOnUiThread(() -> feedback("软重启修复不可用",
                            "内置 root 包装器释放失败：" + rootScript, 2));
                    return;
                }
                shellNoThrow("chmod 755 '" + rootScript + "'");
                // The Shizuku shell cannot execute /system/bin/su on this build,
                // but ksud debug su accepts an executable path on stdin and
                // runs it as root.  Probe ksud first, then fall back to su.
                String rootCmd = null;
                String rootProbe = "";
                java.io.File directSu = findSuEntry();
                if (directSu != null) {
                    rootCmd = directSu.getAbsolutePath() + " -c \"sh '" + rootScript + "'\"";
                    log("SOFT_REBOOT_FIX_DIRECT_SU=" + directSu.getAbsolutePath());
                }
                final String[] ksuds = {
                        WORK + "/ksud_" + flavor + ".manager",
                        WORK + "/ksud_" + flavor,
                        "/data/adb/ksud",
                };
                for (String ksud : ksuds) {
                    if (rootCmd != null) break;
                    String probe = shellNoThrow("echo 'id -u' | '" + ksud + "' debug su 2>&1");
                    rootProbe = String.valueOf(probe).trim();
                    log("SOFT_REBOOT_FIX_KSUD_PROBE=" + ksud + " -> " + rootProbe);
                    if ("0".equals(rootProbe)) {
                        rootCmd = "echo '" + rootScript + "' | '" + ksud + "' debug su";
                        break;
                    }
                }
                if (rootCmd == null) {
                    String suProbe = "";
                    for (String candidate : new String[]{
                            "/data/adb/ksu/bin/su", "/system/bin/su",
                            "/product/bin/su", "/debug_ramdisk/su",
                            "/system_ext/bin/su", "/system/xbin/su",
                            "/vendor/bin/su", "/system/sbin/su", "su"}) {
                        suProbe = String.valueOf(shellNoThrow(
                                candidate + " -c 'id -u' 2>&1")).trim();
                        log("SOFT_REBOOT_FIX_SU_PROBE=" + candidate + " -> " + suProbe);
                        if ("0".equals(suProbe)) {
                            rootCmd = candidate + " -c \"sh '" + rootScript + "'\"";
                            break;
                        }
                    }
                }
                if (rootCmd == null) {
                    runOnUiThread(() -> feedback("软重启修复需要 root",
                            "ksud debug su 和 su 都不可用；请先完成 98260 提权或授权 Shizuku", 2));
                    return;
                }
                final String[] attempts = {
                        rootCmd,
                        WORK + "/pc98260-su -c \"sh '" + rootScript + "'\"",
                };
                String last = "";
                for (String cmd : attempts) {
                    try {
                        String out = shell(cmd);
                        last = out == null ? "" : out;
                        log("SOFT_REBOOT_FIX_CMD=" + cmd + "\n" + last);
                        if (last.contains("Permission denied")
                                || last.contains("inaccessible")
                                || last.contains("not found")) {
                            continue;
                        }
                        log("SOFT_REBOOT_FIX_STARTED=1 log=" + logPath);
                        runOnUiThread(() -> feedback("软重启修复已开始",
                                "界面会在几十秒内重启；完成后打开 LSPosed 管理器确认“已激活”", 1));
                        return;
                    } catch (Throwable t) {
                        last = String.valueOf(t);
                        log("SOFT_REBOOT_FIX_CMD_FAIL=" + last);
                    }
                }
                final String result = last;
                runOnUiThread(() -> feedback("软重启修复失败", result, 2));
            } catch (Throwable t) {
                log("SOFT_REBOOT_FIX_FAILED=" + t);
                runOnUiThread(() -> feedback("软重启修复失败", t.toString(), 2));
            } finally {
                softRebootFixRunning.set(false);
            }
        }, "magicroot-soft-reboot-fix");
    }

    private Process shellProcess(String cmd) throws Exception {
        Exception last = null;
        for (int attempt = 0; attempt < 5; attempt++) {
            try {
                return shellProcessOnce(cmd);
            } catch (IllegalStateException e) {
                String msg = String.valueOf(e.getMessage());
                if (!msg.contains("Shizuku 不可用"))
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
        throw new IllegalStateException("Shizuku 不可用");
    }

    private Process shellProcessOnce(String cmd) throws Exception {
        IBinder binder = Shizuku.getBinder();
        if (binder == null || !binder.pingBinder())
            throw new IllegalStateException("Shizuku 不可用");
        IShizukuService service = IShizukuService.Stub.asInterface(binder);
        IRemoteProcess remote = service.newProcess(
                new String[]{"sh", "-c", cmd},
                new String[]{"PATH=/system/bin:/system/xbin:/data/adb/ksu/bin",
                        "HOME=/", "TMPDIR=/data/local/tmp"},
                "/");
        if (remote == null)
            throw new IllegalStateException("Shizuku 拒绝启动 shell");
        return new RemoteProcess(remote);
    }

    private static String managerLabelOf(String flavor) {
        return KernelLogHelper.managerLabelOf(flavor);
    }

    /** Populate the optional "other installed app" manager picker. */
    public void refreshInstalledApps() {
        if (ui == null)
            return;
        runAsync(() -> {
            List<AppEntry> out = new ArrayList<>();
            try {
                Intent main = new Intent(Intent.ACTION_MAIN);
                main.addCategory(Intent.CATEGORY_LAUNCHER);
                List<android.content.pm.ResolveInfo> ris =
                        getPackageManager().queryIntentActivities(main, 0);
                java.util.HashSet<String> seen = new java.util.HashSet<>();
                for (android.content.pm.ResolveInfo ri : ris) {
                    if (ri.activityInfo == null || ri.activityInfo.packageName == null)
                        continue;
                    String pkg = ri.activityInfo.packageName;
                    if (pkg.equals(getPackageName()) || !seen.add(pkg))
                        continue;
                    CharSequence label = ri.loadLabel(getPackageManager());
                    out.add(new AppEntry(label == null ? pkg : label.toString(), pkg));
                }
                out.sort((a, b) -> a.getLabel().compareToIgnoreCase(b.getLabel()));
            } catch (Throwable ignored) {
            }
            runOnUiThread(() -> ui.updateInstalledApps(out));
        }, "magicroot-apps");
    }

    /** Refresh the five-manager catalog shown by the Compose picker. */
    public void refreshInstalledManagers() {
        if (ui == null)
            return;
        ui.normalizeExplicitManagerSelection();
        List<ManagerInfo> list = new ArrayList<>();
        for (String flavor : FLAVOR_ORDER) {
            String pkg = findInstalledManagerPkg(flavor);
            boolean installed = isPackageInstalled(pkg);
            String version = "";
            String versionCode = "";
            String label = managerLabelOf(flavor);
            try {
                PackageInfo pi = getPackageManager().getPackageInfo(pkg, 0);
                version = pi.versionName == null ? "" : pi.versionName;
                versionCode = String.valueOf(pi.getLongVersionCode());
                CharSequence appLabel = getPackageManager()
                        .getApplicationLabel(pi.applicationInfo);
                if (appLabel != null && !appLabel.toString().trim().isEmpty()) {
                    label = appLabel.toString();
                }
            } catch (Throwable ignored) {
            }
            list.add(new ManagerInfo(flavor, label, pkg,
                    installed, version, versionCode, installed ? "本机" : "未安装"));
        }
        runOnUiThread(() -> {
            ui.updateInstalledManagers(list);
            String override = ui.getManagerPkgOverride();
            if (override != null && !override.trim().isEmpty()
                    && !isPackageInstalled(override.trim())) {
                ui.selectPresetManager(ui.getKsuFlavor());
                log("MANAGER_FALLBACK=installed_catalog reason=override_uninstalled pkg=" + override);
            }
            ManagerInfo current = null;
            for (ManagerInfo mi : list) {
                if (mi.getFlavor().equals(ui.getKsuFlavor())) {
                    current = mi;
                    break;
                }
            }
            boolean explicitInstalled = override != null && !override.trim().isEmpty()
                    && isPackageInstalled(override.trim());
            if (!explicitInstalled && (current == null || !current.getInstalled())) {
                ManagerInfo best = null;
                int bestPriority = Integer.MAX_VALUE;
                for (ManagerInfo mi : list) {
                    if (!mi.getInstalled()) continue;
                    int p = managerPriority(mi.getFlavor());
                    if (p < bestPriority) {
                        bestPriority = p;
                        best = mi;
                    }
                }
                if (best != null && !best.getFlavor().equals(ui.getKsuFlavor())) {
                    log("MANAGER_AUTOSELECT=" + best.getFlavor()
                            + " pkg=" + best.getPkg()
                            + " reason=selected_flavor_not_installed");
                    ui.selectInstalledManager(best);
                }
            }
            ui.updateResolvedManagerPkg(findInstalledManagerPkg(ui.getKsuFlavor()));
        });
    }

    private static String managerDefaultPkg(String flavor) {
        return KernelLogHelper.managerDefaultPkg(flavor);
    }

    /** Deterministic preference when the selected flavor is not installed. */
    private static int managerPriority(String flavor) {
        return KernelLogHelper.managerPriority(flavor);
    }

    /** Resolve only the canonical package.  Dev/CI/beta packages are special
     *  builds and must be chosen explicitly by the user; never auto-selected. */
    private String findInstalledManagerPkg(String flavor) {
        return managerDefaultPkg(flavor);
    }

    /** Run a short status command through rootd/KSU first, then the shell. */
    private String runStatusCommand(String cmd) {
        try {
            return parallelRootExec(cmd, false);
        } catch (Throwable ignored) {
            return shellNoThrow(cmd);
        }
    }

    /** Passive channel/auth state for the top card; event-driven only. */
    private void updateChannelAuth() {
        String channel = "未连接";
        String auth = "未授权";
        try {
            if (Shizuku.pingBinder()) {
                channel = "Shizuku";
                if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                    auth = "Shizuku 已授权";
                }
            }
        } catch (Throwable ignored) {
        }
        if (ui != null) ui.updateChannelAuth(channel, auth);
    }

    /** Refresh channel/root/manager/module/su status for the status deck. */
    public void refreshDeviceStatus() {
        if (ui == null || !deviceStatusRefreshing.compareAndSet(false, true))
            return;
        runAsync(() -> {
            try {
                String channel = "未连接";
                try {
                    if (Shizuku.pingBinder()) channel = "Shizuku";
                } catch (Throwable ignored) {
                }
                String id = safeStatus("id 2>/dev/null");
                boolean root = id != null && id.contains("uid=0");
                String selinux = safeStatus("getenforce 2>/dev/null");
                String modules = safeStatus("grep -i kernelsu /proc/modules 2>/dev/null");
                boolean moduleLive = modules != null && !modules.trim().isEmpty();

                String mgrPkg = ui.getKsuManagerPkg();
                boolean installed = false;
                String version = "";
                String versionCode = "";
                try {
                    PackageInfo pi = getPackageManager().getPackageInfo(mgrPkg, 0);
                    installed = true;
                    version = pi.versionName == null ? "" : pi.versionName;
                    versionCode = String.valueOf(pi.getLongVersionCode());
                } catch (Throwable ignored) {
                }
                String su = "未找到";
                if (new File("/data/adb/ksu/bin/su").exists()) su = "/data/adb/ksu/bin/su";
                else if (new File("/system/bin/su").exists()) su = "/system/bin/su";
                else if (new File(WORK, "pc98260-su").exists()) su = WORK + "/pc98260-su";

                DeviceStatus status = new DeviceStatus(
                        channel,
                        root,
                        selinux == null || selinux.trim().isEmpty() ? "unknown" : selinux.trim(),
                        managerLabelOf(ui.getKsuFlavor()),
                        mgrPkg,
                        version,
                        versionCode,
                        installed,
                        moduleLive,
                        su,
                        Build.MODEL == null ? "unknown" : Build.MODEL,
                        ui.getKernelVersion() == null ? "" : ui.getKernelVersion());
                runOnUiThread(() -> ui.updateDeviceStatus(status));
            } finally {
                deviceStatusRefreshing.set(false);
            }
        }, "magicroot-status");
    }

    private String safeStatus(String cmd) {
        try {
            return runStatusCommand(cmd);
        } catch (Throwable t) {
            return "";
        }
    }

    /** Root diagnosis: uid/caps/SELinux/storage/modules/managers/su. */
    public void doRootDiagnosis() {
        if (!beginAction())
            return;
        ui.updateDiagnosticBusy(true);
        runAsync(() -> {
            try {
                String cmd = "id; echo __CAP__; grep CapEff /proc/self/status 2>/dev/null; "
                        + "echo __SELINUX__; getenforce 2>/dev/null; "
                        + "echo __STORAGE__; df -h /data 2>/dev/null | tail -1; "
                        + "echo __MODULE__; grep -i kernelsu /proc/modules 2>/dev/null; "
                        + "echo __MANAGER__; "
                        + "for p in me.weishu.kernelsu com.rifsxd.ksunext com.sukisu.ultra "
                        + "com.sukisu.nova com.resukisu.resukisu dev.maplesu.manager me.yuki.fina; do "
                        + "pm path $p 2>/dev/null | head -1; done; "
                        + "echo __SU__; ls -l /system/bin/su /data/adb/ksu/bin/su 2>/dev/null; "
                        + "for p in /data/adb/ksu/bin/su /system/bin/su /product/bin/su /debug_ramdisk/su /system_ext/bin/su /system/xbin/su /vendor/bin/su /system/sbin/su; do "
                        + "[ -x \"$p\" ] && { echo SU_PATH=$p; \"$p\" -c id 2>&1; }; done; "
                        + "[ -x " + WORK + "/pc98260-su ] && { echo SU_PATH=" + WORK
                        + "/pc98260-su; " + WORK + "/pc98260-su -c id 2>&1; } || true; "
                        + "command -v su >/dev/null 2>&1 && { echo SU_PATH=$(command -v su); su -c id 2>&1; } || true";
                String out = runStatusCommand(cmd);
                if (out == null) out = "";
                String uid = out.split("__CAP__", 2)[0].trim();
                String cap = section(out, "__CAP__").trim();
                String selinux = section(out, "__SELINUX__").trim();
                String storage = section(out, "__STORAGE__").trim();
                String module = section(out, "__MODULE__").trim();
                String manager = section(out, "__MANAGER__").trim();
                String su = section(out, "__SU__").trim();
                List<String> details = new ArrayList<>();
                for (String line : out.split("\\r?\\n")) {
                    if (!line.trim().isEmpty()) details.add(line.trim());
                }
                boolean anySuOk = su.contains("uid=0(root)");
                boolean rootdSuOk = su.contains("SU_PATH=" + WORK + "/pc98260-su")
                        && su.contains("uid=0(root)");
                boolean ok = uid.contains("uid=0") || anySuOk || rootdSuOk;
                RootDiagnostic diag = new RootDiagnostic(
                        uid, cap, selinux, storage, module, manager, su, details, ok);
                String summary = ok ? "Root 可用" : "未取得 root / 权限不足";
                runOnUiThread(() -> {
                    ui.updateRootDiagnostic(diag, summary);
                    feedback(ok ? "Root 诊断通过" : "Root 诊断异常", summary, ok ? 1 : 2);
                });
                log("ROOT_DIAG=" + summary + "\n" + out);
            } catch (Throwable t) {
                log("ROOT_DIAG_FAILED=" + t);
                runOnUiThread(() -> feedback("Root 诊断失败", t.toString(), 2));
            } finally {
                ui.updateDiagnosticBusy(false);
                endAction();
            }
        }, "magicroot-diagnosis");
    }

    private static String section(String text, String marker) {
        return KernelLogHelper.section(text, marker);
    }

    /** Delete all of /data/local/tmp; refuses while a parked 98260 rootd exists. */
    public void doCleanTmp() {
        if (!beginAction())
            return;
        runAsync(() -> {
            try {
                // /data/local/tmp is shell-writable.  Do not depend on KSU su:
                // CLEAN_ADB deliberately removes that provider, so a later TMP
                // cleanup must use Shizuku first and report channel failures.
                String guard = cleanupShell(
                        "if [ -e /data/local/tmp/.magicroot-98260-parked ] "
                        + "|| [ -S /data/local/tmp/pc98260-root.sock ]; then "
                        + "echo CLEAN_TMP_GUARD_FOUND; else echo CLEAN_TMP_GUARD_CLEAR; fi");
                if (guard != null && guard.contains("CLEAN_TMP_GUARD_FOUND")) {
                    feedback("已阻止清理", "检测到 parked rootd/socket，请先重启设备", 2);
                    runOnUiThread(() -> ui.setStatus("清理已阻止"));
                    return;
                }
                if (guard == null || !guard.contains("CLEAN_TMP_GUARD_CLEAR")) {
                    feedback("清理失败", "无法确认 parked rootd 状态；需要 Shizuku 或可用 root", 2);
                    runOnUiThread(() -> ui.setStatus("清理状态检查失败"));
                    return;
                }
                String out = cleanupShell("rm -rf /data/local/tmp/* /data/local/tmp/.[!.]* "
                        + "/data/local/tmp/..?* 2>&1; echo CLEAN_TMP_DONE");
                log("CLEAN_TMP=" + out);
                boolean ok = out != null && out.contains("CLEAN_TMP_DONE")
                        && !out.toLowerCase(Locale.ROOT).contains("denied")
                        && !out.toLowerCase(Locale.ROOT).contains("read-only");
                String detail = out == null ? "" : out.trim();
                if (detail.isEmpty() || detail.contains("CLEAN_SHELL_FAILED"))
                    detail = "清理通道不可用；需要 Shizuku 或可用 root";
                final String resultDetail = detail;
                runOnUiThread(() -> ui.setStatus(ok ? "已清理 /data/local/tmp" : "清理失败"));
                feedback(ok ? "清理完成" : "清理失败",
                        ok ? "/data/local/tmp 已清空（含隐藏文件）" : resultDetail, ok ? 1 : 2);
            } catch (Throwable t) {
                feedback("清理失败", t.toString(), 2);
                runOnUiThread(() -> ui.setStatus("清理失败"));
            } finally {
                endAction();
            }
        }, "magicroot-clean-tmp");
    }

    /** Delete only the manager/module subdirectories in /data/adb. */
    public void doCleanAdb() {
        if (!beginAction())
            return;
        runAsync(() -> {
            try {
                String out = runStatusCommand(
                        "rm -rf /data/adb/ksu /data/adb/ksud /data/adb/modules "
                        + "/data/adb/post-fs-data.d /data/adb/service.d 2>&1; "
                        + "echo CLEAN_ADB_DONE");
                log("CLEAN_ADB=" + out);
                boolean ok = out != null && out.contains("CLEAN_ADB_DONE")
                        && !out.toLowerCase(Locale.ROOT).contains("denied")
                        && !out.toLowerCase(Locale.ROOT).contains("read-only");
                runOnUiThread(() -> ui.setStatus(ok ? "已清理 /data/adb 管理器数据" : "清理失败"));
                feedback(ok ? "清理完成" : "清理失败",
                        ok ? "已删除 ksu/ksud/modules/post-fs-data.d/service.d"
                                : String.valueOf(out), ok ? 1 : 2);
            } catch (Throwable t) {
                feedback("清理失败", t.toString(), 2);
                runOnUiThread(() -> ui.setStatus("清理失败"));
            } finally {
                endAction();
            }
        }, "magicroot-clean-adb");
    }

    /** Standalone STP clear; never stops or launches Parallel Space. */
    public void doStpClear() {
        if (!beginAction())
            return;
        runAsync(() -> {
            try {
                if (!ensureStpclearRoot())
                    throw new IllegalStateException("stpclear missing (root stage failed)");
                String out = runStpclearRoot();
                log("STP_CLEAR_STANDALONE=" + out);
                if (out == null || out.contains("STP_MISSING"))
                    throw new IllegalStateException("stpclear missing at runtime");
                ui.setStatus("STP 已清理");
                feedback("STP Clear 完成", "未改动用户状态", 1);
            } catch (Throwable t) {
                log("STP_CLEAR_STANDALONE_FAILED=" + t);
                feedback("STP Clear 失败", t.toString(), 2);
                ui.setStatus("STP 清理失败");
            } finally {
                endAction();
            }
        }, "magicroot-stp-clear");
    }

    /**
     * Apply the rootd-only + STP-safe profile: disable the two su detection
     * surfaces, stop auto-loading KernelSU, keep rootd/socket after a
     * successful 98260 run and leave the workdir in place for stpclear.
     * A previously loaded /system/bin/su needs a reboot (or the danger
     * su-surface action) before check-su stops seeing it.
     */
    public void applyStpCompatProfile() {
        runOnUiThread(() -> {
            ui.updateSuCompat(false);
            ui.updateSuEntry(false);
            ui.update98260Ksu(true);
            ui.updateKeepRootdForStp(true);
            ui.updateAutoCleanTemp(false);
            log("STP_PROFILE=su_compat=0 su_entry=0 ksu_auto=1 keep_rootd=1 auto_clean=0");
            ui.setStatus("STP 兼容配置已应用");
            feedback("STP 兼容配置已应用",
                    "已关闭 su entry/su_compat；6.1 CGA 以 force_feature=su_compat:0 在加载时禁用，"
                            + "KernelSU 自动加载保持开启，保留 rootd/socket；"
                            + "当前 boot 的 /system/bin/su 仍可能命中 check-su。",
                    1);
        });
    }

    /**
     * Stop only the rootd listener child and unlink its socket.  The PPID=1
     * exploit parent is deliberately preserved until reboot; killing it can
     * trip posix_cpu_timers_exit.
     */
    public void stopRootdAndCleanSockets() {
        if (!beginAction())
            return;
        feedback("停止 rootd", "仅停止 listener 子进程并清理 socket", 0);
        runAsync(() -> {
            try {
                String script = WORK + "/rootd_stop.sh";
                String check = shellNoThrow("test -f '" + script + "' && echo OK");
                if (check == null || !check.contains("OK")) {
                    runOnUiThread(() -> feedback("未找到 rootd_stop.sh",
                            "请先完成一次资产部署/提权后再试", 2));
                    return;
                }
                String out;
                try {
                    out = parallelRootExec("sh '" + script + "'", false);
                } catch (Throwable t) {
                    out = String.valueOf(t);
                }
                String logText = shellNoThrow(
                        "cat '" + WORK + "/rootd-stop.log' 2>/dev/null");
                String all = (out == null ? "" : out) + "\n"
                        + (logText == null ? "" : logText);
                log("ROOTD_STOP=" + all);
                boolean ok = all.contains("ROOTD_STOP_DONE")
                        && (all.contains("ROOTD_SOCK_REMOVE=ok")
                            || all.contains("ROOTD_SOCK_REMOVE=absent"));
                final String detail = ok
                        ? "listener 已停止，socket 已清理；PPID=1 父进程保留到重启"
                        : all.trim();
                runOnUiThread(() -> {
                    ui.setStatus(ok ? "rootd 已停止" : "rootd 停止未完成");
                    feedback(ok ? "rootd 已停止" : "rootd 停止未完成",
                            detail, ok ? 1 : 2);
                });
            } catch (Throwable t) {
                log("ROOTD_STOP_FAILED=" + t);
                runOnUiThread(() -> feedback("rootd 停止失败", t.toString(), 2));
            } finally {
                endAction();
            }
        }, "magicroot-rootd-stop");
    }

    /**
     * Danger action: disable su_compat, remove MagicRoot's su wrappers and
     * attempt to remove /system/bin/su.  rootd stays alive; KSU su may be
     * broken until the manager reinstalls it or the device reboots.
     */
    public void cleanupSuDetectionSurface() {
        if (!beginAction())
            return;
        feedback("清理 su 检测面", "关闭 su_compat 并移除 su 入口", 0);
        runAsync(() -> {
            try {
                String script = WORK + "/su_surface_clean.sh";
                String check = shellNoThrow("test -f '" + script + "' && echo OK");
                if (check == null || !check.contains("OK")) {
                    runOnUiThread(() -> feedback("未找到 su_surface_clean.sh",
                            "请先完成一次资产部署/提权后再试", 2));
                    return;
                }
                String out;
                try {
                    out = parallelRootExec("sh '" + script + "'", false);
                } catch (Throwable t) {
                    out = String.valueOf(t);
                }
                String logText = shellNoThrow(
                        "cat '" + WORK + "/su-surface-clean.log' 2>/dev/null");
                String all = (out == null ? "" : out) + "\n"
                        + (logText == null ? "" : logText);
                log("SU_SURFACE_CLEAN=" + all);
                boolean ok = all.contains("SU_SURFACE_CLEAN_DONE")
                        && (all.contains("SYSTEM_SU=removed")
                            || all.contains("SYSTEM_SU=absent"));
                final String detail = ok
                        ? "su_compat 已关闭；/system/bin/su 已移除或不存在。KSU su 可能失效，rootd 保留。"
                        : all.trim();
                runOnUiThread(() -> {
                    ui.setStatus(ok ? "su 检测面已清理" : "su 检测面清理未完成");
                    feedback(ok ? "su 检测面已清理" : "su 检测面清理未完成",
                            detail, ok ? 1 : 2);
                });
            } catch (Throwable t) {
                log("SU_SURFACE_CLEAN_FAILED=" + t);
                runOnUiThread(() -> feedback("su 检测面清理失败", t.toString(), 2));
            } finally {
                endAction();
            }
        }, "magicroot-su-surface");
    }

    private boolean isPackageInstalled(String pkg) {
        try {
            getPackageManager().getPackageInfo(pkg, 0);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static final class RemoteProcess extends Process {
        private final IRemoteProcess remote;
        private OutputStream stdin;
        private InputStream stdout;
        private InputStream stderr;
        private Integer exitCode;

        RemoteProcess(IRemoteProcess remote) {
            this.remote = remote;
            // Drain stderr asynchronously so a noisy child process (>64 KB on
            // stderr without 2>&1) cannot block on a full pipe and hang waitFor,
            // and ensure the remote stderr ParcelFileDescriptor is closed at EOF.
            Thread drain = new Thread(() -> {
                try (InputStream err = getErrorStream()) {
                    byte[] buf = new byte[4096];
                    while (err.read(buf) != -1) {
                        // discard after draining pipe buffer
                    }
                } catch (Throwable ignored) {
                }
            }, "magicroot-stderr-drain");
            drain.setDaemon(true);
            drain.start();
        }

        @Override
        public synchronized OutputStream getOutputStream() {
            if (stdin == null) {
                try {
                    stdin = new ParcelFileDescriptor.AutoCloseOutputStream(remote.getOutputStream());
                } catch (Throwable t) {
                    throw new RuntimeException("stdin", t);
                }
            }
            return stdin;
        }

        @Override
        public synchronized InputStream getInputStream() {
            if (stdout == null) {
                try {
                    stdout = new ParcelFileDescriptor.AutoCloseInputStream(remote.getInputStream());
                } catch (Throwable t) {
                    throw new RuntimeException("stdout", t);
                }
            }
            return stdout;
        }

        @Override
        public synchronized InputStream getErrorStream() {
            if (stderr == null) {
                try {
                    stderr = new ParcelFileDescriptor.AutoCloseInputStream(remote.getErrorStream());
                } catch (Throwable t) {
                    throw new RuntimeException("stderr", t);
                }
            }
            return stderr;
        }

        @Override
        public synchronized int waitFor() throws InterruptedException {
            try {
                exitCode = remote.waitFor();
                return exitCode;
            } catch (Throwable t) {
                throw new RuntimeException("waitFor", t);
            }
        }

        @Override
        public synchronized boolean waitFor(long timeout, TimeUnit unit)
                throws InterruptedException {
            try {
                boolean exited = remote.waitForTimeout(timeout, unit.toString());
                if (exited)
                    exitCode = remote.exitValue();
                return exited;
            } catch (Throwable t) {
                String message = t.getMessage();
                if (message != null &&
                        (message.contains("process not end") || message.contains("not end"))) {
                    // Shizuku reports a normal timeout as an exception.  The
                    // Process contract requires false, never a Java crash.
                    return false;
                }
                throw new RuntimeException("waitForTimeout", t);
            }
        }

        @Override
        public synchronized int exitValue() {
            try {
                if (exitCode == null)
                    exitCode = remote.exitValue();
                return exitCode;
            } catch (Throwable t) {
                throw new RuntimeException("exitValue", t);
            }
        }

        @Override
        public void destroy() {
            try {
                remote.destroy();
            } catch (Throwable ignored) {
            }
        }
    }
}
