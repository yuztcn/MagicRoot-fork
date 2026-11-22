package com.aoki.magicroot;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Manager APK payload extraction and native-lib execution resolution.
 *
 * No public paths are created.  All temporary payloads live under the app's
 * cache dir in a random directory, are 0600, and are deleted by cleanup().
 */
final class AdaptiveManager {
    interface Log { void line(String s); }

    static final int EXEC_OK = 1;
    static final int EXEC_DENIED = 0;
    static final int EXEC_INVALID = -1;

    static final class Result {
        File file;
        String source;
        String detail;
        int execState;
        Result(File f, String s, String d, int state) {
            file = f; source = s; detail = d; execState = state;
        }
    }

    private static final class Candidate {
        byte[] data;
        String source;
        String vermagic;
        String release;
        String kmi;
        int rank;
    }

    private final Context ctx;
    private final File work;
    private final Log log;
    private final List<File> tempDirs = new ArrayList<>();

    AdaptiveManager(Context ctx, File work, Log log) {
        this.ctx = ctx;
        this.work = work;
        this.log = log;
        File cache = ctx.getCacheDir();
        File[] stale = cache == null ? null : cache.listFiles();
        if (stale != null) {
            for (File f : stale) {
                if (f.isDirectory() && f.getName().startsWith("mgr-")) {
                    deleteTree(f);
                    log.line("MANAGER_TEMP_CLEAN=stale path=" + f.getName());
                }
            }
        }
    }

    private File newTempDir() throws IOException {
        File d = new File(ctx.getCacheDir(), "mgr-" + UUID.randomUUID());
        if (!d.mkdirs()) throw new IOException("mkdir_private_failed");
        d.setReadable(true, true);
        d.setWritable(true, true);
        d.setExecutable(true, true);
        tempDirs.add(d);
        return d;
    }

    private File writePrivate(byte[] data, String suffix) throws IOException {
        File d = newTempDir();
        File f = new File(d, UUID.randomUUID() + suffix);
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(data);
            out.getFD().sync();
        }
        f.setReadable(true, true);
        f.setWritable(false, false);
        f.setExecutable(true, true);
        return f;
    }

    void cleanup() {
        for (File d : tempDirs) deleteTree(d);
        tempDirs.clear();
    }

    private static void deleteTree(File f) {
        if (f == null) return;
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        //noinspection ResultOfMethodCallIgnored
        f.delete();
    }

    private List<String> apks(String pkg) throws Exception {
        PackageManager pm = ctx.getPackageManager();
        ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
        List<String> out = new ArrayList<>();
        if (ai.sourceDir != null) out.add(ai.sourceDir);
        addAll(out, ai.splitSourceDirs);
        addAll(out, ai.splitPublicSourceDirs);
        return out;
    }

    private static void addAll(List<String> out, String[] values) {
        if (values == null) return;
        for (String v : values)
            if (v != null && !out.contains(v)) out.add(v);
    }

    private static boolean isElf(byte[] b) {
        return b != null && b.length > 4 && b[0] == 0x7f && b[1] == 'E'
                && b[2] == 'L' && b[3] == 'F';
    }

    private static String vermagic(byte[] ko) {
        if (ko == null) return "";
        String s = new String(ko, StandardCharsets.ISO_8859_1);
        int i = s.indexOf("vermagic=");
        if (i < 0) return "";
        int p = i + "vermagic=".length();
        int e = p;
        while (e < s.length() && s.charAt(e) != 0 && s.charAt(e) != '\n'
                && s.charAt(e) != '\r') e++;
        return s.substring(p, Math.min(e, p + 256));
    }

    private static String release(String vm) {
        int sp = vm.indexOf(' ');
        return sp > 0 ? vm.substring(0, sp) : vm;
    }

    private static String kmi(String v) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("(\\d+)\\.(\\d+)").matcher(v == null ? "" : v);
        return m.find() ? m.group(1) + "." + m.group(2) : "";
    }

    private static String patch(String v) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("(\\d+)\\.(\\d+)\\.(\\d+)").matcher(v == null ? "" : v);
        return m.find() ? m.group(1) + "." + m.group(2) + "." + m.group(3) : "";
    }

    private void addCandidate(List<Candidate> list, byte[] data, String source,
                              String targetKernel, String targetKmi, String targetPatch) {
        if (list.size() >= 256 || !isElf(data)) return;
        String vm = vermagic(data);
        if (vm.isEmpty()) {
            log.line("MANAGER_LKM_REJECT source=" + source + " reason=no_vermagic");
            return;
        }
        String rel = release(vm);
        String k = kmi(vm);
        int rank = 0;
        if (rel.equals(targetKernel)) rank = 3;
        else if (patch(rel).equals(targetPatch)) rank = 2;
        else if (k.equals(targetKmi)) rank = 1;
        if (rank == 0) {
            log.line("MANAGER_LKM_REJECT source=" + source + " kmi=" + k
                    + " vm=" + vm + " reason=not_target");
            return;
        }
        Candidate c = new Candidate();
        c.data = data;
        c.source = source;
        c.vermagic = vm;
        c.release = rel;
        c.kmi = k;
        c.rank = rank;
        list.add(c);
        log.line("MANAGER_LKM_CANDIDATE source=" + source + " bytes=" + data.length
                + " release=" + rel + " kmi=" + k + " rank="
                + (rank == 3 ? "exact" : rank == 2 ? "patch" : "kmi"));
    }

    private void carve(byte[] data, String source, List<Candidate> out,
                       String targetKernel, String targetKmi, String targetPatch) {
        if (!isElf(data)) {
            log.line("MANAGER_LKM_REJECT source=" + source + " reason=not_elf");
            return;
        }
        long deadline = System.currentTimeMillis() + 60000L;

        // Some managers (SukiSU) store nested ELF .ko images, not raw-deflate
        // streams.  Scan those first; do not burn 15k inflate attempts on a
        // container that is not deflate-based.
        int nested = 0;
        for (int off = 1; off + 4 < data.length && nested < 32; off++) {
            if (System.currentTimeMillis() > deadline) break;
            if ((data[off] & 0xff) != 0x7f || data[off + 1] != 'E'
                    || data[off + 2] != 'L' || data[off + 3] != 'F')
                continue;
            int max = Math.min(900000, data.length - off);
            if (max < 65536) continue;
            byte[] sub = java.util.Arrays.copyOfRange(data, off, off + max);
            addCandidate(out, sub, source + "@elf0x" + Integer.toHexString(off),
                    targetKernel, targetKmi, targetPatch);
            nested++;
        }
        if (nested > 0) {
            log.line("MANAGER_LKM_ELF_SCAN source=" + source + " nested=" + nested);
            return;
        }

        int corrupt = 0;
        for (int off = 0; off + 4 < data.length && out.size() < 256; off++) {
            if (System.currentTimeMillis() > deadline) break;
            if ((data[off] & 0xff) != 0xED) continue;
            Inflater inf = new Inflater(true);
            try {
                inf.setInput(data, off, data.length - off);
                byte[] head = new byte[4];
                if (inf.inflate(head) != 4 || !isElf(head)) continue;
                ByteArrayOutputStream bos = new ByteArrayOutputStream(1 << 20);
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
                if (!inf.finished()) { corrupt++; continue; }
                byte[] ko = bos.toByteArray();
                if (ko.length < 65536 || ko.length > 900000) continue;
                addCandidate(out, ko, source + "@0x" + Integer.toHexString(off),
                        targetKernel, targetKmi, targetPatch);
            } catch (Throwable t) {
                corrupt++;
            } finally {
                inf.end();
            }
        }
        if (corrupt > 0)
            log.line("MANAGER_LKM_REJECT source=" + source + " reason=not_raw_deflate count=" + corrupt);
    }

    /**
     * Priority: exact full release > same major.minor.patch > same KMI.
     * All candidates are evaluated; fail closed when nothing matches.
     */
    private InputStream openBundledAsset(String name) throws java.io.IOException {
        try {
            return ctx.getAssets().open(name);
        } catch (java.io.FileNotFoundException e) {
            String canonical = KernelLogHelper.resolveCanonicalAsset(name);
            if (canonical != null && !canonical.equals(name)) {
                return ctx.getAssets().open(canonical);
            }
            throw e;
        }
    }

    private static String[] bundledTemplateNames(String flavor, String kmi) {
        if (kmi != null && kmi.startsWith("6.6"))
            return new String[] {
                    "ksu-template-66118-" + flavor + ".ko",
                    "ksu-template-66118.ko",
                    "ksu-template-" + flavor + ".ko",
                    "ksu-template.ko"
            };
        return new String[] {
                "ksu-template-" + flavor + ".ko",
                "ksu-template.ko"
        };
    }

    Result extractLkm(String pkg, String targetKernel, String targetKmi,
                      String targetPatch, String flavor) {
        List<Candidate> candidates = new ArrayList<>();
        try {
            for (String apk : apks(pkg)) {
                try (ZipFile zf = new ZipFile(new File(apk))) {
                    Enumeration<? extends ZipEntry> en = zf.entries();
                    while (en.hasMoreElements()) {
                        ZipEntry e = en.nextElement();
                        String n = e.getName();
                        String ln = n.toLowerCase();
                        if (ln.contains("susfs")) continue;
                        if (ln.endsWith(".ko")) {
                            byte[] data = read(zf, e);
                            addCandidate(candidates, data, apk + "!" + n,
                                    targetKernel, targetKmi, targetPatch);
                        } else if (n.startsWith("lib/arm64-v8a/") && n.endsWith(".so")) {
                            byte[] data = read(zf, e);
                            carve(data, apk + "!" + n, candidates,
                                    targetKernel, targetKmi, targetPatch);
                        }
                    }
                } catch (Throwable t) {
                    log.line("MANAGER_LKM_REJECT source=" + apk + " reason=" + t);
                }
            }
            // No manager-embedded KO: fall back to the bundled template, still
            // strictly KMI checked.  This is not a deployment failure.
            for (String tpl : bundledTemplateNames(flavor, targetKmi)) {
                try (InputStream in = openBundledAsset(tpl)) {
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] b = new byte[65536];
                    int n;
                    while ((n = in.read(b)) > 0) bos.write(b, 0, n);
                    int before = candidates.size();
                    addCandidate(candidates, bos.toByteArray(), "bundled:" + tpl,
                            targetKernel, targetKmi, targetPatch);
                    if (candidates.size() > before) break;
                } catch (Throwable ignored) {
                }
            }
            if (candidates.isEmpty()) {
                log.line("MANAGER_LKM_SELECT none package=" + pkg + " target=" + targetKernel);
                return null;
            }
            Candidate best = null;
            for (Candidate c : candidates) {
                if (best == null || c.rank > best.rank
                        || (c.rank == best.rank && c.release.equals(targetKernel)
                            && !best.release.equals(targetKernel)))
                    best = c;
            }
            if (best == null || !best.kmi.equals(targetKmi)) {
                log.line("MANAGER_LKM_SELECT none package=" + pkg + " reason=no_kmi_match target=" + targetKmi);
                return null;
            }
            File f = writePrivate(best.data, ".ko");
            log.line("MANAGER_LKM_SELECT source=" + best.source + " bytes=" + best.data.length
                    + " release=" + best.release + " kmi=" + best.kmi
                    + " rank=" + (best.rank == 3 ? "exact" : best.rank == 2 ? "patch" : "kmi")
                    + " path=" + f.getAbsolutePath());
            return new Result(f, best.source, best.vermagic, EXEC_OK);
        } catch (Throwable t) {
            log.line("MANAGER_LKM_SELECT none package=" + pkg + " reason=" + t);
            return null;
        }
    }

    Result extractKsud(String pkg) {
        try {
            for (String apk : apks(pkg)) {
                try (ZipFile zf = new ZipFile(new File(apk))) {
                    List<ZipEntry> ordered = new ArrayList<>();
                    ZipEntry preferred = zf.getEntry("lib/arm64-v8a/libksud.so");
                    if (preferred != null) ordered.add(preferred);
                    Enumeration<? extends ZipEntry> en = zf.entries();
                    while (en.hasMoreElements()) {
                        ZipEntry e = en.nextElement();
                        String n = e.getName();
                        if (n.equals("lib/arm64-v8a/libksud.so")) continue;
                        if (n.startsWith("lib/arm64-v8a/") && n.endsWith(".so")
                                && !n.contains("libandroidx") && !n.contains("libdatastore")) {
                            ordered.add(e);
                        } else if (n.equals("assets/ksud") || n.equals("lib/arm64-v8a/libksud")) {
                            ordered.add(e);
                        }
                    }
                    Result deniedBest = null;
                    long deniedSize = -1;
                    for (ZipEntry e : ordered) {
                        byte[] data = read(zf, e);
                        if (!isElf(data)) {
                            log.line("MANAGER_KSUD_REJECT source=" + apk + "!" + e.getName()
                                    + " reason=not_elf");
                            continue;
                        }
                        File f = writePrivate(data, ".bin");
                        int st = probe(f, "-V");
                        if (st == EXEC_OK) {
                            log.line("MANAGER_KSUD_SELECT source=" + apk + "!" + e.getName()
                                    + " bytes=" + data.length + " path=" + f.getAbsolutePath());
                            return new Result(f, apk + "!" + e.getName(), "ksud", EXEC_OK);
                        }
                        if (st == EXEC_DENIED) {
                            boolean prefKsud = e.getName().contains("libksud")
                                    || e.getName().endsWith("/ksud");
                            if (deniedBest == null || prefKsud
                                    || (long) data.length > deniedSize) {
                                if (deniedBest != null) deniedBest.file.delete();
                                deniedBest = new Result(f, apk + "!" + e.getName(), "ksud_root",
                                        EXEC_DENIED);
                                deniedSize = data.length;
                                log.line("MANAGER_KSUD_ROOT_ONLY source=" + apk + "!" + e.getName()
                                        + " bytes=" + data.length);
                            } else {
                                f.delete();
                            }
                        } else {
                            f.delete();
                        }
                    }
                    if (deniedBest != null) {
                        log.line("MANAGER_KSUD_SELECT root_only path=" + deniedBest.file.getAbsolutePath());
                        return deniedBest;
                    }
                } catch (Throwable t) {
                    log.line("MANAGER_KSUD_REJECT source=" + apk + " reason=" + t);
                }
            }
            log.line("MANAGER_KSUD_SELECT none package=" + pkg);
            return null;
        } catch (Throwable t) {
            log.line("MANAGER_KSUD_SELECT none package=" + pkg + " reason=" + t);
            return null;
        }
    }

    private static byte[] read(ZipFile zf, ZipEntry e) throws Exception {
        try (InputStream in = zf.getInputStream(e)) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] b = new byte[65536];
            int n;
            while ((n = in.read(b)) > 0) bos.write(b, 0, n);
            return bos.toByteArray();
        }
    }

    /**
     * Execute probe tri-state.  Exit 0 is the only EXEC_OK.  EACCES means the
     * payload may still be executable by root and must not be discarded as
     * corrupt; it is EXEC_DENIED.
     */
    int probe(File f, String arg) {
        if (f == null || !f.isFile()) {
            log.line("LIBEXEC=invalid path=" + (f == null ? "null" : f.getAbsolutePath())
                    + " reason=missing");
            return EXEC_INVALID;
        }
        if (!f.canExecute()) {
            log.line("LIBEXEC=denied path=" + f.getAbsolutePath() + " reason=not_exec_bit");
            return EXEC_DENIED;
        }
        Process p = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(f.getAbsolutePath(), arg);
            pb.redirectOutput(ProcessBuilder.Redirect.to(new File("/dev/null")));
            pb.redirectError(ProcessBuilder.Redirect.to(new File("/dev/null")));
            p = pb.start();
            boolean finished = p.waitFor(2000, TimeUnit.MILLISECONDS);
            if (!finished) {
                p.destroyForcibly();
                p.waitFor(1000, TimeUnit.MILLISECONDS);
                log.line("LIBEXEC=invalid path=" + f.getAbsolutePath()
                        + " reason=timeout probe=" + arg);
                return EXEC_INVALID;
            }
            int rc = p.exitValue();
            if (rc == 0) {
                log.line("LIBEXEC=ok path=" + f.getAbsolutePath() + " probe=" + arg);
                return EXEC_OK;
            }
            log.line("LIBEXEC=invalid path=" + f.getAbsolutePath()
                    + " reason=exit_" + rc + " probe=" + arg);
            return EXEC_INVALID;
        } catch (Throwable t) {
            String m = String.valueOf(t).toLowerCase();
            if (m.contains("permission") || m.contains("denied")
                    || m.contains("eacces") || m.contains("errno=13")) {
                log.line("LIBEXEC=denied path=" + f.getAbsolutePath() + " reason=" + t);
                return EXEC_DENIED;
            }
            log.line("LIBEXEC=invalid path=" + f.getAbsolutePath() + " reason=" + t);
            return EXEC_INVALID;
        } finally {
            if (p != null && p.isAlive()) p.destroyForcibly();
        }
    }

    /** nativeLibraryDir first, then the legacy WORK copy; never create paths. */
    Result resolve(String tag, String libName, String legacyName) {
        String dir = null;
        try {
            ApplicationInfo ai = ctx.getApplicationInfo();
            dir = ai.nativeLibraryDir;
        } catch (Throwable ignored) {
        }
        if (dir != null) {
            File n = new File(dir, libName);
            int st = probe(n, "-V");
            if (st == EXEC_OK)
                return new Result(n, "nativeLibraryDir", tag, EXEC_OK);
            log.line("LIBEXEC=fallback tag=" + tag + " state=" + st
                    + " native=" + n.getAbsolutePath());
        }
        File w = new File(work, legacyName);
        if (w.isFile() && w.canExecute()) {
            log.line("LIBEXEC=legacy tag=" + tag + " path=" + w.getAbsolutePath());
            return new Result(w, "legacy_work", tag, EXEC_OK);
        }
        log.line("LIBEXEC=unavailable tag=" + tag + " lib=" + libName + " legacy=" + legacyName);
        return null;
    }
}
