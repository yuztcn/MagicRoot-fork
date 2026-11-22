package com.aoki.magicroot;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure-Java helpers for kernel version/vermagic parsing, 6.1.x route lookup,
 * manager metadata, and run-log text slicing.
 *
 * <p>Deliberately free of Android framework imports so unit tests can compile
 * and execute directly via {@code javac}/{@code java} in {@code tools/check.sh}.</p>
 */
public final class KernelLogHelper {
    private static final Pattern KMI_PATTERN = Pattern.compile("(\\d+)\\.(\\d+)");
    private static final Pattern PATCH_PATTERN = Pattern.compile("(\\d+)\\.(\\d+)\\.(\\d+)");

    private KernelLogHelper() {
    }

    /** 1=DONE, 2=FAIL=, 0=unfinished; only line starts match. */
    public static int finishKind(String tail) {
        if (tail == null || tail.isEmpty()) return 0;
        for (String line : tail.split("\n")) {
            String s = line.trim();
            if (s.equals("DONE"))
                return 1;
            if (s.startsWith("FAIL="))
                return 2;
        }
        return 0;
    }

    public static String tailLines(String text, int count) {
        if (text == null || text.isEmpty() || count <= 0)
            return "";
        String[] lines = text.split("\n");
        int start = Math.max(0, lines.length - count);
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < lines.length; i++)
            sb.append(lines[i]).append('\n');
        return sb.toString();
    }

    public static String section(String text, String marker) {
        if (text == null || marker == null) return "";
        String[] parts = text.split(Pattern.quote(marker), 2);
        return parts.length < 2 ? "" : parts[1].split("__[A-Z]+__", 2)[0];
    }

    /** Pick the first (os.version, uname -r, /proc/version) with a KMI. */
    public static String firstKernelRelease(String... values) {
        if (values == null) return "";
        for (String value : values) {
            if (value != null && !value.trim().isEmpty()
                    && !kmiOfKernel(value).isEmpty())
                return value.trim();
        }
        return "";
    }

    /** major.minor of a kernel release string, e.g. 6.12.58 -> 6.12. */
    public static String kmiOfKernel(String value) {
        if (value == null) return "";
        Matcher m = KMI_PATTERN.matcher(value);
        return m.find() ? m.group(1) + "." + m.group(2) : "";
    }

    /** major.minor of an ELF vermagic, e.g. 6.12.76-4k -> 6.12. */
    public static String kmiOfVermagic(String value) {
        if (value == null) return "";
        Matcher m = KMI_PATTERN.matcher(value.trim());
        return m.find() ? m.group(1) + "." + m.group(2) : "";
    }

    /** major.minor.patch of a release, e.g. 6.12.58-android -> 6.12.58. */
    public static String patchOfKernel(String value) {
        if (value == null) return "";
        Matcher m = PATCH_PATTERN.matcher(value);
        return m.find() ? m.group(1) + "." + m.group(2) + "." + m.group(3) : "";
    }

    /** Release part (before first space) of a vermagic. */
    public static String releaseOfVermagic(String value) {
        if (value == null) return "";
        int space = value.indexOf(' ');
        return space > 0 ? value.substring(0, space) : value;
    }

    /** Read the NUL-terminated vermagic string from a carved .ko .modinfo. */
    public static String modinfoVermagic(byte[] ko) {
        if (ko == null || ko.length == 0) return "";
        String s = new String(ko, StandardCharsets.ISO_8859_1);
        int i = s.indexOf("vermagic=");
        if (i < 0) return "";
        int end = i + "vermagic=".length();
        while (end < s.length() && s.charAt(end) != 0
                && s.charAt(end) != '\n' && s.charAt(end) != '\r')
            end++;
        return s.substring(i + "vermagic=".length(), end);
    }

    public static String managerLabelOf(String flavor) {
        if (flavor == null) return "KernelSU";
        switch (flavor) {
            case "fina": return "FinaSU";
            case "sukisu": return "SukiSU";
            case "next": return "KernelSU-Next";
            case "nova": return "SukiSU Nova";
            case "maplesu": return "MapleSU";
            case "resukisu": return "BakaSU";
            default: return "KernelSU";
        }
    }

    public static String managerDefaultPkg(String flavor) {
        if (flavor == null) return "com.resukisu.resukisu";
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

    public static int managerPriority(String flavor) {
        if (flavor == null) return 9;
        switch (flavor) {
            case "kernelsu": return 0;
            case "next": return 1;
            case "sukisu": return 2;
            case "resukisu": return 3;
            case "fina": return 4;
            case "nova": return 5;
            case "maplesu": return 6;
            default: return 9;
        }
    }

    public static final class Profile6157 {
        public final String id;
        public final String releasePrefix;
        public final String payloadDir;
        public final String cgaBase;

        Profile6157(String id, String releasePrefix, String payloadDir, String cgaBase) {
            this.id = id;
            this.releasePrefix = releasePrefix;
            this.payloadDir = payloadDir;
            this.cgaBase = cgaBase;
        }
    }

    public static final Profile6157[] PROFILES_6157 = {
            new Profile6157("g7d", "6.1.157-android14-11-g7d3922fade43", "98260-6157", null),
            new Profile6157("g264", "6.1.157-android14-11-g2646292297b1", "98260-g264", "g264/ksm-g264-base.ko"),
            new Profile6157("gaaa", "6.1.157-android14-11-gaaa383620ebf", "98260-gaaa", "g264/ksm-gaaa-base.ko"),
            new Profile6157("g3306", "6.1.157-android14-11-g3306a328b7be", "98260-g3306", "g264/ksm-g3306-base.ko"),
            new Profile6157("g84", "6.1.157-android14-11-g84ffa64b710b", "98260-g84", "g264/ksm-g84-base.ko"),
            new Profile6157("g77f", "6.1.157-android14-11-g77f76e323a02", "98260-g77f", "g264/ksm-g77f-base.ko"),
            new Profile6157("g8d6", "6.1.157-android14-11-g8d63307071ad", "98260-g8d6", "g264/ksm-g8d6-base.ko"),
            new Profile6157("gce849", "6.1.99-android14-11-gce84935796c9", "98260-gce849", "g264/ksm-gce849-base.ko"),
            new Profile6157("g5859", "6.1.99-android14-11-g5859fbdbad8c", "98260-g5859", "g264/ksm-g5859-base.ko"),
            new Profile6157("g54d", "6.1.99-android14-11-g54d40b4fb287", "98260-g54d", "g264/ksm-g54d-base.ko"),
            new Profile6157("g40b1", "6.1.128-android14-11-g40b1fd119d9b", "98260-g40b1", "g264/ksm-g40b1-base.ko"),
            new Profile6157("g8a496", "6.1.128-android14-11-g8a4968670f1c", "98260-g8a496", "g264/ksm-g8a496-base.ko"),
            new Profile6157("g2e1f", "6.1.128-android14-11-g2e1f0741dafb", "98260-g2e1f", "g264/ksm-g2e1f-base.ko"),
            new Profile6157("ge9da", "6.1.99-android14-11-ge9da27488f45", "98260-ge9da", "g264/ksm-ge9da-base.ko"),
            new Profile6157("g19a", "6.1.157-android14-11-g19a495a97bff", "61157", null),
    };

    public static Profile6157 findProfile6157(String release) {
        if (release == null) return null;
        for (Profile6157 p : PROFILES_6157) {
            if (release.startsWith(p.releasePrefix)) return p;
        }
        return null;
    }

    public static String payloadDirFor6157(String release) {
        Profile6157 p = findProfile6157(release);
        return p == null ? null : p.payloadDir;
    }

    public static String cgaBaseFor6157(String release) {
        Profile6157 p = findProfile6157(release);
        return p == null ? null : p.cgaBase;
    }

    /** Assets that have no consumer outside the 6.1.x route. */
    public static boolean is6157OnlyAsset(String name) {
        if (name == null) return false;
        if (name.equals("98260/run6157_full.sh") || name.equals("6157-integrity.tsv"))
            return true;
        if (name.startsWith("61157/") || name.startsWith("g264/")
                || name.startsWith("su-g264/") || name.startsWith("ksu6157/")
                || name.startsWith("ksu6157-g264/") || name.startsWith("ksu6157-m6/"))
            return true;
        for (Profile6157 p : PROFILES_6157) {
            if (name.startsWith(p.payloadDir + "/")) return true;
        }
        return false;
    }

    /**
     * Single deployment planner for every supported 6.1.x route.
     *
     * <p>Only exact releases in {@link #PROFILES_6157} receive assets.  The
     * per-build payload and CGA base always come from the same profile; M6,
     * g264's legacy handoff and g19a's old 61157 route stay isolated.  Shared
     * userspace tools are common, but no absolute-symbol module is inherited
     * by another build.</p>
     */
    public static boolean shouldStage6157Asset(String name, String release) {
        if (name == null || release == null || !release.startsWith("6.1.")) return false;
        Profile6157 p = findProfile6157(release);
        boolean legacy61157 = p != null && "g19a".equals(p.id);
        boolean m6 = p != null && "g7d".equals(p.id);
        boolean g264 = p != null && "g264".equals(p.id);
        boolean cga = p != null && p.cgaBase != null;
        boolean run6157 = p != null && !legacy61157;

        if (name.equals("98260/run6157_full.sh")) return run6157;
        if (name.startsWith("98260-")) {
            return run6157 && name.startsWith(p.payloadDir + "/");
        }
        if (name.equals("g264/ko_slide_patch")) return cga;
        if (name.startsWith("g264/ksm-") && name.endsWith("-base.ko")) {
            return cga && name.equals(p.cgaBase);
        }
        // Per-build CGA-resolved symbol table for the manager-KO test path.
        // g7d keeps cgaBase=null (M6 handoff) but still needs its table when
        // the experimental manager-KO attempt runs before M6.
        if (name.equals("g264/syms-g7d.txt")) return m6;
        if (name.startsWith("g264/syms-") && name.endsWith(".txt")) {
            return cga && p.cgaBase != null
                    && name.equals(p.cgaBase.replace("ksm-", "syms-")
                            .replace("-base.ko", ".txt"));
        }
        if (name.startsWith("su-g264/")) return cga;
        if (name.equals("ksu6157-g264/ksud") || name.equals("ksu6157-g264/sigparam")) {
            return cga;
        }
        if (name.startsWith("ksu6157-g264/")) return g264;
        if (name.startsWith("ksu6157-m6/")) return m6;
        if (name.startsWith("ksu6157/")) return m6 || legacy61157;
        if (name.startsWith("61157/")) {
            if (!legacy61157) return false;
            String leaf = name.substring("61157/".length());
            return !leaf.equals("brm_plant") && !leaf.equals("kernelsu-honor.ko")
                    && !leaf.equals("ksu-loader") && !leaf.equals("syms_elp_an00.txt");
        }

        if (run6157) {
            return name.equals("run.sh") || name.equals("clean.sh")
                    || name.equals("lib.sh") || name.equals("kernel_profiles.sh")
                    || name.equals("ko_patch") || name.equals("addrcalc")
                    || name.equals("root_stage.sh") || name.equals("su_entry.sh")
                    || name.equals("pc98260-su") || name.equals("libadbroot.so")
                    || name.equals("su_forward") || name.equals("stpclear")
                    || name.equals("wait_helper") || name.equals("ksu_flavor")
                    || name.equals("rootd_stop.sh") || name.equals("su_surface_clean.sh")
                    || name.equals("lsposed-hotfix.sh") || name.equals("soft-reboot-root.sh")
                    || name.equals("susfs_insmod") || name.equals("6157-integrity.tsv");
        }
        if (legacy61157) {
            return name.equals("ko_patch") || name.equals("run.sh")
                    || name.equals("lib.sh") || name.equals("clean.sh")
                    || name.equals("kernel_profiles.sh") || name.equals("root_stage.sh")
                    || name.equals("su_entry.sh") || name.equals("pc98260-su")
                    || name.equals("stpclear") || name.equals("rootd_stop.sh")
                    || name.equals("su_surface_clean.sh") || name.equals("lsposed-hotfix.sh")
                    || name.equals("soft-reboot-root.sh") || name.equals("libadbroot.so")
                    || name.equals("su_forward") || name.equals("addrcalc")
                    || name.equals("wait_helper") || name.equals("ksu_flavor");
        }
        return false;
    }

    public static boolean shouldStage98260Asset(
            String name, String dir, String release, String model) {
        if (name == null || dir == null || name.contains("/exploit-android-perf"))
            return false;
        boolean aphModel = model != null
                && model.toUpperCase(java.util.Locale.ROOT).startsWith("APH-");
        if ("98260".equals(dir)) {
            if (name.endsWith("/run98260.sh") || name.endsWith("/stpclear")
                    || name.endsWith("/SHA256SUMS.txt")) {
                return true;
            }
            return release != null
                    && release.startsWith("6.12.58-android16-6-g3a7ac1674240");
        }
        if ("98260-61258b".equals(dir))
            return release != null
                    && release.startsWith("6.12.58-android16-6-g459a4285ccf8")
                    && !aphModel;
        if ("98260-61258c".equals(dir))
            return release != null
                    && release.startsWith("6.12.58-android16-6-g42fcf008ff5c");
        if ("98260-6138".equals(dir))
            return release != null && release.startsWith("6.12.38-android16-5-gfde");
        if ("98260-6123".equals(dir))
            return release != null && release.startsWith("6.12.23-android16-5-g45");
        if ("98260-g856".equals(dir))
            return release != null
                    && release.startsWith("6.12.23-android16-5-gcd85666d7884");
        if ("98260-6138y".equals(dir))
            return release != null && release.startsWith("6.12.38-android16-5-g7ae");
        if ("98260-g4b36".equals(dir))
            return release != null
                    && release.startsWith("6.12.38-android16-5-g4b3671e1f5b7");
        if ("98260-g52d15".equals(dir))
            return release != null
                    && release.startsWith("6.12.81-android16-6-g52d15df5db87");
        if ("98260-aph112".equals(dir))
            return release != null
                    && release.startsWith("6.12.58-android16-6-g459a4285ccf8")
                    && aphModel;
        if ("98260-6658".equals(dir))
            return release != null
                    && release.startsWith("6.6.58-android15-8-g6484937db664");
        if ("98260-g554".equals(dir))
            return release != null && release.startsWith("6.6.118-android15-8-g554929766a0d");
        if ("98260-f171".equals(dir))
            return release != null && release.startsWith("6.6.118-android15-8-gf17133276a57");
        if ("98260-6689".equals(dir))
            return release != null && release.startsWith("6.6.89-android15-8-g082e5a98dac1");
        if ("98260-g142".equals(dir))
            return release != null && release.startsWith("6.12.58-android16-6-g142ddad31e60");
        if ("98260-ga812".equals(dir))
            return release != null && release.startsWith("6.6.118-android15-8-ga812a1946391");
        if ("98260-g893".equals(dir))
            return release != null && release.startsWith("6.6.118-android15-8-g893e848657cc");
        if ("98260-61821".equals(dir))
            return release != null && release.startsWith("6.18.21-android17-5-g928d1bb4f1d7");
        if ("98260-61821-brm".equals(dir))
            return release != null && release.startsWith("6.18.21-android17-5-ge186062ea75f");
        if ("98260-61821-117".equals(dir))
            return release != null && release.startsWith("6.18.21-android17-5-gfee2325de189");
        if ("98260-h1c".equals(dir))
            return release != null && release.startsWith("6.18.21-android17-5-");
        return false;
    }

    private static final java.util.Map<String, String> DEDUP_ASSET_MAP;
    static {
        java.util.Map<String, String> m = new java.util.HashMap<>(64);
        m.put("98260-g264/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-g8d6/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-gaaa/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-g2e1f/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-g3306/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-g40b1/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-g54d/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-g5859/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-g77f/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-g84/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-g8a496/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-gce849/pc98260-su", "98260-6157/pc98260-su");
        m.put("98260-ge9da/pc98260-su", "98260-6157/pc98260-su");
        m.put("64560-61821/ksud", "61157/ksud");
        m.put("ksu6157-g264/ksud", "61157/ksud");
        m.put("ksu6157/ksud", "61157/ksud");
        m.put("ksu6157/kernelsu-honor.ko", "61157/kernelsu-honor.ko");
        m.put("98260-61821-brm/ksu-template-61821-sukisu.ko", "ksu-template-61821-sukisu.ko");
        m.put("98260-61821/ksu-template-61821-sukisu.ko", "ksu-template-61821-sukisu.ko");
        m.put("98260-61821-brm/ksu-template-61821-fina.ko", "ksu-template-61821-fina.ko");
        m.put("98260-61821/ksu-template-61821-fina.ko", "ksu-template-61821-fina.ko");
        m.put("98260-61821-brm/ksu-template-61821-next.ko", "ksu-template-61821-next.ko");
        m.put("98260-61821/ksu-template-61821-next.ko", "ksu-template-61821-next.ko");
        m.put("98260-61821-brm/ksu-template-61821-bakasu.ko", "ksu-template-61821-bakasu.ko");
        m.put("98260-61821/ksu-template-61821-bakasu.ko", "ksu-template-61821-bakasu.ko");
        m.put("98260-6658/pc98260-su", "pc98260-su");
        m.put("98260-6689/pc98260-su", "pc98260-su");
        m.put("98260-g142/pc98260-su", "pc98260-su");
        m.put("98260-ga812/pc98260-su", "pc98260-su");
        m.put("98260-g893/pc98260-su", "pc98260-su");
        m.put("98260-61821-brm/ksu-template.ko", "98260-61821-brm/ksu-template-61821-kernelsu.ko");
        m.put("98260-h1c/ksu-template-115.ko", "98260-61821-brm/ksu-template-61821-kernelsu.ko");
        m.put("98260-61821/ksu-template.ko", "64560-61821/ksu-template.ko");
        m.put("61157/g264/ko_slide_patch", "g264/ko_slide_patch");
        m.put("61157/g264/ksm-g264-base.ko", "g264/ksm-g264-base.ko");
        m.put("61157/su-g264/su_lkm", "su-g264/su_lkm");
        m.put("su-g264/su_overlay_helper", "ksu6157-m6/su_overlay_helper");
        m.put("61157/su-g264/su_overlay_helper", "ksu6157-m6/su_overlay_helper");
        m.put("98260-h1c/addrcalc", "addrcalc");
        m.put("61157/su-g264/su_optional.sh", "su-g264/su_optional.sh");
        m.put("98260-g554/syms_66118_kernelsu.txt", "98260-g554/syms_66118.txt");
        m.put("98260-f171/syms_66118_kernelsu.txt", "98260-f171/syms_66118.txt");
        m.put("98260-aph112/exploit-android-key-ptr", "98260-61258b/exploit-android-key-ptr");
        DEDUP_ASSET_MAP = java.util.Collections.unmodifiableMap(m);
    }

    /**
     * Return the canonical APK asset path when {@code name} was deduplicated at
     * APK packaging time by {@code tools/strip_baseline.py}, or {@code name}
     * itself if it is already canonical.
     */
    public static String resolveCanonicalAsset(String name) {
        if (name == null) return null;
        String canonical = DEDUP_ASSET_MAP.get(name);
        return canonical != null ? canonical : name;
    }
}
