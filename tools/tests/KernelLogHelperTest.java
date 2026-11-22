package com.aoki.magicroot;

import java.nio.charset.StandardCharsets;

/**
 * Plain-Java unit tests for {@link KernelLogHelper}.
 *
 * <p>Compiled and executed directly by {@code tools/check.sh} without needing
 * Android SDK or Gradle daemon.</p>
 */
public final class KernelLogHelperTest {
    private static int failures;

    private static void check(boolean ok, String name, String detail) {
        if (ok) {
            System.out.println("ok   " + name);
        } else {
            failures++;
            System.out.println("FAIL " + name + ": " + detail);
        }
    }

    public static void main(String[] args) {
        // finishKind
        check(KernelLogHelper.finishKind("STEP=1\nDONE\n") == 1,
                "finishKind detects DONE", "");
        check(KernelLogHelper.finishKind("STEP=1\nFAIL=kernel_unsupported\n") == 2,
                "finishKind detects FAIL=", "");
        check(KernelLogHelper.finishKind("STEP=1\nalmost DONE\n") == 0,
                "finishKind ignores substring DONE", "");
        check(KernelLogHelper.finishKind("") == 0 && KernelLogHelper.finishKind(null) == 0,
                "finishKind handles empty/null", "");

        // tailLines & section
        check("b\nc\n".equals(KernelLogHelper.tailLines("a\nb\nc\n", 2)),
                "tailLines returns last N lines", "");
        check("val1".equals(KernelLogHelper.section("__A__val1__B__val2", "__A__")),
                "section slices between markers", "");

        // KMI / patch / vermagic helpers
        String rel = "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k";
        check("6.12".equals(KernelLogHelper.kmiOfKernel(rel)),
                "kmiOfKernel parses 6.12", "");
        check("6.12.58".equals(KernelLogHelper.patchOfKernel(rel)),
                "patchOfKernel parses 6.12.58", "");
        String vm = "6.12.76-android16-5-g1234 SMP preempt mod_unload modversions aarch64";
        check("6.12".equals(KernelLogHelper.kmiOfVermagic(vm)),
                "kmiOfVermagic parses 6.12", "");
        check("6.12.76-android16-5-g1234".equals(KernelLogHelper.releaseOfVermagic(vm)),
                "releaseOfVermagic strips flags", "");
        check(rel.equals(KernelLogHelper.firstKernelRelease("", "unknown", rel)),
                "firstKernelRelease picks first valid KMI", "");

        byte[] fakeKo = ("ELF\0random\0vermagic=" + vm + "\0tail").getBytes(StandardCharsets.ISO_8859_1);
        check(vm.equals(KernelLogHelper.modinfoVermagic(fakeKo)),
                "modinfoVermagic extracts NUL-terminated vermagic", "");

        // 6.1.x payloadDir & cgaBase routing
        check("98260-6157".equals(KernelLogHelper.payloadDirFor6157("6.1.157-android14-11-g7d3922fade43-ab")),
                "g7d payload dir is 98260-6157", "");
        check(KernelLogHelper.cgaBaseFor6157("6.1.157-android14-11-g7d3922fade43-ab") == null,
                "g7d has no CGA base (uses M6)", "");
        check("98260-g264".equals(KernelLogHelper.payloadDirFor6157("6.1.157-android14-11-g2646292297b1")),
                "g264 payload dir", "");
        check("g264/ksm-g264-base.ko".equals(KernelLogHelper.cgaBaseFor6157("6.1.157-android14-11-g2646292297b1")),
                "g264 CGA base", "");
        check("98260-gaaa".equals(KernelLogHelper.payloadDirFor6157("6.1.157-android14-11-gaaa383620ebf")),
                "gaaa payload dir", "");
        check("g264/ksm-gaaa-base.ko".equals(KernelLogHelper.cgaBaseFor6157("6.1.157-android14-11-gaaa383620ebf")),
                "gaaa CGA base", "");
        check("98260-g8d6".equals(KernelLogHelper.payloadDirFor6157("6.1.157-android14-11-g8d63307071ad")),
                "g8d6 payload dir", "");
        check("g264/ksm-g8d6-base.ko".equals(KernelLogHelper.cgaBaseFor6157("6.1.157-android14-11-g8d63307071ad")),
                "g8d6 CGA base", "");
        check("98260-g8a496".equals(KernelLogHelper.payloadDirFor6157("6.1.128-android14-11-g8a4968670f1c")),
                "g8a496 payload dir", "");
        check("g264/ksm-g2e1f-base.ko".equals(KernelLogHelper.cgaBaseFor6157("6.1.128-android14-11-g2e1f0741dafb")),
                "g2e1f CGA base", "");

        // Unified 6.1 deployment planner: every CGA profile receives its own
        // runner, payload and CGA base, never another build's absolute symbols.
        String[][] cga = {
                {"g264", "6.1.157-android14-11-g2646292297b1"},
                {"gaaa", "6.1.157-android14-11-gaaa383620ebf"},
                {"g3306", "6.1.157-android14-11-g3306a328b7be"},
                {"g84", "6.1.157-android14-11-g84ffa64b710b"},
                {"g77f", "6.1.157-android14-11-g77f76e323a02"},
                {"g8d6", "6.1.157-android14-11-g8d63307071ad"},
                {"gce849", "6.1.99-android14-11-gce84935796c9"},
                {"g5859", "6.1.99-android14-11-g5859fbdbad8c"},
                {"g54d", "6.1.99-android14-11-g54d40b4fb287"},
                {"g40b1", "6.1.128-android14-11-g40b1fd119d9b"},
                {"g8a496", "6.1.128-android14-11-g8a4968670f1c"},
                {"g2e1f", "6.1.128-android14-11-g2e1f0741dafb"},
                {"ge9da", "6.1.99-android14-11-ge9da27488f45"},
        };
        for (String[] target : cga) {
            String id = target[0];
            String release = target[1];
            String dir = "98260-" + id;
            String base = "g264/ksm-" + id + "-base.ko";
            boolean ok = KernelLogHelper.shouldStage6157Asset("98260/run6157_full.sh", release)
                    && KernelLogHelper.shouldStage6157Asset(dir + "/exploit-android-key-ptr", release)
                    && KernelLogHelper.shouldStage6157Asset(dir + "/pc98260-su", release)
                    && KernelLogHelper.shouldStage6157Asset(dir + "/target.sh", release)
                    && KernelLogHelper.shouldStage6157Asset(base, release)
                    && KernelLogHelper.shouldStage6157Asset("g264/ko_slide_patch", release)
                    && KernelLogHelper.shouldStage6157Asset("su-g264/setup_su_app.sh", release)
                    && KernelLogHelper.shouldStage6157Asset("ksu6157-g264/ksud", release)
                    && KernelLogHelper.shouldStage6157Asset("run.sh", release)
                    && KernelLogHelper.shouldStage6157Asset("6157-integrity.tsv", release)
                    && KernelLogHelper.shouldStage6157Asset("root_stage.sh", release)
                    && !KernelLogHelper.shouldStage6157Asset("ksu6157-m6/load_ko", release)
                    && !KernelLogHelper.shouldStage6157Asset("61157/run61157.sh", release)
                    && !KernelLogHelper.shouldStage6157Asset("ksu6157/ksu_prepare", release);
            for (String[] other : cga) {
                if (id.equals(other[0])) continue;
                ok &= !KernelLogHelper.shouldStage6157Asset(
                        "98260-" + other[0] + "/exploit-android-key-ptr", release);
                ok &= !KernelLogHelper.shouldStage6157Asset(
                        "g264/ksm-" + other[0] + "-base.ko", release);
            }
            boolean legacyExpected = id.equals("g264");
            ok &= KernelLogHelper.shouldStage6157Asset("ksu6157-g264/ksu-loader", release)
                    == legacyExpected;
            check(ok, id + " unified CGA deployment and cross-kernel isolation", "");
        }
        String g7d = "6.1.157-android14-11-g7d3922fade43";
        check(KernelLogHelper.shouldStage6157Asset("98260/run6157_full.sh", g7d)
                        && KernelLogHelper.shouldStage6157Asset("6157-integrity.tsv", g7d)
                        && KernelLogHelper.shouldStage6157Asset("98260-6157/exploit-android-key-ptr", g7d)
                        && KernelLogHelper.shouldStage6157Asset("ksu6157-m6/load_ko", g7d)
                        && KernelLogHelper.shouldStage6157Asset("ksu6157/sigparam", g7d)
                        && !KernelLogHelper.shouldStage6157Asset("g264/ksm-g7d-base.ko", g7d)
                        && !KernelLogHelper.shouldStage6157Asset("su-g264/su_lkm", g7d)
                        && !KernelLogHelper.shouldStage6157Asset("61157/run61157.sh", g7d),
                "g7d keeps isolated M6 handoff", "");
        String g19a = "6.1.157-android14-11-g19a495a97bff";
        check(KernelLogHelper.shouldStage6157Asset("61157/run61157.sh", g19a)
                        && KernelLogHelper.shouldStage6157Asset("61157/kernelsu-magicpad.ko", g19a)
                        && KernelLogHelper.shouldStage6157Asset("61157/ksu-loader-magicpad", g19a)
                        && !KernelLogHelper.shouldStage6157Asset("61157/kernelsu-honor.ko", g19a)
                        && !KernelLogHelper.shouldStage6157Asset("98260/run6157_full.sh", g19a)
                        && !KernelLogHelper.shouldStage6157Asset("g264/ksm-g264-base.ko", g19a)
                        && KernelLogHelper.shouldStage6157Asset("run.sh", g19a),
                "g19a keeps isolated legacy 61157 handoff", "");
        check(!KernelLogHelper.shouldStage6157Asset("run.sh", "6.1.99-android14-11-gunknown")
                        && !KernelLogHelper.shouldStage6157Asset("98260/run6157_full.sh", "6.1.99-android14-11-gunknown"),
                "unknown 6.1 release fails closed", "");

        boolean only6157 = true;
        for (KernelLogHelper.Profile6157 p : KernelLogHelper.PROFILES_6157)
            only6157 &= KernelLogHelper.is6157OnlyAsset(p.payloadDir + "/payload.bin");
        only6157 &= KernelLogHelper.is6157OnlyAsset("ksu6157-m6/load_ko")
                && KernelLogHelper.is6157OnlyAsset("ksu6157-g264/ksu_prepare")
                && KernelLogHelper.is6157OnlyAsset("6157-integrity.tsv")
                && !KernelLogHelper.is6157OnlyAsset("98260/run98260.sh")
                && !KernelLogHelper.is6157OnlyAsset("98260-g142/exploit-android-key-ptr")
                && !KernelLogHelper.is6157OnlyAsset("run.sh");
        check(only6157, "6.1-only asset classification covers every profile without capturing shared/6.12 assets", "");

        // Manager metadata
        check("BakaSU".equals(KernelLogHelper.managerLabelOf("resukisu"))
                && "com.resukisu.resukisu".equals(KernelLogHelper.managerDefaultPkg("resukisu"))
                && KernelLogHelper.managerPriority("kernelsu") < KernelLogHelper.managerPriority("fina"),
                "manager metadata helpers", "");

        // 98260 profile staging filter
        check(KernelLogHelper.shouldStage98260Asset("98260/run98260.sh", "98260", "6.1.157-any", "ELP-AN00"),
                "shared 98260/run98260.sh always staged", "");
        check(!KernelLogHelper.shouldStage98260Asset("98260/exploit-android-perf", "98260", rel, "MLY-AN00"),
                "exploit-android-perf never staged", "");
        check(KernelLogHelper.shouldStage98260Asset("98260-aph112/exploit-android-key-ptr", "98260-aph112",
                "6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k", "APH-AN00"),
                "APH-AN00 stages 98260-aph112", "");
        check(!KernelLogHelper.shouldStage98260Asset("98260-61258b/exploit-android-key-ptr", "98260-61258b",
                "6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k", "APH-AN00"),
                "APH-AN00 excludes 98260-61258b", "");
        String g142 = "6.12.58-android16-6-g142ddad31e60-abogki576095858-4k";
        check(KernelLogHelper.shouldStage98260Asset("98260-g142/exploit-android-key-ptr", "98260-g142", g142, "ANY")
                        && KernelLogHelper.shouldStage98260Asset("98260-g142/SHA256SUMS.txt", "98260-g142", g142, "ANY")
                        && !KernelLogHelper.shouldStage98260Asset("98260-g142/exploit-android-key-ptr", "98260-g142", rel, "ANY"),
                "g142 assets are exact-kernel isolated", "");
        check(KernelLogHelper.shouldStage98260Asset("98260-h1c/run_h1c.sh", "98260-h1c",
                "6.18.21-android17-5-g928d1bb4f1d7", "ANY"),
                "6.18.21 stages 98260-h1c", "");

        // APK asset deduplication resolution
        check("98260-6157/pc98260-su".equals(
                KernelLogHelper.resolveCanonicalAsset("98260-g264/pc98260-su")),
                "dedup resolves 98260-g264/pc98260-su -> 98260-6157/pc98260-su", "");
        check("98260-6157/pc98260-su".equals(
                KernelLogHelper.resolveCanonicalAsset("98260-gaaa/pc98260-su")),
                "dedup resolves 98260-gaaa/pc98260-su", "");
        check("pc98260-su".equals(KernelLogHelper.resolveCanonicalAsset("98260-g142/pc98260-su"))
                        && "pc98260-su".equals(KernelLogHelper.resolveCanonicalAsset("98260-ga812/pc98260-su")),
                "dedup resolves g142/ga812 rootd clients to the shared canonical asset", "");
        check("61157/ksud".equals(
                KernelLogHelper.resolveCanonicalAsset("ksu6157-g264/ksud")),
                "dedup resolves ksu6157-g264/ksud -> 61157/ksud", "");
        check("run.sh".equals(KernelLogHelper.resolveCanonicalAsset("run.sh")),
                "non-dedup asset returns self", "");

        if (failures != 0) {
            System.out.println("KernelLogHelperTest failures=" + failures);
            System.exit(1);
        }
        System.out.println("KernelLogHelperTest all passed");
    }
}
