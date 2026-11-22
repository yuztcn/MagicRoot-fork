package com.aoki.magicroot;

/**
 * Plain-Java regression tests for the run-log progress classifier.
 *
 * <p>Compiled by tools/test_98260_finalize.py, so it does not need Android or
 * Gradle. RunProgress deliberately has no Android dependencies.</p>
 */
public final class RunProgressTest {
    private static int failures;

    private static void check(boolean ok, String name, String detail) {
        if (ok) {
            System.out.println("ok   " + name);
        } else {
            failures++;
            System.out.println("FAIL " + name + ": " + detail);
        }
    }

    private static RunProgress.Step step(String line, int current) {
        return RunProgress.classify(line, current);
    }

    private static void expectStage(String line, int current, String needle, String name) {
        RunProgress.Step s = step(line, current);
        check(s != null && s.stage != null && s.stage.contains(needle), name,
                "got " + (s == null ? "null" : s.percent + " / " + s.stage));
    }

    private static void expectNull(String line, int current, String name) {
        RunProgress.Step s = step(line, current);
        check(s == null, name, "got " + (s == null ? "null" : s.percent + " / " + s.stage));
    }

    public static void main(String[] args) {
        // The screenshot case: SuSFS is off, but the old parser treated every
        // SuSFS_* line as "module loading" and left the UI at 98%.
        expectStage("SuSFS_LKM_LOAD=disabled reason=switch_off", 98,
                "收尾", "disabled SuSFS is not reported as loading");
        RunProgress.Step disabled = step("SuSFS_LKM_LOAD=disabled reason=switch_off", 98);
        check(disabled != null && !disabled.stage.contains("模块加载"),
                "disabled SuSFS has no loading label",
                "got " + (disabled == null ? "null" : disabled.stage));

        // A real load still gets the slow-load label.
        expectStage("SuSFS_LKM_TRY=/data/local/tmp/magic/susfs_guard_lkm-6.12.ko", 98,
                "模块加载", "real SuSFS attempt is reported as loading");
        expectStage("SuSFS_LKM_LOAD_RC=0", 98,
                "模块加载", "SuSFS load result is reported as loading");

        // A failed load is not left looking like an infinite load.
        expectStage("SuSFS_LKM_LOADED=0 reason=not_loaded", 98,
                "未加载", "failed SuSFS load reports failure and finalization");
        expectStage("SuSFS_LKM_LOAD=already_loaded verify=module_or_proc", 98,
                "已加载", "already-loaded SuSFS is reported as loaded");

        // Finalization is explicit, so rootd cleanup no longer looks like
        // SuSFS loading.
        expectStage("98260_FINALIZE_BEGIN susfs=0", 98,
                "收尾", "finalization begin is visible");
        expectStage("98260_FINALIZE_END", 98,
                "收尾完成", "finalization end is visible");
        expectStage("98260_ROOTD_CLEANUP=root_helper ROOTD_PID=123", 98,
                "收尾", "rootd cleanup is visible as finalization");

        // Normal completion remains the only 100% transition.
        RunProgress.Step done = step("DONE", 98);
        check(done != null && done.percent == 100 && "完成".equals(done.stage),
                "DONE reaches 100%", "got " + (done == null ? "null" : done.percent + " / " + done.stage));

        // 6.18.21 H1C engine markers must move the bar; before this they were
        // invisible and the UI sat at "初始化链路" for the whole run.
        expectStage("98260_ENGINE=h1c only=1", 0, "H1C", "H1C engine is recognised");
        expectStage("98260_H1C_BEGIN profile=61821brm kernel=6.18.21", 10,
                "H1C 链路初始化", "H1C begin is visible");
        // The three stages below (PREFLIGHT_OK, ROOTD_WAIT, MODULE_LOAD_RC)
        // are real run_h1c.sh log lines that previously had no coverage: the
        // "current" values of the surrounding tests already skipped past
        // them (12->22, 34->58, 42->76), so a regression that dropped or
        // mis-ordered these branches would have gone unnoticed.
        expectStage("98260_H1C_PREFLIGHT_OK=1", 12, "预检", "H1C preflight ok is visible");
        expectStage("98260_H1C_SLIDE=0x20000000 site=0xffffffc0a03e1fd0", 16,
                "KASLR", "H1C slide is visible");
        expectStage("98260_H1C_PATCHED=438096", 22, "修补", "H1C ko patch is visible");
        expectStage("98260_H1C_PLANT_STARTED=1 pid=123 wait_cap=300s", 34,
                "UAF", "H1C plant start is visible");
        expectStage("98260_H1C_ROOTD_WAIT elapsed=5s attempt=2 rc=1 out=empty", 42,
                "页面竞争", "H1C rootd wait is visible");
        expectStage("98260_H1C_ROOTD_READY=1 waited=3s attempts=2 id=uid=0(root)", 48,
                "rootd", "H1C rootd ready is visible");
        expectStage("98260_H1C_MODULE_LOAD_RC=0", 58, "加载 KernelSU",
                "H1C module load rc is visible");
        expectStage("98260_H1C_MODULE_LIVE=1 waited=1s", 68, "KernelSU",
                "H1C module live is visible");
        expectStage("98260_H1C_ROOT_STAGE_RC=0", 76, "管理器",
                "H1C root stage is visible");
        expectStage("98260_H1C_DIRECT_SU=ok id=uid=0(root)", 88,
                "su 已就绪", "H1C direct su is visible");
        expectStage("98260_H1C_DONE=1", 94, "准备收尾", "H1C done is visible");
        expectStage("98260_H1C=already_loaded", 58, "准备收尾",
                "H1C ksu reuse reports completion");
        RunProgress.Step h1cDone = step("98260_H1C_DONE=1", 94);
        check(h1cDone != null && h1cDone.percent == 96,
                "H1C done sits below DONE", "got " + (h1cDone == null ? "null" : h1cDone.percent));

        // real-cred in-process markers must move past the KO patch label; the
        // old classifier stayed at 36% while UAF/cap/finit were still running.
        expectStage("98260_REAL_CRED_INPROC=1 proof=module_load", 36,
                "UAF", "real-cred UAF stage is visible");
        expectStage("98260_REAL_CRED_KO_READY=/data/local/tmp/magic/98260/ksu-patched.ko", 40,
                "等待提权", "KO ready is not still patching");
        expectStage("98260_REAL_CRED_INPROC_FINIT_READY path=/data/local/tmp/magic/98260/ksu-patched.ko", 44,
                "加载 KernelSU", "in-process finit wait is visible");
        expectStage("98260_REAL_CRED_INPROC_OK=1 waited=3s", 48,
                "已加载", "in-process module load is visible");
        expectStage("98260_REAL_CRED_SU_PROOF=ok provider=su", 64,
                "su 已就绪", "in-process su proof is visible");
        expectStage("98260_MANAGER_REGISTER_BEGIN pkg=com.sukisu.ultra", 82,
                "注册", "manager registration is visible");
        expectStage("98260_MANAGER_REGISTER=done pkg=com.sukisu.ultra", 86,
                "已注册", "manager registration completion is visible");

        // Early SuSFS lines must not jump the progress bar.
        expectNull("SuSFS_SWITCH=0 source=env", 8, "early SuSFS line is ignored");
        expectNull("SOFT_REBOOT_REPAIR=disabled reason=use_explicit_zygote_hotfix", 98,
                "unrelated finalization line does not move progress");

        if (failures != 0) {
            System.out.println("RunProgressTest failures=" + failures);
            System.exit(1);
        }
        System.out.println("RunProgressTest all passed");
    }
}
