package com.aoki.magicroot;

/**
 * Pure classifier for run.log lines.
 *
 * <p>Kept free of Android imports so it can be compiled and tested with plain
 * javac (tools/tests/RunProgressTest.java). MainActivity only applies the
 * returned step to UiState.</p>
 */
final class RunProgress {
    private RunProgress() {
    }

    static final class Step {
        final int percent;
        final String stage;

        Step(int percent, String stage) {
            this.percent = percent;
            this.stage = stage;
        }
    }

    /**
     * @param line    one line from run.log
     * @param current highest progress already shown
     * @return a step to display, or null when the line does not move or rename
     *         the current stage
     */
    static Step classify(String line, int current) {
        if (line == null || line.isEmpty())
            return null;

        int progress = 0;
        String stage = "";
        if (line.startsWith("PREFLIGHT_WAIT")) {
            progress = 3;
            stage = "等待系统稳定（刚开机/系统繁忙）";
        } else if (line.startsWith("PREFLIGHT_OK")) {
            progress = 5;
            stage = "系统稳定，准备链路";
        } else if (line.startsWith("PREFLIGHT_SKIP")) {
            progress = 4;
            stage = "已跳过开机等待";
        } else if (line.startsWith("PREVIOUS_RUN_INCOMPLETE")) {
            progress = 4;
            stage = "上次运行中断（检测到重启）";
        } else if (line.startsWith("== 1.")) {
            progress = 10;
            stage = "KASLR";
        } else if (line.startsWith("== 2.")) {
            progress = 18;
            stage = "模块修补";
        } else if (line.startsWith("== 3.")) {
            progress = 28;
            stage = "SELinux permissive";
        } else if (line.startsWith("== 4.")) {
            progress = 42;
            stage = "cred 捕获";
        } else if (line.startsWith("== 5.")) {
            progress = 55;
            stage = "fsuid / fsgid";
        } else if (line.startsWith("== 6.")) {
            progress = 72;
            stage = "phase1 / phase2";
        } else if (line.contains("phase2 landed")) {
            progress = 84;
            stage = "phase2 landed";
        } else if (line.startsWith("== 7.")) {
            progress = 90;
            stage = "KernelSU 用户态";
        } else if (line.contains("MODULE_LOADED")) {
            progress = 94;
            stage = "模块已加载";
        } else if (line.contains("ROOT_STAGE_OK")) {
            progress = 98;
            stage = "root 环境完成";
        } else if (line.startsWith("SuSFS_")) {
            // run.sh prints SuSFS_SWITCH/FLAVOR at the very start and the
            // actual LKM result at the end. Only surface the slow-load stage
            // for lines that really are loading. "disabled"/"skipped" used to
            // be mislabeled as loading, which made the SuSFS-off path look
            // stuck at 98% while rootd cleanup was running.
            if (current >= 90) {
                if (line.startsWith("SuSFS_LKM_TRY=")
                        || line.startsWith("SuSFS_LKM_LOAD_RC=")
                        || line.startsWith("SuSFS_LKM_VERIFIED=")
                        || line.startsWith("SuSFS_LKM_LOADED=1")) {
                    progress = 98;
                    stage = "SuSFS 模块加载（可能较慢）";
                } else if (line.startsWith("SuSFS_LKM_LOADED=0")) {
                    progress = 98;
                    stage = "SuSFS 未加载，继续收尾";
                } else if (line.startsWith("SuSFS_LKM_LOAD=already_loaded")) {
                    progress = 98;
                    stage = "SuSFS 已加载，收尾清理";
                } else if (line.startsWith("SuSFS_LKM_LOAD=disabled")
                        || line.startsWith("SuSFS_LKM_LOAD=skipped")
                        || line.startsWith("SuSFS_LKM_LOAD=skip")) {
                    progress = 98;
                    stage = "SuSFS 未加载，收尾清理";
                }
            }
        } else if (line.startsWith("61157_CHAIN_BEGIN")) {
            progress = 8;
            stage = "6.1.157：初始化链路";
        } else if (line.startsWith("61157_SETTLE")) {
            progress = 14;
            stage = "6.1.157：等待系统稳定";
        } else if (line.startsWith("61157_PLANT_START")) {
            progress = 22;
            stage = "6.1.157：启动 UAF";
        } else if (line.startsWith("61157_ROOTD_READY")) {
            progress = 72;
            stage = "6.1.157：rootd 已就绪";
        } else if (line.startsWith("98260_ENGINE=h1c")) {
            progress = 10;
            stage = "98260：H1C 引擎";
        } else if (line.startsWith("98260_H1C=already_loaded")) {
            progress = 96;
            stage = "98260：KernelSU 已加载，准备收尾";
        } else if (line.startsWith("98260_H1C_BEGIN")) {
            progress = 12;
            stage = "98260：H1C 链路初始化";
        } else if (line.startsWith("98260_H1C_PREFLIGHT_OK=1")) {
            progress = 16;
            stage = "98260：H1C 预检通过";
        } else if (line.startsWith("98260_H1C_SLIDE=")) {
            progress = 22;
            stage = "98260：KASLR 已标定";
        } else if (line.startsWith("98260_H1C_PATCHED=")) {
            progress = 34;
            stage = "98260：修补 KernelSU 模块";
        } else if (line.startsWith("98260_H1C_PLANT_STARTED=1")) {
            progress = 42;
            stage = "98260：启动 H1C UAF";
        } else if (line.startsWith("98260_H1C_ROOTD_WAIT")) {
            progress = 48;
            stage = "98260：等待 rootd（UAF 页面竞争）";
        } else if (line.startsWith("98260_H1C_ROOTD_READY=1")) {
            progress = 58;
            stage = "98260：rootd 已就绪";
        } else if (line.startsWith("98260_H1C_MODULE_LOAD_RC=0")) {
            progress = 68;
            stage = "98260：加载 KernelSU 模块";
        } else if (line.startsWith("98260_H1C_MODULE_LIVE=1")) {
            progress = 76;
            stage = "98260：KernelSU 已加载";
        } else if (line.startsWith("98260_H1C_ROOT_STAGE_RC=")) {
            progress = 88;
            stage = "98260：初始化管理器";
        } else if (line.startsWith("98260_H1C_DIRECT_SU=ok")) {
            progress = 94;
            stage = "98260：su 已就绪";
        } else if (line.startsWith("98260_H1C_DONE=1")) {
            progress = 96;
            stage = "98260：链路完成，准备收尾";
        } else if (line.startsWith("98260_SLIDE_SOURCE")) {
            progress = 10;
            stage = "98260：KASLR 已标定";
        } else if (line.startsWith("ROOTD_READY")) {
            progress = 30;
            stage = "98260：rootd 已就绪";
        } else if (line.startsWith("98260_CHAIN_BEGIN")) {
            progress = 8;
            stage = "98260：初始化链路";
        } else if (line.startsWith("98260_EXEC_PID=")) {
            progress = 12;
            stage = "98260：启动 UAF/rootd";
        } else if (line.startsWith("98260_OPTIONS=") || line.startsWith("98260_SYMBOLS=")) {
            progress = 20;
            stage = "98260：解析 profile/syms";
        } else if (line.startsWith("98260_KSU_PATCH_RC=0")) {
            progress = 36;
            stage = "98260：修补 KernelSU 模块";
        } else if (line.startsWith("98260_REAL_CRED_INPROC=1")) {
            progress = 40;
            stage = "98260：real-cred UAF 提权";
        } else if (line.startsWith("98260_REAL_CRED_KO_READY=")) {
            progress = 44;
            stage = "98260：KO 已修补，等待提权";
        } else if (line.startsWith("98260_REAL_CRED_INPROC_FINIT_READY")) {
            progress = 48;
            stage = "98260：等待 real-cred 加载 KernelSU";
        } else if (line.startsWith("98260_REAL_CRED_INPROC_OK=1")) {
            progress = 64;
            stage = "98260：KernelSU 已加载";
        } else if (line.startsWith("98260_REAL_CRED_SU_PROOF=ok")) {
            progress = 82;
            stage = "98260：su 已就绪";
        } else if (line.startsWith("98260_MANAGER_REGISTER_BEGIN")) {
            progress = 86;
            stage = "98260：注册所选管理器";
        } else if (line.startsWith("98260_MANAGER_REGISTER=done")) {
            progress = 88;
            stage = "98260：管理器已注册";
        } else if (line.startsWith("98260_KSU_LATELOAD_PRIMARY_BEGIN")) {
            progress = 48;
            stage = "98260：加载 KernelSU";
        } else if (line.startsWith("98260_KSU=loaded") || line.contains("98260_KSU_LATELOAD_PRIMARY_OK=1")) {
            progress = 64;
            stage = "98260：KernelSU 已加载";
        } else if (line.startsWith("98260_KSUD_INSTALL_RC=0")) {
            progress = 74;
            stage = "98260：初始化管理器";
        } else if (line.startsWith("98260_SU_PROVIDER=ready")) {
            progress = 82;
            stage = "98260：su 已就绪";
        } else if (line.startsWith("98260_FEATURE_")) {
            progress = 88;
            stage = "98260：应用内核特性";
        } else if (line.startsWith("98260_SUCCESS=1")) {
            progress = 96;
            stage = "98260：链路完成，准备收尾";
        } else if (line.startsWith("CHAIN_98260_DONE")) {
            progress = 98;
            stage = "98260：链路完成，收尾中";
        } else if (line.startsWith("98260_FINALIZE_BEGIN")) {
            progress = 98;
            stage = "98260：收尾清理（有超时保护）";
        } else if (line.startsWith("98260_FINALIZE_END")) {
            progress = 98;
            stage = "98260：收尾完成";
        } else if (line.startsWith("98260_ROOTD_CLEANUP=")
                || line.startsWith("RUNSH_ROOTD_")
                || line.startsWith("RUNSH_STALE_SOCKETS_")) {
            if (current >= 98) {
                progress = 98;
                stage = "98260：rootd 收尾清理";
            }
        } else if (line.trim().equals("DONE")) {
            progress = 100;
            stage = "完成";
        }

        if (progress == 0)
            return null;
        // Log lines can arrive out of order (e.g. SLIDE_SOURCE before
        // CHAIN_BEGIN). Never move the bar backwards or jump early.
        if (progress < current)
            return null;
        if (progress == current && (stage == null || stage.isEmpty()))
            return null;
        return new Step(progress, stage);
    }
}
