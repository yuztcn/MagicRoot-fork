#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/moduleparam.h>

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "hook/syscall_hook_manager.h"
#include "hook/lsm_hook.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "feature/sulog.h"
#include "supercall/supercall.h"
#include "ksu.h"
#include "infra/file_wrapper.h"
#include "selinux/selinux.h"
#include "hook/syscall_hook.h"
#include "feature/adb_root.h"
#include "feature/selinux_hide.h"
#include "feature/module_blacklist.h"
#include "feature/shell_su_adb_only.h"
#include "infra/symbol_resolver.h"

#if defined(__x86_64__) && !defined(CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER)
#include <asm/cpufeature.h>
#include <linux/version.h>
#ifndef X86_FEATURE_INDIRECT_SAFE
#error "FATAL: Your kernel is missing the indirect syscall bypass patches!"
#endif
#endif

// workaround for A12-5.10 kernel
// Some third-party kernel (e.g. linegaeOS) uses wrong toolchain, which supports
// CC_HAVE_STACKPROTECTOR_SYSREG while gki's toolchain doesn't.
// Therefore, ksu lkm, which uses gki toolchain, requires this __stack_chk_guard,
// while those third-party kernel can't provide.
// Thus, we manually provide it instead of using kernel's
#if defined(CONFIG_STACKPROTECTOR) &&                                                                                  \
    (defined(CONFIG_ARM64) && defined(MODULE) && !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void __init ksu_setup_stack_chk_guard()
{
    unsigned long canary;

    /* Try to get a semi random initial value. */
    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelsu_init_early(void)
{
    asm("mov x19, x30;\n"
        "bl ksu_setup_stack_chk_guard;\n"
        "mov x30, x19;\n"
        "b kernelsu_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

struct cred *ksu_cred;
bool ksu_late_loaded;

#ifdef CONFIG_KSU_DEBUG
bool allow_shell = true;
#else
bool allow_shell = false;
#endif
module_param(allow_shell, bool, 0);

bool ksu_no_custom_rc = false;
module_param_named(norc, ksu_no_custom_rc, bool, 0);

#ifdef MODULE
bool ksu_bundled = false;
module_param_named(bundled, ksu_bundled, bool, 0);
#endif

int __init kernelsu_init(void)
{
    pr_info("welcome to KernelSU version " __stringify(KERNEL_SU_VERSION) ", package name " KSU_PACKAGE_NAME "\n");
#if defined(__x86_64__) && !defined(CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER)
    // If the kernel has the hardening patch, X86_FEATURE_INDIRECT_SAFE must be set
    if (!boot_cpu_has(X86_FEATURE_INDIRECT_SAFE)) {
        pr_alert("*************************************************************");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("**                                                         **");
        pr_alert("**        X86_FEATURE_INDIRECT_SAFE is not enabled!        **");
        pr_alert("**      KernelSU will abort initialization to prevent      **");
        pr_alert("**                     kernel panic.                       **");
        pr_alert("**                                                         **");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("*************************************************************");
        return -ENOSYS;
    }
#endif

#ifdef MODULE
    ksu_late_loaded = (current->pid != 1);
#else
    ksu_late_loaded = false;
#endif

#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif
    if (allow_shell) {
        pr_alert("shell is allowed at init!");
    }

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
        return -ENOSYS;
    }

    ksu_init_symbol_resolver();
    ksu_syscall_hook_init();

    // Block modules early, before vendor modules are loaded in second stage.
    ksu_module_blacklist_init();

    ksu_feature_init();
    ksu_sulog_init();
    ksu_adb_root_init();
    ksu_lsm_hook_init();
    ksu_selinux_hide_init();
    ksu_shell_su_adb_only_init();

    ksu_supercalls_init();
    ksu_app_profile_init();

    if (ksu_late_loaded) {
        pr_info("late load mode, skipping kprobe hooks\n");

        /*
         * [SELINUX-RULES] 恢复 KernelSU sepolicy 注入。
         *
         * 目标：让 u:r:ksu:s0 域真正存在，从而可以进入 enforcing。
         * 之前剥离是因为担心 policydb 布局，但核对链接产物后确认：
         *   apply_kernelsu_rules / cache_sid / setup_ksu_cred / setenforce
         *   均已编译进模块，且 selinux_state、avc_ss_reset、policydb_*
         *   等内核符号全部经 kallsyms 解析成功（未定义符号数 = 0）。
         *
         * 分阶段：本版本只注入规则，不调用 setenforce(true)，
         * 先验证 ksu 域能否建立、系统是否稳定。
         */
        pr_info("SELINUX-RULES: applying kernelsu sepolicy rules ...\n");
        apply_kernelsu_rules();
        pr_info("SELINUX-RULES: rules applied, caching sid ...\n");
        cache_sid();
        pr_info("SELINUX-RULES: setup ksu cred ...\n");
        setup_ksu_cred();
        pr_info("SELINUX-RULES: done (still permissive)\n");

        // Grant current process (ksud late-load) root
        // with KSU SELinux domain before enforcing SELinux, so it
        // can continue to access /data/app etc. after enforcement.
        escape_to_root_for_init();

        ksu_allowlist_init();
        ksu_load_allow_list();

        ksu_syscall_hook_manager_init();

        ksu_throne_tracker_init();
        ksu_observer_init();
        ksu_file_wrapper_init();

        ksu_boot_completed = true;
        track_throne(false);

        ksu_feature_apply_forced();

        /*
         * [SELINUX-ENFORCE] 切回强制模式。
         *
         * 本机 ro.boot.selinux=enforcing，原厂就是强制模式；之所以运行时
         * 看到 Permissive，是提权工具临时 setenforce 0 的结果。
         *
         * 前提已由上面的 SELINUX-RULES 保证：
         *   - u:r:ksu:s0 域已注入并可用（实测进程能切到该域）
         *   - ksu 域在策略里是 permissive（KSU 的 ksu_permissive 设计），
         *     因此强制模式下 ksu 域内的 root 操作不受限
         *   - 实测 enforce=1 后：AVC 拒绝 0 条，system_server/zygote 存活，
         *     libksud.so debug su 仍能拿到 uid=0 / u:r:ksu:s0
         *
         * 注意：切强制后，shell 域的旧根通道（rootd）会被切断，
         * 后续请改用管理器自带的 libksud.so 作为根通道。
         */
        pr_info("SELINUX-ENFORCE: switching to enforcing ...\n");
        setenforce(true);
        pr_info("SELINUX-ENFORCE: enforcing=%d\n", getenforce());

    } else {
        ksu_syscall_hook_manager_init();

        ksu_allowlist_init();

        ksu_throne_tracker_init();

        ksu_ksud_init();

        ksu_file_wrapper_init();
    }

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
    /* [FIX] 不再 kobject_del 模块自己的 sysfs 节点：
     * 删除后 free_module() 里的 sysfs_remove_group() 会解引用 NULL
     * (kernfs_find_and_get_ns+0x14)，导致 rmmod 段错误。 */
#endif
#endif
    return 0;
}

void __exit kernelsu_exit(void)
{
    // Phase 1: Stop all hooks first to prevent new callbacks
    ksu_syscall_hook_manager_exit();

    ksu_supercalls_exit();

    if (!ksu_late_loaded)
        ksu_ksud_exit();

    // Wait for any in-flight RCU readers (e.g. handler traversing allow_list)
    synchronize_rcu();

    // Phase 2: Now safe to release data structures
    ksu_observer_exit();

    ksu_throne_tracker_exit();

    ksu_allowlist_exit();

    ksu_shell_su_adb_only_exit();
    ksu_selinux_hide_exit();
    ksu_lsm_hook_exit();
    ksu_adb_root_exit();
    ksu_sulog_exit();
    ksu_feature_exit();
    ksu_module_blacklist_exit();

    put_cred(ksu_cred);
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelsu_init_early);
#else
module_init(kernelsu_init);
#endif
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
