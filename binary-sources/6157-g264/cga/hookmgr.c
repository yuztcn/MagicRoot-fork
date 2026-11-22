#include "linux/printk.h"
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/tracepoint.h>
#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <trace/events/syscalls.h>

#include <linux/version.h>
#include <linux/sched/task_stack.h>
#include <linux/compat.h>

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "hook/syscall_hook_manager.h"
#include "hook/tp_marker.h"
#include "feature/sucompat.h"
#include "hook/setuid_hook.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"
#if defined(__riscv)
#include "hook/riscv64/syscall_regs.h"
#endif

#ifdef CONFIG_KRETPROBES

static struct kretprobe *init_kretprobe(const char *name, kretprobe_handler_t handler)
{
    struct kretprobe *rp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL);
    if (!rp)
        return NULL;
    rp->kp.symbol_name = name;
    rp->handler = handler;
    rp->data_size = 0;
    rp->maxactive = 0;

    int ret = register_kretprobe(rp);
    pr_info("hook_manager: register_%s kretprobe: %d\n", name, ret);
    if (ret) {
        kfree(rp);
        return NULL;
    }

    return rp;
}

static void destroy_kretprobe(struct kretprobe **rp_ptr)
{
    struct kretprobe *rp = *rp_ptr;
    if (!rp)
        return;
    unregister_kretprobe(rp);
    synchronize_rcu();
    kfree(rp);
    *rp_ptr = NULL;
}

static int syscall_regfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    ksu_tp_marker_lock(&flags);
    if (ksu_tp_marker_reg_count() < 1) {
        // while install our tracepoint, mark our processes
        ksu_mark_running_process_locked();
    } else if (ksu_tp_marker_reg_count() == 1) {
        // while other tracepoint first added, mark all processes
        ksu_mark_all_process();
    }
    ksu_tp_marker_inc_reg_count();
    ksu_tp_marker_unlock(&flags);
    return 0;
}

static int syscall_unregfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    ksu_tp_marker_lock(&flags);
    ksu_tp_marker_dec_reg_count();
    if (ksu_tp_marker_reg_count() <= 0) {
        // while no tracepoint left, unmark all processes
        ksu_unmark_all_process();
    } else if (ksu_tp_marker_reg_count() == 1) {
        // while just our tracepoint left, unmark disallowed processes
        ksu_mark_running_process_locked();
    }
    ksu_tp_marker_unlock(&flags);
    return 0;
}

static struct kretprobe *syscall_regfunc_rp = NULL;
static struct kretprobe *syscall_unregfunc_rp = NULL;
#endif

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
// sys_enter handler: redirect hooked syscalls to the dispatcher
static void ksu_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
#if defined(__x86_64__)
    if (unlikely(in_compat_syscall()))
#elif defined(__aarch64__) || defined(__riscv)
    if (unlikely(is_compat_task()))
#endif
        return;

    if (ksu_dispatcher_nr < 0)
        return;

    if (ksu_has_syscall_hook(id)) {
        struct pt_regs *current_regs = task_pt_regs(current);

#if defined(__x86_64__)
        // Stash the original syscall number in ax.
        // We use ax because it currently just holds -ENOSYS and is safe to overwrite.
        current_regs->ax = id;
        current_regs->orig_ax = ksu_dispatcher_nr;
#elif defined(__aarch64__)
        PT_REGS_ORIG_SYSCALL(current_regs) = id;
        current_regs->syscallno = ksu_dispatcher_nr;
#elif defined(__riscv)
        /* orig_a0 retains argument zero; a0 is the -ENOSYS return slot. */
        ksu_riscv_redirect_syscall(current_regs, id, ksu_dispatcher_nr);
#endif
    }
}
#endif

static bool sys_enter_registered;
static bool syscall_features_registered;

void __init ksu_syscall_hook_manager_init(void)
{
    static const struct {
        int nr;
        ksu_syscall_hook_fn fn;
    } hooks[] = {
        { __NR_setresuid, ksu_hook_setresuid },
        { __NR_execve, ksu_hook_execve },
        { __NR_execveat, ksu_hook_execveat },
        { __NR_newfstatat, ksu_hook_newfstatat },
        { __NR_faccessat, ksu_hook_faccessat },
    };
    int ret;
    int registered = 0;

    pr_info("hook_manager: ksu_hook_manager_init called\n");

#ifdef CONFIG_KRETPROBES
    syscall_regfunc_rp = init_kretprobe("syscall_regfunc", syscall_regfunc_handler);
    syscall_unregfunc_rp = init_kretprobe("syscall_unregfunc", syscall_unregfunc_handler);
    if (!syscall_regfunc_rp || !syscall_unregfunc_rp) {
        pr_err("hook_manager: kretprobe setup incomplete; keeping legacy supercall path\n");
        goto fail;
    }
#endif

    /* Never redirect syscalls until the dispatcher write is readable back. */
    if (!ksu_syscall_dispatcher_ready()) {
        pr_err("hook_manager: dispatcher is not installed; keeping legacy supercall path\n");
        goto fail;
    }

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    ret = register_trace_prio_sys_enter(ksu_sys_enter_handler, NULL, INT_MIN);
    if (ret) {
        pr_err("hook_manager: failed to register sys_enter tracepoint: %d\n", ret);
        goto fail;
    }
    sys_enter_registered = true;
#ifndef CONFIG_KRETPROBES
    ksu_mark_running_process_locked();
#endif
    pr_info("hook_manager: sys_enter tracepoint registered\n");
#else
    pr_err("hook_manager: syscall tracepoints are unavailable\n");
    goto fail;
#endif

    for (registered = 0; registered < ARRAY_SIZE(hooks); registered++) {
        ret = ksu_register_syscall_hook(hooks[registered].nr, hooks[registered].fn);
        if (ret) {
            pr_err("hook_manager: failed to register syscall %d: %d\n", hooks[registered].nr, ret);
            goto fail;
        }
    }

    ksu_setuid_hook_init();
    ksu_sucompat_init();
    syscall_features_registered = true;
    pr_info("CGA-FEATURES: su_compat and kernel_umount registered\n");
    return;

fail:
    while (registered > 0)
        ksu_unregister_syscall_hook(hooks[--registered].nr);
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    if (sys_enter_registered) {
        unregister_trace_sys_enter(ksu_sys_enter_handler, NULL);
        tracepoint_synchronize_unregister();
        sys_enter_registered = false;
    }
#endif
#ifdef CONFIG_KRETPROBES
    destroy_kretprobe(&syscall_regfunc_rp);
    destroy_kretprobe(&syscall_unregfunc_rp);
#endif
    pr_err("CGA-FEATURES: syscall features unavailable; legacy supercall path retained\n");
}

void __exit ksu_syscall_hook_manager_exit(void)
{
    pr_info("hook_manager: ksu_hook_manager_exit called\n");
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    if (sys_enter_registered) {
        unregister_trace_sys_enter(ksu_sys_enter_handler, NULL);
        tracepoint_synchronize_unregister();
        sys_enter_registered = false;
        pr_info("hook_manager: sys_enter tracepoint unregistered\n");
    }
#endif

#ifdef CONFIG_KRETPROBES
    destroy_kretprobe(&syscall_regfunc_rp);
    destroy_kretprobe(&syscall_unregfunc_rp);
#endif

    ksu_unregister_syscall_hook(__NR_setresuid);
    ksu_unregister_syscall_hook(__NR_execve);
    ksu_unregister_syscall_hook(__NR_execveat);
    ksu_unregister_syscall_hook(__NR_newfstatat);
    ksu_unregister_syscall_hook(__NR_faccessat);

    ksu_syscall_hook_exit();

    if (syscall_features_registered) {
        ksu_sucompat_exit();
        ksu_setuid_hook_exit();
        syscall_features_registered = false;
    }
}
