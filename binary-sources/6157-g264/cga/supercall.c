#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/seccomp.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "util.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "manager/manager_identity.h"
#include "policy/app_profile.h"
#include "policy/allowlist.h"
#include "infra/seccomp_cache.h"
#include "hook/tp_marker.h"
#include "hook/syscall_hook.h"

#define KSU_DRIVER_PERMISSION_SU_SESSION (1UL << 0)

/* [LEGACY-PRCTL] 老协议命令号：管理器 3.3.1 实测为 2 (GET_INFO) */
#define KSU_PRCTL_CMD_GET_INFO 2

struct ksu_driver_context {
    unsigned long permissions;
};

struct ksu_install_fd_tw {
    struct callback_head cb;
    int __user *outp;
};

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
    kfree(filp->private_data);
    pr_info("ksu fd released\n");
    return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return ksu_supercall_handle_ioctl(filp, cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = anon_ksu_ioctl,
    .compat_ioctl = anon_ksu_ioctl,
    .release = anon_ksu_release,
};

static int ksu_install_fd_with_permissions(unsigned int fd_flags, unsigned long permissions)
{
    struct ksu_driver_context *context;
    struct file *filp;
    const char *name;
    int fd;

    context = kzalloc(sizeof(*context), GFP_KERNEL);
    if (!context)
        return -ENOMEM;

    context->permissions = permissions;
    name = permissions & KSU_DRIVER_PERMISSION_SU_SESSION ? "[ksu_driver_su]" : "[ksu_driver]";

    fd = get_unused_fd_flags(fd_flags);
    if (fd < 0) {
        pr_err("ksu_install_fd: failed to get unused fd\n");
        kfree(context);
        return fd;
    }

    filp = anon_inode_getfile(name, &anon_ksu_fops, context, O_RDWR);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        kfree(context);
        return PTR_ERR(filp);
    }

    fd_install(fd, filp);
    pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);
    return fd;
}

int ksu_install_fd(void)
{
    return ksu_install_fd_with_permissions(O_CLOEXEC, 0);
}

int ksu_install_su_fd(void)
{
    // This descriptor must be installed after the exec into ksud.
    return ksu_install_fd_with_permissions(O_CLOEXEC, KSU_DRIVER_PERMISSION_SU_SESSION);
}

bool ksu_is_su_session_fd(const struct file *filp)
{
    const struct ksu_driver_context *context = filp->private_data;

    return context && (context->permissions & KSU_DRIVER_PERMISSION_SU_SESSION);
}

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();

    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);
    if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
        pr_err("install ksu fd reply err\n");
        ksu_close_fd(fd);
    }

    kfree(tw);
}

static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int magic1 = (int)PT_REGS_SYSCALL_PARM1(real_regs);
    int magic2 = (int)PT_REGS_PARM2(real_regs);

    if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
        struct ksu_install_fd_tw *tw;
        unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);

        tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
        if (!tw)
            return 0;

        tw->outp = (int __user *)arg4;
        tw->cb.func = ksu_install_fd_tw_func;

        if (task_work_add(current, &tw->cb, TWA_RESUME)) {
            kfree(tw);
            pr_warn("install fd add task_work failed\n");
        }
    }

    return 0;
}

static struct kprobe reboot_kp = {
    .symbol_name = REBOOT_SYMBOL,
    .pre_handler = reboot_handler_pre,
};

/*
 * [LEGACY-PRCTL] 兼容 prctl(0xDEADBEEF, cmd, a1, a2, a3) 老协议
 *
 * 管理器 3.3.1 实测反汇编：
 *   movz w0,#0xbeef ; movk w0,#0xdead   -> prctl arg1 = 0xDEADBEEF
 *   movz w1,#2                          -> prctl arg2 = 命令号 2 (GET_INFO)
 *   add  x2,sp,..  x3,sp,..  x4,sp,..   -> 三个用户态指针
 *
 * 命令 2 语义：写出 {version, flags, result}
 *
 * 注意：kprobe pre_handler 上下文里**不能**直接 copy_to_user ——
 * 用户页缺页时无法安全处理，会触发内核 BUG（管理器冷启动即崩溃）。
 * 必须用 task_work_add 延后到安全上下文执行，这也是官方
 * ksu_install_fd_tw_func 采用的做法。
 */
struct legacy_prctl_tw {
    struct callback_head cb;
    void __user *a1;
    void __user *a2;
    void __user *a3;
    s32 version;
    s32 flags;
    s32 result;
    bool install_fd;
};

/* 当前进程是否已持有 [ksu_driver] fd（避免重复安装导致 fd 泄漏） */
static bool ksu_current_has_driver_fd(void)
{
    struct files_struct *files = current->files;
    struct fdtable *fdt;
    unsigned int i;
    bool found = false;

    if (!files)
        return false;

    spin_lock(&files->file_lock);
    fdt = files_fdtable(files);
    for (i = 0; i < fdt->max_fds; i++) {
        struct file *f = rcu_dereference_raw(fdt->fd[i]);

        if (f && f->f_op == &anon_ksu_fops) {
            found = true;
            break;
        }
    }
    spin_unlock(&files->file_lock);
    return found;
}

static void legacy_prctl_tw_func(struct callback_head *cb)
{
    struct legacy_prctl_tw *tw = container_of(cb, struct legacy_prctl_tw, cb);

    /*
     * [SECCOMP-GRANT] 管理器是 untrusted_app，带 seccomp 过滤，其中把
     * __NR_reboot 判为 EPERM。而 ksud 正是靠 reboot(0xDEADBEEF,...) 安装
     * [ksu_driver] fd，于是日志出现：
     *   "KernelSU driver install syscall was blocked by seccomp"
     *   "could not retrieve kernelsu driver fd"
     *   "Created process is not a shell"  -> rootAvailable()=false
     * 官方由 ksu_handle_setresuid() 在 zygote 切到管理器 uid 时调用
     * ksu_seccomp_allow_cache(filter, __NR_reboot) 放行；我们剥离了那条
     * 路径，所以在这里补上：把 reboot 从 seccomp 黑名单里摘掉，并打上
     * tracepoint 标记，让子进程继承后也能装 fd。
     */
    if (tw->install_fd) {
        struct seccomp_filter *filter = current->seccomp.filter;

        if (filter) {
            spin_lock_irq(&current->sighand->siglock);
            ksu_seccomp_allow_cache(filter, __NR_reboot);
            ksu_set_task_tracepoint_flag(current);
            spin_unlock_irq(&current->sighand->siglock);
            pr_info("SECCOMP-GRANT: __NR_reboot allowed for uid=%d\n",
                    current_uid().val);
        } else {
            pr_info("SECCOMP-GRANT: no seccomp filter, uid=%d\n",
                    current_uid().val);
        }
    }

    /*
     * 装 fd，让管理器后续可以走完整的 fd + ioctl 路径。
     *
     * [INHERIT-FD] 关键：这里必须用 0 而非 O_CLOEXEC！
     * 管理器是通过 fork+exec 拉起 "libksud.so debug su" 来建 root shell 的，
     * ksud 内部会扫描 /proc/self/fd 去 "claim inherited KernelSU driver fd"，
     * 从而省掉 reboot(0xDEADBEEF,...) 那一步（那条路在 untrusted_app 的
     * seccomp 里被拦，日志表现为 "blocked by seccomp" -> "could not retrieve
     * kernelsu driver fd" -> KsuCli "Created process is not a shell"）。
     * 若带 O_CLOEXEC，exec 时 fd 被关闭，ksud 只能走被拦的 syscall 路径。
     */
    if (tw->install_fd && !ksu_current_has_driver_fd()) {
        int fd = ksu_install_fd_with_permissions(0, 0);

        if (fd >= 0)
            pr_info("LEGACY-PRCTL: inheritable driver fd installed = %d\n", fd);
        else
            pr_warn("LEGACY-PRCTL: install driver fd failed %d\n", fd);
    }

    if (tw->a1)
        copy_to_user(tw->a1, &tw->version, sizeof(tw->version));
    if (tw->a2)
        copy_to_user(tw->a2, &tw->flags, sizeof(tw->flags));
    if (tw->a3)
        copy_to_user(tw->a3, &tw->result, sizeof(tw->result));

    kfree(tw);
}

static int prctl_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real = PT_REAL_REGS(regs);
    unsigned int magic = (unsigned int)PT_REGS_SYSCALL_PARM1(real);
    unsigned int cmd = (unsigned int)PT_REGS_PARM2(real);

    if (magic != KSU_INSTALL_MAGIC1)
        return 0;

    /*
     * 协议 A：prctl(0xDEADBEEF, 0xCAFEBABE, 0, &fd, 0)
     *   ksud / 新版管理器用它安装 [ksu_driver] fd（后续走 ioctl）
     */
    if (cmd == KSU_INSTALL_MAGIC2) {
        struct ksu_install_fd_tw *tw;
        unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real);

        tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
        if (!tw)
            return 0;
        tw->outp = (int __user *)arg4;
        tw->cb.func = ksu_install_fd_tw_func;

        if (task_work_add(current, &tw->cb, TWA_RESUME)) {
            kfree(tw);
            pr_warn("LEGACY-PRCTL: install fd task_work failed\n");
            return 0;
        }
        pr_info("LEGACY-PRCTL: install fd queued\n");
        return 0;
    }

    if (cmd == KSU_PRCTL_CMD_GET_INFO) {
        struct legacy_prctl_tw *tw = kzalloc(sizeof(*tw), GFP_ATOMIC);

        if (!tw)
            return 0;

        tw->a1 = (void __user *)PT_REGS_PARM3(real);
        tw->a2 = (void __user *)PT_REGS_SYSCALL_PARM4(real);
        tw->a3 = (void __user *)PT_REGS_PARM5(real);
        tw->version = KERNEL_SU_VERSION;
        tw->flags = 0;
#ifdef MODULE
        tw->flags |= KSU_GET_INFO_FLAG_LKM;
#endif
        if (ksu_late_loaded)
            tw->flags |= KSU_GET_INFO_FLAG_LATE_LOAD;
        if (is_manager())
            tw->flags |= KSU_GET_INFO_FLAG_MANAGER;
        tw->result = 0;
        /* 关键：让管理器等进程自动获得 [ksu_driver] fd，从而走完整 ioctl 路径 */
        tw->install_fd = true;
        tw->cb.func = legacy_prctl_tw_func;

        if (task_work_add(current, &tw->cb, TWA_RESUME)) {
            kfree(tw);
            pr_warn("LEGACY-PRCTL: task_work_add failed\n");
            return 0;
        }

        ((struct pt_regs *)real)->regs[0] = 0;
        pr_info("LEGACY-PRCTL: GET_INFO queued v=%d flags=0x%x\n",
                tw->version, tw->flags);
    } else {
        pr_info("LEGACY-PRCTL: unhandled cmd=%u\n", cmd);
    }
    return 0;
}

static struct kprobe prctl_kp = {
    .symbol_name = "__arm64_sys_prctl",
    .pre_handler = prctl_handler_pre,
};

/*
 * [SETUID-GRANT] 拦截 setresuid(0,0,0)
 *
 * 背景：管理器点「越狱」时由 AppZygotePreload 派生子进程，该子进程会调用
 * setuid(0) 然后 exec ksud late-load --magica。原生内核路径下它没有
 * CAP_SETUID，setuid(0) 直接 EPERM，于是 _exit(1)，管理器显示「获取 Root 失败」。
 *
 * 官方实现靠 ksu_register_syscall_hook(__NR_setresuid) 拦截，但本机内核的
 * sys_call_table 写保护（EL2）无法绕过，故改用 kprobe 直接完成提权：
 * 只对 "setresuid(0,0,0)" 且调用者是 shell / 管理器 uid 的进程放行。
 */
struct ksu_setuid_tw {
    struct callback_head cb;
    bool do_escape;
};

static void ksu_setuid_tw_func(struct callback_head *cb)
{
    struct ksu_setuid_tw *tw = container_of(cb, struct ksu_setuid_tw, cb);

    if (tw->do_escape) {
        int ret = escape_with_root_profile();

        pr_info("SETUID-GRANT: escape_with_root_profile ret=%d uid=%d\n",
                ret, current_uid().val);
    }
    kfree(tw);
}

static bool ksu_uid_may_grant_root(uid_t uid)
{
    /* 管理器自身 / shell / 已经是 root 的进程 */
    if (is_uid_manager(uid))
        return true;
    if (uid == 0 || uid == 2000 /* SHELL_UID */)
        return true;
    return ksu_is_allow_uid_for_current(uid);
}

static int setresuid_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real = PT_REAL_REGS(regs);
    uid_t ruid = (uid_t)PT_REGS_PARM1(real);
    uid_t euid = (uid_t)PT_REGS_PARM2(real);
    uid_t suid = (uid_t)PT_REGS_PARM3(real);
    struct ksu_setuid_tw *tw;

    /*
     * [MANAGER-INSTALL] 官方 ksu_handle_setresuid 的等价路径。
     *
     * zygote 在 fork 出管理器后会执行
     *     setresuid(10246, 10246, 10246)
     * 官方正是在这一刻给该进程放行 __NR_reboot（seccomp cache）、
     * 打 task tracepoint、并装入 [ksu_driver] fd。管理器随后 fork+exec
     * libksud.so debug su，ksud 靠继承来的 fd（或 reboot syscall）拿到
     * 驱动，KsuCli 才会认为 "Created process is a shell"。
     *
     * 我们剥离了 syscall hook，所以在这里用 kprobe 补上：
     * 只要目标 uid 是管理器 appid（或 shell），就做这套安装动作。
     */
    if (ruid != (uid_t)-1 && is_uid_manager(ruid)) {
        struct seccomp_filter *filter;

        /* The restored dispatcher already runs ksu_handle_setresuid(). */
        if (ksu_has_syscall_hook(__NR_setresuid)) {
            pr_info("MANAGER-INSTALL: dispatcher owns setresuid uid=%d\n", ruid);
            return 0;
        }

        spin_lock_irq(&current->sighand->siglock);
        filter = current->seccomp.filter;
        if (filter) {
            ksu_seccomp_allow_cache(filter, __NR_reboot);
        }
        ksu_set_task_tracepoint_flag(current);
        spin_unlock_irq(&current->sighand->siglock);

        if (!ksu_current_has_driver_fd()) {
            /* 不带 O_CLOEXEC，好让 fork+exec 出来的 ksud 继承并 claim */
            int fd = ksu_install_fd_with_permissions(0, 0);

            pr_info("MANAGER-INSTALL: uid=%d setresuid, fd=%d, seccomp=%d\n",
                    ruid, fd, filter ? 1 : 0);
        } else {
            pr_info("MANAGER-INSTALL: uid=%d setresuid, fd already present\n",
                    ruid);
        }
        return 0;
    }

    /* 只关心 setresuid(0,0,0) / setresuid(-1,0,-1) 这类"要 root"的调用 */
    if (!((ruid == 0 || ruid == (uid_t)-1) &&
          (euid == 0 || euid == (uid_t)-1) &&
          (suid == 0 || suid == (uid_t)-1)))
        return 0;

    /* 已经在 root 上下文里，无需处理 */
    if (current_uid().val == 0)
        return 0;

    if (!ksu_uid_may_grant_root(current_uid().val)) {
        pr_info("SETUID-GRANT: deny uid=%d\n", current_uid().val);
        return 0;
    }

    tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
    if (!tw)
        return 0;

    tw->do_escape = true;
    tw->cb.func = ksu_setuid_tw_func;

    if (task_work_add(current, &tw->cb, TWA_RESUME)) {
        kfree(tw);
        return 0;
    }

    /* 让 setresuid 直接返回成功，真实提权在 task_work 里完成 */
    ((struct pt_regs *)real)->regs[0] = 0;
    pr_info("SETUID-GRANT: queued for uid=%d\n", current_uid().val);
    return 0;
}

static struct kprobe setresuid_kp = {
    .symbol_name = "__arm64_sys_setresuid",
    .pre_handler = setresuid_handler_pre,
};

void __init ksu_supercalls_init(void)
{
    int rc;

    ksu_supercall_dump_commands();

    rc = register_kprobe(&reboot_kp);
    if (rc) {
        pr_err("reboot kprobe failed: %d\n", rc);
    } else {
        pr_info("reboot kprobe registered successfully\n");
    }

    rc = register_kprobe(&prctl_kp);
    if (rc) {
        pr_err("LEGACY-PRCTL: prctl kprobe failed: %d\n", rc);
    } else {
        pr_info("LEGACY-PRCTL: prctl kprobe registered\n");
    }

    rc = register_kprobe(&setresuid_kp);
    if (rc) {
        pr_err("SETUID-GRANT: setresuid kprobe failed: %d\n", rc);
    } else {
        pr_info("SETUID-GRANT: setresuid kprobe registered\n");
    }
}

void __exit ksu_supercalls_exit(void)
{
    unregister_kprobe(&setresuid_kp);
    unregister_kprobe(&prctl_kp);
    unregister_kprobe(&reboot_kp);
    ksu_supercall_cleanup_state();
}
