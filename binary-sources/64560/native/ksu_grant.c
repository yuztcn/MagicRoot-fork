/*
 * Minimal KernelSU root-fd bootstrap (MagicRoot).
 *
 * /sdcard is mounted noexec, so root_stage.sh cannot be execve'd directly.
 * Instead exec /system/bin/sh with the script path; the shell reads the
 * script from Download without needing execute permission.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KSU_MAGIC_1 0xdeadbeefU
#define KSU_MAGIC_2_LOCAL 0xcafebabeU    /* our patched LKM builds */
#define KSU_MAGIC_2_REF   0xdeadcafeU    /* reference-patched LKM builds */
#define KSU_IOCTL_GRANT_ROOT 0x4b01UL

extern char **environ;

int main(void) {
    int fd = -1;
    long reboot_rc = 0;
    int reboot_errno = 0;
    const char *source = "reboot_syscall_magic_cafebabe";
    errno = 0;
    reboot_rc = syscall(SYS_reboot, KSU_MAGIC_1, KSU_MAGIC_2_LOCAL, 0, &fd);
    reboot_errno = errno;
    printf("reboot_rc=%ld errno=%d(%s) fd=%d magic2=0x%x\n",
           reboot_rc, reboot_errno, strerror(reboot_errno), fd, KSU_MAGIC_2_LOCAL);

    /* Some manager/LKM builds register the same reboot hook but expect the
     * reference magic pair.  A failed reboot() with an unhandled magic simply
     * returns EINVAL; it must be retried, not treated as a real reboot. */
    if (fd < 0) {
        source = "reboot_syscall_magic_deadcafe";
        errno = 0;
        reboot_rc = syscall(SYS_reboot, KSU_MAGIC_1, KSU_MAGIC_2_REF, 0, &fd);
        reboot_errno = errno;
        printf("reboot_retry_rc=%ld errno=%d(%s) fd=%d magic2=0x%x\n",
               reboot_rc, reboot_errno, strerror(reboot_errno), fd, KSU_MAGIC_2_REF);
    }

    /* Last resort: a module that supports the KernelSU dev node only. */
    if (fd < 0) {
        source = "dev_ksu_open";
        fd = open("/dev/ksu", O_RDWR | O_CLOEXEC);
        printf("dev_ksu_fd=%d errno=%d(%s)\n", fd, errno, strerror(errno));
    }

    printf("KSU_FD_SOURCE=%s\n", fd >= 0 ? source : "none");

    if (fd < 0) {
        printf("NO_KSU_FD\n");
        return 2;
    }
    printf("reboot_rc=%ld errno=%d(%s) fd=%d\n",
           reboot_rc, reboot_errno, strerror(reboot_errno), fd);

    errno = 0;
    long grant_rc = ioctl(fd, KSU_IOCTL_GRANT_ROOT, 0);
    int grant_errno = errno;
    printf("grant_root_rc=%ld errno=%d(%s)\n",
           grant_rc, grant_errno, strerror(grant_errno));
    printf("uid=%d euid=%d\n", getuid(), geteuid());
    fflush(stdout);

    if (grant_rc != 0 || geteuid() != 0) {
        close(fd);
        return 3;
    }

    /* KernelSU 的 grant-root 主要保证 euid=0；显式把 real/saved/fs uid/gid
     * 一并归零，避免 root_stage 里出现 uid=0 但 cp 仍被 DAC 拒绝的边界状态。 */
    if (setresgid(0, 0, 0) != 0)
        printf("setresgid_errno=%d(%s)\n", errno, strerror(errno));
    if (setresuid(0, 0, 0) != 0)
        printf("setresuid_errno=%d(%s)\n", errno, strerror(errno));
    setfsgid(0);
    setfsuid(0);

    char ctx[128];
    ssize_t ctx_len = readlink("/proc/self/attr/current", ctx, sizeof(ctx) - 1);
    if (ctx_len < 0)
        ctx_len = 0;
    ctx[ctx_len] = 0;
    printf("post_grant uid=%d euid=%d fsuid=%d context=%s\n",
           getuid(), geteuid(), setfsuid(-1), ctx);
    fflush(stdout);

    char *const argv[] = {
        (char *)"/data/local/tmp/magic/root_stage.sh",
        NULL
    };
    execve("/data/local/tmp/magic/root_stage.sh", argv, environ);

    int exec_errno = errno;
    printf("EXEC_FAIL errno=%d(%s)\n", exec_errno, strerror(exec_errno));
    close(fd);
    return 4;
}
