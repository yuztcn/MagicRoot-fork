#!/usr/bin/env python3
"""ksu_grant: try the reboot-syscall fd backdoor with both known magic pairs,
then fall back to /dev/ksu and log the source explicitly."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent
P = WS / "main/app/native/ksu_grant.c"
t = P.read_text(encoding="utf-8")

old = '''#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <unistd.h>

#define KSU_MAGIC_1 0xdeadbeefU
#define KSU_MAGIC_2 0xcafebabeU
#define KSU_IOCTL_GRANT_ROOT 0x4b01UL

extern char **environ;

int main(void) {
    int fd = -1;
    errno = 0;
    long reboot_rc = syscall(SYS_reboot, KSU_MAGIC_1, KSU_MAGIC_2, 0, &fd);
    int reboot_errno = errno;

    printf("reboot_rc=%ld errno=%d(%s) fd=%d\\n",
           reboot_rc, reboot_errno, strerror(reboot_errno), fd);

    if (fd < 0) {
        printf("NO_KSU_FD\\n");
        return 2;
    }'''

new = '''#include <errno.h>
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
    printf("reboot_rc=%ld errno=%d(%s) fd=%d magic2=0x%x\\n",
           reboot_rc, reboot_errno, strerror(reboot_errno), fd, KSU_MAGIC_2_LOCAL);

    /* Some manager/LKM builds register the same reboot hook but expect the
     * reference magic pair.  A failed reboot() with an unhandled magic simply
     * returns EINVAL; it must be retried, not treated as a real reboot. */
    if (fd < 0) {
        source = "reboot_syscall_magic_deadcafe";
        errno = 0;
        reboot_rc = syscall(SYS_reboot, KSU_MAGIC_1, KSU_MAGIC_2_REF, 0, &fd);
        reboot_errno = errno;
        printf("reboot_retry_rc=%ld errno=%d(%s) fd=%d magic2=0x%x\\n",
               reboot_rc, reboot_errno, strerror(reboot_errno), fd, KSU_MAGIC_2_REF);
    }

    /* Last resort: a module that supports the KernelSU dev node only. */
    if (fd < 0) {
        source = "dev_ksu_open";
        fd = open("/dev/ksu", O_RDWR | O_CLOEXEC);
        printf("dev_ksu_fd=%d errno=%d(%s)\\n", fd, errno, strerror(errno));
    }

    printf("KSU_FD_SOURCE=%s\\n", fd >= 0 ? source : "none");

    if (fd < 0) {
        printf("NO_KSU_FD\\n");
        return 2;
    }
    printf("reboot_rc=%ld errno=%d(%s) fd=%d\\n",
           reboot_rc, reboot_errno, strerror(reboot_errno), fd);'''

if old not in t:
    raise SystemExit("ksu_grant anchor missing")
t = t.replace(old, new, 1)
P.write_text(t, encoding="utf-8", newline="\n")
print("patched ksu_grant.c")
