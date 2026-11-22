#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define KSU_INSTALL_MAGIC1 0xDEADBEEF
#define KSU_INSTALL_MAGIC2 0xCAFEBABE
#define KSU_IOCTL_GRANT_ROOT 0x4B01

static int root_ok(void) { return getuid() == 0 || geteuid() == 0; }

int main(int argc, char **argv) {
    const char *cmd = NULL;
    int i = 1;

    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "-c") == 0) {
            if (i + 1 < argc) cmd = argv[i + 1];
            i += 2;
            break;
        }
        i++;
    }
    if (!cmd && i < argc &&
        (strcmp(argv[i], "0") == 0 || (argv[i][0] >= '0' && argv[i][0] <= '9')))
        i++;

    int fd = -1;
    prctl(KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd, 0);
    if (fd >= 0) {
        ioctl(fd, KSU_IOCTL_GRANT_ROOT, 0);
        close(fd);
    }
    if (!root_ok()) {
        setresuid(0, 0, 0);
        setresgid(0, 0, 0);
    }
    if (!root_ok()) {
        fprintf(stderr, "su: grant failed uid=%d fd=%d errno=%d\n", getuid(), fd, errno);
        return 1;
    }

    if (cmd)
        execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
    if (i < argc)
        execv(argv[i], &argv[i]);
    execl("/system/bin/sh", "sh", (char *)NULL);
    perror("su: exec");
    return 127;
}
