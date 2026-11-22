/* Generic 6.1.157 late-load helper.
 *
 * Keeps the task that KernelSU transitions to its domain alive for ksud.
 * Usage:
 *   ksu-loader-generic <module.ko> <ksud> <package-name> <kmi> [--restore-sig]
 *
 * Difference from load_and_run.c: the package name and KMI are runtime
 * arguments, so the same loader can initialize the bundled official ksud or
 * the ksud extracted from a locally installed manager.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

static int restore_sig(void)
{
    const char *path = "/sys/module/module/parameters/sig_enforce";
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[handoff] restore sig_enforce: open errno=%d\n", errno);
        return -1;
    }
    ssize_t n = write(fd, "Y\n", 2);
    int saved = errno;
    close(fd);
    if (n != 2) {
        fprintf(stderr, "[handoff] restore sig_enforce failed errno=%d\n", saved);
        return -1;
    }
    fprintf(stderr, "[handoff] sig_enforce restored to Y\n");
    return 0;
}

int main(int argc, char **argv)
{
    struct utsname uts;
    struct stat st;
    int restore = 0;

    if (argc < 5 || argc > 6) {
        fprintf(stderr,
                "usage: %s <module.ko> <ksud> <package-name> <kmi> [--restore-sig]\n",
                argv[0]);
        return 2;
    }
    if (argc == 6) {
        if (strcmp(argv[5], "--restore-sig")) {
            fprintf(stderr, "[handoff] unknown option: %s\n", argv[5]);
            return 2;
        }
        restore = 1;
    }
    if (getuid() || geteuid() || uname(&uts)) {
        fprintf(stderr, "[handoff] requires uid=0 and a working uname\n");
        return 2;
    }
    if (strncmp(uts.release, "6.1.157-android14-11-", 21)) {
        fprintf(stderr, "[handoff] unsupported kernel: %s\n", uts.release);
        return 2;
    }

    int fd = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 4096 || st.st_size > 8388608) {
        fprintf(stderr, "[handoff] invalid module file\n");
        if (fd >= 0) close(fd);
        return 3;
    }
    void *image = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (image == MAP_FAILED) return 3;

    fprintf(stderr, "[handoff] init_module, %lld bytes\n", (long long)st.st_size);
    fflush(NULL);
    if (syscall(SYS_init_module, image, st.st_size, "allow_shell=1")) {
        int saved = errno;
        fprintf(stderr, "[handoff] init_module failed: %d (%s)\n", saved,
                strerror(saved));
        munmap(image, st.st_size);
        if (restore) restore_sig();
        return 4;
    }
    munmap(image, st.st_size);
    fprintf(stderr, "[handoff] driver initialized; continuing in the same task\n");
    fflush(NULL);

    if (restore) (void)restore_sig();

    setenv("LD_LIBRARY_PATH",
           "/data/local/tmp/magic:/data/local/tmp/magic/61157", 1);
    char *const args[] = { argv[2], "late-load", "--allow-shell",
                           "--kmi", argv[4], "--package-name", argv[3], NULL };
    execv(argv[2], args);
    fprintf(stderr, "[handoff] exec ksud failed: %s\n", strerror(errno));
    return 5;
}
