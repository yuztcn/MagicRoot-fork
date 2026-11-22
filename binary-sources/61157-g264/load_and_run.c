/* Keep the task that KernelSU transitions to its domain alive for ksud. */
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

#define TARGET "6.1.157-android14-11-g2646292297b1"

int main(int argc, char **argv)
{
    struct utsname uts;
    struct stat st;
    if (argc != 3 || getuid() || geteuid() || uname(&uts) || strcmp(uts.release, TARGET)) {
        fprintf(stderr, "[handoff] requires target kernel, uid=0, module and ksud paths\n");
        return 2;
    }
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 4096 || st.st_size > 8388608) {
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
        fprintf(stderr, "[handoff] init_module failed: %d (%s)\n", saved, strerror(saved));
        munmap(image, st.st_size);
        return 4;
    }
    munmap(image, st.st_size);
    fprintf(stderr, "[handoff] driver initialized; continuing in the same task\n");
    fflush(NULL);
    char *const args[] = { argv[2], "late-load", "--allow-shell", "--kmi", "android14-6.1",
                          "--package-name", "me.weishu.kernelsu", NULL };
    execv(argv[2], args);
    fprintf(stderr, "[handoff] exec ksud failed: %s\n", strerror(errno));
    return 5;
}
