/*
 * Minimal su_forward: exec /system/bin/su with the original arguments.
 *
 * KernelSU's su_compat hooks the /system/bin/su exec path and routes an
 * authorized caller to ksud. This wrapper exists only to provide a physical
 * command-search entry (for example /system_ext/bin/su) while preserving the
 * normal /system/bin/su authorization path.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
    (void)argc;
    if (argv != NULL && argv[0] != NULL)
        argv[0] = (char *)"/system/bin/su";

    execve("/system/bin/su", argv, environ);
    fprintf(stderr, "su: cannot execute /system/bin/su: %s\n", strerror(errno));
    return 127;
}
