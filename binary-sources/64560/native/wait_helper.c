/*
 * wait_helper -- block until a file/line/marker appears, without shell polling.
 *
 * usage:
 *   wait_helper line <file> <prefix> <timeout_ms> [pid]
 *   wait_helper file <path> <timeout_ms> [pid]
 *   wait_helper any-file <timeout_ms> <pid> <path> [path...]
 *   wait_helper futex <sync_file> <cred|module> <timeout_ms> [pid]
 *   wait_helper futex-cred <sync_file> <timeout_ms> [pid]
 *   wait_helper futex-live <sync_file> <event_timeout_ms> <live_timeout_ms> [pid]
 *   wait_helper live [timeout_ms]
 *
 * Exit: 0 found, 3 watched process exited before the event, 124 timeout, 2 usage.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include "futex_sync.h"
#include <time.h>
#include <unistd.h>

#define MAX_WATCH 16

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int process_alive(pid_t pid)
{
    if (pid <= 0)
        return 1;
    if (kill(pid, 0) != 0 && errno != EPERM)
        return 0;
    char path[64], buf[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    char *p = strrchr(buf, ')');
    if (p && p[1] == ' ' && p[2] == 'Z')
        return 0;
    return 1;
}

static int find_line(const char *path, const char *prefix, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    char line[8192];
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = 0;
        if (!strncmp(line, prefix, strlen(prefix))) {
            if (out && cap)
                snprintf(out, cap, "%s", line);
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

static int file_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

static int watch_parent(int ifd, const char *path)
{
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (!slash)
        return -1;
    if (slash == dir)
        dir[1] = 0;
    else
        *slash = 0;
    return inotify_add_watch(ifd, dir,
                             IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE |
                                 IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF);
}

static void drain_inotify(int fd)
{
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    while (read(fd, buf, sizeof(buf)) > 0) {
    }
}

static int wait_line(const char *path, const char *prefix, int timeout_ms,
                     pid_t pid)
{
    long long end = now_ms() + timeout_ms;
    char out[8192];
    if (find_line(path, prefix, out, sizeof(out))) {
        if (out[0])
            printf("%s\n", out);
        return 0;
    }

    int ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (ifd < 0)
        return 2;
    if (watch_parent(ifd, path) < 0) {
        close(ifd);
        return 2;
    }

    for (;;) {
        if (find_line(path, prefix, out, sizeof(out))) {
            if (out[0])
                printf("%s\n", out);
            close(ifd);
            return 0;
        }
        if (!process_alive(pid)) {
            close(ifd);
            return 3;
        }
        long long left = end - now_ms();
        if (left <= 0) {
            close(ifd);
            return 124;
        }
        struct pollfd pfd = {.fd = ifd, .events = POLLIN};
        int wait = (int)(left > 100 ? 100 : left);
        int pr = poll(&pfd, 1, wait);
        if (pr > 0)
            drain_inotify(ifd);
    }
}

static int wait_file(const char *path, int timeout_ms, pid_t pid)
{
    long long end = now_ms() + timeout_ms;
    if (file_exists(path)) {
        printf("%s\n", path);
        return 0;
    }
    int ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (ifd < 0)
        return 2;
    if (watch_parent(ifd, path) < 0) {
        close(ifd);
        return 2;
    }
    for (;;) {
        if (file_exists(path)) {
            printf("%s\n", path);
            close(ifd);
            return 0;
        }
        if (!process_alive(pid)) {
            close(ifd);
            return 3;
        }
        long long left = end - now_ms();
        if (left <= 0) {
            close(ifd);
            return 124;
        }
        struct pollfd pfd = {.fd = ifd, .events = POLLIN};
        int wait = (int)(left > 100 ? 100 : left);
        int pr = poll(&pfd, 1, wait);
        if (pr > 0)
            drain_inotify(ifd);
    }
}

static int wait_any_file(int timeout_ms, pid_t pid, char **paths, int count)
{
    long long end = now_ms() + timeout_ms;
    for (int i = 0; i < count; i++) {
        if (file_exists(paths[i])) {
            printf("%s\n", paths[i]);
            return 0;
        }
    }
    int ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (ifd < 0)
        return 2;
    char dirs[MAX_WATCH][PATH_MAX];
    int ndirs = 0;
    for (int i = 0; i < count && ndirs < MAX_WATCH; i++) {
        char dir[PATH_MAX];
        snprintf(dir, sizeof(dir), "%s", paths[i]);
        char *slash = strrchr(dir, '/');
        if (!slash)
            continue;
        if (slash == dir)
            dir[1] = 0;
        else
            *slash = 0;
        int seen = 0;
        for (int j = 0; j < ndirs; j++)
            if (!strcmp(dirs[j], dir))
                seen = 1;
        if (seen)
            continue;
        snprintf(dirs[ndirs], sizeof(dirs[ndirs]), "%s", dir);
        if (inotify_add_watch(ifd, dirs[ndirs],
                              IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE |
                                  IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF) >= 0)
            ndirs++;
    }
    if (!ndirs) {
        close(ifd);
        return 2;
    }
    for (;;) {
        for (int i = 0; i < count; i++) {
            if (file_exists(paths[i])) {
                printf("%s\n", paths[i]);
                close(ifd);
                return 0;
            }
        }
        if (!process_alive(pid)) {
            close(ifd);
            return 3;
        }
        long long left = end - now_ms();
        if (left <= 0) {
            close(ifd);
            return 124;
        }
        struct pollfd pfd = {.fd = ifd, .events = POLLIN};
        int wait = (int)(left > 100 ? 100 : left);
        int pr = poll(&pfd, 1, wait);
        if (pr > 0)
            drain_inotify(ifd);
    }
}

static int map_sync(const char *path, struct futex_sync **out)
{
    int fd = open(path, O_RDWR | O_CREAT, 0666);
    if (fd < 0)
        return -1;
    if (ftruncate(fd, (off_t)sizeof(struct futex_sync)) != 0) {
        close(fd);
        return -1;
    }
    void *p = mmap(NULL, sizeof(struct futex_sync), PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return -1;
    *out = (struct futex_sync *)p;
    return 0;
}

static void futex_wake_all(struct futex_sync *s)
{
    __sync_synchronize();
    syscall(SYS_futex, (uint32_t *)&s->seq, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}

static int wait_futex_raw(const char *path, int want, int timeout_ms,
                          pid_t pid, int *out_event)
{
    struct futex_sync *s = NULL;
    if (map_sync(path, &s) != 0)
        return 2;
    long long end = now_ms() + timeout_ms;
    for (;;) {
        __sync_synchronize();
        int ev = s->event;
        if (ev == FUTEX_EV_FAIL) {
            munmap(s, sizeof(struct futex_sync));
            return 3;
        }
        if (ev >= want || (want == FUTEX_EV_MODULE && ev == FUTEX_EV_MODULE_SKIP)) {
            if (out_event)
                *out_event = ev;
            munmap(s, sizeof(struct futex_sync));
            return 0;
        }
        if (!process_alive(pid)) {
            munmap(s, sizeof(struct futex_sync));
            return 3;
        }
        long long left = end - now_ms();
        if (left <= 0) {
            munmap(s, sizeof(struct futex_sync));
            return 124;
        }
        uint32_t seq = s->seq;
        __sync_synchronize();
        if (s->event != ev)
            continue;
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = left > 100 ? 100000000L : (long)left * 1000000L;
        syscall(SYS_futex, (uint32_t *)&s->seq, FUTEX_WAIT, seq, &ts, NULL, 0);
    }
}

static int wait_futex(const char *path, const char *kind, int timeout_ms,
                      pid_t pid)
{
    int want = !strcmp(kind, "module") ? FUTEX_EV_MODULE : FUTEX_EV_CRED;
    int ev = 0;
    int rc = wait_futex_raw(path, want, timeout_ms, pid, &ev);
    if (rc)
        return rc;
    if (want == FUTEX_EV_CRED) {
        /* Re-open only for display; the event fields are still in the mapping. */
        struct futex_sync *s = NULL;
        if (map_sync(path, &s) != 0)
            return 2;
        if (s->cred)
            printf("CRED=0x%llx bit16=%d PID=%d\n",
                   (unsigned long long)s->cred, (int)s->bit16, (int)s->pid);
        else
            printf("CRED=NONE event=%d\n", ev);
        munmap(s, sizeof(struct futex_sync));
    } else {
        printf("FUTEX_EVENT=%d\n", ev);
    }
    return 0;
}

static int wait_futex_cred(const char *path, int timeout_ms, pid_t pid)
{
    int ev = 0;
    int rc = wait_futex_raw(path, FUTEX_EV_CRED, timeout_ms, pid, &ev);
    if (rc)
        return rc;
    struct futex_sync *s = NULL;
    if (map_sync(path, &s) != 0)
        return 2;
    if (!s->cred) {
        munmap(s, sizeof(struct futex_sync));
        return 3;
    }
    printf("CRED=0x%llx bit16=%d PID=%d\n",
           (unsigned long long)s->cred, (int)s->bit16, (int)s->pid);
    munmap(s, sizeof(struct futex_sync));
    return 0;
}

static int wait_live(int timeout_ms);

static int wait_futex_live(const char *path, int event_timeout_ms,
                           int live_timeout_ms, pid_t pid)
{
    int ev = 0;
    int rc = wait_futex_raw(path, FUTEX_EV_MODULE, event_timeout_ms, pid, &ev);
    if (rc)
        return rc;
    if (ev == FUTEX_EV_MODULE_SKIP) {
        printf("SKIP\n");
        return 0;
    }
    return wait_live(live_timeout_ms);
}

/* Test-only publisher, used to verify WAIT/WAKE without running the exploit. */
static int futex_signal(const char *path, int event, unsigned long long cred)
{
    struct futex_sync *s = NULL;
    if (map_sync(path, &s) != 0)
        return 2;
    s->cred = cred;
    s->bit16 = (int)(((cred + 0x40) >> 16) & 1);
    s->pid = (int)getpid();
    __sync_synchronize();
    s->event = event;
    __sync_synchronize();
    s->seq++;
    futex_wake_all(s);
    munmap(s, sizeof(struct futex_sync));
    return 0;
}

static int module_live(void)
{
    FILE *f = fopen("/proc/modules", "r");
    char line[4096];
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "kernelsu ", 9) && strstr(line, " Live")) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

static int wait_live(int timeout_ms)
{
    long long end = now_ms() + timeout_ms;
    for (;;) {
        if (module_live()) {
            printf("LIVE\n");
            return 0;
        }
        if (now_ms() >= end)
            return 124;
        usleep(20000);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;

    if (!strcmp(argv[1], "line")) {
        if (argc < 5)
            return 2;
        pid_t pid = argc > 5 ? (pid_t)atoi(argv[5]) : 0;
        return wait_line(argv[2], argv[3], atoi(argv[4]), pid);
    }
    if (!strcmp(argv[1], "file")) {
        if (argc < 4)
            return 2;
        pid_t pid = argc > 4 ? (pid_t)atoi(argv[4]) : 0;
        return wait_file(argv[2], atoi(argv[3]), pid);
    }
    if (!strcmp(argv[1], "any-file")) {
        if (argc < 5)
            return 2;
        return wait_any_file(atoi(argv[2]), argc > 4 ? (pid_t)atoi(argv[3]) : 0, &argv[4], argc - 4);
    }
    if (!strcmp(argv[1], "futex")) {
        if (argc < 5)
            return 2;
        pid_t pid = argc > 5 ? (pid_t)atoi(argv[5]) : 0;
        return wait_futex(argv[2], argv[3], atoi(argv[4]), pid);
    }
    if (!strcmp(argv[1], "futex-cred")) {
        if (argc < 4)
            return 2;
        pid_t pid = argc > 4 ? (pid_t)atoi(argv[4]) : 0;
        return wait_futex_cred(argv[2], atoi(argv[3]), pid);
    }
    if (!strcmp(argv[1], "futex-live")) {
        if (argc < 5)
            return 2;
        pid_t pid = argc > 5 ? (pid_t)atoi(argv[5]) : 0;
        return wait_futex_live(argv[2], atoi(argv[3]), atoi(argv[4]), pid);
    }
    if (!strcmp(argv[1], "futex-signal")) {
        if (argc < 4)
            return 2;
        return futex_signal(argv[2], atoi(argv[3]),
                            argc > 4 ? strtoull(argv[4], NULL, 0) : 0);
    }
    if (!strcmp(argv[1], "live")) {
        return wait_live(argc > 2 ? atoi(argv[2]) : 5000);
    }
    return 2;
}




