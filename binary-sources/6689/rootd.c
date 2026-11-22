#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define ROOT_SOCK "/data/local/tmp/pc98260-root.sock"

static int g_rootd_shutdown;

static int read_exact(int fd, void *buffer, size_t length)
{
	char *p = buffer;
	while (length) {
		ssize_t got = read(fd, p, length);
		if (got < 0 && errno == EINTR) continue;
		if (got <= 0) return -1;
		p += got;
		length -= (size_t)got;
	}
	return 0;
}

static void set_su_context(void)
{
	/* The exploit process has a NULL/invalid SELinux context.  init/property
	   service then fails getpeercon() and refuses setprop.  Switch the exec
	   child to a valid root-ish domain first; permissive mode permits it. */
	static const char ctx[] = "u:r:system_server:s0";
	int fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t n = write(fd, ctx, sizeof(ctx) - 1);
		if (n < 0)
			dprintf(STDERR_FILENO, "[rootd] setcon su failed errno=%d\n", errno);
		close(fd);
	}
}

static void exec_direct(char *command)
{
	/* Experimental protocol: a command beginning with '!' is parsed as
	   whitespace-separated argv and exec'd directly, without /system/bin/sh.
	   The rootd process is full-cap, while sh deliberately drops to shell
	   uid 2000 on this ROM, so m6 cleanup must use this path. */
	char *argv[32];
	char *save = NULL;
	int argc = 0;
	char *token = strtok_r(command, " \t", &save);
	while (token && argc < 31) {
		argv[argc++] = token;
		token = strtok_r(NULL, " \t", &save);
	}
	argv[argc] = NULL;
	if (!argc) _exit(127);
	char *const env[] = { (char *)"PATH=/system/bin:/vendor/bin:/data/local/tmp",
		(char *)"HOME=/", NULL };
	execve(argv[0], argv, env);
	_exit(127);
}

static void handle_client(int fd)
{
	uint32_t length = 0;
	char command[4097];
	if (read_exact(fd, &length, sizeof(length)) || length > 4096U ||
	    read_exact(fd, command, length)) return;
	command[length] = 0;
	static const char finit_prefix[] = "__PC98260_FINIT__ ";
	static const char finit_exit_prefix[] = "__PC98260_FINIT_EXIT__ ";
	int finit_exit = !strncmp(command, finit_exit_prefix,
		sizeof(finit_exit_prefix) - 1);
	if (finit_exit || !strncmp(command, finit_prefix, sizeof(finit_prefix) - 1)) {
		size_t prefix_len = finit_exit ? sizeof(finit_exit_prefix) - 1 :
			sizeof(finit_prefix) - 1;
		char *path = command + prefix_len;
		char *params = strchr(path, ' ');
		long rc = -1;
		int err = 0;
		if (params)
			*params++ = 0;
		if (!*path) {
			err = EINVAL;
		} else {
			int mfd = open(path, O_RDONLY | O_CLOEXEC);
			if (mfd < 0) {
				err = errno;
			} else {
				errno = 0;
				rc = syscall(SYS_finit_module, mfd,
					params ? params : "", 0);
				err = errno;
				close(mfd);
			}
		}
		dprintf(fd, "FINIT_RC=%ld ERRNO=%d\n", rc, err);
		if (finit_exit && rc == 0)
			g_rootd_shutdown = 1;
		return;
	}
	if (!strcmp(command, "__PC98260_SHUTDOWN__")) {
		g_rootd_shutdown = 1;
		return;
	}
	pid_t child = fork();
	if (child < 0) return;
	if (child == 0) {
		set_su_context();
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO) close(fd);
		char *const env[] = { (char *)"PATH=/system/bin:/vendor/bin:/data/local/tmp",
			(char *)"HOME=/", NULL };
		if (length && command[0] == '!') {
			exec_direct(command + 1);
		}
		if (length) {
			char *const argv[] = { (char *)"sh", (char *)"-c",
				command, NULL };
			execve("/system/bin/sh", argv, env);
		} else {
			char *const argv[] = { (char *)"sh", (char *)"-i", NULL };
			execve("/system/bin/sh", argv, env);
		}
		_exit(127);
	}
	int status;
	while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
}

int pc98260_run_rootd(void)
{
	if (geteuid() != 0) return 1;
	const char *path = ROOT_SOCK;
	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGPIPE, SIG_IGN);
	int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0) return 1;
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	if (strlen(path) >= sizeof(address.sun_path)) {
		close(listener);
		return 1;
	}
	strncpy(address.sun_path, path, sizeof(address.sun_path) - 1);
	(void)unlink(path);
	mode_t old_umask = umask(007);
	int bound = bind(listener, (struct sockaddr *)&address, sizeof(address));
	(void)umask(old_umask);
	if (bound) {
		dprintf(STDERR_FILENO, "[rootd] bind failed errno=%d (%s)\n",
			errno, strerror(errno));
		close(listener);
		return 1;
	}
	/* A uid-only fake cred may not retain CAP_CHOWN.  Keep the socket usable
	 * for the shell peer even when changing its group is denied; handle_client
	 * still accepts only uid 0/2000. */
	if (chown(path, 0, 2000)) {
		int e = errno;
		dprintf(STDERR_FILENO,
			"[rootd] chown denied errno=%d; using mode 0666 fallback\n", e);
		if (chmod(path, 0666)) {
			dprintf(STDERR_FILENO,
				"[rootd] chmod fallback failed errno=%d (%s)\n",
				errno, strerror(errno));
			close(listener);
			return 1;
		}
	} else if (chmod(path, 0660)) {
		dprintf(STDERR_FILENO, "[rootd] chmod failed errno=%d (%s)\n",
			errno, strerror(errno));
		close(listener);
		return 1;
	}
	if (listen(listener, 8)) {
		dprintf(STDERR_FILENO, "[rootd] listen failed errno=%d (%s)\n",
			errno, strerror(errno));
		close(listener);
		return 1;
	}
	dprintf(STDERR_FILENO, "[rootd] listening at %s pid=%d\n",
		path, getpid());
	for (;;) {
		int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
		if (client < 0) {
			if (errno == EINTR) continue;
			break;
		}
		struct ucred peer;
		socklen_t peer_len = sizeof(peer);
		if (!getsockopt(client, SOL_SOCKET, SO_PEERCRED,
				&peer, &peer_len) &&
		    (peer.uid == 0 || peer.uid == 2000))
			handle_client(client);
		close(client);
		if (g_rootd_shutdown)
			break;
	}
	close(listener);
	return g_rootd_shutdown ? 0 : 1;
}
