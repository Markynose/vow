/* SPDX-License-Identifier: 0BSD */
/*
 * exampled: the smallest daemon that shows a sandboxed service.
 *
 *   exampled MOTD OUTSIDE
 *
 * it prints the file MOTD (which the profile unveils), tries to open OUTSIDE (which the profile does not
 * unveil, so the open must fail), then prints a line every second until it gets SIGTERM.
 * static, no libvow: the sandbox is applied from outside by vow-run.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t term;

static void
on_term(int sig)
{
	(void)sig;
	term = 1;
}

int
main(int argc, char **argv)
{
	struct sigaction sa;
	char buf[256];
	ssize_t n;
	int fd;

	if (argc != 3)
		return 2;
	setvbuf(stdout, NULL, _IOLBF, 0);
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_term;
	sigaction(SIGTERM, &sa, NULL);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		printf("exampled: cannot read %s: %s\n", argv[1], strerror(errno));
	else {
		n = read(fd, buf, sizeof buf - 1);
		if (n > 0) {
			buf[n] = '\0';
			printf("exampled: motd: %s", buf);
		}
		close(fd);
	}
	fd = open(argv[2], O_RDONLY);
	if (fd < 0)
		printf("exampled: %s is outside the profile: %s\n", argv[2], strerror(errno));
	else {
		printf("exampled: %s was readable, the sandbox is not in place\n", argv[2]);
		close(fd);
	}
	printf("exampled: up, pid %d\n", (int)getpid());
	while (!term) {
		struct timespec ts = { 1, 0 };

		nanosleep(&ts, NULL);
	}
	printf("exampled: got TERM, leaving\n");
	return 0;
}
