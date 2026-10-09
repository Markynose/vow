/*
 * a small program for the exec tests. built twice: static, and dynamic against the libc.
 * what it does is chosen by its first argument; the exit status says what happened.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "ok";

	if (strcmp(mode, "ok") == 0)
		return 0;
	if (strcmp(mode, "print") == 0) {
		printf("helper says hello\n");
		return 0;
	}
	if (strcmp(mode, "socket") == 0)
		return socket(AF_INET, SOCK_DGRAM, 0) >= 0 ? 10 : 11;
	if (strcmp(mode, "status") == 0) {
		char line[256];
		int nnp = 0, seccomp = 0;
		FILE *f = fopen("/proc/self/status", "r");

		if (f == NULL)
			return 3;
		while (fgets(line, sizeof line, f)) {
			if (strncmp(line, "NoNewPrivs:", 11) == 0)
				nnp = atoi(line + 11);
			if (strncmp(line, "Seccomp:", 8) == 0)
				seccomp = atoi(line + 8);
		}
		fclose(f);
		return !nnp ? 1 : seccomp != 2 ? 2 : 0;
	}
	if (strcmp(mode, "open") == 0 && argc > 2) {
		int fd = open(argv[2], O_RDONLY);

		if (fd >= 0)
			return 10;
		return errno == EACCES ? 0 : 12;
	}
	if (strcmp(mode, "writefd") == 0 && argc > 2)
		return write(atoi(argv[2]), "x", 1) == 1 ? 0 : 20 + (errno & 0x1f);
	if (strcmp(mode, "sig") == 0 && argc > 2) {
		if (kill((pid_t)atoi(argv[2]), 0) == 0)
			return 10;
		return errno == EPERM ? 0 : 12;
	}
	return 99;
}
