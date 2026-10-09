/* SPDX-License-Identifier: LGPL-3.0-only */
#ifndef T_H
#define T_H

#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define T_SKIP 77

#define CHECK(c) do { \
	if (!(c)) { \
		fprintf(stderr, "    check failed %s:%d: %s (errno %d: %s)\n", \
		    __FILE__, __LINE__, #c, errno, strerror(errno)); \
		_exit(1); \
	} \
} while (0)

#define SKIP(why) do { fprintf(stderr, "    skip: %s\n", why); _exit(T_SKIP); } while (0)

struct test {
	const char *name;
	void (*fn)(void);
	int sig;	/* 0: must exit 0; else: must die from this signal */
};

/*
 * every test runs in its own forked child, because landlock and seccomp
 * restrictions cannot be undone. skips are counted apart from passes and
 * the expected total is fixed so a silently dropped test fails the run.
 */
static int
t_main(const struct test *tests, int count, int expect)
{
	int i, pass = 0, fail = 0, skip = 0;
	struct rlimit nocore = { 0, 0 };

	/* seccomp kills dump core by default; do not litter */
	setrlimit(RLIMIT_CORE, &nocore);

	if (count != expect) {
		fprintf(stderr, "expected %d tests, table has %d\n", expect, count);
		return 1;
	}
	for (i = 0; i < count; i++) {
		pid_t p;
		int st;

		fflush(NULL);
		p = fork();
		if (p < 0) {
			perror("fork");
			return 1;
		}
		if (p == 0) {
			setpgid(0, 0);	/* so that whatever the test leaves behind can be killed as a group */
			alarm(60);	/* a hung test is a failed test */
			tests[i].fn();
			fflush(NULL);
			_exit(0);
		}
		setpgid(p, p);
		waitpid(p, &st, 0);
		kill(-p, SIGKILL);	/* helpers a test started and did not wait for would hold the output open */
		if (tests[i].sig != 0 && WIFSIGNALED(st) && WTERMSIG(st) == tests[i].sig) {
			pass++;
			printf("pass  %s (killed by signal %d)\n", tests[i].name, tests[i].sig);
		} else if (tests[i].sig == 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0) {
			pass++;
			printf("pass  %s\n", tests[i].name);
		} else if (WIFEXITED(st) && WEXITSTATUS(st) == T_SKIP) {
			skip++;
			printf("SKIP  %s\n", tests[i].name);
		} else {
			fail++;
			printf("FAIL  %s (status 0x%x)\n", tests[i].name, st);
		}
	}
	printf("%d passed, %d failed, %d skipped\n", pass, fail, skip);
	return fail != 0;
}

#endif
