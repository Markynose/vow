/* SPDX-License-Identifier: LGPL-3.0-only */
#include <errno.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "vow.h"
#include "filter.h"
#include "lock.h"

#define MAXLEN 1024

struct name {
	const char *s;
	unsigned bit;
};

/* the promises that are enforced today */
static const struct name impl[] = {
	{ "stdio", P_STDIO },
	{ "rpath", P_RPATH },
	{ "wpath", P_WPATH },
	{ "cpath", P_CPATH },
	{ "inet", P_INET },
	{ "exec", P_EXEC },
};

/*
 * openbsd promise names that are known but not enforced yet: asking for
 * them is "not supported", which is different from a typo.
 */
static const char *const later[] = {
	"proc", "dns", "unix", "tty", "fattr",
	"flock", "recvfd", "sendfd", "unveil", "getpw", "chown", "dpath", "tmppath", "id",
	"route", "mcast", "audio", "video", "bpf", "error", "settime", "prot_exec", "vminfo",
	"pf", "drm", "vmm", "wroute", "disklabel", "ps", "cpath", "inet",
};

static vow_lock_t plock;
static __thread int in_p;	/* this thread is inside pledge(): a signal handler must not wait for it */
static unsigned cur;	/* promises in force; meaningful when have. guarded by plock */
static int have;
static int scoped;	/* the process is inside the landlock signal scope. it cannot be left */

#ifdef VOW_TEST
long vow_test_seccomp_nr;

unsigned
vow_test_promises(void)
{
	return have ? cur : 0xffffu;
}

int
vow_test_scope_state(void)
{
	return scoped;
}
#endif

int
vow_pledge_blocks_unveil(void)
{
	int r;

	if (in_p)
		return -1;
	vow_lock(&plock);
	r = have && !(cur & P_RPATH);
	vow_unlock(&plock);
	return r;
}

int
vow_pledge_lock(void)
{
	if (in_p)
		return 0;
	vow_lock(&plock);
	return 1;
}

void
vow_pledge_unlock(int took)
{
	if (took)
		vow_unlock(&plock);
}

int
vow_install(const struct vow_insn *prog, size_t n)
{
	struct vow_prog fp;
	long nr = VOW_NR_seccomp, r;

#ifdef VOW_TEST
	if (vow_test_seccomp_nr)
		nr = vow_test_seccomp_nr;
#endif
	if (n == 0 || n > 4096) {
		errno = EINVAL;
		return -1;
	}
	if (prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		return -1;
	fp.len = (uint16_t)n;
	fp.filter = (struct vow_insn *)prog;
	r = syscall(nr, VOW_SECCOMP_SET_MODE_FILTER, VOW_SECCOMP_FILTER_FLAG_TSYNC, &fp);
	if (r == 0)
		return 0;
	/* a positive value is the id of a thread that could not be synchronized: nothing was installed */
	if (r > 0)
		errno = EBUSY;
	return -1;
}

/* one pass over the tokens; EINVAL beats ENOTSUP so a typo is never reported as a missing feature */
static int
parse(const char *s, unsigned *out)
{
	char buf[MAXLEN], *tok, *save = NULL;
	unsigned bits = 0;
	int bad = 0, unsup = 0;
	size_t i;

	if (strlen(s) >= sizeof buf) {
		errno = EINVAL;
		return -1;
	}
	strcpy(buf, s);
	for (tok = strtok_r(buf, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
		for (i = 0; i < sizeof impl / sizeof *impl; i++)
			if (strcmp(tok, impl[i].s) == 0)
				break;
		if (i < sizeof impl / sizeof *impl) {
			bits |= impl[i].bit;
			continue;
		}
		for (i = 0; i < sizeof later / sizeof *later; i++)
			if (strcmp(tok, later[i]) == 0)
				break;
		if (i < sizeof later / sizeof *later)
			unsup = 1;
		else
			bad = 1;
	}
	if (bad) {
		errno = EINVAL;
		return -1;
	}
	if (unsup) {
		errno = ENOTSUP;
		return -1;
	}
	*out = bits;
	return 0;
}

static int
pledge_locked(const char *promises, const char *execpromises)
{
	struct vow_insn prog[VOW_MAX_INSNS];
	struct vow_ctx ctx;
	unsigned np = 0, ne = 0;
	size_t n;

	if (promises == NULL && execpromises == NULL)
		return 0;
	if (promises != NULL && parse(promises, &np) < 0)
		return -1;
	if (execpromises != NULL && parse(execpromises, &ne) < 0)
		return -1;
	if (promises == NULL) {
		/* only execpromises: they can only equal what is already in force */
		if (!have || ne != cur) {
			errno = ENOTSUP;
			return -1;
		}
		return 0;
	}
	/*
	 * filters and landlock domains survive execve and cannot be swapped, so
	 * the program that is exec-ed always runs under the current promises.
	 * anything else cannot be honoured and is never ignored.
	 */
	if (execpromises != NULL && ne != np) {
		errno = ENOTSUP;
		return -1;
	}
	if (have && (np & ~cur)) {
		errno = EPERM;
		return -1;
	}
	if (have && np == cur)
		return 0;
#ifdef VOW_TEST
	if (vow_test_window)
		vow_test_window();
#endif

	if ((np & P_STDIO) && !scoped) {
		/* see scope.c: ENOSYS, EOPNOTSUPP or EBUSY mean no scope, and then no stdio */
		if (vow_scope_enter() < 0)
			return -1;
		scoped = 1;	/* the domain exists now, even if the install below fails */
	}
	ctx.deny = VOW_SECCOMP_RET_KILL_PROCESS;
	n = vow_build(np, &ctx, prog, VOW_MAX_INSNS);
	if (n == 0)
		return -1;
	if (vow_install(prog, n) < 0)
		return -1;
	cur = np;
	have = 1;
	return 0;
}

/* the check of the state in force, the install and the update are one step */
int
pledge(const char *promises, const char *execpromises)
{
	int r;

	vow_atfork_register();
	/* waiting for a lock that the interrupted code of this same thread holds would never end */
	if (in_p) {
		errno = EDEADLK;
		return -1;
	}
	vow_lock(&plock);
	in_p = 1;
	r = pledge_locked(promises, execpromises);
	in_p = 0;
	vow_unlock(&plock);
	return r;
}
