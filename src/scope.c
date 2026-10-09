#include <errno.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "filter.h"

/*
 * enter a landlock domain that only scopes signals: from now on this process can send signals only
 * to processes in the same domain or in domains nested inside it. no filesystem rights are handled.
 * the domain cannot be left. only for a process with one thread, on any abi: a domain binds the
 * calling thread, and the only way to reach the others (TSYNC) replaces whatever domain they
 * had (DESIGN.md 6). threads made later inherit it. a child that inherits it is in the same
 * domain and can still signal its parent; calling this again in the child nests a new domain,
 * and a process in a nested domain cannot signal one in its ancestors.
 *   ENOSYS/EOPNOTSUPP  no landlock (the kernel's word); ENOSYS also for abi below 6
 *   EBUSY              not provably one thread, before or right after the domain was entered
 */
static int
enter(int check)
{
	struct vow_ruleset_attr6 attr;
	int a = vow_landlock_abi(), rs, err;

	if (a < 0)
		return -1;
	if (a < VOW_SCOPE_ABI) {
		errno = ENOSYS;
		return -1;
	}
	if (check) {
		err = vow_threads_single();
		if (err <= 0) {
			if (err == 0)
				errno = EBUSY;
			return -1;
		}
	}
	memset(&attr, 0, sizeof attr);
	attr.scoped = VOW_LL_SCOPE_SIGNAL;
	rs = (int)syscall(VOW_SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
	if (rs < 0)
		return -1;
	if (prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
	    syscall(VOW_SYS_landlock_restrict_self, rs, 0) < 0) {
		err = errno;
		close(rs);
		errno = err;
		return -1;
	}
	close(rs);
#ifdef VOW_TEST
	if (vow_test_after_restrict)
		vow_test_after_restrict();
#endif
	if (check && vow_threads_single() != 1) {
		errno = EBUSY;
		return -1;
	}
	return 0;
}

int
vow_scope_enter(void)
{
	return enter(1);
}

int
vow_scope_enter_child(void)
{
	return enter(0);
}
