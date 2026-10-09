#include <pthread.h>

#include "filter.h"

/*
 * a spin lock held by another thread at the moment of fork() would stay locked
 * forever in the child, which has only the forking thread. so fork takes both
 * locks first (the state is then not half way through an update), and both
 * sides give them back; the child also opens its own thread list. nothing else happens in the child: it stays in the
 * landlock domains of its parent, signal scope included (DESIGN.md 2.7).
 * registered once, on the first call into the library. these handlers run for
 * fork() of the libc only: a raw fork, clone or vfork system call does not run
 * them (documented, tested).
 */

static __thread int tu, tp;	/* what this thread took in prepare, so it gives back only that */

static void
prepare(void)
{
	tu = vow_unveil_lock();
	tp = vow_pledge_lock();
}

static void
after(void)
{
	vow_pledge_unlock(tp);
	vow_unveil_unlock(tu);
}

static void
after_in_child(void)
{
	after();
	vow_threads_forked();
}

void
vow_atfork_register(void)
{
	static volatile int done;

	/* if registering fails, fork() from another thread during a call is the caller's risk */
	if (!__sync_lock_test_and_set(&done, 1)) {
		(void)pthread_atfork(prepare, after, after_in_child);
		vow_threads_prepare();	/* before any restriction can hide /proc */
	}
}
