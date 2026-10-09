/* SPDX-License-Identifier: LGPL-3.0-only */
#ifndef VOW_LOCK_H
#define VOW_LOCK_H

/*
 * a spin lock that makes no system call. pledge() may already be in force
 * when another thread calls in, and futex or sched_yield may be forbidden by
 * it, so waiting must not need the kernel. critical sections are short (one
 * seccomp or landlock call). not async-signal-safe: do not call pledge() or
 * unveil() from a signal handler.
 */

typedef volatile int vow_lock_t;

static void
vow_lock(vow_lock_t *l)
{
	while (__sync_lock_test_and_set(l, 1))
		while (*l)
			;
}

static void
vow_unlock(vow_lock_t *l)
{
	__sync_lock_release(l);
}

#endif
