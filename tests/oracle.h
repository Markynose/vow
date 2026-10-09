#ifndef ORACLE_H
#define ORACLE_H

/*
 * the oracle: what a policy should decide for a syscall, written directly
 * from the rule tables and the kernel argument model, never from generated
 * bytecode. it shares the tables with the generator (there is one policy),
 * but not the argument handling: that is written out again here, and the
 * kernel tests check both against what the kernel really does.
 */

#include "filter.h"
#include "bpfi.h"

static int
oracle_cond(const struct vow_cond *c, const uint64_t a[6])
{
	uint64_t x = a[c->arg];
	uint32_t lo = (uint32_t)x, m = (uint32_t)c->v;
	unsigned i;

	switch (c->op) {
	case VC_EQ:
		return c->kind == VK_LO32 ? lo == m : x == c->v;
	case VC_IN:
		for (i = 0; i < c->nset; i++)
			if (lo == c->set[i])
				return 1;
		return 0;
	case VC_ALLBITS:
		return (lo & m) == m;
	case VC_NOTALLBITS:
		return (lo & m) != m;
	case VC_ONLYBITS:
		return (lo & ~m) == 0;
	case VC_MASKEQ:
		return (lo & c->m) == m;
	}
	fprintf(stderr, "oracle: unknown cond op %d\n", c->op);
	abort();
}

/*
 * opening files, stated again from the matrix in DESIGN.md without looking at
 * the generated rule classes in src/filter.c:
 *   reading   needed for access mode 0, 2, 3
 *   writing   needed for access mode 1, 2, 3, for O_TRUNC, for O_TMPFILE
 *   creating  needed for O_CREAT and O_TMPFILE
 *   O_PATH    (open, openat) only looks a path up: reading is enough, other flags are dropped
 * creat() is create + write + truncate, openat2 is refused with ENOSYS, the flags are an int.
 */
static int
oracle_is_open_family(uint32_t nr)
{
	return nr == VOW_NR_open || nr == VOW_NR_openat || nr == VOW_NR_creat || nr == VOW_NR_openat2;
}

static uint32_t
oracle_open(unsigned promises, const struct vow_ctx *ctx, const struct sdata *d)
{
	int R = (promises & P_RPATH) != 0, W = (promises & P_WPATH) != 0, C = (promises & P_CPATH) != 0;
	uint32_t f, mode;
	int rd, wr, cr;

	if (!R && !W && !C)
		return ctx->deny;
	if (d->nr == VOW_NR_openat2)
		return VOW_SECCOMP_RET_ERRNO | 38;
	if (d->nr == VOW_NR_creat)
		return (W && C) ? VOW_SECCOMP_RET_ALLOW : ctx->deny;
	f = (uint32_t)d->args[d->nr == VOW_NR_open ? 1 : 2];
	if (f & 0x200000)	/* O_PATH */
		return R ? VOW_SECCOMP_RET_ALLOW : ctx->deny;
	mode = f & 3;
	rd = mode == 0 || mode == 2 || mode == 3;
	wr = mode != 0 || (f & 0x200) != 0 || (f & 0x400000) != 0;
	cr = (f & 0x40) != 0 || (f & 0x400000) != 0;
	if ((rd && !R) || (wr && !W) || (cr && !C))
		return ctx->deny;
	return VOW_SECCOMP_RET_ALLOW;
}

/*
 * the path calls other than open, again written down on their own. what each asks of the set:
 *   read   stat lstat newfstatat statx access faccessat faccessat2 readlink readlinkat getdents
 *          getdents64 getcwd chdir fchdir statfs fstatfs
 *   write  truncate ftruncate fallocate
 *   create mkdir mkdirat rmdir unlink unlinkat rename renameat link symlink symlinkat, and
 *          renameat2 unless RENAME_WHITEOUT (0x4, argument 4), linkat unless AT_EMPTY_PATH
 *          (0x1000, argument 4); both flags are 32 bits wide
 * returns 1 and sets *out when nr is one of these.
 */
static int
oracle_path_call(unsigned promises, const struct vow_ctx *ctx, const struct sdata *d, uint32_t *out)
{
	static const uint32_t rd[] = {
		VOW_NR_stat, VOW_NR_lstat, VOW_NR_newfstatat, VOW_NR_statx, VOW_NR_access,
		VOW_NR_faccessat, VOW_NR_faccessat2, VOW_NR_readlink, VOW_NR_readlinkat, VOW_NR_getdents,
		VOW_NR_getdents64, VOW_NR_getcwd, VOW_NR_chdir, VOW_NR_fchdir, VOW_NR_statfs, VOW_NR_fstatfs
	};
	static const uint32_t wr[] = { VOW_NR_truncate, VOW_NR_ftruncate, VOW_NR_fallocate };
	static const uint32_t cr[] = {
		VOW_NR_mkdir, VOW_NR_mkdirat, VOW_NR_rmdir, VOW_NR_unlink, VOW_NR_unlinkat, VOW_NR_rename,
		VOW_NR_renameat, VOW_NR_renameat2, VOW_NR_link, VOW_NR_linkat, VOW_NR_symlink, VOW_NR_symlinkat
	};
	unsigned i;
	int ok;

	for (i = 0; i < sizeof rd / sizeof *rd; i++)
		if (d->nr == rd[i]) {
			*out = (promises & P_RPATH) ? VOW_SECCOMP_RET_ALLOW : ctx->deny;
			return 1;
		}
	for (i = 0; i < sizeof wr / sizeof *wr; i++)
		if (d->nr == wr[i]) {
			*out = (promises & P_WPATH) ? VOW_SECCOMP_RET_ALLOW : ctx->deny;
			return 1;
		}
	for (i = 0; i < sizeof cr / sizeof *cr; i++)
		if (d->nr == cr[i]) {
			ok = (promises & P_CPATH) != 0;
			if (d->nr == VOW_NR_renameat2 && ((uint32_t)d->args[4] & 0x4))
				ok = 0;
			if (d->nr == VOW_NR_linkat && ((uint32_t)d->args[4] & 0x1000))
				ok = 0;
			*out = ok ? VOW_SECCOMP_RET_ALLOW : ctx->deny;
			return 1;
		}
	return 0;
}

/*
 * sending signals, stated on its own: the five calls pass with stdio and any arguments, and without
 * stdio they do not. who can be signalled is not the filter's business (the landlock scope that
 * pledge() enters before it installs a filter with stdio decides that).
 */
static int
oracle_signal(unsigned promises, const struct vow_ctx *ctx, const struct sdata *d, uint32_t *out)
{
	if (d->nr != VOW_NR_kill && d->nr != VOW_NR_tgkill && d->nr != VOW_NR_tkill &&
	    d->nr != VOW_NR_rt_sigqueueinfo && d->nr != VOW_NR_rt_tgsigqueueinfo)
		return 0;
	*out = (promises & P_STDIO) ? VOW_SECCOMP_RET_ALLOW : ctx->deny;
	return 1;
}

/*
 * sockets and exec, stated on their own.
 *   exec     execve and execveat
 *   inet     socket() for domain 2 or 10, type 1 or 2 once SOCK_NONBLOCK (0x800) and SOCK_CLOEXEC (0x80000)
 *            are taken off, protocol 0 or the one the type means (6 for 1, 17 for 2); connect bind listen
 *            accept accept4 sendmmsg recvmmsg sendto with any arguments
 *   stdio    sendto only without an address (argument 4 as a 64-bit pointer); setsockopt only for the
 *            (level, option) pairs below, both 32-bit
 */
static int
oracle_setsockopt_ok(uint32_t level, uint32_t opt)
{
	switch (level) {
	case 1:		/* SOL_SOCKET */
		return opt == 2 || opt == 5 || opt == 6 || opt == 7 || opt == 8 || opt == 9 || opt == 10 ||
		    opt == 13 || opt == 15 || opt == 16 || opt == 18 || opt == 20 || opt == 21 || opt == 29 ||
		    opt == 63 || opt == 66 || opt == 67;
	case 0:		/* IPPROTO_IP */
		return opt == 1 || opt == 2 || opt == 8 || (opt >= 10 && opt <= 13);
	case 6:		/* IPPROTO_TCP */
		return (opt >= 1 && opt <= 10) || opt == 12 || opt == 18 || opt == 23 || opt == 25 || opt == 30;
	case 17:	/* IPPROTO_UDP */
		return opt == 1;
	case 41:	/* IPPROTO_IPV6 */
		return opt == 16 || opt == 23 || opt == 25 || opt == 26 || opt == 49 || opt == 51 || opt == 62 ||
		    opt == 66 || opt == 67;
	}
	return 0;
}

static int
oracle_net(unsigned promises, const struct vow_ctx *ctx, const struct sdata *d, uint32_t *out)
{
	int inet = (promises & P_INET) != 0, stdio = (promises & P_STDIO) != 0;
	uint32_t ok = VOW_SECCOMP_RET_ALLOW;

	switch (d->nr) {
	case VOW_NR_execve:
	case VOW_NR_execveat:
		*out = (promises & P_EXEC) ? ok : ctx->deny;
		return 1;
	case VOW_NR_socket: {
		uint32_t dom = (uint32_t)d->args[0], type = (uint32_t)d->args[1] & ~(uint32_t)(0x800 | 0x80000);
		uint32_t proto = (uint32_t)d->args[2];
		int good = (dom == 2 || dom == 10) &&
		    ((type == 1 && (proto == 0 || proto == 6)) || (type == 2 && (proto == 0 || proto == 17)));

		*out = inet && good ? ok : ctx->deny;
		return 1;
	}
	case VOW_NR_connect: case VOW_NR_bind: case VOW_NR_listen: case VOW_NR_accept: case VOW_NR_accept4:
	case VOW_NR_sendmmsg: case VOW_NR_recvmmsg:
		*out = inet ? ok : ctx->deny;
		return 1;
	case 44:	/* sendto */
		*out = (inet || (stdio && d->args[4] == 0)) ? ok : ctx->deny;
		return 1;
	case 54:	/* setsockopt */
		*out = stdio && oracle_setsockopt_ok((uint32_t)d->args[1], (uint32_t)d->args[2]) ? ok : ctx->deny;
		return 1;
	}
	return 0;
}

/* first rule of the tables in order whose number matches and whose conditions hold; else deny */
static uint32_t
oracle_scan(const struct vow_table *t, size_t nt, const struct vow_ctx *ctx, const struct sdata *d)
{
	size_t i, j;
	unsigned k;

	if (d->arch != VOW_AUDIT_ARCH_X86_64 || (d->nr & VOW_X32_BIT))
		return ctx->deny;
	for (i = 0; i < nt; i++) {
		for (j = 0; j < t[i].n; j++) {
			const struct vow_rule *r = &t[i].r[j];
			int ok = 1;

			if (r->nr != d->nr)
				continue;
			if (r->err)
				return VOW_SECCOMP_RET_ERRNO | r->err;
			for (k = 0; k < r->ncond; k++)
				if (!oracle_cond(&r->cond[k], d->args))
					ok = 0;
			if (ok)
				return VOW_SECCOMP_RET_ALLOW;
		}
	}
	return ctx->deny;
}

static uint32_t
oracle(unsigned promises, const struct vow_ctx *ctx, const struct sdata *d)
{
	struct vow_table t[VOW_MAX_TABLES];
	struct vow_policy pol;
	size_t nt;

	if (d->arch != VOW_AUDIT_ARCH_X86_64 || (d->nr & VOW_X32_BIT))
		return ctx->deny;
	if (oracle_is_open_family(d->nr))
		return oracle_open(promises, ctx, d);
	{
		uint32_t v;

		if (oracle_path_call(promises, ctx, d, &v))
			return v;
		if (oracle_signal(promises, ctx, d, &v))
			return v;
		if (oracle_net(promises, ctx, d, &v))
			return v;
	}
	nt = vow_tables(promises, &pol, t);
	return oracle_scan(t, nt, ctx, d);
}

#endif
