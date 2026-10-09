/* SPDX-License-Identifier: LGPL-3.0-only */
#include <errno.h>
#include <string.h>

#include "filter.h"

#ifdef VOW_TEST
void (*vow_test_window)(void);
struct vow_table vow_test_extra;
#endif

#define ARR(a) (sizeof (a) / sizeof *(a))

/* conditions */
#define EQ32(i, val)	{ VC_EQ, (i), VK_LO32, 0, (val), NULL, 0 }
#define EQ64(i, val)	{ VC_EQ, (i), VK_FULL64, 0, (val), NULL, 0 }
#define IN32(i, s)	{ VC_IN, (i), VK_LO32, ARR(s), 0, (s), 0 }
#define ALLB(i, m)	{ VC_ALLBITS, (i), VK_LO32, 0, (m), NULL, 0 }
#define NOTALLB(i, m)	{ VC_NOTALLBITS, (i), VK_LO32, 0, (m), NULL, 0 }
#define ONLYB(i, m)	{ VC_ONLYBITS, (i), VK_LO32, 0, (m), NULL, 0 }
#define NOFLAG(i, m)	{ VC_MASKEQ, (i), VK_LO32, 0, 0, NULL, (m) }	/* (arg & m) == 0 */

/* rules */
#define ALLOW(name)		{ VOW_NR_##name, 0, 0, NULL }
#define WHEN(name, c)		{ VOW_NR_##name, 0, ARR(c), (c) }
#define ERRNO(name, e)		{ VOW_NR_##name, (e), 0, NULL }

/* always allowed: they can only tighten, or leave the process */
/*
 * the flags of the two always-allowed calls are limited to the ones vow itself uses. the seccomp
 * flags SPEC_ALLOW (switches off a speculation mitigation), NEW_LISTENER and LOG and every landlock
 * flag (audit logging off, and TSYNC, which replaces the domain of sibling threads) are not
 * needed to tighten a process and not allowed.
 */
static const uint32_t seccomp_flags[] = { 0, VOW_SECCOMP_FILTER_FLAG_TSYNC };
static const struct vow_cond c_seccomp[] = { EQ32(0, VOW_SECCOMP_SET_MODE_FILTER), IN32(1, seccomp_flags) };
static const struct vow_cond c_llrestrict[] = { EQ32(1, 0) };	/* no TSYNC: it would replace the domains of sibling threads */
static const struct vow_cond c_nnp[] = { EQ32(0, VOW_PR_SET_NO_NEW_PRIVS), EQ64(1, 1) };

static const struct vow_rule core[] = {
	ALLOW(exit), ALLOW(exit_group), ALLOW(rt_sigreturn), ALLOW(restart_syscall),
	ALLOW(landlock_create_ruleset), ALLOW(landlock_add_rule), WHEN(landlock_restrict_self, c_llrestrict),
	WHEN(seccomp, c_seccomp),
	WHEN(prctl, c_nnp),
};

/* stdio argument sets */
static const uint32_t fcntl_cmds[] = {
	0 /* F_DUPFD */, 1 /* F_GETFD */, 2 /* F_SETFD */, 3 /* F_GETFL */, 4 /* F_SETFL */,
	5 /* F_GETLK */, 6 /* F_SETLK */, 7 /* F_SETLKW */, 36 /* F_OFD_GETLK */,
	37 /* F_OFD_SETLK */, 38 /* F_OFD_SETLKW */, 1030 /* F_DUPFD_CLOEXEC */,
	1032 /* F_GETPIPE_SZ */
};
static const uint32_t ioctl_cmds[] = {
	0x541b /* FIONREAD */, 0x5421 /* FIONBIO */, 0x5451 /* FIOCLEX */,
	0x5450 /* FIONCLEX */, 0x5401 /* TCGETS */, 0x5413 /* TIOCGWINSZ */
};
static const uint32_t arch_prctl_codes[] = { 0x1002 /* ARCH_SET_FS */, 0x1003 /* ARCH_GET_FS */ };
static const uint32_t prctl_names[] = { 15 /* PR_SET_NAME */, 16 /* PR_GET_NAME */ };

static const struct vow_cond c_fcntl[] = { IN32(1, fcntl_cmds) };
static const struct vow_cond c_ioctl[] = { IN32(1, ioctl_cmds) };
/* no region that is writable and executable at once */
static const struct vow_cond c_prot[] = { NOTALLB(2, 0x6) };
/*
 * threads only: the flags every libc uses for pthread_create (vm fs files
 * sighand thread sysvsem), plus the optional ones (settls parent_settid
 * child_cleartid child_settid, and the obsolete detached bit musl sets).
 * no namespaces, no ptrace, no exit signal.
 */
static const struct vow_cond c_clone[] = { ALLB(0, 0x50f00), ONLYB(0, 0x50f00 | 0x80000 | 0x100000 | 0x200000 | 0x400000 | 0x1000000) };
static const struct vow_cond c_prlimit[] = { EQ32(0, 0), EQ64(2, 0) };
static const struct vow_cond c_archprctl[] = { IN32(0, arch_prctl_codes) };
static const struct vow_cond c_prctl[] = { IN32(0, prctl_names) };
static const struct vow_cond c_sendto[] = { EQ64(4, 0) };	/* no destination address */
static const struct vow_cond c_socketpair[] = { EQ32(0, 1) };	/* AF_UNIX */

/*
 * setsockopt on sockets that exist: only options that tune a connection. not allowed, among others:
 * attaching filters or programs (SO_ATTACH_FILTER, SO_ATTACH_BPF), SO_BINDTODEVICE, SO_MARK,
 * SO_PRIORITY, IP_OPTIONS (source routing), IP_HDRINCL, IP_FREEBIND, IP_TRANSPARENT, the multicast
 * options, TCP_ULP (loads a kernel module), TCP_MD5SIG, TCP_REPAIR, TCP_CONGESTION. getsockopt stays open.
 * levels: 1 SOL_SOCKET, 0 IPPROTO_IP, 6 IPPROTO_TCP, 17 IPPROTO_UDP, 41 IPPROTO_IPV6
 */
static const uint32_t so_sock[] = { 2, 5, 6, 7, 8, 9, 10, 13, 15, 16, 18, 20, 21, 29, 63, 66, 67 };
static const uint32_t so_ip[] = { 1, 2, 8, 10, 11, 12, 13 };
static const uint32_t so_tcp[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 18, 23, 25, 30 };
static const uint32_t so_udp[] = { 1 };
static const uint32_t so_ipv6[] = { 16, 23, 25, 26, 49, 51, 62, 66, 67 };
static const struct vow_cond c_so_sock[] = { EQ32(1, 1), IN32(2, so_sock) };
static const struct vow_cond c_so_ip[] = { EQ32(1, 0), IN32(2, so_ip) };
static const struct vow_cond c_so_tcp[] = { EQ32(1, 6), IN32(2, so_tcp) };
static const struct vow_cond c_so_udp[] = { EQ32(1, 17), IN32(2, so_udp) };
static const struct vow_cond c_so_ipv6[] = { EQ32(1, 41), IN32(2, so_ipv6) };

static const struct vow_rule stdio[] = {
	/* descriptors that already exist */
	ALLOW(read), ALLOW(write), ALLOW(readv), ALLOW(writev), ALLOW(pread64), ALLOW(pwrite64),
	ALLOW(preadv), ALLOW(pwritev), ALLOW(preadv2), ALLOW(pwritev2), ALLOW(lseek),
	ALLOW(close), ALLOW(close_range), ALLOW(dup), ALLOW(dup2), ALLOW(dup3), ALLOW(fsync),
	ALLOW(fdatasync), ALLOW(sync_file_range), ALLOW(fadvise64), ALLOW(fstat),
	WHEN(fcntl, c_fcntl), WHEN(ioctl, c_ioctl),
	/* memory */
	WHEN(mmap, c_prot), WHEN(mprotect, c_prot), ALLOW(munmap), ALLOW(mremap), ALLOW(brk),
	ALLOW(madvise), ALLOW(mincore), ALLOW(msync),
	/* time */
	ALLOW(clock_gettime), ALLOW(clock_getres), ALLOW(gettimeofday), ALLOW(time),
	ALLOW(nanosleep), ALLOW(clock_nanosleep),
	/* process information */
	ALLOW(getpid), ALLOW(getppid), ALLOW(gettid), ALLOW(getuid), ALLOW(geteuid),
	ALLOW(getgid), ALLOW(getegid), ALLOW(getgroups), ALLOW(getrlimit),
	WHEN(prlimit64, c_prlimit), ALLOW(uname), ALLOW(sysinfo), ALLOW(getrandom),
	ALLOW(sched_yield), ALLOW(sched_getaffinity), ALLOW(getrusage), ALLOW(times),
	ALLOW(rt_sigaction), ALLOW(rt_sigprocmask), ALLOW(rt_sigpending), ALLOW(rt_sigsuspend),
	ALLOW(rt_sigtimedwait), ALLOW(sigaltstack), ALLOW(pause),
	/*
	 * sending signals. the filter cannot tell whose process or thread an id names, so it does
	 * not try: it lets the calls through, and pledge() does not install a filter with stdio
	 * before the process is inside a landlock signal scope, which confines every signal this process
	 * sends to its own domain (DESIGN.md 2.7). a filter built without that is not safe to use
	 */
	ALLOW(kill), ALLOW(tgkill), ALLOW(tkill), ALLOW(rt_sigqueueinfo), ALLOW(rt_tgsigqueueinfo),
	/* threads */
	WHEN(clone, c_clone), ERRNO(clone3, ENOSYS), ALLOW(futex), ALLOW(set_tid_address),
	ALLOW(set_robust_list), ALLOW(rseq), WHEN(arch_prctl, c_archprctl), WHEN(prctl, c_prctl),
	/* waiting, pipes, event fds */
	ALLOW(poll), ALLOW(ppoll), ALLOW(select), ALLOW(pselect6), ALLOW(epoll_create),
	ALLOW(epoll_create1), ALLOW(epoll_ctl), ALLOW(epoll_wait), ALLOW(epoll_pwait),
	ALLOW(eventfd), ALLOW(eventfd2), ALLOW(timerfd_create), ALLOW(timerfd_settime),
	ALLOW(timerfd_gettime), ALLOW(pipe), ALLOW(pipe2),
	/* sockets that exist already, and local pairs. sendmsg contents cannot be inspected */
	WHEN(socketpair, c_socketpair), ALLOW(sendmsg), ALLOW(recvmsg), ALLOW(recvfrom),
	WHEN(sendto, c_sendto), ALLOW(shutdown), ALLOW(getsockname), ALLOW(getpeername),
	ALLOW(getsockopt),
	WHEN(setsockopt, c_so_sock), WHEN(setsockopt, c_so_ip), WHEN(setsockopt, c_so_tcp),
	WHEN(setsockopt, c_so_udp), WHEN(setsockopt, c_so_ipv6),
};

/*
 * rpath: reading paths and their metadata. fstat on an open descriptor is
 * in stdio. how a path is opened is decided by the flag classes below.
 */
static const struct vow_rule rpath[] = {
	ALLOW(stat), ALLOW(lstat), ALLOW(newfstatat), ALLOW(statx), ALLOW(access),
	ALLOW(faccessat), ALLOW(faccessat2), ALLOW(readlink), ALLOW(readlinkat),
	ALLOW(getdents), ALLOW(getdents64), ALLOW(getcwd), ALLOW(chdir), ALLOW(fchdir),
	ALLOW(statfs), ALLOW(fstatfs),
};

/*
 * inet: IP sockets. socket() is allowed for AF_INET and AF_INET6 with a stream or datagram type (after
 * masking SOCK_NONBLOCK and SOCK_CLOEXEC, the only flags the kernel accepts) and with the default
 * protocol or the one that type means (tcp for streams, udp for datagrams). other protocols open
 * more kernel code (sctp, dccp, mptcp, udplite, ping sockets) and are not part of this promise.
 * the other calls cannot look at the address (it is in memory) and take any descriptor,
 * whatever family that socket has: see DESIGN.md.
 */
static const uint32_t inet_domains[] = { 2 /* AF_INET */, 10 /* AF_INET6 */ };
static const uint32_t inet_proto_stream[] = { 0, 6 };
static const uint32_t inet_proto_dgram[] = { 0, 17 };
#define TYPE_IS(t)	{ VC_MASKEQ, 1, VK_LO32, 0, (t), NULL, ~(uint32_t)(0x800 | 0x80000) }
static const struct vow_cond c_sock_stream[] = {
	IN32(0, inet_domains), TYPE_IS(1), IN32(2, inet_proto_stream)
};
static const struct vow_cond c_sock_dgram[] = {
	IN32(0, inet_domains), TYPE_IS(2), IN32(2, inet_proto_dgram)
};

static const struct vow_rule inet[] = {
	WHEN(socket, c_sock_stream), WHEN(socket, c_sock_dgram),
	ALLOW(connect), ALLOW(bind), ALLOW(listen), ALLOW(accept), ALLOW(accept4),
	ALLOW(sendto), ALLOW(sendmmsg), ALLOW(recvmmsg),
};

/* exec: replace this process image. what the new image may do is what this process may do */
static const struct vow_rule execp[] = {
	ALLOW(execve), ALLOW(execveat),
};

/*
 * wpath: changing file contents without a new open. opening for write is in the open classes.
 * fallocate also punches holes and collapses ranges: all of it changes contents.
 */
static const struct vow_rule wpath[] = {
	ALLOW(truncate), ALLOW(ftruncate), ALLOW(fallocate),
};

/*
 * cpath: making and removing names. renameat2 may leave a whiteout (a character device node,
 * needs CAP_MKNOD) with RENAME_WHITEOUT: refused. linkat with AT_EMPTY_PATH names an inode
 * through a descriptor (needs CAP_DAC_READ_SEARCH): refused. mknod and mknodat are not here:
 * device nodes, fifos and sockets are not part of this promise.
 */
static const struct vow_cond c_renameat2[] = { NOFLAG(4, VOW_RENAME_WHITEOUT) };
static const struct vow_cond c_linkat[] = { NOFLAG(4, VOW_AT_EMPTY_PATH) };

static const struct vow_rule cpath[] = {
	ALLOW(mkdir), ALLOW(mkdirat), ALLOW(rmdir), ALLOW(unlink), ALLOW(unlinkat),
	ALLOW(rename), ALLOW(renameat), WHEN(renameat2, c_renameat2),
	ALLOW(link), WHEN(linkat, c_linkat), ALLOW(symlink), ALLOW(symlinkat),
};

/*
 * open(2), openat(2) and creat(2) by what the call needs. the matrix, with
 * f = flags without O_PATH:
 *
 *   read   (R): access mode 0, 2 or 3
 *   write  (W): access mode 1, 2 or 3; O_TRUNC (linux truncates a file opened
 *               read-only too); O_TMPFILE
 *   create (C): O_CREAT; O_TMPFILE
 *   O_PATH: the kernel drops every other flag for open and openat, so the
 *           call only looks a path up: R, whatever else is set
 *
 * an open is allowed when everything it needs is in the promise set. flags
 * the matrix does not name (O_CLOEXEC, O_NONBLOCK, O_DIRECTORY, ...) change
 * nothing about the need and are ignored, as the kernel ignores unknown ones.
 */
#define NEED_R 1u
#define NEED_W 2u
#define NEED_C 4u

static unsigned
have_of(unsigned promises)
{
	return ((promises & P_RPATH) ? NEED_R : 0) | ((promises & P_WPATH) ? NEED_W : 0) |
	    ((promises & P_CPATH) ? NEED_C : 0);
}

static unsigned
open_need(uint32_t f)
{
	unsigned need = 0;

	switch (f & VOW_O_ACCMODE) {
	case 0:
		need |= NEED_R;
		break;
	case VOW_O_WRONLY:
		need |= NEED_W;
		break;
	default:	/* O_RDWR, and 3, which the kernel checks as read and write */
		need |= NEED_R | NEED_W;
	}
	if (f & VOW_O_TRUNC)
		need |= NEED_W;
	if (f & VOW_O_CREAT)
		need |= NEED_C;
	if (f & VOW_O_TMPFILE_BIT)
		need |= NEED_W | NEED_C;
	return need;
}

static const uint32_t open_feat[5] = {
	VOW_O_TMPFILE_BIT, VOW_O_CREAT, VOW_O_TRUNC, VOW_O_RDWR, VOW_O_WRONLY
};

struct cubes {
	uint32_t mask[24], val[24];
	size_t n;
};

/* split the five flag features until every part is all allowed or all refused */
static void
open_cubes(unsigned have, size_t i, uint32_t mask, uint32_t val, struct cubes *c)
{
	size_t j, rest = 5 - i;
	unsigned total = 1u << rest, ok = 0, k;

	for (k = 0; k < total; k++) {
		uint32_t f = val;

		for (j = 0; j < rest; j++)
			if (k & (1u << j))
				f |= open_feat[i + j];
		if ((open_need(f) & ~have) == 0)
			ok++;
	}
	if (ok == 0)
		return;
	if (ok == total) {
		if (c->n < 24) {
			c->mask[c->n] = mask | VOW_O_PATH;	/* these are the non-O_PATH calls */
			c->val[c->n] = val;
			c->n++;
		}
		return;
	}
	open_cubes(have, i + 1, mask | open_feat[i], val, c);
	open_cubes(have, i + 1, mask | open_feat[i], val | open_feat[i], c);
}

static void
policy_rule(struct vow_policy *pol, uint32_t nr, uint32_t err, int arg, uint32_t mask, uint32_t val)
{
	struct vow_rule *r;

	if (pol->nrule >= VOW_POLICY_RULES || pol->ncond >= VOW_POLICY_CONDS)
		return;	/* the table is sized with room to spare; tests check the largest set */
	r = &pol->rule[pol->nrule++];
	r->nr = nr;
	r->err = err;
	r->ncond = 0;
	r->cond = NULL;
	if (arg >= 0) {
		struct vow_cond *c = &pol->cond[pol->ncond++];

		c->op = VC_MASKEQ;
		c->arg = (uint8_t)arg;
		c->kind = VK_LO32;
		c->nset = 0;
		c->v = val;
		c->set = NULL;
		c->m = mask;
		r->ncond = 1;
		r->cond = c;
	}
}

static void
open_rules(struct vow_policy *pol, unsigned have)
{
	struct cubes c;
	size_t i;

	c.n = 0;
	open_cubes(have, 0, 0, 0, &c);
	/* open(path, flags) has flags in argument 1, openat(dirfd, path, flags) in argument 2 */
	if (have & NEED_R) {
		policy_rule(pol, VOW_NR_open, 0, 1, VOW_O_PATH, VOW_O_PATH);
		policy_rule(pol, VOW_NR_openat, 0, 2, VOW_O_PATH, VOW_O_PATH);
	}
	for (i = 0; i < c.n; i++) {
		policy_rule(pol, VOW_NR_open, 0, 1, c.mask[i], c.val[i]);
		policy_rule(pol, VOW_NR_openat, 0, 2, c.mask[i], c.val[i]);
	}
	/* creat(path, mode) is open(path, O_CREAT | O_WRONLY | O_TRUNC, mode) */
	if ((have & (NEED_W | NEED_C)) == (NEED_W | NEED_C))
		policy_rule(pol, VOW_NR_creat, 0, -1, 0, 0);
	/* the flags of openat2 are inside a struct the filter cannot read: refuse by policy */
	policy_rule(pol, VOW_NR_openat2, ENOSYS, -1, 0, 0);
}

size_t
vow_tables(unsigned promises, struct vow_policy *pol, struct vow_table out[VOW_MAX_TABLES])
{
	size_t k = 0;
	unsigned have = have_of(promises);

	pol->nrule = pol->ncond = 0;
	out[k].r = core;
	out[k++].n = ARR(core);
	if (promises & P_STDIO) {
		out[k].r = stdio;
		out[k++].n = ARR(stdio);
	}
	if (have & NEED_R) {
		out[k].r = rpath;
		out[k++].n = ARR(rpath);
	}
	if (promises & P_INET) {
		out[k].r = inet;
		out[k++].n = ARR(inet);
	}
	if (promises & P_EXEC) {
		out[k].r = execp;
		out[k++].n = ARR(execp);
	}
	if (have & NEED_W) {
		out[k].r = wpath;
		out[k++].n = ARR(wpath);
	}
	if (have & NEED_C) {
		out[k].r = cpath;
		out[k++].n = ARR(cpath);
	}
	if (have) {
		open_rules(pol, have);
		out[k].r = pol->rule;
		out[k++].n = pol->nrule;
	}
#ifdef VOW_TEST
	if (vow_test_extra.r)
		out[k++] = vow_test_extra;
#endif
	/* core, stdio, signals, inet, exec, rpath, wpath, cpath, open classes, test rules: at most 10 */
	return k;
}

/* program builder */

struct bld {
	struct vow_insn *p;
	size_t n, max;
	int err;
};

static size_t
emit(struct bld *b, unsigned code, unsigned jt, unsigned jf, uint32_t k)
{
	size_t at = b->n;

	if (b->n >= b->max) {
		b->err = E2BIG;
		return at;
	}
	b->p[b->n].code = (uint16_t)code;
	b->p[b->n].jt = (uint8_t)jt;
	b->p[b->n].jf = (uint8_t)jf;
	b->p[b->n].k = k;
	b->n++;
	return at;
}

#define LD(b, off)	emit(b, VOW_BPF_LD | VOW_BPF_W | VOW_BPF_ABS, 0, 0, (off))
#define RET(b, v)	emit(b, VOW_BPF_RET | VOW_BPF_K, 0, 0, (v))

/* a forward jump to be resolved when the end of the block is known */
struct fix {
	size_t at;
	int on_true;
};

#define MAXFIX 32

static void
fix_add(struct bld *b, struct fix *f, size_t *nf, size_t at, int on_true)
{
	if (*nf >= MAXFIX) {
		b->err = E2BIG;
		return;
	}
	f[*nf].at = at;
	f[*nf].on_true = on_true;
	(*nf)++;
}

static void
fix_apply(struct bld *b, const struct fix *f, size_t nf, size_t target)
{
	size_t i;

	for (i = 0; i < nf; i++) {
		size_t off;

		if (f[i].at >= b->n)
			continue;
		off = target - f[i].at - 1;
		if (off > 255) {
			b->err = E2BIG;
			return;
		}
		if (f[i].on_true)
			b->p[f[i].at].jt = (uint8_t)off;
		else
			b->p[f[i].at].jf = (uint8_t)off;
	}
}

static void
emit_cond(struct bld *b, const struct vow_cond *c, struct fix *f, size_t *nf)
{
	uint32_t lo = (uint32_t)c->v, hi = (uint32_t)(c->v >> 32);
	size_t i, at, in_start;
	struct fix local[MAXFIX];
	size_t nl = 0;

	switch (c->op) {
	case VC_EQ:
		if (c->kind == VK_FULL64) {
			LD(b, VOW_SD_ARG(c->arg) + 4);
			at = emit(b, VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K, 0, 0, hi);
			fix_add(b, f, nf, at, 0);
		}
		LD(b, VOW_SD_ARG(c->arg));
		at = emit(b, VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K, 0, 0, lo);
		fix_add(b, f, nf, at, 0);
		break;
	case VC_IN:
		if (c->nset == 0) {
			b->err = EINVAL;
			return;
		}
		LD(b, VOW_SD_ARG(c->arg));
		for (i = 0; i + 1 < c->nset; i++) {
			at = emit(b, VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K, 0, 0, c->set[i]);
			fix_add(b, local, &nl, at, 1);
		}
		at = emit(b, VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K, 0, 0, c->set[c->nset - 1]);
		fix_add(b, f, nf, at, 0);
		in_start = b->n;
		fix_apply(b, local, nl, in_start);
		break;
	case VC_ALLBITS:
		LD(b, VOW_SD_ARG(c->arg));
		emit(b, VOW_BPF_ALU | VOW_BPF_AND | VOW_BPF_K, 0, 0, lo);
		at = emit(b, VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K, 0, 0, lo);
		fix_add(b, f, nf, at, 0);
		break;
	case VC_NOTALLBITS:
		LD(b, VOW_SD_ARG(c->arg));
		emit(b, VOW_BPF_ALU | VOW_BPF_AND | VOW_BPF_K, 0, 0, lo);
		at = emit(b, VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K, 0, 0, lo);
		fix_add(b, f, nf, at, 1);
		break;
	case VC_ONLYBITS:
		LD(b, VOW_SD_ARG(c->arg));
		emit(b, VOW_BPF_ALU | VOW_BPF_AND | VOW_BPF_K, 0, 0, ~lo);
		at = emit(b, VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K, 0, 0, 0);
		fix_add(b, f, nf, at, 0);
		break;
	case VC_MASKEQ:
		LD(b, VOW_SD_ARG(c->arg));
		emit(b, VOW_BPF_ALU | VOW_BPF_AND | VOW_BPF_K, 0, 0, c->m);
		at = emit(b, VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K, 0, 0, lo);
		fix_add(b, f, nf, at, 0);
		break;
	default:
		b->err = EINVAL;
	}
}

/* [load nr] [jeq nr, else skip block] [conds, each failing to skip] [ret] */
static void
emit_rule(struct bld *b, const struct vow_rule *r)
{
	struct fix f[MAXFIX];
	size_t nf = 0, at, i;

	LD(b, VOW_SD_NR);
	at = emit(b, VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K, 0, 0, r->nr);
	fix_add(b, f, &nf, at, 0);
	if (r->err) {
		RET(b, VOW_SECCOMP_RET_ERRNO | r->err);
	} else {
		for (i = 0; i < r->ncond; i++)
			emit_cond(b, &r->cond[i], f, &nf);
		RET(b, VOW_SECCOMP_RET_ALLOW);
	}
	fix_apply(b, f, nf, b->n);
}

size_t
vow_build_tables(const struct vow_table *t, size_t nt, const struct vow_ctx *ctx, struct vow_insn *out, size_t max)
{
	struct bld b;
	size_t i, j;
	size_t at;

	b.p = out;
	b.n = 0;
	b.max = max;
	b.err = 0;

	/* only x86-64 native calls are judged: a 32-bit or x32 entry is denied outright */
	LD(&b, VOW_SD_ARCH);
	emit(&b, VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K, 1, 0, VOW_AUDIT_ARCH_X86_64);
	RET(&b, ctx->deny);
	LD(&b, VOW_SD_NR);
	emit(&b, VOW_BPF_JMP | VOW_BPF_JSET | VOW_BPF_K, 0, 1, VOW_X32_BIT);
	RET(&b, ctx->deny);

	for (i = 0; i < nt; i++)
		for (j = 0; j < t[i].n; j++)
			emit_rule(&b, &t[i].r[j]);
	at = RET(&b, ctx->deny);
	(void)at;
	if (b.err) {
		errno = b.err;
		return 0;
	}
	return b.n;
}

size_t
vow_build(unsigned promises, const struct vow_ctx *ctx, struct vow_insn *out, size_t max)
{
	struct vow_table t[VOW_MAX_TABLES];
	struct vow_policy pol;
	size_t nt = vow_tables(promises, &pol, t);

	return vow_build_tables(t, nt, ctx, out, max);
}
