/* SPDX-License-Identifier: LGPL-3.0-only */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <elf.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <dirent.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "vow.h"
#include "filter.h"
#include "oracle.h"
#include "t.h"

extern long vow_test_seccomp_nr;

static char self[4096];
static char root[4096];	/* a private directory for the files these tests make */

static const char *
tp(const char *name)
{
	static char buf[4][8192];
	static int i;
	char *b = buf[i++ & 3];

	snprintf(b, sizeof buf[0], "%s/%s", root, name);
	return b;
}

static void
mkfile(const char *path, const char *content, unsigned mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);

	if (fd < 0 || write(fd, content, strlen(content)) != (ssize_t)strlen(content))
		_exit(2);
	close(fd);
	chmod(path, mode);
}

#define JUNK 0xdeadbeef00000000ull
#define SENTINEL 1001u	/* a value no kernel returns as an errno */

/* ------------------------------------------------------------------ */
/* kernel differential: the same bytecode, judged by the interpreter, */
/* the oracle and the running kernel                                  */
/* ------------------------------------------------------------------ */

struct report {
	int bad, cases, checked, last, pairs_checked;
	unsigned lastnr;
	char msg[24][200];
};

static struct vow_ctx ctx;
static unsigned curset;
static struct vow_insn prog[VOW_MAX_INSNS];
static size_t nprog;

#define MAXC 12000
static struct kc {
	uint32_t nr;
	uint64_t a[6];
	uint32_t want;
} kc[MAXC];
static int nkc;

static void
addc(uint32_t nr, const uint64_t a[6])
{
	struct sdata d;
	uint32_t g, o;

	memset(&d, 0, sizeof d);
	d.arch = VOW_AUDIT_ARCH_X86_64;
	d.nr = nr;
	memcpy(d.args, a, sizeof d.args);
	g = bpf_run(prog, nprog, &d);
	o = oracle(curset, &ctx, &d);
	if (g != o) {
		fprintf(stderr, "    interpreter 0x%x vs oracle 0x%x for nr %u\n", g, o, nr);
		_exit(2);
	}
	if (nkc >= MAXC) {
		fprintf(stderr, "    too many cases\n");
		_exit(2);
	}
	kc[nkc].nr = nr;
	memcpy(kc[nkc].a, a, sizeof kc[nkc].a);
	kc[nkc].want = g;
	nkc++;
}

static struct vow_policy gpol;

static int
mentioned(uint32_t nr)
{
	struct vow_table t[VOW_MAX_TABLES];
	size_t nt = vow_tables(curset, &gpol, t), i, j;

	for (i = 0; i < nt; i++)
		for (j = 0; j < t[i].n; j++)
			if (t[i].r[j].nr == nr)
				return 1;
	return 0;
}

/* the values worth trying for one argument of one syscall, from the rules themselves */
static size_t
vals(uint32_t nr, unsigned idx, uint64_t *out, size_t max)
{
	struct vow_table t[VOW_MAX_TABLES];
	size_t nt = vow_tables(curset, &gpol, t), i, j, k, n = 0;

#define PUT(v) do { if (n < max) out[n++] = (v); } while (0)
	PUT(0);
	PUT(1ull << 32);
	for (i = 0; i < nt; i++)
		for (j = 0; j < t[i].n; j++) {
			if (t[i].r[j].nr != nr)
				continue;
			for (k = 0; k < t[i].r[j].ncond; k++) {
				const struct vow_cond *c = &t[i].r[j].cond[k];
				unsigned s;

				if (c->arg != idx)
					continue;
				PUT(c->v);
				PUT(c->v | JUNK);
				PUT(c->v ^ 1);
				PUT(c->v ^ (1ull << 32));
				PUT(c->v & (c->v - 1));	/* one bit fewer */
				PUT(c->v | 0x2000);
				for (s = 0; s < c->nset; s++) {
					PUT(c->set[s]);
					PUT(c->set[s] | JUNK);
					PUT(c->set[s] + 1);
				}
			}
		}
#undef PUT
	return n;
}

/*
 * ground truth about the kernel, independent of any filter: for an argument the table calls
 * LO32 the kernel must ignore the high half, so a call with junk up there has the same result
 * as one without; for the exact value of a FULL64 comparison it must not, or the table is wrong.
 * these pairs run before the filter is installed.
 */
#define MAXP 1024
static struct pair {
	uint32_t nr;
	uint64_t a[6], b[6];
	int same;
	unsigned idx;
} pairs[MAXP];
static int npairs;

static void
addpair(uint32_t nr, const uint64_t base[6], unsigned idx, uint64_t va, uint64_t vb, int same)
{
	if (nr == VOW_NR_seccomp || npairs >= MAXP)
		return;
	pairs[npairs].nr = nr;
	memcpy(pairs[npairs].a, base, sizeof pairs[0].a);
	memcpy(pairs[npairs].b, base, sizeof pairs[0].b);
	pairs[npairs].a[idx] = va;
	pairs[npairs].b[idx] = vb;
	pairs[npairs].same = same;
	pairs[npairs].idx = idx;
	npairs++;
}

static void
register_pairs(uint32_t nr, const uint64_t base[6], unsigned idx, const uint64_t *v, size_t n)
{
	struct vow_table t[VOW_MAX_TABLES];
	size_t nt = vow_tables(curset, &gpol, t), i, j, k, m;

	for (i = 0; i < nt; i++)
		for (j = 0; j < t[i].n; j++) {
			if (t[i].r[j].nr != nr)
				continue;
			for (k = 0; k < t[i].r[j].ncond; k++) {
				const struct vow_cond *c = &t[i].r[j].cond[k];

				if (c->arg != idx || c->op == VC_ALLBITS || c->op == VC_NOTALLBITS ||
				    c->op == VC_ONLYBITS)
					continue;
				if (c->kind == VK_LO32) {
					for (m = 0; m < n; m++)
						addpair(nr, base, idx, v[m] & 0xffffffffull,
						    (v[m] & 0xffffffffull) | JUNK, 1);
				} else if (c->op == VC_EQ) {
					addpair(nr, base, idx, c->v, c->v | (1ull << 32), 0);
				}
			}
		}
}

static void
vary(uint32_t nr, const uint64_t base[6], unsigned idx, const uint64_t *extra, size_t nextra)
{
	uint64_t v[128], a[6];
	size_t n = vals(nr, idx, v, 128), i;

	for (i = 0; i < nextra && n < 128; i++)
		v[n++] = extra[i];
	for (i = 0; i < n; i++) {
		memcpy(a, base, sizeof a);
		a[idx] = v[i];
		addc(nr, a);
	}
	register_pairs(nr, base, idx, v, n);
}

static int pfd[2], sv[2];
static char tmpdir[4096];
static unsigned char *sp, *mp, *bufp;
static struct rlimit rl;
static unsigned long fsbase;

static void
templates(void)
{
	uint64_t b[6];
	uint64_t pid = (uint64_t)getpid(), tid = (uint64_t)syscall(SYS_gettid);
	uint64_t x[] = { 2, 3, 4, 5, 6, 7, 0x2a, 0x1c0 };
	uint64_t y[] = { (uint64_t)(uintptr_t)bufp, (uint64_t)(uintptr_t)&rl, 8, 5 };

	/* base arguments are chosen so an unexpected allow does no harm */
	memset(b, 0, sizeof b);
	b[0] = (uint64_t)pfd[0]; b[1] = 1; vary(VOW_NR_fcntl, b, 1, x, 8);
	memset(b, 0, sizeof b);
	b[0] = (uint64_t)pfd[0]; b[1] = 0x541b; b[2] = (uint64_t)(uintptr_t)bufp;
	{
		uint64_t e[] = { 0x5412, 0x5413, 0x5401, 0x5421, 0x5451, 0x5450, 0x541b, 0x5414 };

		vary(VOW_NR_ioctl, b, 1, e, 8);
	}
	memset(b, 0, sizeof b);
	b[1] = 4096; b[2] = 1; b[3] = 0x22; b[4] = ~0ull;
	{
		uint64_t pr[] = { 0, 1, 2, 3, 4, 5, 6, 7 };

		vary(VOW_NR_mmap, b, 2, pr, 8);
	}
	memset(b, 0, sizeof b);
	b[0] = (uint64_t)(uintptr_t)mp; b[1] = 4096; b[2] = 3;
	{
		uint64_t pr[] = { 0, 1, 2, 3, 4, 5, 6, 7 };

		vary(VOW_NR_mprotect, b, 2, pr, 8);
	}
	memset(b, 0, sizeof b);
	b[0] = pid; b[1] = 0;
	vary(VOW_NR_kill, b, 0, y + 2, 0);
	memset(b, 0, sizeof b);
	b[0] = pid; b[1] = tid; b[2] = 0;
	vary(VOW_NR_tgkill, b, 0, y + 2, 0);
	memset(b, 0, sizeof b);
	b[0] = tid; b[1] = 0;
	vary(VOW_NR_tkill, b, 0, y + 2, 0);
	memset(b, 0, sizeof b);
	b[0] = pid; b[1] = 0; b[2] = (uint64_t)(uintptr_t)bufp;
	vary(VOW_NR_rt_sigqueueinfo, b, 0, y + 2, 0);
	memset(b, 0, sizeof b);
	b[0] = pid; b[1] = tid; b[2] = 0; b[3] = (uint64_t)(uintptr_t)bufp;
	vary(VOW_NR_rt_tgsigqueueinfo, b, 0, y + 2, 0);
	memset(b, 0, sizeof b);
	addc(VOW_NR_clone3, b);
	memset(b, 0, sizeof b);
	b[1] = 7; b[3] = (uint64_t)(uintptr_t)bufp;
	{
		uint64_t pp[] = { 1, 2, 4242, 0x7fffffff };

		vary(VOW_NR_prlimit64, b, 0, pp, 4);
	}
	b[0] = 0; b[2] = 0;
	{
		uint64_t pp[] = { (uint64_t)(uintptr_t)&rl, (uint64_t)(uintptr_t)bufp };

		vary(VOW_NR_prlimit64, b, 2, pp, 2);
	}
	/* arch_prctl: set_fs must be given the current value, get_* a buffer */
	{
		uint64_t codes[] = { 0x1002, 0x1003, 0x1001, 0x1004, 0x1011, 0x1012, 0x1002 | JUNK };
		size_t i;

		for (i = 0; i < sizeof codes / sizeof *codes; i++) {
			memset(b, 0, sizeof b);
			b[0] = codes[i];
			b[1] = (uint32_t)codes[i] == 0x1002 ? fsbase : (uint64_t)(uintptr_t)bufp;
			addc(VOW_NR_arch_prctl, b);
		}
	}
	memset(b, 0, sizeof b);
	b[0] = 15; b[1] = (uint64_t)(uintptr_t)bufp;
	{
		uint64_t o[] = { 15, 16, 3, 4, 21, 22, 38, 39, 15 | JUNK, 0x59616d61 };

		vary(VOW_NR_prctl, b, 0, o, 10);
	}
	memset(b, 0, sizeof b);
	b[0] = 38; b[1] = 1;
	{
		uint64_t one[] = { 1, 0, 2, 1ull << 32, 1 | JUNK };

		vary(VOW_NR_prctl, b, 1, one, 5);
	}
	memset(b, 0, sizeof b);
	b[0] = 1;
	{
		uint64_t op[] = { 0, 1, 2, 3, 1 | JUNK };
		uint64_t fl[] = { 0, 1, 2, 4, 8, 16, 32, 1 | JUNK, 4 | JUNK };

		vary(VOW_NR_seccomp, b, 0, op, 5);
		vary(VOW_NR_seccomp, b, 1, fl, 9);
	}
	memset(b, 0, sizeof b);
	b[0] = (uint64_t)-1;	/* no ruleset: the call fails whatever the flags say, except -1 with the log flag, which only mutes logs */
	{
		uint64_t fl[] = { 0, 8, 1, 2, 4, 16, 8 | JUNK, 4 | JUNK };

		vary(VOW_NR_landlock_restrict_self, b, 1, fl, 8);
	}
	memset(b, 0, sizeof b);
	b[0] = 1; b[1] = 1; b[3] = (uint64_t)(uintptr_t)bufp;
	{
		uint64_t d[] = { 1, 2, 10, 16, 1 | JUNK };

		vary(VOW_NR_socketpair, b, 0, d, 5);
	}
	memset(b, 0, sizeof b);
	b[0] = (uint64_t)sv[0]; b[1] = (uint64_t)(uintptr_t)bufp; b[2] = 1; b[3] = 0x40; b[5] = 16;
	{
		uint64_t ad[] = { 0, (uint64_t)(uintptr_t)bufp, 1ull << 32, 8 };

		vary(VOW_NR_sendto, b, 4, ad, 4);
	}
}


static int dfd;

/* every open flag class, on a directory so that nothing is created or damaged if one slips through */
static void
open_templates(void)
{
	static const uint32_t feat[5] = { 0x400000, 0x40, 0x200, 0x2, 0x1 };
	static const uint32_t neutral[3] = { 0, 0x88000 /* O_CLOEXEC|O_LARGEFILE */, 0x10000 /* O_DIRECTORY */ };
	uint64_t a[6];
	unsigned m, k, path;
	size_t n;

	for (path = 0; path < 2; path++)
		for (m = 0; m < 32; m++)
			for (k = 0; k < 3; k++) {
				uint32_t f = neutral[k] | (path ? 0x200000 : 0);
				size_t i;
				int j;

				for (i = 0; i < 5; i++)
					if (m & (1u << i))
						f |= feat[i];
				for (j = 0; j < 2; j++) {
					uint64_t fl = j ? (f | JUNK) : f;

					memset(a, 0, sizeof a);
					a[0] = (uint64_t)(uintptr_t)tmpdir;
					a[1] = fl;
					addc(VOW_NR_open, a);
					memset(a, 0, sizeof a);
					a[0] = (uint64_t)-100;
					a[1] = (uint64_t)(uintptr_t)tmpdir;
					a[2] = fl;
					addc(VOW_NR_openat, a);
				}
				/* the kernel must read the flags as an int */
				memset(a, 0, sizeof a);
				a[0] = (uint64_t)(uintptr_t)tmpdir;
				addpair(VOW_NR_open, a, 1, f, f | JUNK, 1);
				memset(a, 0, sizeof a);
				a[0] = (uint64_t)-100;
				a[1] = (uint64_t)(uintptr_t)tmpdir;
				addpair(VOW_NR_openat, a, 2, f, f | JUNK, 1);
			}
	memset(a, 0, sizeof a);
	a[0] = (uint64_t)(uintptr_t)tmpdir;
	addc(VOW_NR_creat, a);
	memset(a, 0, sizeof a);
	a[0] = (uint64_t)-100;
	a[1] = (uint64_t)(uintptr_t)tmpdir;
	a[2] = (uint64_t)(uintptr_t)bufp;
	a[3] = 24;
	addc(VOW_NR_openat2, a);
	(void)n;
}

static void
rpath_templates(void)
{
	uint64_t a[6];
	uint64_t path = (uint64_t)(uintptr_t)tmpdir, buf = (uint64_t)(uintptr_t)bufp, at = (uint64_t)-100;

#define RUN(nr, a0, a1, a2, a3, a4) do { memset(a, 0, sizeof a); a[0] = (a0); a[1] = (a1); a[2] = (a2); a[3] = (a3); a[4] = (a4); addc(nr, a); } while (0)
	RUN(VOW_NR_stat, path, buf, 0, 0, 0);
	RUN(VOW_NR_lstat, path, buf, 0, 0, 0);
	RUN(VOW_NR_newfstatat, at, path, buf, 0, 0);
	RUN(VOW_NR_statx, at, path, 0, 0xfff, buf);
	RUN(VOW_NR_access, path, 0, 0, 0, 0);
	RUN(VOW_NR_faccessat, at, path, 0, 0, 0);
	RUN(VOW_NR_faccessat2, at, path, 0, 0, 0);
	RUN(VOW_NR_readlink, path, buf, 64, 0, 0);
	RUN(VOW_NR_readlinkat, at, path, buf, 64, 0);
	RUN(VOW_NR_getdents, (uint64_t)dfd, buf, 256, 0, 0);
	RUN(VOW_NR_getdents64, (uint64_t)dfd, buf, 256, 0, 0);
	RUN(VOW_NR_getcwd, buf, 256, 0, 0, 0);
	RUN(VOW_NR_chdir, path, 0, 0, 0, 0);
	RUN(VOW_NR_fchdir, (uint64_t)dfd, 0, 0, 0, 0);
	RUN(VOW_NR_statfs, path, buf, 0, 0, 0);
	RUN(VOW_NR_fstatfs, (uint64_t)dfd, buf, 0, 0, 0);
#undef RUN
}

static char nx1[8192], nx2[8192];	/* names whose parent does not exist: harmless to hand to any call */

/* the write and create calls, aimed at names that cannot exist, so nothing happens if one slips through */
static void
pathop_templates(unsigned set)
{
	uint64_t a[6];
	uint64_t p1 = (uint64_t)(uintptr_t)nx1, p2 = (uint64_t)(uintptr_t)nx2, at = (uint64_t)-100;
	static const uint32_t f2[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 0x10 };
	static const uint32_t fl[] = { 0, 0x400, 0x1000, 0x1400, 0x100, 0x200 };
	size_t i;

	snprintf(nx1, sizeof nx1, "%s/no/such/one", root);
	snprintf(nx2, sizeof nx2, "%s/no/such/two", root);
#define RUN(nr, a0, a1, a2, a3, a4) do { memset(a, 0, sizeof a); a[0] = (a0); a[1] = (a1); a[2] = (a2); a[3] = (a3); a[4] = (a4); addc(nr, a); } while (0)
	if (set & P_WPATH) {
		RUN(VOW_NR_truncate, p1, 0, 0, 0, 0);
		RUN(VOW_NR_ftruncate, (uint64_t)pfd[0], 0, 0, 0, 0);
		RUN(VOW_NR_fallocate, (uint64_t)pfd[0], 0, 0, 1, 0);
	}
	if (set & P_CPATH) {
		RUN(VOW_NR_mkdir, p1, 0700, 0, 0, 0);
		RUN(VOW_NR_mkdirat, at, p1, 0700, 0, 0);
		RUN(VOW_NR_rmdir, p1, 0, 0, 0, 0);
		RUN(VOW_NR_unlink, p1, 0, 0, 0, 0);
		RUN(VOW_NR_unlinkat, at, p1, 0, 0, 0);
		RUN(VOW_NR_unlinkat, at, p1, 0x200, 0, 0);
		RUN(VOW_NR_rename, p1, p2, 0, 0, 0);
		RUN(VOW_NR_renameat, at, p1, at, p2, 0);
		RUN(VOW_NR_link, p1, p2, 0, 0, 0);
		RUN(VOW_NR_symlink, p1, p2, 0, 0, 0);
		RUN(VOW_NR_symlinkat, p1, at, p2, 0, 0);
		for (i = 0; i < sizeof f2 / sizeof *f2; i++) {
			RUN(VOW_NR_renameat2, at, p1, at, p2, f2[i]);
			RUN(VOW_NR_renameat2, at, p1, at, p2, f2[i] | JUNK);
			RUN(VOW_NR_renameat2, at, p1, at, p2, f2[i] | (1ull << 32));
			memset(a, 0, sizeof a);
			a[0] = at; a[1] = p1; a[2] = at; a[3] = p2;
			addpair(VOW_NR_renameat2, a, 4, f2[i], f2[i] | JUNK, 1);
		}
		for (i = 0; i < sizeof fl / sizeof *fl; i++) {
			RUN(VOW_NR_linkat, at, p1, at, p2, fl[i]);
			RUN(VOW_NR_linkat, at, p1, at, p2, fl[i] | JUNK);
			memset(a, 0, sizeof a);
			a[0] = at; a[1] = p1; a[2] = at; a[3] = p2;
			addpair(VOW_NR_linkat, a, 4, fl[i], fl[i] | JUNK, 1);
		}
		memset(a, 0, sizeof a);
		a[0] = at; a[1] = p1; a[2] = 0;
		addpair(VOW_NR_unlinkat, a, 2, 0x200, 0x200 | JUNK, 1);
	}
#undef RUN
}

/* sockets, socket options and exec, aimed at things that cannot do harm if a call slips through */
static void
net_templates(unsigned set)
{
	uint64_t a[6];
	static const uint64_t doms[] = { 0, 1, 2, 3, 10, 16, 17, 31, 2 | JUNK, 10 | JUNK, 40 };
	static const uint64_t types[] = { 0, 1, 2, 3, 5, 1 | 0x80000, 2 | 0x800, 1 | 0x80800, 2 | 0x1000, 1 | JUNK };
	static const uint64_t protos[] = { 0, 1, 6, 17, 132, 136, 262, 6 | JUNK };
	static const uint64_t levels[] = { 0, 1, 6, 17, 41, 255, 1 | JUNK, 6 | (1ull << 32) };
	size_t i, j, k;
	unsigned o;

	if (set & P_INET) {
		for (i = 0; i < sizeof doms / sizeof *doms; i++)
			for (j = 0; j < sizeof types / sizeof *types; j++)
				for (k = 0; k < sizeof protos / sizeof *protos; k++) {
					memset(a, 0, sizeof a);
					a[0] = doms[i]; a[1] = types[j]; a[2] = protos[k];
					addc(VOW_NR_socket, a);
				}
		/* the kernel must read all three as ints */
		for (i = 0; i < 4; i++) {
			static const uint64_t d[] = { 2, 10, 1, 17 };

			memset(a, 0, sizeof a);
			a[1] = 1;
			addpair(VOW_NR_socket, a, 0, d[i], d[i] | JUNK, 1);
		}
		for (i = 0; i < 5; i++) {
			static const uint64_t t[] = { 1, 2, 3, 1 | 0x80000, 2 | 0x800 };

			memset(a, 0, sizeof a);
			a[0] = 2;
			addpair(VOW_NR_socket, a, 1, t[i], t[i] | JUNK, 1);
		}
		for (i = 0; i < 4; i++) {
			static const uint64_t pr[] = { 0, 6, 17, 132 };

			memset(a, 0, sizeof a);
			a[0] = 2; a[1] = 1;
			addpair(VOW_NR_socket, a, 2, pr[i], pr[i] | JUNK, 1);
		}
	}
	if (set & P_STDIO) {
		/* options on a local socket pair: harmless whatever happens */
		for (i = 0; i < sizeof levels / sizeof *levels; i++)
			for (o = 0; o < 60; o++) {
				memset(a, 0, sizeof a);
				a[0] = (uint64_t)sv[0]; a[1] = levels[i]; a[2] = o;
				a[3] = (uint64_t)(uintptr_t)bufp; a[4] = 4;
				addc(54 /* setsockopt */, a);
			}
		for (i = 0; i < 4; i++) {
			static const uint64_t lv[] = { 1, 6, 0, 41 };
			static const uint64_t op[] = { 2, 1, 1, 26 };

			memset(a, 0, sizeof a);
			a[0] = (uint64_t)sv[0]; a[3] = (uint64_t)(uintptr_t)bufp; a[4] = 4;
			a[2] = op[i];
			addpair(54, a, 1, lv[i], lv[i] | JUNK, 1);
			memset(a, 0, sizeof a);
			a[0] = (uint64_t)sv[0]; a[1] = lv[i]; a[3] = (uint64_t)(uintptr_t)bufp; a[4] = 4;
			addpair(54, a, 2, op[i], op[i] | JUNK, 1);
		}
	}
	if (set & P_INET) {
		uint64_t p0 = (uint64_t)pfd[0];

#define RUN(nr, a0, a1, a2, a3, a4) do { memset(a, 0, sizeof a); a[0] = (a0); a[1] = (a1); a[2] = (a2); a[3] = (a3); a[4] = (a4); addc(nr, a); } while (0)
		RUN(VOW_NR_connect, p0, 0, 0, 0, 0);
		RUN(VOW_NR_bind, p0, 0, 0, 0, 0);
		RUN(VOW_NR_listen, p0, 1, 0, 0, 0);
		RUN(VOW_NR_accept, p0, 0, 0, 0, 0);
		RUN(VOW_NR_accept4, p0, 0, 0, 0, 0);
		RUN(VOW_NR_sendmmsg, p0, 0, 0, 0, 0);
		RUN(VOW_NR_recvmmsg, p0, 0, 0, 0, 0);
		RUN(44, p0, (uint64_t)(uintptr_t)bufp, 1, 0x40, 0);
#undef RUN
	}
	if (set & P_EXEC) {
		/* a null path: the kernel answers efault, nothing is executed */
		memset(a, 0, sizeof a);
		addc(VOW_NR_execve, a);
		memset(a, 0, sizeof a);
		a[0] = (uint64_t)-100;
		addc(VOW_NR_execveat, a);
	}
}

/* numbers whose real call would hurt if the filter wrongly let them through */
static int
dangerous(unsigned nr)
{
	switch (nr) {
	case 34: case 56: case 57: case 58: case 59: case 60: case 61: case 101: case 169:
	case 231: case 246: case 320: case 322: case 435:
		return 1;
	case 335: case 336:
		/* uretprobe and uprobe: exempt from seccomp in the kernel; user calls get SIGILL or EPROTO */
		return 1;
	}
	return 0;
}

static void
kdiff(unsigned set)
{
	struct report *rep = mmap(NULL, sizeof *rep, PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pid_t p;
	int st, i;

	CHECK(rep != MAP_FAILED);
	nkc = npairs = 0;
	fflush(NULL);
	p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		long r;
		unsigned nr;
		int i;

		alarm(30);
		curset = set;
		ctx.deny = VOW_SECCOMP_RET_ERRNO | SENTINEL;
		nprog = vow_build(set, &ctx, prog, VOW_MAX_INSNS);
		if (nprog == 0 || !bpf_validate(prog, nprog))
			_exit(2);
		/* resources the templates need, made before the filter exists */
		if (pipe(pfd) < 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
			_exit(2);
		sp = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		mp = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		bufp = sp;
		snprintf(tmpdir, sizeof tmpdir, "%s", root);
		dfd = open(root, O_RDONLY | O_DIRECTORY);
		if (dfd < 0)
			_exit(2);
		getrlimit(RLIMIT_NOFILE, &rl);
		syscall(VOW_NR_arch_prctl, 0x1003, &fsbase);
		/* every number the policy does not mention must be refused, run with zero arguments */
		for (nr = 0; nr < 460; nr++) {
			uint64_t z[6] = { 0 };

			if (!mentioned(nr) && !dangerous(nr))
				addc(nr, z);
		}
		{
			uint64_t z[6] = { 0 };

			addc(41, z);
			addc(VOW_X32_BIT | 39, z);
			addc(VOW_X32_BIT | VOW_NR_exit_group, z);
		}
		templates();
		if (set & (P_RPATH | P_WPATH | P_CPATH))
			open_templates();
		if (set & P_RPATH)
			rpath_templates();
		if (set & (P_WPATH | P_CPATH))
			pathop_templates(set);
		if (set & (P_INET | P_STDIO | P_EXEC))
			net_templates(set);
		/* the argument model against the bare kernel, with no filter in the way */
		for (i = 0; i < npairs; i++) {
			const struct pair *q = &pairs[i];
			long ra, rb;
			int ea, eb, same;

			errno = 0;
			ra = syscall((long)q->nr, q->a[0], q->a[1], q->a[2], q->a[3], q->a[4], q->a[5]);
			ea = errno;
			errno = 0;
			rb = syscall((long)q->nr, q->b[0], q->b[1], q->b[2], q->b[3], q->b[4], q->b[5]);
			eb = errno;
			if (q->nr == 41 || q->nr == 2 || q->nr == 257) {
				if (ra >= 0)
					close((int)ra);
				if (rb >= 0)
					close((int)rb);
			}
			/* descriptors returned by successful calls differ by number only */
			same = (ra >= 0) == (rb >= 0) && (ra >= 0 || ea == eb);
			rep->pairs_checked++;
			if (same != q->same) {
				rep->bad++;
				if (rep->bad <= 24)
					snprintf(rep->msg[rep->bad - 1], sizeof rep->msg[0],
					    "argument model: nr %u arg %u 0x%llx vs 0x%llx: kernel %s (%ld/%d, %ld/%d), table says %s",
					    q->nr, q->idx, (unsigned long long)q->a[q->idx],
					    (unsigned long long)q->b[q->idx], same ? "treats them alike" : "tells them apart",
					    ra, ea, rb, eb, q->same ? "alike" : "apart");
			}
		}
		if (vow_install(prog, nprog) < 0)
			_exit(3);
		rep->cases = nkc;
		for (i = 0; i < nkc; i++) {
			const struct kc *c = &kc[i];
			int e, ok;

			rep->last = i;
			rep->lastnr = c->nr;
			errno = 0;
			r = syscall((long)c->nr, c->a[0], c->a[1], c->a[2], c->a[3], c->a[4], c->a[5]);
			e = errno;
			if (r >= 0 && (c->nr == 41 || c->nr == 2 || c->nr == 257 || c->nr == 85))
				close((int)r);	/* do not run out of descriptors */
			if (c->want == VOW_SECCOMP_RET_ALLOW)
				ok = !(r == -1 && e == (int)SENTINEL);
			else
				ok = r == -1 && e == (int)(c->want & 0xffff);
			rep->checked++;
			if (!ok) {
				rep->bad++;
				if (rep->bad <= 24)
					snprintf(rep->msg[rep->bad - 1], sizeof rep->msg[0],
					    "nr %u args %llx %llx %llx: want 0x%x, kernel r=%ld errno=%d",
					    c->nr, (unsigned long long)c->a[0], (unsigned long long)c->a[1],
					    (unsigned long long)c->a[2], c->want, r, e);
			}
		}
		_exit(rep->bad ? 1 : 0);
	}
	CHECK(waitpid(p, &st, 0) == p);
	printf("    set 0x%x: %d cases and %d argument-model probes against the kernel, %d disagreements\n", set, rep->checked, rep->pairs_checked, rep->bad);
	for (i = 0; i < rep->bad && i < 24; i++)
		fprintf(stderr, "    %s\n", rep->msg[i]);
	if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0))
		fprintf(stderr, "    child status 0x%x, ran %d of %d, died in case nr %u args %llx %llx %llx\n", st, rep->checked, rep->cases, rep->lastnr, 0ull, 0ull, 0ull);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	CHECK(rep->checked == rep->cases && rep->cases > 200);
	if (set & P_STDIO)
		CHECK(rep->pairs_checked > 40);
}

static void t_kdiff_stdio(void) { kdiff(P_STDIO); }
static void t_kdiff_empty(void) { kdiff(0); }

/* the path promises, alone and together, with and without stdio */
static void
t_kdiff_paths(void)
{
	static const unsigned sets[] = {
		P_RPATH, P_WPATH, P_CPATH, P_RPATH | P_WPATH, P_RPATH | P_CPATH, P_WPATH | P_CPATH,
		P_RPATH | P_WPATH | P_CPATH, P_STDIO | P_RPATH, P_STDIO | P_RPATH | P_WPATH | P_CPATH,
		P_INET, P_STDIO | P_INET, P_EXEC, P_STDIO | P_RPATH | P_EXEC,
		P_STDIO | P_RPATH | P_WPATH | P_CPATH | P_INET | P_EXEC
	};
	size_t i;

	for (i = 0; i < sizeof sets / sizeof *sets; i++)
		kdiff(sets[i]);
}

/* ------------------------------------------------------------------ */
/* pledge() itself                                                    */
/* ------------------------------------------------------------------ */

#define OK(x) CHECK((x) == 0)
#define ERR(expr, e) do { errno = 0; CHECK((expr) == -1 && errno == (e)); } while (0)

extern int vow_test_abi_cap;
extern int vow_landlock_abi(void);
extern void (*vow_test_after_restrict)(void);

/* stdio needs a landlock signal scope (abi 6, abi 8 with threads): without one these tests cannot run */
static void
need_scope(void)
{
	if (vow_landlock_abi() < VOW_SCOPE_ABI)
		SKIP("kernel landlock abi < 6: no signal scope, no stdio");
}


static void
pl(const char *p)
{
	if (strstr(p, "stdio"))
		need_scope();
	CHECK(pledge(p, NULL) == 0);
	if (strstr(p, "stdio"))
		CHECK(vow_test_scope_state() == 1);
}

#define pls pl

/* proof that nothing has been installed: a call stdio forbids still works */
static void
nothing_installed(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	CHECK(fd >= 0);
	close(fd);
}

static void
t_args(void)
{
	OK(pledge(NULL, NULL));
	ERR(pledge("bogus", NULL), EINVAL);
	ERR(pledge("stdio bogus", NULL), EINVAL);
	ERR(pledge("proc", NULL), ENOTSUP);
	ERR(pledge("stdio unix", NULL), ENOTSUP);
	ERR(pledge("dns", NULL), ENOTSUP);
	/* a typo is a typo even when next to a feature that is not there yet */
	ERR(pledge("wpath bogus", NULL), EINVAL);
	ERR(pledge("STDIO", NULL), EINVAL);
	ERR(pledge("stdio", "bogus"), EINVAL);
	ERR(pledge("stdio", ""), ENOTSUP);
	ERR(pledge("stdio", "rpath"), ENOTSUP);
	ERR(pledge("", "stdio"), ENOTSUP);
	ERR(pledge(NULL, "stdio"), ENOTSUP);	/* nothing in force yet */
	{
		char big[3000];

		memset(big, 's', sizeof big - 1);
		big[sizeof big - 1] = 0;
		ERR(pledge(big, NULL), EINVAL);
	}
	nothing_installed();
}

static void
t_exec_promises_equal(void)
{
	OK(pledge("stdio", "stdio"));
	OK(pledge("stdio  stdio", "stdio"));	/* repeated blanks and duplicates are fine */
	OK(pledge(NULL, "stdio"));
	ERR(pledge(NULL, ""), ENOTSUP);
	ERR(pledge("stdio", "rpath"), ENOTSUP);
}

static void
t_widen_refused(void)
{
	OK(pledge("", NULL));
	ERR(pledge("stdio", NULL), EPERM);
	ERR(pledge("stdio", "stdio"), EPERM);
	OK(pledge("", ""));
	OK(pledge("", NULL));
	_exit(0);
}

static void
t_narrow_then_dead(void)
{
	pl("stdio");
	pl("stdio");	/* no change is not an error */
	pl("");
	(void)getpid();	/* no longer allowed: killed */
	_exit(0);
}

static void
t_empty_exit_ok(void)
{
	pl("");
	_exit(0);
}

static void
t_empty_getpid(void)
{
	pl("");
	(void)getpid();
	_exit(0);
}

static void
t_intersection(void)
{
	struct vow_insn all[1];

	pl("stdio");
	/* installing an allow-everything filter can only add a layer; the first still applies */
	all[0].code = VOW_BPF_RET | VOW_BPF_K;
	all[0].jt = all[0].jf = 0;
	all[0].k = VOW_SECCOMP_RET_ALLOW;
	OK(vow_install(all, 1));
	(void)socket(AF_INET, SOCK_DGRAM, 0);
	_exit(0);
}

static void
t_install_failure(void)
{
	/* the kernel refuses (no such syscall): the call fails and nothing changes */
	vow_test_seccomp_nr = 9999;
	ERR(pledge("stdio", NULL), ENOSYS);
	nothing_installed();
	vow_test_seccomp_nr = 0;
	/* state did not move: the first real call is still a first call, so "" is allowed... */
	OK(pledge("", NULL));
	/* ...and then widening is refused */
	ERR(pledge("stdio", NULL), EPERM);
}

static void
t_unveil_locked(void)
{
	pl("stdio");
	ERR(unveil("/", "r"), EPERM);
	ERR(unveil(NULL, NULL), EPERM);
	ERR(unveil("/", "z"), EPERM);
}

/* filters and no_new_privs survive execve: the exec-ed program is still judged */
static void
t_exec_inherits(void)
{
	struct vow_insn p[VOW_MAX_INSNS];
	struct vow_ctx c;
	pid_t pid;
	int st;
	size_t n, i;

	/* a filter that only refuses socket(2), with errno instead of a kill, and allows exec */
	(void)p; (void)c; (void)n; (void)i;
	{
		struct vow_insn f[4];

		f[0].code = VOW_BPF_LD | VOW_BPF_W | VOW_BPF_ABS; f[0].jt = f[0].jf = 0; f[0].k = VOW_SD_NR;
		f[1].code = VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K; f[1].jt = 0; f[1].jf = 1; f[1].k = 41;
		f[2].code = VOW_BPF_RET | VOW_BPF_K; f[2].jt = f[2].jf = 0; f[2].k = VOW_SECCOMP_RET_ERRNO | SENTINEL;
		f[3].code = VOW_BPF_RET | VOW_BPF_K; f[3].jt = f[3].jf = 0; f[3].k = VOW_SECCOMP_RET_ALLOW;
		OK(vow_install(f, 4));
	}
	pid = fork();
	CHECK(pid >= 0);
	if (pid == 0) {
		execl(self, self, "--probe", (char *)NULL);
		_exit(99);
	}
	CHECK(waitpid(pid, &st, 0) == pid);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/* ------------------------------------------------------------------ */
/* behavior under pledge("stdio") with a static musl                   */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t got;

static void
handler(int s)
{
	got = s;
}

static void *
thr(void *arg)
{
	int *v = arg;
	void *m = malloc(1 << 20);	/* big enough for mmap and munmap */

	*v += 1;
	free(m);
	return NULL;
}

static void
t_smoke(void)
{
	pthread_t t;
	struct pollfd pf;
	struct timespec ts;
	struct msghdr mh;
	struct iovec iv;
	char buf[64], c = 'q';
	int fds[2], pair[2], v = 0, i;
	void *m;
	stack_t ss;
	struct sigaction sa;
	struct rlimit r;

	fflush(NULL);
	OK(pipe(fds));
	OK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler;
	OK(sigaction(SIGUSR1, &sa, NULL));
	ss.ss_sp = malloc(65536);
	ss.ss_size = 65536;
	ss.ss_flags = 0;
	pl("stdio");

	/* printing, buffers, heap */
	printf("    smoke: stdio under pledge\n");
	fflush(stdout);
	m = malloc(5 << 20);
	CHECK(m != NULL);
	m = realloc(m, 9 << 20);
	CHECK(m != NULL);
	memset(m, 1, 9 << 20);
	free(m);
	/* threads: create, run, join, a few times */
	for (i = 0; i < 4; i++) {
		CHECK(pthread_create(&t, NULL, thr, &v) == 0);
		CHECK(pthread_join(t, NULL) == 0);
	}
	CHECK(v == 4);
	/* clocks, sleep, randomness */
	CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
	ts.tv_sec = 0;
	ts.tv_nsec = 1000000;
	CHECK(nanosleep(&ts, NULL) == 0);
	CHECK(syscall(VOW_NR_getrandom, buf, 16, 0) == 16);
	/* pipes, poll, fcntl, dup */
	CHECK(write(fds[1], &c, 1) == 1);
	pf.fd = fds[0];
	pf.events = POLLIN;
	CHECK(poll(&pf, 1, 1000) == 1);
	CHECK(read(fds[0], buf, 1) == 1);
	CHECK(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
	CHECK(fcntl(fds[0], F_GETFL) & O_NONBLOCK);
	i = dup(fds[0]);
	CHECK(i >= 0);
	close(i);
	/* terminal queries used by stdio */
	(void)isatty(1);
	/* local socket pair with ordinary and descriptor-less messages */
	CHECK(send(pair[0], "x", 1, 0) == 1);
	memset(&mh, 0, sizeof mh);
	iv.iov_base = buf;
	iv.iov_len = sizeof buf;
	mh.msg_iov = &iv;
	mh.msg_iovlen = 1;
	CHECK(recvmsg(pair[1], &mh, 0) == 1);
	CHECK(sendmsg(pair[1], &mh, 0) >= 0);
	/* limits can be read, not set */
	CHECK(getrlimit(RLIMIT_NOFILE, &r) == 0);
	/* signals to self, with an alternate stack and a handler return */
	OK(sigaltstack(&ss, NULL));
	got = 0;
	CHECK(kill(getpid(), SIGUSR1) == 0 && got == SIGUSR1);
	got = 0;
	CHECK(syscall(VOW_NR_tgkill, getpid(), syscall(VOW_NR_gettid), SIGUSR1) == 0 && got == SIGUSR1);
	/* protection changes that keep w^x */
	m = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(m != MAP_FAILED);
	CHECK(mprotect(m, 8192, PROT_READ) == 0);
	CHECK(mprotect(m, 8192, PROT_READ | PROT_EXEC) == 0);
	CHECK(munmap(m, 8192) == 0);
	printf("    smoke: done\n");
	_exit(0);
}




/*
 * enosys is this policy's answer, not a promise that every caller copes:
 * glibc pthread_create falls back to clone, but another runtime might not.
 * musl never asks for clone3, so only the raw call can show the answer.
 */
static void
t_clone3_answer(void)
{
	pl("stdio");
	errno = 0;
	CHECK(syscall(VOW_NR_clone3, 0, 0) == -1 && errno == ENOSYS);
}

static void
t_abort_dies(void)
{
	pl("stdio");
	abort();	/* main thread: raise works, so this is a real SIGABRT */
	_exit(0);
}







static void
t_fork(void)
{
	pl("stdio");
	fork();
	_exit(0);
}

static void
t_mprotect_wx(void)
{
	void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	CHECK(m != MAP_FAILED);
	pl("stdio");
	mprotect(m, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
	_exit(0);
}

static void
t_mmap_wx(void)
{
	pl("stdio");
	mmap(NULL, 4096, PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	_exit(0);
}

static void *
wx_thread(void *arg)
{
	void *m = arg;

	mprotect(m, 4096, PROT_WRITE | PROT_EXEC);
	return NULL;
}

/* one thread breaking the policy ends the whole process, not just itself */
static void
t_thread_violation(void)
{
	pthread_t t;
	void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	CHECK(m != MAP_FAILED);
	pl("stdio");
	CHECK(pthread_create(&t, NULL, wx_thread, m) == 0);
	pthread_join(t, NULL);
	_exit(0);
}

static int gate[2], hello[2];

static void *
late_socket(void *arg)
{
	char c;

	(void)arg;
	CHECK(write(hello[1], "r", 1) == 1);
	CHECK(read(gate[0], &c, 1) == 1);
	(void)socket(AF_INET, SOCK_DGRAM, 0);
	return NULL;
}

/* a thread that already exists when pledge is called is covered (tsync) */
static void
t_existing_thread(void)
{
	pthread_t t;
	char c;

	CHECK(pipe(gate) == 0 && pipe(hello) == 0);
	/* the scope needs a single thread, so the first pledge comes before the thread; narrowing later is seccomp's tsync */
	pl("stdio rpath");
	CHECK(pthread_create(&t, NULL, late_socket, NULL) == 0);
	CHECK(read(hello[0], &c, 1) == 1);
	pl("stdio");
	CHECK(write(gate[1], "g", 1) == 1);
	pthread_join(t, NULL);
	_exit(0);
}

static void *
new_socket(void *arg)
{
	(void)arg;
	(void)socket(AF_INET, SOCK_DGRAM, 0);
	return NULL;
}

static void
t_new_thread(void)
{
	pthread_t t;

	pl("stdio");
	CHECK(pthread_create(&t, NULL, new_socket, NULL) == 0);
	pthread_join(t, NULL);
	_exit(0);
}

static void
t_socket(void)
{
	pl("stdio");
	(void)socket(AF_INET, SOCK_STREAM, 0);
	_exit(0);
}

static void
t_open(void)
{
	pl("stdio");
	(void)open("/dev/null", O_RDONLY);
	_exit(0);
}

static void
t_sendto_addr(void)
{
	int p[2];
	char sa[16] = { 1 };

	OK(socketpair(AF_UNIX, SOCK_DGRAM, 0, p));
	pl("stdio");
	/* without an address: fine */
	CHECK(send(p[0], "x", 1, 0) == 1);
	sendto(p[0], "x", 1, 0, (struct sockaddr *)sa, sizeof sa);
	_exit(0);
}

static void
t_setrlimit(void)
{
	struct rlimit r;

	OK(getrlimit(RLIMIT_NOFILE, &r));
	pl("stdio");
	CHECK(getrlimit(RLIMIT_NOFILE, &r) == 0);
	setrlimit(RLIMIT_NOFILE, &r);
	_exit(0);
}

static void
t_prlimit_other(void)
{
	struct rlimit r;

	pl("stdio");
	syscall(VOW_NR_prlimit64, 1, RLIMIT_NOFILE, NULL, &r);
	_exit(0);
}

static void
t_tiocsti(void)
{
	char c = 'x';

	pl("stdio");
	ioctl(0, 0x5412, &c);
	_exit(0);
}

static void
t_setown(void)
{
	pl("stdio");
	fcntl(0, F_SETOWN, 1);
	_exit(0);
}

static void
t_x32(void)
{
	pl("stdio");
	syscall(VOW_X32_BIT | VOW_NR_getpid);
	_exit(0);
}

static long
int80(void)
{
	long r;

	__asm__ volatile ("int $0x80" : "=a" (r) : "a" (20L) : "memory");	/* i386 getpid */
	return r;
}

static void
t_int80(void)
{
	pid_t p = fork();
	int st;

	CHECK(p >= 0);
	if (p == 0)
		_exit(int80() > 0 ? 0 : 1);
	CHECK(waitpid(p, &st, 0) == p);
	if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0))
		SKIP("32-bit emulation is not available on this kernel");
	pl("stdio");
	int80();
	_exit(0);
}


/* ------------------------------------------------------------------ */
/* corrections after the milestone 2 review                           */
/* ------------------------------------------------------------------ */

extern void (*vow_test_window)(void);
extern unsigned vow_test_promises(void);

typedef long (*fn_long)(void);

/* data pointer to function pointer without a cast the standard forbids */
static long
call_at(void *m)
{
	fn_long f;

	memcpy(&f, &m, sizeof f);
	return f();
}

/* w^x is not enforced over time: write, flip to executable, run; flip back, rewrite, run again */
static void
t_wx_transitions(void)
{
	unsigned char *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	static const unsigned char c42[] = { 0xb8, 0x2a, 0, 0, 0, 0xc3 };	/* mov eax,42; ret */

	CHECK(m != MAP_FAILED);
	pl("stdio");
	memcpy(m, c42, sizeof c42);
	CHECK(mprotect(m, 4096, PROT_READ | PROT_EXEC) == 0);
	CHECK(call_at(m) == 42);
	CHECK(mprotect(m, 4096, PROT_READ | PROT_WRITE) == 0);
	m[1] = 43;
	CHECK(mprotect(m, 4096, PROT_EXEC) == 0);	/* execute only */
	CHECK(call_at(m) == 43);
	/* a fresh executable-only anonymous mapping is fine too (and empty) */
	{
		void *x = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		CHECK(x != MAP_FAILED);
	}
}

/* injected code runs, but under the same filter */
static void
t_injected_code(void)
{
	unsigned char *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	/* mov edi,2; mov esi,2; xor edx,edx; mov eax,41 (socket); syscall; ret */
	static const unsigned char sc[] = { 0xbf, 2, 0, 0, 0, 0xbe, 2, 0, 0, 0, 0x31, 0xd2,
	    0xb8, 0x29, 0, 0, 0, 0x0f, 0x05, 0xc3 };

	CHECK(m != MAP_FAILED);
	pl("stdio");
	memcpy(m, sc, sizeof sc);
	CHECK(mprotect(m, 4096, PROT_READ | PROT_EXEC) == 0);
	call_at(m);
	_exit(0);
}

static void
t_mprotect_wx_high_bits(void)
{
	void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	CHECK(m != MAP_FAILED);
	pl("stdio");
	/* the kernel would refuse this with EINVAL; the filter looks at the named bits only and kills */
	syscall(VOW_NR_mprotect, m, 4096ul, (unsigned long)(PROT_WRITE | PROT_EXEC) | (1ul << 32));
	_exit(0);
}

static void
t_mprotect_growsdown_wx(void)
{
	void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	CHECK(m != MAP_FAILED);
	pl("stdio");
	mprotect(m, 4096, PROT_WRITE | PROT_EXEC | 0x01000000 /* PROT_GROWSDOWN */);
	_exit(0);
}

/* nothing about a failed install is undone, and no_new_privs in particular stays set */
static void
t_failed_install_keeps_nnp(void)
{
	CHECK(prctl(39 /* PR_GET_NO_NEW_PRIVS */, 0, 0, 0, 0) == 0);
	vow_test_seccomp_nr = 9999;
	ERR(pledge("stdio", NULL), ENOSYS);
	vow_test_seccomp_nr = 0;
	CHECK(prctl(39, 0, 0, 0, 0) == 1);
	nothing_installed();
}

/*
 * the scope outlives a failed filter install and is entered only once: a retry loop that fails many
 * times does not stack a layer per try (a new layer each time would run into the limit of 16)
 */
static void
t_scope_entered_once_over_failed_installs(void)
{
	int i;

	for (i = 0; i < 20; i++) {
		vow_test_seccomp_nr = 9999;
		ERR(pledge("stdio", NULL), ENOSYS);
		vow_test_seccomp_nr = 0;
	}
	nothing_installed();
	/* the promise then takes effect: a call outside stdio kills (a child, because stdio has no fork) */
	if (fork() == 0) {
		OK(pledge("stdio", NULL));
		open("/dev/null", O_RDONLY);
		_exit(0);
	}
	{
		int st;

		CHECK(wait(&st) > 0 && WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
	}
}

/* a refused promise string changes nothing: not the state, not the filter */
static void
t_bad_promise_changes_nothing(void)
{
	ERR(pledge("stdio bogus", NULL), EINVAL);
	ERR(pledge("stdio dns", NULL), ENOTSUP);
	nothing_installed();
	OK(pledge("stdio rpath", NULL));
	ERR(pledge("stdio rpath wpath", NULL), EPERM);
	OK(pledge("stdio rpath", NULL));
}

static volatile int tc_stage;
static volatile long tc_tid;

static void *
conflicting_filter(void *arg)
{
	struct vow_insn all[1];
	struct vow_prog fp;

	(void)arg;
	all[0].code = VOW_BPF_RET | VOW_BPF_K;
	all[0].jt = all[0].jf = 0;
	all[0].k = VOW_SECCOMP_RET_ALLOW;
	fp.len = 1;
	fp.filter = all;
	tc_tid = syscall(VOW_NR_gettid);
	/* a filter on this thread only: it is not in the history of the main thread */
	if (prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
	    syscall(VOW_NR_seccomp, VOW_SECCOMP_SET_MODE_FILTER, 0, &fp) != 0)
		tc_stage = -1;
	else
		tc_stage = 1;
	while (tc_stage == 1)
		;
	return NULL;
}

/* tsync cannot be applied to a thread that has an unrelated filter: positive return, nothing installed */
static void
t_tsync_conflict(void)
{
	struct vow_insn all[1];
	struct vow_prog fp;
	pthread_t t;
	long r;

	pl("stdio rpath");	/* single threaded: the scope and the first filter. the conflict is about the next one */
	CHECK(pthread_create(&t, NULL, conflicting_filter, NULL) == 0);
	while (tc_stage == 0)
		;
	CHECK(tc_stage == 1);
	all[0].code = VOW_BPF_RET | VOW_BPF_K;
	all[0].jt = all[0].jf = 0;
	all[0].k = VOW_SECCOMP_RET_ALLOW;
	fp.len = 1;
	fp.filter = all;
	CHECK(prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	errno = 0;
	r = syscall(VOW_NR_seccomp, VOW_SECCOMP_SET_MODE_FILTER, VOW_SECCOMP_FILTER_FLAG_TSYNC, &fp);
	printf("    raw tsync with a conflicting thread returned %ld (that thread is %ld)\n", r, tc_tid);
	CHECK(r > 0 && r == tc_tid);
	/* vow turns the positive value into a failure and changes nothing */
	ERR(pledge("stdio", NULL), EBUSY);
	ERR(pledge("", NULL), EBUSY);
	CHECK(vow_test_promises() == (P_STDIO | P_RPATH));
	{
		int fd = open("/dev/null", O_RDONLY);	/* rpath is still in force: nothing was narrowed */

		CHECK(fd >= 0);
		close(fd);
	}
	/* once the conflicting thread is gone the same call works */
	tc_stage = 2;
	pthread_join(t, NULL);
	OK(pledge("stdio", NULL));
}

static void
spin_window(void)
{
	volatile int i;

	for (i = 0; i < 30000; i++)
		;
}

#define RACERS 6

static volatile int race_go, race_done, race_ready;
static volatile int race_rc[RACERS];

static void *
racer(void *arg)
{
	long i = (long)arg;
	int rc;

	/* thread start-up itself needs system calls: finish it before anything is pledged */
	__sync_fetch_and_add(&race_ready, 1);
	while (!race_go)
		;
	rc = pledge(i % 2 ? "" : "stdio", NULL);
	race_rc[i] = rc == 0 ? 0 : errno;
	__sync_fetch_and_add(&race_done, 1);
	/* no system call from here on: the filter may forbid all of them */
	for (;;)
		;
	return NULL;
}

struct racerep {
	volatile unsigned cur;
	volatile int rc[RACERS];
};

/* many threads change the promises at once; user space state and kernel state must tell one story */
static void
t_pledge_race(void)
{
	struct racerep *rep = mmap(NULL, sizeof *rep, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	int round, killed_empty = 0, alive_stdio = 0;

	CHECK(rep != MAP_FAILED);
	vow_test_window = spin_window;
	for (round = 0; round < 40; round++) {
		pid_t p;
		int st, i;

		rep->cur = 0xdead;
		fflush(NULL);
		p = fork();
		CHECK(p >= 0);
		if (p == 0) {
			pthread_t t[RACERS];

			alarm(20);
			if (pledge("stdio rpath", NULL) != 0)	/* single threaded, then the threads, then narrowing */
				_exit(3);
			race_go = race_done = race_ready = 0;
			for (i = 0; i < RACERS; i++)
				if (pthread_create(&t[i], NULL, racer, (void *)(long)i) != 0)
					_exit(2);
			while (race_ready < RACERS)
				;
			race_go = 1;
			while (race_done < RACERS)
				;
			rep->cur = vow_test_promises();
			for (i = 0; i < RACERS; i++)
				rep->rc[i] = race_rc[i];
			/* getpid is allowed by stdio and forbidden by the empty set: the kernel's own opinion */
			(void)getpid();
			_exit(0);
		}
		CHECK(waitpid(p, &st, 0) == p);
		if (!(rep->cur == 0 || rep->cur == P_STDIO))
			fprintf(stderr, "    round %d: child status 0x%x, cur 0x%x\n", round, st, rep->cur);
		CHECK(rep->cur == 0 || rep->cur == P_STDIO);	/* anything else: state corrupt or never got there */
		if (rep->cur == 0) {
			CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
			killed_empty++;
		} else {
			CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
			alive_stdio++;
		}
		for (i = 0; i < RACERS; i++) {
			if (i % 2)
				CHECK(rep->rc[i] == 0);	/* the empty set always works */
			else
				CHECK(rep->rc[i] == 0 || rep->rc[i] == EPERM);
		}
	}
	printf("    40 rounds: kernel and library agreed each time (%d ended empty, %d stayed stdio)\n",
	    killed_empty, alive_stdio);
	/* the empty set is requested by half of the racers, so it must have won every round */
	CHECK(killed_empty == 40);
}


/* ------------------------------------------------------------------ */
/* milestone 3: opening files                                         */
/* ------------------------------------------------------------------ */

static long
fsize(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 ? (long)st.st_size : -1;
}

static int
count_entries(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	int n = 0;

	if (d == NULL)
		return -1;
	while ((e = readdir(d)) != NULL)
		if (e->d_name[0] != '.')
			n++;
	closedir(d);
	return n;
}

/*
 * what the bare kernel really does with the flags the policy classifies. no filter, no landlock:
 * if a kernel ever behaves differently the matrix in DESIGN.md is wrong and this fails first.
 */
static void
t_kernel_open_truths(void)
{
	char d[8192];
	int fd, before;

	snprintf(d, sizeof d, "%s/truths", root);
	OK(mkdir(d, 0700));
	mkfile(tp("truths/f"), "some content\n", 0600);

	/* O_RDONLY|O_TRUNC empties the file: a read-only open can write */
	fd = open(tp("truths/f"), O_RDONLY | O_TRUNC);
	CHECK(fd >= 0);
	close(fd);
	CHECK(fsize(tp("truths/f")) == 0);

	/* O_PATH drops every other flag: nothing is truncated, nothing is created */
	mkfile(tp("truths/g"), "keep me\n", 0600);
	fd = open(tp("truths/g"), O_PATH | O_WRONLY | O_CREAT | O_TRUNC);
	CHECK(fd >= 0);
	close(fd);
	CHECK(fsize(tp("truths/g")) == 8);
	errno = 0;
	CHECK(open(tp("truths/absent"), O_PATH | O_WRONLY | O_CREAT | O_TRUNC) == -1 && errno == ENOENT);
	CHECK(fsize(tp("truths/absent")) == -1);
	fd = (int)syscall(VOW_NR_openat, -100, tp("truths/g"), O_PATH | O_RDWR | O_CREAT | O_TRUNC, 0);
	CHECK(fd >= 0);
	close(fd);
	CHECK(fsize(tp("truths/g")) == 8);

	/* O_CREAT with a read-only mode still creates; O_EXCL without O_CREAT creates nothing */
	fd = open(tp("truths/c"), O_RDONLY | O_CREAT, 0600);
	CHECK(fd >= 0);
	close(fd);
	CHECK(fsize(tp("truths/c")) == 0);
	errno = 0;
	CHECK(open(tp("truths/never"), O_RDONLY | O_EXCL) == -1 && errno == ENOENT);
	CHECK(fsize(tp("truths/never")) == -1);

	/* unknown flag bits are ignored by open and openat */
	fd = open(tp("truths/g"), O_RDONLY | 0x80000000u | 0x40000000u);
	CHECK(fd >= 0);
	close(fd);

	/* access mode 3 is checked as read plus write permission */
	if (geteuid() != 0) {
		mkfile(tp("truths/wo"), "x", 0200);
		mkfile(tp("truths/ro"), "x", 0400);
		mkfile(tp("truths/rw"), "x", 0600);
		errno = 0;
		CHECK(open(tp("truths/wo"), 3) == -1 && errno == EACCES);
		errno = 0;
		CHECK(open(tp("truths/ro"), 3) == -1 && errno == EACCES);
		fd = open(tp("truths/rw"), 3);
		CHECK(fd >= 0);
		close(fd);
	}

	/* O_TMPFILE: needs a write mode, O_DIRECTORY and no O_CREAT, and leaves no name behind */
	before = count_entries(d);
	errno = 0;
	CHECK(open(d, O_TMPFILE | O_RDONLY) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(open(d, 0x400000 | O_WRONLY) == -1 && errno == EINVAL);
	errno = 0;
	CHECK(open(d, O_TMPFILE | O_CREAT | O_WRONLY, 0600) == -1 && errno == EINVAL);
	fd = open(d, O_TMPFILE | O_WRONLY, 0600);
	if (fd < 0 && (errno == EOPNOTSUPP || errno == EISDIR))
		SKIP("filesystem without O_TMPFILE");
	CHECK(fd >= 0);
	CHECK(write(fd, "x", 1) == 1);
	close(fd);
	CHECK(count_entries(d) == before);
}

/* ------------------------------------------------------------------ */
/* behavior under pledge("stdio rpath")                               */
/* ------------------------------------------------------------------ */

static void
t_rpath_works(void)
{
	char buf[256], d[8192];
	struct stat st;
	struct statfs sf;
	DIR *dir;
	FILE *fp;
	int fd, dfd2, n = 0;
	struct dirent *e;

	snprintf(d, sizeof d, "%s/rp", root);
	OK(mkdir(d, 0700));
	mkfile(tp("rp/file"), "hello rpath\n", 0600);
	OK(symlink("file", tp("rp/link")));
	OK(mkdir(tp("rp/sub"), 0700));
	pl("stdio rpath");

	fd = open(tp("rp/file"), O_RDONLY);
	CHECK(fd >= 0 && read(fd, buf, sizeof buf) == 12);
	close(fd);
	fp = fopen(tp("rp/file"), "r");
	CHECK(fp != NULL && fgets(buf, sizeof buf, fp) != NULL && strcmp(buf, "hello rpath\n") == 0);
	fclose(fp);
	dfd2 = open(d, O_RDONLY | O_DIRECTORY);
	CHECK(dfd2 >= 0);
	fd = openat(dfd2, "file", O_RDONLY | O_CLOEXEC);
	CHECK(fd >= 0);
	close(fd);
	dir = opendir(d);
	CHECK(dir != NULL);
	while ((e = readdir(dir)) != NULL)
		if (e->d_name[0] != '.')
			n++;
	closedir(dir);
	CHECK(n == 3);
	CHECK(stat(tp("rp/file"), &st) == 0 && st.st_size == 12);
	CHECK(lstat(tp("rp/link"), &st) == 0 && S_ISLNK(st.st_mode));
	CHECK(fstatat(dfd2, "file", &st, 0) == 0);
	CHECK(syscall(VOW_NR_statx, dfd2, "file", 0, 0xfff, buf) == 0);
	CHECK(access(tp("rp/file"), R_OK) == 0);
	CHECK(syscall(VOW_NR_faccessat2, dfd2, "file", R_OK, 0) == 0);
	CHECK(readlink(tp("rp/link"), buf, sizeof buf) == 4);
	CHECK(statfs(d, &sf) == 0);
	CHECK(getcwd(buf, sizeof buf) != NULL);
	CHECK(chdir(d) == 0 && fchdir(dfd2) == 0);
	/* a descriptor that looks a path up only: usable as a base and for fstat */
	fd = open(tp("rp/file"), O_PATH);
	CHECK(fd >= 0 && fstat(fd, &st) == 0 && st.st_size == 12);
	close(fd);
	/* O_PATH with write and truncate flags: the kernel drops them, so does the policy's view */
	fd = open(tp("rp/file"), O_PATH | O_WRONLY | O_CREAT | O_TRUNC);
	CHECK(fd >= 0);
	close(fd);
	CHECK(stat(tp("rp/file"), &st) == 0 && st.st_size == 12);
	/* openat2 is answered by policy, with a name the caller can see */
	errno = 0;
	CHECK(syscall(VOW_NR_openat2, dfd2, "file", buf, 24) == -1 && errno == ENOSYS);
	/* rpath leaves visible what unveil does not hide: a path outside any rule can still be probed */
	CHECK(stat("/", &st) == 0);
}

#define KILLTEST(name, stmt) \
static void \
name(void) \
{ \
	mkfile(tp("k_" #name), "x", 0600); \
	pl("stdio rpath"); \
	stmt; \
	_exit(0); \
}

KILLTEST(k_wronly, (void)open(tp("k_k_wronly"), O_WRONLY))
KILLTEST(k_rdwr, (void)open(tp("k_k_rdwr"), O_RDWR))
KILLTEST(k_mode3, (void)open(tp("k_k_mode3"), 3))
KILLTEST(k_creat_rd, (void)open(tp("k_k_creat_rd"), O_RDONLY | O_CREAT, 0600))
KILLTEST(k_trunc_rd, (void)open(tp("k_k_trunc_rd"), O_RDONLY | O_TRUNC))
KILLTEST(k_tmpfile, (void)open(root, O_TMPFILE | O_WRONLY, 0600))
KILLTEST(k_creat_call, (void)creat(tp("k_k_creat_call"), 0600))
KILLTEST(k_openat_wr, (void)openat(AT_FDCWD, tp("k_k_openat_wr"), O_WRONLY))
KILLTEST(k_junk_wr, syscall(VOW_NR_open, tp("k_k_junk_wr"), (unsigned long)O_WRONLY | (7ul << 32), 0))
KILLTEST(k_unlink, (void)unlink(tp("k_k_unlink")))
KILLTEST(k_mkdir, (void)mkdir(tp("k_k_mkdir"), 0700))
KILLTEST(k_rename, (void)rename(tp("k_k_rename"), tp("k_k_rename2")))
KILLTEST(k_truncate, (void)truncate(tp("k_k_truncate"), 0))
KILLTEST(k_chmod, (void)chmod(tp("k_k_chmod"), 0600))
KILLTEST(k_socket, (void)socket(AF_INET, SOCK_STREAM, 0))

/* without rpath nothing of this works, even though stdio is there */
static void
t_stdio_only_stat(void)
{
	struct stat st;

	pl("stdio");
	(void)stat("/", &st);
	_exit(0);
}

/* ---- landlock and seccomp together ---- */

static void
t_unveil_then_rpath(void)
{
	char buf[64];
	int fd;

	OK(mkdir(tp("ur"), 0700));
	OK(mkdir(tp("ur/in"), 0700));
	OK(mkdir(tp("ur/out"), 0700));
	mkfile(tp("ur/in/f"), "inside\n", 0600);
	mkfile(tp("ur/out/f"), "outside\n", 0600);
	OK(unveil(tp("ur/in"), "r"));
	OK(unveil(NULL, NULL));
	pl("stdio rpath");
	fd = open(tp("ur/in/f"), O_RDONLY);
	CHECK(fd >= 0 && read(fd, buf, sizeof buf) == 7);
	/* landlock says no with an error; seccomp has no opinion on a read-only open */
	errno = 0;
	CHECK(open(tp("ur/out/f"), O_RDONLY) == -1 && errno == EACCES);
	/* the documented gap: lookups of hidden paths are still possible */
	{
		struct stat st;

		CHECK(stat(tp("ur/out/f"), &st) == 0);
		fd = open(tp("ur/out/f"), O_PATH);
		CHECK(fd >= 0);
	}
}

/* unveil grants write here, but the pledge does not have wpath: seccomp is the stricter one */
static void
t_unveil_write_pledge_read(void)
{
	OK(mkdir(tp("uw"), 0700));
	mkfile(tp("uw/f"), "x", 0600);
	OK(unveil(tp("uw"), "rw"));
	OK(unveil(NULL, NULL));
	pl("stdio rpath");
	(void)open(tp("uw/f"), O_WRONLY);
	_exit(0);
}

/* pledge first with rpath, then unveil still works: the library's own lookups are inside rpath */
static void
t_rpath_then_unveil(void)
{
	char buf[64];
	int fd;

	OK(mkdir(tp("ru"), 0700));
	OK(mkdir(tp("ru/in"), 0700));
	OK(mkdir(tp("ru/out"), 0700));
	mkfile(tp("ru/in/f"), "inside\n", 0600);
	mkfile(tp("ru/out/f"), "outside\n", 0600);
	pl("stdio rpath");
	OK(unveil(tp("ru/in"), "r"));
	OK(unveil(NULL, NULL));
	fd = open(tp("ru/in/f"), O_RDONLY);
	CHECK(fd >= 0 && read(fd, buf, sizeof buf) == 7);
	errno = 0;
	CHECK(open(tp("ru/out/f"), O_RDONLY) == -1 && errno == EACCES);
	/* once unveil is sealed it stays sealed */
	ERR(unveil(tp("ru/out"), "r"), EPERM);
	/* narrowing the pledge afterwards locks unveil by definition, and it already is */
	pl("stdio");
	ERR(unveil(NULL, NULL), EPERM);
}

static void
t_rpath_unveil_denied_path_kills_nothing(void)
{
	struct stat st;

	OK(mkdir(tp("ud"), 0700));
	mkfile(tp("ud/f"), "x", 0600);
	pl("stdio rpath");
	OK(unveil(tp("ud"), "r"));
	OK(unveil(NULL, NULL));
	errno = 0;
	CHECK(open("/etc/passwd", O_RDONLY) == -1 && errno == EACCES);
	CHECK(stat("/etc/passwd", &st) == 0);	/* metadata is not covered by landlock */
}


/* ------------------------------------------------------------------ */
/* milestone 3, second part: wpath and cpath                          */
/* ------------------------------------------------------------------ */

static char P[8192];

static const char *
pp(const char *name)
{
	static char buf[4][8192];
	static int i;
	char *b = buf[i++ & 3];

	snprintf(b, sizeof buf[0], "%s/%s", P, name);
	return b;
}

/* a fresh directory with a few files in it: f, g, d/, e/inner */
static void
pdir(const char *name)
{
	snprintf(P, sizeof P, "%s/%s", root, name);
	if (mkdir(P, 0700) != 0)
		_exit(2);
	mkfile(pp("f"), "abc\n", 0600);
	mkfile(pp("g"), "xyz\n", 0600);
	if (mkdir(pp("d"), 0700) != 0 || mkdir(pp("e"), 0700) != 0)
		_exit(2);
	mkfile(pp("e/inner"), "i", 0600);
}

/* ---- wpath alone ---- */

static void
t_wpath_works(void)
{
	int fd;

	pdir("wp1");
	pl("stdio wpath");
	fd = open(pp("f"), O_WRONLY | O_TRUNC);
	CHECK(fd >= 0 && write(fd, "hello\n", 6) == 6);
	CHECK(ftruncate(fd, 3) == 0);
	CHECK(posix_fallocate(fd, 0, 100) == 0);
	CHECK(fsync(fd) == 0);
	close(fd);
	fd = open(pp("f"), O_WRONLY | O_APPEND);
	CHECK(fd >= 0 && write(fd, "x", 1) == 1);
	close(fd);
	CHECK(truncate(pp("g"), 1) == 0);
	/* the file really changed, seen from outside the pledge */
}

#define PKILL(name, prom, setup, stmt) \
static void \
name(void) \
{ \
	pdir(#name); \
	setup; \
	pl(prom); \
	stmt; \
	_exit(0); \
}

PKILL(w_rdonly, "stdio wpath", (void)0, (void)open(pp("f"), O_RDONLY))
PKILL(w_rdwr, "stdio wpath", (void)0, (void)open(pp("f"), O_RDWR))
PKILL(w_creat, "stdio wpath", (void)0, (void)open(pp("new"), O_WRONLY | O_CREAT, 0600))
PKILL(w_creat_call, "stdio wpath", (void)0, (void)creat(pp("new"), 0600))
PKILL(w_mkdir, "stdio wpath", (void)0, (void)mkdir(pp("new"), 0700))
PKILL(w_unlink, "stdio wpath", (void)0, (void)unlink(pp("f")))
PKILL(w_rename, "stdio wpath", (void)0, (void)rename(pp("f"), pp("h")))
PKILL(w_stat, "stdio wpath", (void)0, { struct stat st; (void)stat(pp("f"), &st); })
PKILL(w_opath, "stdio wpath", (void)0, (void)open(pp("f"), O_PATH))
PKILL(w_tmpfile, "stdio wpath", (void)0, (void)open(P, O_TMPFILE | O_WRONLY, 0600))
PKILL(w_symlink, "stdio wpath", (void)0, (void)symlink("f", pp("sl")))

/* ---- cpath alone ---- */

static void
t_cpath_works(void)
{
	int dfd;
	char target[16];

	pdir("cp1");
	dfd = open(P, O_RDONLY | O_DIRECTORY);	/* a descriptor from before the pledge, for the *at calls */
	CHECK(dfd >= 0);
	pl("stdio cpath");
	CHECK(mkdir(pp("new"), 0700) == 0);
	CHECK(rmdir(pp("new")) == 0);
	CHECK(unlink(pp("f")) == 0);
	CHECK(rename(pp("g"), pp("g2")) == 0);
	CHECK(link(pp("g2"), pp("g3")) == 0);
	CHECK(symlink("g2", pp("sl")) == 0);
	CHECK(unlink(pp("sl")) == 0);
	CHECK(mkdirat(dfd, "x", 0700) == 0);
	CHECK(unlinkat(dfd, "x", AT_REMOVEDIR) == 0);
	CHECK(renameat(dfd, "g3", dfd, "g4") == 0);
	CHECK(syscall(VOW_NR_renameat2, dfd, "g4", dfd, "g5", 1) == 0);	/* RENAME_NOREPLACE */
	CHECK(syscall(VOW_NR_renameat2, dfd, "g5", dfd, "g2", 2) == 0);	/* RENAME_EXCHANGE */
	CHECK(symlinkat("t", dfd, "ls") == 0);
	CHECK(linkat(dfd, "g2", dfd, "g6", 0) == 0);
	CHECK(linkat(dfd, "g2", dfd, "g7", AT_SYMLINK_FOLLOW) == 0);
	CHECK(unlinkat(dfd, "ls", 0) == 0);
	CHECK(unlinkat(dfd, "g6", 0) == 0);
	(void)target;
}

PKILL(c_rdonly, "stdio cpath", (void)0, (void)open(pp("f"), O_RDONLY))
PKILL(c_wronly, "stdio cpath", (void)0, (void)open(pp("f"), O_WRONLY))
PKILL(c_creat_wr, "stdio cpath", (void)0, (void)open(pp("new"), O_WRONLY | O_CREAT, 0600))
PKILL(c_creat_rd, "stdio cpath", (void)0, (void)open(pp("new"), O_RDONLY | O_CREAT, 0600))
PKILL(c_creat_call, "stdio cpath", (void)0, (void)creat(pp("new"), 0600))
PKILL(c_truncate, "stdio cpath", (void)0, (void)truncate(pp("f"), 0))
PKILL(c_stat, "stdio cpath", (void)0, { struct stat st; (void)stat(pp("f"), &st); })
PKILL(c_mkfifo, "stdio cpath", (void)0, (void)mkfifo(pp("ff"), 0600))
PKILL(c_whiteout, "stdio cpath", (void)0, (void)syscall(VOW_NR_renameat2, AT_FDCWD, pp("f"), AT_FDCWD, pp("h"), VOW_RENAME_WHITEOUT))
PKILL(c_whiteout_junk, "stdio cpath", (void)0, (void)syscall(VOW_NR_renameat2, AT_FDCWD, pp("f"), AT_FDCWD, pp("h"), (unsigned long)VOW_RENAME_WHITEOUT | (3ul << 32)))
PKILL(c_empty_path, "stdio cpath", (void)0, (void)syscall(VOW_NR_linkat, AT_FDCWD, "", AT_FDCWD, pp("h"), VOW_AT_EMPTY_PATH))
PKILL(c_empty_path_junk, "stdio cpath", (void)0, (void)syscall(VOW_NR_linkat, AT_FDCWD, "", AT_FDCWD, pp("h"), (unsigned long)VOW_AT_EMPTY_PATH | (3ul << 32)))
PKILL(c_chmod, "stdio cpath", (void)0, (void)chmod(pp("f"), 0600))
PKILL(c_exec, "stdio cpath", (void)0, (void)execl("/bin/true", "true", (char *)NULL))

/* ---- combinations ---- */

static void
t_rpath_cpath(void)
{
	int fd;
	char buf[8];

	pdir("rc1");
	pl("stdio rpath cpath");
	/* create and read, no write */
	fd = open(pp("new"), O_RDONLY | O_CREAT | O_EXCL, 0600);
	CHECK(fd >= 0 && read(fd, buf, sizeof buf) == 0);
	close(fd);
	CHECK(unlink(pp("new")) == 0);
	fd = open(pp("f"), O_RDONLY);
	CHECK(fd >= 0 && read(fd, buf, sizeof buf) == 4);
}

PKILL(rc_wr, "stdio rpath cpath", (void)0, (void)open(pp("new"), O_WRONLY | O_CREAT, 0600))
PKILL(rc_trunc, "stdio rpath cpath", (void)0, (void)open(pp("f"), O_RDONLY | O_TRUNC))
PKILL(rc_creat_trunc, "stdio rpath cpath", (void)0, (void)open(pp("new"), O_RDONLY | O_CREAT | O_TRUNC, 0600))

static void
t_wpath_cpath(void)
{
	int fd;

	pdir("wc1");
	pl("stdio wpath cpath");
	fd = open(pp("new"), O_WRONLY | O_CREAT | O_EXCL, 0600);
	CHECK(fd >= 0 && write(fd, "w", 1) == 1);
	close(fd);
	fd = creat(pp("new2"), 0600);
	CHECK(fd >= 0);
	close(fd);
	fd = open(P, O_TMPFILE | O_WRONLY, 0600);
	CHECK(fd >= 0 || errno == EOPNOTSUPP || errno == EISDIR);
	if (fd >= 0)
		close(fd);
	CHECK(truncate(pp("f"), 0) == 0);
}

PKILL(wc_rdwr_creat, "stdio wpath cpath", (void)0, (void)open(pp("new"), O_RDWR | O_CREAT, 0600))
PKILL(wc_rdonly, "stdio wpath cpath", (void)0, (void)open(pp("f"), O_RDONLY))
PKILL(wc_stat, "stdio wpath cpath", (void)0, { struct stat st; (void)stat(pp("f"), &st); })

static void
t_rpath_wpath(void)
{
	int fd;
	char buf[8];

	pdir("rw1");
	pl("stdio rpath wpath");
	fd = open(pp("f"), O_RDWR);
	CHECK(fd >= 0 && read(fd, buf, sizeof buf) == 4 && lseek(fd, 0, SEEK_SET) == 0 && write(fd, "Q", 1) == 1);
	close(fd);
	fd = open(pp("f"), O_RDONLY | O_TRUNC);	/* truncating through a read-only open needs wpath, which is here */
	CHECK(fd >= 0);
	close(fd);
	CHECK(truncate(pp("g"), 0) == 0);
}

PKILL(rw_creat, "stdio rpath wpath", (void)0, (void)open(pp("new"), O_RDWR | O_CREAT, 0600))
PKILL(rw_mkdir, "stdio rpath wpath", (void)0, (void)mkdir(pp("new"), 0700))
PKILL(rw_unlink, "stdio rpath wpath", (void)0, (void)unlink(pp("f")))
PKILL(rw_tmpfile, "stdio rpath wpath", (void)0, (void)open(P, O_TMPFILE | O_RDWR, 0600))

static void
t_all_three(void)
{
	int fd;
	char buf[16];
	char proc[64];

	pdir("rwc1");
	pl("stdio rpath wpath cpath");
	fd = open(pp("new"), O_RDWR | O_CREAT | O_EXCL, 0600);
	CHECK(fd >= 0 && write(fd, "data\\n", 5) == 5 && lseek(fd, 0, SEEK_SET) == 0 && read(fd, buf, sizeof buf) == 5);
	CHECK(ftruncate(fd, 2) == 0);
	close(fd);
	CHECK(rename(pp("new"), pp("moved")) == 0);
	CHECK(link(pp("moved"), pp("hard")) == 0);
	CHECK(symlink("moved", pp("soft")) == 0);
	CHECK(readlink(pp("soft"), buf, sizeof buf) == 5);
	CHECK(unlink(pp("soft")) == 0 && unlink(pp("hard")) == 0 && unlink(pp("moved")) == 0);
	CHECK(mkdir(pp("dir"), 0700) == 0 && rmdir(pp("dir")) == 0);
	/* an unnamed file made visible through /proc, the usual use of O_TMPFILE */
	fd = open(P, O_TMPFILE | O_RDWR, 0600);
	if (fd >= 0) {
		snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
		if (access(proc, F_OK) == 0) {
			CHECK(write(fd, "t", 1) == 1);
			CHECK(linkat(AT_FDCWD, proc, AT_FDCWD, pp("published"), AT_SYMLINK_FOLLOW) == 0);
			CHECK(access(pp("published"), F_OK) == 0);
		}
		close(fd);
	}
}

PKILL(a_mkfifo, "stdio rpath wpath cpath", (void)0, (void)mkfifo(pp("ff"), 0600))
PKILL(a_whiteout, "stdio rpath wpath cpath", (void)0, (void)syscall(VOW_NR_renameat2, AT_FDCWD, pp("f"), AT_FDCWD, pp("h"), VOW_RENAME_WHITEOUT))
PKILL(a_empty_path, "stdio rpath wpath cpath", (void)0, (void)syscall(VOW_NR_linkat, AT_FDCWD, "", AT_FDCWD, pp("h"), VOW_AT_EMPTY_PATH))
PKILL(a_chmod, "stdio rpath wpath cpath", (void)0, (void)chmod(pp("f"), 0600))
PKILL(a_utimens, "stdio rpath wpath cpath", (void)0, (void)syscall(280, AT_FDCWD, pp("f"), NULL, 0))
PKILL(a_setxattr, "stdio rpath wpath cpath", (void)0, (void)syscall(188, pp("f"), "user.x", "v", 1, 0))
PKILL(a_exec, "stdio rpath wpath cpath", (void)0, (void)execl("/bin/true", "true", (char *)NULL))
PKILL(a_socket, "stdio rpath wpath cpath", (void)0, (void)socket(AF_INET, SOCK_STREAM, 0))
PKILL(a_mount, "stdio rpath wpath cpath", (void)0, (void)syscall(165, "none", pp("d"), "tmpfs", 0, NULL))

/* ---- with unveil: landlock says no with an error, seccomp kills ---- */

static void
u_setup(const char *name)
{
	char in[8192];

	snprintf(P, sizeof P, "%s/%s", root, name);
	if (mkdir(P, 0700) != 0)
		_exit(2);
	snprintf(in, sizeof in, "%s/in", P);
	if (mkdir(in, 0700) != 0 || mkdir(pp("out"), 0700) != 0)
		_exit(2);
	mkfile(pp("in/f"), "inside\n", 0600);
	mkfile(pp("in/g"), "inside\n", 0600);
	mkfile(pp("out/f"), "outside\n", 0600);
	mkfile(pp("out/g"), "outside\n", 0600);
	if (mkdir(pp("in/d"), 0700) != 0 || mkdir(pp("out/d"), 0700) != 0)
		_exit(2);
}

/* seccomp would allow all of it; unveil grants read and write but not create */
static void
t_unveil_rw_all_promises(void)
{
	int fd;

	u_setup("uv1");
	OK(unveil(pp("in"), "rw"));
	OK(unveil(NULL, NULL));
	pl("stdio rpath wpath cpath");
	fd = open(pp("in/f"), O_WRONLY | O_TRUNC);
	CHECK(fd >= 0);
	close(fd);
	CHECK(truncate(pp("in/g"), 0) == 0);
	errno = 0;
	CHECK(open(pp("in/new"), O_WRONLY | O_CREAT, 0600) == -1 && errno == EACCES);
	ERR(mkdir(pp("in/nd"), 0700), EACCES);
	ERR(unlink(pp("in/f")), EACCES);
	ERR(rename(pp("in/f"), pp("in/h")), EACCES);
	ERR(symlink("f", pp("in/sl")), EACCES);
	ERR(link(pp("in/f"), pp("in/hl")), EACCES);
	/* and nothing outside */
	errno = 0;
	CHECK(open(pp("out/f"), O_WRONLY) == -1 && errno == EACCES);
	ERR(truncate(pp("out/g"), 0), EACCES);
}

static void
t_unveil_rwc_all_promises(void)
{
	int fd;

	u_setup("uv2");
	OK(unveil(pp("in"), "rwc"));
	OK(unveil(NULL, NULL));
	pl("stdio rpath wpath cpath");
	fd = open(pp("in/new"), O_RDWR | O_CREAT | O_EXCL, 0600);
	CHECK(fd >= 0);
	close(fd);
	CHECK(mkdir(pp("in/nd"), 0700) == 0 && rmdir(pp("in/nd")) == 0);
	CHECK(rename(pp("in/new"), pp("in/new2")) == 0);
	CHECK(symlink("f", pp("in/sl")) == 0);
	CHECK(link(pp("in/f"), pp("in/hl")) == 0);
	CHECK(unlink(pp("in/hl")) == 0);
	/* outside the rule landlock refuses every one of them */
	ERR(mkdir(pp("out/nd"), 0700), EACCES);
	ERR(unlink(pp("out/f")), EACCES);
	ERR(rmdir(pp("out/d")), EACCES);
	ERR(symlink("f", pp("out/sl")), EACCES);
	ERR(truncate(pp("out/g"), 0), EACCES);
	errno = 0;
	CHECK(open(pp("out/new"), O_WRONLY | O_CREAT, 0600) == -1 && errno == EACCES);
	/* moving across the boundary, either way, and linking across it */
	CHECK(rename(pp("in/f"), pp("out/moved")) == -1 && (errno == EACCES || errno == EXDEV));
	CHECK(rename(pp("out/f"), pp("in/moved")) == -1 && (errno == EACCES || errno == EXDEV));
	CHECK(link(pp("out/f"), pp("in/hl2")) == -1 && (errno == EACCES || errno == EXDEV));
	CHECK(link(pp("in/f"), pp("out/hl3")) == -1 && (errno == EACCES || errno == EXDEV));
}

static void
u_write_seccomp_wins(void)
{
	u_setup("uv3");
	OK(unveil(pp("in"), "rwc"));
	OK(unveil(NULL, NULL));
	pl("stdio rpath");
	(void)open(pp("in/f"), O_WRONLY);
	_exit(0);
}

static void
u_mkdir_seccomp_wins(void)
{
	u_setup("uv4");
	OK(unveil(pp("in"), "rwc"));
	OK(unveil(NULL, NULL));
	pl("stdio rpath wpath");
	(void)mkdir(pp("in/nd"), 0700);
	_exit(0);
}

static void
t_unveil_after_pledge_paths(void)
{
	u_setup("uv5");
	pl("stdio rpath wpath cpath");
	OK(unveil(pp("in"), "rwc"));
	OK(unveil(NULL, NULL));
	CHECK(mkdir(pp("in/nd"), 0700) == 0);
	ERR(mkdir(pp("out/nd"), 0700), EACCES);
}



/* ------------------------------------------------------------------ */
/* fork, signal handlers, descriptors                                 */
/* ------------------------------------------------------------------ */

/*
 * v0.1 has no way to fork under a pledge (clone without CLONE_THREAD is a violation), so the
 * tests that need a forked child of a pledged process add two rules to every set through
 * the test hook: fork's clone (flags exactly SIGCHLD) and wait4. the rest is the real
 * pledge() and the real filter, with the pid it captured.
 */
static const struct vow_rule x_rules[] = {
	{ 57 /* fork: musl calls it directly on x86-64 */, 0, 0, NULL },
	{ 61 /* wait4 */, 0, 0, NULL },
};

static void
enable_fork(void)
{
	vow_test_extra.r = x_rules;
	vow_test_extra.n = sizeof x_rules / sizeof *x_rules;
}


/* run fn in a child; return its wait status */
static int
child_status(void (*fn)(void))
{
	pid_t p;
	int st = -1;

	fflush(NULL);
	p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		fn();
		_exit(0);
	}
	CHECK(waitpid(p, &st, 0) == p);
	return st;
}

#define EXPECT_EXIT0(fn) CHECK(child_status(fn) == 0)
#define EXPECT_SIG(fn, sig) do { int st_ = child_status(fn); CHECK(WIFSIGNALED(st_) && WTERMSIG(st_) == (sig)); } while (0)

static int
try_open_dir(const char *path)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY);

	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}



/* a forked child of a pledged process: filter, state and the captured pid, all inherited */


/* ---- signal handlers calling back in ---- */

static volatile int re_rc, re_errno, re_done;

static void
re_handler(int sig)
{
	(void)sig;
	errno = 0;
	re_rc = pledge("stdio", NULL);
	re_errno = errno;
	re_done++;
}

static void
re_handler_unveil(int sig)
{
	(void)sig;
	errno = 0;
	re_rc = unveil("/", "r");
	re_errno = errno;
	re_done++;
}

static void
re_window(void)
{
	vow_test_window = NULL;
	raise(SIGUSR1);	/* delivered to this very thread, inside the critical region */
}

static void
t_reentrant_pledge(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = re_handler;
	OK(sigaction(SIGUSR1, &sa, NULL));
	alarm(5);
	vow_test_window = re_window;
	OK(pledge("stdio", NULL));
	/* the handler ran inside, found the library busy and said so instead of waiting for itself */
	CHECK(re_done == 1 && re_rc == -1 && re_errno == EDEADLK);
	CHECK(vow_test_promises() == P_STDIO);
}

static void
t_reentrant_pledge_into_unveil(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = re_handler_unveil;
	OK(sigaction(SIGUSR1, &sa, NULL));
	alarm(5);
	vow_test_window = re_window;
	OK(pledge("stdio", NULL));
	CHECK(re_done == 1 && re_rc == -1 && re_errno == EDEADLK);
}

static void
t_reentrant_unveil(void)
{
	struct sigaction sa;

	pdir("re3");
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = re_handler_unveil;
	OK(sigaction(SIGUSR1, &sa, NULL));
	alarm(5);
	vow_test_window = re_window;
	OK(unveil(pp("d"), "r"));
	CHECK(re_done == 1 && re_rc == -1 && re_errno == EDEADLK);
	/* the interrupted call finished normally */
	OK(unveil(NULL, NULL));
	CHECK(try_open_dir(pp("d")) == 0);
}

/* ---- fork while another thread is inside a call ---- */

static volatile int win_in;

static void
slow_window(void)
{
	volatile long i;

	win_in = 1;
	for (i = 0; i < 30000000; i++)
		;
}

static char *atfork_dir;

static void *
unveil_in_thread(void *arg)
{
	(void)arg;
	(void)unveil(atfork_dir, "r");
	return NULL;
}

static void
t_atfork_unveil(void)
{
	pthread_t t;
	pid_t p;
	int st;

	pdir("af1");
	atfork_dir = (char *)pp("d");
	atfork_dir = strdup(atfork_dir);
	vow_test_window = slow_window;
	CHECK(pthread_create(&t, NULL, unveil_in_thread, NULL) == 0);
	while (!win_in)
		;
	/* the other thread is inside unveil(), holding the lock: fork waits for it to finish */
	p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		alarm(10);	/* a child that waits for a lock nobody can release must not live on */
		vow_test_window = NULL;
		if (unveil(NULL, NULL) != 0)
			_exit(1);
		if (try_open_dir(atfork_dir) != 0)	/* the rule the other thread was adding is there */
			_exit(2);
		if (try_open_dir(root) != EACCES)
			_exit(3);
		_exit(0);
	}
	CHECK(waitpid(p, &st, 0) == p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	pthread_join(t, NULL);
}

static void *
pledge_in_thread(void *arg)
{
	(void)arg;
	vow_test_seccomp_nr = 9999;	/* the install fails: no filter lands, the lock was still held */
	(void)pledge("stdio", NULL);
	vow_test_seccomp_nr = 0;
	return NULL;
}

static void
t_atfork_pledge(void)
{
	pthread_t t;
	pid_t p;
	int st;

	vow_test_window = slow_window;
	CHECK(pthread_create(&t, NULL, pledge_in_thread, NULL) == 0);
	while (!win_in)
		;
	p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		alarm(10);
		vow_test_window = NULL;
		vow_test_seccomp_nr = 0;
		if (pledge("stdio", NULL) != 0)
			_exit(1);
		_exit(0);
	}
	CHECK(waitpid(p, &st, 0) == p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
	pthread_join(t, NULL);
}

/* ---- descriptors and what they let a process do ---- */

/*
 * what unveil does and does not compensate for, observed: descriptors from before the sandbox
 * and the *at calls. every line is an observation of linux 7.2.9 that the document relies on.
 */
static void
t_descriptor_exposure(void)
{
	int outdir, outfile, outfd_rw;
	char proc[64];
	int r;

	u_setup("dx1");
	outdir = open(pp("out"), O_PATH | O_DIRECTORY);
	outfile = open(pp("out/f"), O_PATH);
	outfd_rw = open(pp("out/g"), O_RDWR);
	CHECK(outdir >= 0 && outfile >= 0 && outfd_rw >= 0);
	OK(unveil(pp("in"), "rwc"));
	OK(unveil(NULL, NULL));
	pl("stdio rpath wpath cpath");

	/* a directory descriptor from before: landlock still judges the directory it names */
	errno = 0;
	CHECK(mkdirat(outdir, "nd", 0700) == -1 && errno == EACCES);
	errno = 0;
	CHECK(unlinkat(outdir, "f", 0) == -1 && errno == EACCES);
	errno = 0;
	CHECK(symlinkat("x", outdir, "sl") == -1 && errno == EACCES);
	errno = 0;
	CHECK(renameat(outdir, "f", outdir, "f2") == -1 && errno == EACCES);
	errno = 0;
	CHECK(openat(outdir, "g", O_WRONLY) == -1 && errno == EACCES);
	/* a path to an inode through /proc: linking it in from outside is refused too */
	snprintf(proc, sizeof proc, "/proc/self/fd/%d", outfile);
	if (access(proc, F_OK) == 0) {
		errno = 0;
		r = linkat(AT_FDCWD, proc, AT_FDCWD, pp("in/stolen"), AT_SYMLINK_FOLLOW);
		CHECK(r == -1 && (errno == EACCES || errno == EXDEV));
	}
	/* but a writable descriptor from before keeps working: landlock checks at open, not at use */
	CHECK(ftruncate(outfd_rw, 0) == 0);
	CHECK(posix_fallocate(outfd_rw, 0, 4096) == 0);
	CHECK(write(outfd_rw, "still writable\n", 15) == 15);
}


/* ------------------------------------------------------------------ */
/* signal isolation with a landlock scope                              */
/* ------------------------------------------------------------------ */



/* an unrelated process of the same user, outside every landlock domain; it dies with the test */
static pid_t
spawn_unrelated(void)
{
	pid_t p = fork();

	CHECK(p >= 0);
	if (p == 0) {
		alarm(100);	/* a scoped parent cannot kill it with PDEATHSIG, so it ends by itself */
		for (;;)
			pause();
	}
	usleep(50000);
	return p;
}


static void
set_handler(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler;
	if (sigaction(SIGUSR1, &sa, NULL) != 0)
		_exit(2);
}

/* signals to the process itself work in every form; to anyone else they fail with eperm, not a kill */
static void
check_confined(pid_t other, pid_t outside)
{
	union sigval v;
	siginfo_t si;

	memset(&v, 0, sizeof v);
	got = 0;
	CHECK(raise(SIGUSR1) == 0 && got == SIGUSR1);
	got = 0;
	CHECK(pthread_kill(pthread_self(), SIGUSR1) == 0 && got == SIGUSR1);
	got = 0;
	CHECK(kill(getpid(), SIGUSR1) == 0 && got == SIGUSR1);
	got = 0;
	CHECK(syscall(VOW_NR_tkill, syscall(VOW_NR_gettid), SIGUSR1) == 0 && got == SIGUSR1);
	got = 0;
	CHECK(syscall(VOW_NR_tgkill, getpid(), syscall(VOW_NR_gettid), SIGUSR1) == 0 && got == SIGUSR1);
	got = 0;
	CHECK(sigqueue(getpid(), SIGUSR1, v) == 0 && got == SIGUSR1);
	/* unrelated processes of the same user, and the process that started this test */
	ERR(kill(other, 0), EPERM);
	ERR(syscall(VOW_NR_tkill, other, 0), EPERM);
	ERR(syscall(VOW_NR_tgkill, other, other, 0), EPERM);
	memset(&si, 0, sizeof si);
	si.si_code = -1;	/* SI_QUEUE */
	ERR(syscall(VOW_NR_rt_sigqueueinfo, other, 0, &si), EPERM);
	ERR(syscall(VOW_NR_rt_tgsigqueueinfo, other, other, 0, &si), EPERM);
	ERR(kill(outside, 0), EPERM);
	ERR(kill(1, 0), EPERM);
	/* a broadcast reaches only the domain: it succeeds because the process itself is in it */
	CHECK(kill(-1, 0) == 0);
}

static void
t_scope_main_thread(void)
{
	pid_t other;

	set_handler();
	other = spawn_unrelated();
	pls("stdio");
	check_confined(other, getppid());
}

static volatile int sc_stop, sc_ready;
static pid_t sc_other, sc_outside;
static volatile int sc_res[8];

static void *
sc_thread(void *arg)
{
	long own = syscall(VOW_NR_gettid);
	int pre = arg != NULL;	/* created before the pledge */

	set_handler();
	(void)pre;
	while (!sc_ready)
		;
	got = 0;
	sc_res[0] = raise(SIGUSR1) == 0 && got == SIGUSR1;
	got = 0;
	sc_res[1] = pthread_kill(pthread_self(), SIGUSR1) == 0 && got == SIGUSR1;
	got = 0;
	sc_res[2] = syscall(VOW_NR_tkill, own, SIGUSR1) == 0 && got == SIGUSR1;
	errno = 0;
	sc_res[3] = kill(sc_other, 0) == -1 && errno == EPERM;
	errno = 0;
	sc_res[4] = syscall(VOW_NR_tkill, sc_other, 0) == -1 && errno == EPERM;
	errno = 0;
	sc_res[5] = kill(sc_outside, 0) == -1 && errno == EPERM;
	sc_res[6] = 1;
	/* stay alive and cancellable: nanosleep is a cancellation point */
	while (!sc_stop) {
		struct timespec ts = { 0, 1000000 };

		nanosleep(&ts, NULL);
	}
	return NULL;
}

/* a thread made after the pledge is in the domain (it inherits it), is confined, and can be cancelled */

static void
t_scope_threads(void)
{
	pthread_t t;
	void *ret = NULL;
	int i;

	set_handler();
	sc_other = spawn_unrelated();
	sc_outside = getppid();
	pls("stdio");
	CHECK(pthread_create(&t, NULL, sc_thread, (void *)1) == 0);
	sc_ready = 1;
	while (!sc_res[6])
		;
	for (i = 0; i < 6; i++)
		if (!sc_res[i])
			fprintf(stderr, "    thread check %d failed\\n", i);
	for (i = 0; i < 6; i++)
		CHECK(sc_res[i]);
	/* the cancellation signal is a tkill to another thread: it works */
	CHECK(pthread_cancel(t) == 0);
	CHECK(pthread_join(t, &ret) == 0 && ret == PTHREAD_CANCELED);
	sc_stop = 1;
}

static void *
sc_new_thread(void *arg)
{
	(void)arg;
	errno = 0;
	sc_res[0] = kill(sc_other, 0) == -1 && errno == EPERM;
	sc_res[1] = 1;
	return NULL;
}

static void
t_scope_new_thread(void)
{
	pthread_t t;

	set_handler();
	sc_other = spawn_unrelated();
	pls("stdio");
	CHECK(pthread_create(&t, NULL, sc_new_thread, NULL) == 0);
	CHECK(pthread_join(t, NULL) == 0);
	CHECK(sc_res[0] && sc_res[1]);
}

static void
t_scope_abort_main(void)
{
	pls("stdio");
	abort();
	_exit(0);
}

static void *
sc_abort_thread(void *arg)
{
	(void)arg;
	abort();
	return NULL;
}

static void
t_scope_abort_thread(void)
{
	pthread_t t;

	pls("stdio");
	CHECK(pthread_create(&t, NULL, sc_abort_thread, NULL) == 0);
	pthread_join(t, NULL);
	_exit(0);
}

/* two processes that each pledged have their own domain and cannot signal one another */
static void
t_scope_siblings(void)
{
	int a2b[2], b2a[2];
	pid_t a, b;
	int st;
	char c;

	if (vow_landlock_abi() < VOW_SCOPE_ABI)
		SKIP("kernel landlock abi < 6");
	CHECK(pipe(a2b) == 0 && pipe(b2a) == 0);
	a = fork();
	CHECK(a >= 0);
	if (a == 0) {
		alarm(100);	/* a scoped parent cannot kill it with PDEATHSIG, so it ends by itself */
		if (pledge("stdio", NULL) != 0)
			_exit(1);
		if (write(a2b[1], "x", 1) != 1 || read(b2a[0], &c, 1) != 1)	/* wait until b has tried */
			_exit(2);
		_exit(0);
	}
	CHECK(read(a2b[0], &c, 1) == 1);
	b = fork();
	CHECK(b >= 0);
	if (b == 0) {
		if (pledge("stdio", NULL) != 0)
			_exit(1);
		errno = 0;
		if (kill(a, 0) != -1 || errno != EPERM)
			_exit(3);
		if (write(b2a[1], "y", 1) != 1)
			_exit(4);
		_exit(0);
	}
	CHECK(waitpid(b, &st, 0) == b && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	CHECK(waitpid(a, &st, 0) == a && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

/* ---- fork ---- */

static pid_t sc_parent, sc_unrelated;
static int sc_raw;
static int sc_gate[2], sc_back[2];







/* ---- capability failures and unsupported abis ---- */







/* ---- with unveil, in both orders ---- */

static void
unveil_scope_common(pid_t other)
{
	char buf[16];
	int fd;

	check_confined(other, getppid());
	fd = open(pp("in/f"), O_RDONLY);
	CHECK(fd >= 0 && read(fd, buf, sizeof buf) == 7);
	errno = 0;
	CHECK(open(pp("out/f"), O_RDONLY) == -1 && errno == EACCES);
}

static void
t_scope_unveil_first(void)
{
	pid_t other;

	set_handler();
	u_setup("sc_uv1");
	other = spawn_unrelated();
	OK(unveil(pp("in"), "r"));
	OK(unveil(NULL, NULL));
	pls("stdio rpath");
	unveil_scope_common(other);
}

static void
t_scope_pledge_first(void)
{
	pid_t other;

	set_handler();
	u_setup("sc_uv2");
	other = spawn_unrelated();
	pls("stdio rpath");
	OK(unveil(pp("in"), "r"));
	OK(unveil(NULL, NULL));
	unveil_scope_common(other);
}


/* ------------------------------------------------------------------ */
/* S2: stdio needs the signal scope; there is no fallback             */
/* ------------------------------------------------------------------ */

static void
t_s2_old_abi_refused(void)
{
	vow_test_abi_cap = 5;	/* a kernel before landlock scopes */
	ERR(pledge("stdio", NULL), ENOSYS);
	ERR(pledge("stdio rpath wpath cpath inet exec", NULL), ENOSYS);
	CHECK(vow_test_scope_state() == 0 && vow_test_promises() == 0xffff);
	nothing_installed();	/* no filter, no scope, no state */
	/* promises that cannot send signals do not need a scope */
	OK(pledge("rpath wpath cpath inet exec", NULL));
	ERR(pledge("stdio rpath", NULL), EPERM);	/* and stdio cannot be added later */
}

static void
t_s2_no_landlock_refused(void)
{
	vow_test_abi_cap = -1;	/* no landlock at all */
	ERR(pledge("stdio", NULL), ENOSYS);
	CHECK(vow_test_scope_state() == 0);
	nothing_installed();
	OK(pledge("rpath", NULL));
}

static void *
s2_idle(void *arg)
{
	(void)arg;
	while (!sc_stop)
		;
	return NULL;
}

static void
t_s2_abi7_threads_refused(void)
{
	pthread_t t;
	pid_t other;

	/* more threads than one: refused, on any abi (a scope binds one thread, and tsync would replace domains) */
	if (vow_landlock_abi() < VOW_SCOPE_ABI)
		SKIP("kernel landlock abi < 6");
	other = spawn_unrelated();
	CHECK(pthread_create(&t, NULL, s2_idle, NULL) == 0);
	ERR(pledge("stdio", NULL), EBUSY);
	CHECK(vow_test_scope_state() == 0 && vow_test_promises() == 0xffff);
	nothing_installed();
	CHECK(kill(other, 0) == 0);	/* and no scope was entered either: this thread can still signal anyone */
	sc_stop = 1;
	CHECK(pthread_join(t, NULL) == 0);
}

static void
t_s2_abi7_single_thread_ok(void)
{
	pid_t other;

	if (vow_landlock_abi() < VOW_SCOPE_ABI)
		SKIP("kernel landlock abi < 6");
	set_handler();
	other = spawn_unrelated();
	vow_test_abi_cap = 7;
	OK(pledge("stdio", NULL));
	CHECK(vow_test_scope_state() == 1);
	check_confined(other, getppid());
}

static void
t_s2_error_not_hidden(void)
{
	struct rlimit rl, old;
	int fd, top = 0;

	need_scope();
	for (fd = 0; fd < 256; fd++)
		if (fcntl(fd, F_GETFD) >= 0)
			top = fd + 1;
	CHECK(getrlimit(RLIMIT_NOFILE, &old) == 0);
	rl = old;
	rl.rlim_cur = (rlim_t)top;
	CHECK(setrlimit(RLIMIT_NOFILE, &rl) == 0);
	ERR(pledge("stdio", NULL), EMFILE);
	CHECK(setrlimit(RLIMIT_NOFILE, &old) == 0);
	CHECK(vow_test_scope_state() == 0 && vow_test_promises() == 0xffff);
	nothing_installed();
	OK(pledge("stdio", NULL));
	CHECK(vow_test_scope_state() == 1);
}

/* the filter has no pid and no thread id in it: every signal call passes it, the scope decides */
static void
t_s2_filter_has_no_ids(void)
{
	struct vow_insn p[VOW_MAX_INSNS];
	struct vow_ctx c;
	size_t n, i;

	c.deny = VOW_SECCOMP_RET_KILL_PROCESS;
	n = vow_build(P_STDIO, &c, p, VOW_MAX_INSNS);
	CHECK(n > 0);
	/* the five signal calls are plain allows: no instruction after their match looks at an argument */
	for (i = 0; i + 3 < n; i++)
		if (p[i].code == (VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K) &&
		    (p[i].k == VOW_NR_kill || p[i].k == VOW_NR_tgkill || p[i].k == VOW_NR_tkill)) {
			CHECK(p[i + 1].code == (VOW_BPF_RET | VOW_BPF_K) && p[i + 1].k == VOW_SECCOMP_RET_ALLOW);
			break;
		}
	CHECK(i + 3 < n);
}

/* ---- children share the domain ---- */

static pid_t sc_parent, sc_unrelated;

static void
child_shares_domain(void)
{
	set_handler();
	if (kill(sc_parent, 0) != 0)	/* the parent: same domain, allowed */
		_exit(1);
	if (syscall(VOW_NR_tkill, sc_parent, 0) != 0)
		_exit(2);
	got = 0;
	if (kill(getpid(), SIGUSR1) != 0 || got != SIGUSR1)
		_exit(3);
	/*
	 * raise in a raw-forked child is a trap of its own, not vow's: musl keeps the thread id in
	 * memory and only its fork() updates it, so raise signals the parent. do not do that here.
	 */
	if (!sc_raw) {
		got = 0;
		if (raise(SIGUSR1) != 0 || got != SIGUSR1)
			_exit(4);
	}
	errno = 0;
	if (kill(sc_unrelated, 0) != -1 || errno != EPERM)	/* still no one else */
		_exit(5);
}

static void
t_fork_libc_shares_domain(void)
{
	enable_fork();
	sc_unrelated = spawn_unrelated();
	pls("stdio");
	sc_parent = getpid();
	/* a libc fork adds nothing: the child is in the domain of its parent, and the parent in the child's */
	CHECK(child_status(child_shares_domain) == 0);
}

static int
child_status_raw_(void (*fn)(void))
{
	pid_t p;
	int st = -1;

	p = (pid_t)syscall(57 /* fork */);
	CHECK(p >= 0);
	if (p == 0) {
		fn();
		_exit(0);
	}
	CHECK(waitpid(p, &st, 0) == p);
	return st;
}

static void
t_fork_raw_shares_domain(void)
{
	enable_fork();
	sc_unrelated = spawn_unrelated();
	pls("stdio");
	sc_parent = getpid();
	sc_raw = 1;
	CHECK(child_status_raw_(child_shares_domain) == 0);
}

/* what an explicit isolation step does: enter a scope of its own in the child */
static int sc_gate[2], sc_back[2];

static void
child_nested(void)
{
	char c;

	if (vow_scope_enter_child() != 0)
		_exit(10);
	errno = 0;
	if (kill(sc_parent, 0) != -1 || errno != EPERM)
		_exit(1);
	errno = 0;
	if (syscall(VOW_NR_tkill, sc_parent, 0) != -1 || errno != EPERM)
		_exit(2);
	set_handler();
	got = 0;
	if (kill(getpid(), SIGUSR1) != 0 || got != SIGUSR1)
		_exit(3);
	errno = 0;
	if (kill(sc_unrelated, 0) != -1 || errno != EPERM)
		_exit(4);
	if (write(sc_back[1], "r", 1) != 1 || read(sc_gate[0], &c, 1) != 1)
		_exit(5);
}

static void
t_fork_explicit_nesting(void)
{
	pid_t c;
	int st;
	char ch;

	enable_fork();
	sc_unrelated = spawn_unrelated();
	pls("stdio");
	sc_parent = getpid();
	CHECK(pipe(sc_gate) == 0 && pipe(sc_back) == 0);
	fflush(NULL);
	c = fork();
	CHECK(c >= 0);
	if (c == 0) {
		child_nested();
		_exit(0);
	}
	/* the parent reaches into the nested domain; the child cannot reach out */
	CHECK(read(sc_back[0], &ch, 1) == 1);
	CHECK(kill(c, 0) == 0);
	CHECK(syscall(VOW_NR_tkill, c, 0) == 0);
	CHECK(write(sc_gate[1], "g", 1) == 1);
	CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static void
grandchild_nested(void)
{
	if (vow_scope_enter_child() != 0)
		_exit(10);
	errno = 0;
	if (kill(sc_parent, 0) != -1 || errno != EPERM)
		_exit(1);
	errno = 0;
	if (kill(getppid(), 0) != -1 || errno != EPERM)	/* its own parent is in an ancestor domain too */
		_exit(2);
}

static void
child_makes_grandchild(void)
{
	pid_t g;
	int st;

	if (vow_scope_enter_child() != 0)
		_exit(10);
	fflush(NULL);
	g = fork();
	if (g < 0)
		_exit(1);
	if (g == 0) {
		grandchild_nested();
		_exit(0);
	}
	if (kill(g, 0) != 0)	/* down the tree is allowed */
		_exit(2);
	if (waitpid(g, &st, 0) != g || !WIFEXITED(st) || WEXITSTATUS(st) != 0)
		_exit(3);
}

static void
t_fork_nesting_generations(void)
{
	enable_fork();
	pls("stdio");
	sc_parent = getpid();
	CHECK(child_status(child_makes_grandchild) == 0);
}

/* the cost of nesting: the kernel allows 16 stacked domains, and every scope is one */
static void
t_nesting_layer_limit(void)
{
	int n = 0, e = 0;

	need_scope();
	while (n < 40) {
		if (vow_scope_enter_child() != 0) {
			e = errno;
			break;
		}
		n++;
	}
	printf("    %d nested scope domains entered, then errno %d (%s)\n", n, e, e ? strerror(e) : "none");
	CHECK(e == E2BIG && n >= 8 && n <= 16);
	nothing_installed();	/* the process itself is still usable */
}

/* ---- supervisors, parent-death signals, shutdown ---- */

static int sup_up[2], sup_dn[2], sup_rdy[2];

static void
on_term(int sig)
{
	static const char m[] = "b";

	(void)sig;
	(void)!write(sup_up[1], m, 1);
	_exit(0);
}

static void
sup_mk(void)
{
	if (pipe(sup_up) != 0 || pipe(sup_dn) != 0 || pipe(sup_rdy) != 0)
		_exit(2);
}

/* a worker: pledged, tells the supervisor it is ready, then waits for the supervisor to act */
static void
worker_wait(int graceful)
{
	struct sigaction sa;
	char c;

	if (graceful) {
		memset(&sa, 0, sizeof sa);
		sa.sa_handler = on_term;
		if (sigaction(SIGTERM, &sa, NULL) != 0)
			_exit(2);
	}
	if (pledge("stdio", NULL) != 0)
		_exit(3);
	if (write(sup_rdy[1], "r", 1) != 1)
		_exit(4);
	if (read(sup_dn[0], &c, 1) < 0)
		_exit(5);
	_exit(0);
}

static pid_t
start_worker(int graceful)
{
	pid_t p;
	char c;

	fflush(NULL);
	p = fork();
	CHECK(p >= 0);
	if (p == 0)
		worker_wait(graceful);
	CHECK(read(sup_rdy[0], &c, 1) == 1);
	return p;
}

/* the supervisor is outside the domain: it can stop, terminate and kill the pledged worker */
static void
t_sup_signals_worker(void)
{
	pid_t w;
	int st;
	char c;

	need_scope();
	sup_mk();
	/* graceful: a handler for SIGTERM that says goodbye and exits */
	w = start_worker(1);
	CHECK(kill(w, SIGTERM) == 0);
	CHECK(waitpid(w, &st, 0) == w && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	CHECK(read(sup_up[0], &c, 1) == 1 && c == 'b');
	/* default action of SIGTERM */
	w = start_worker(0);
	CHECK(kill(w, SIGTERM) == 0);
	CHECK(waitpid(w, &st, 0) == w && WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
	/* stop, continue, kill */
	w = start_worker(0);
	CHECK(kill(w, SIGSTOP) == 0);
	CHECK(waitpid(w, &st, WUNTRACED) == w && WIFSTOPPED(st));
	CHECK(kill(w, SIGCONT) == 0);
	CHECK(kill(w, SIGKILL) == 0);
	CHECK(waitpid(w, &st, 0) == w && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
}

static volatile int chld_seen;

static void
on_chld(int sig)
{
	(void)sig;
	chld_seen++;
}

static void
worker_exit_normally(void)
{
	if (pledge("stdio", NULL) != 0)
		_exit(3);
	printf("worker output\n");	/* stdio flushes through writev at exit */
	exit(7);
}

/* normal shutdown: exit status reaches the supervisor, output is flushed, the kernel still sends SIGCHLD */
static void
t_sup_normal_shutdown(void)
{
	struct sigaction sa;
	pid_t w;
	int st, p[2];
	char buf[32];
	ssize_t n;

	need_scope();
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_chld;
	OK(sigaction(SIGCHLD, &sa, NULL));
	CHECK(pipe(p) == 0);
	fflush(NULL);
	w = fork();
	CHECK(w >= 0);
	if (w == 0) {
		close(p[0]);
		dup2(p[1], 1);
		worker_exit_normally();
	}
	close(p[1]);
	CHECK(waitpid(w, &st, 0) == w && WIFEXITED(st) && WEXITSTATUS(st) == 7);
	n = read(p[0], buf, sizeof buf);
	CHECK(n == 14 && memcmp(buf, "worker output\n", 14) == 0);
	CHECK(chld_seen >= 1);	/* generated by the kernel when the worker exited: no scope covers it */
}

static void
worker_signals_supervisor(void)
{
	char c;

	if (pledge("stdio", NULL) != 0)
		_exit(3);
	errno = 0;
	if (kill(getppid(), SIGUSR1) != -1 || errno != EPERM)
		_exit(1);
	errno = 0;
	if (kill(getppid(), SIGTERM) != -1 || errno != EPERM)
		_exit(2);
	errno = 0;
	if (syscall(VOW_NR_tkill, getppid(), SIGUSR1) != -1 || errno != EPERM)
		_exit(4);
	/* the way to tell the supervisor something is a descriptor */
	if (write(sup_up[1], "u", 1) != 1 || read(sup_dn[0], &c, 1) < 0)
		_exit(5);
	_exit(0);
}

static void
t_sup_worker_cannot_signal_supervisor(void)
{
	pid_t w;
	int st;
	char c;

	need_scope();
	set_handler();
	sup_mk();
	got = 0;
	fflush(NULL);
	w = fork();
	CHECK(w >= 0);
	if (w == 0)
		worker_signals_supervisor();
	CHECK(read(sup_up[0], &c, 1) == 1 && c == 'u');
	CHECK(write(sup_dn[1], "x", 1) == 1);
	CHECK(waitpid(w, &st, 0) == w && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	CHECK(got == 0);
}

/* parent-death signal from a supervisor that is not sandboxed: the kernel delivers it */
static void
pdeath_worker(void)
{
	struct sigaction sa;

	prctl(PR_SET_PDEATHSIG, SIGTERM);	/* must be set before the pledge: prctl is not in stdio */
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_term;
	if (sigaction(SIGTERM, &sa, NULL) != 0 || pledge("stdio", NULL) != 0)
		_exit(3);
	if (getppid() == 1)
		_exit(4);
	if (write(sup_rdy[1], "r", 1) != 1)
		_exit(5);
	{
		char c;

		(void)read(sup_dn[0], &c, 1);
	}
	_exit(6);
}

static void
t_sup_pdeathsig_from_outside(void)
{
	pid_t s;
	int st;
	struct pollfd pf;
	char c;

	need_scope();
	sup_mk();
	fflush(NULL);
	s = fork();
	CHECK(s >= 0);
	if (s == 0) {
		pid_t w = fork();

		if (w == 0)
			pdeath_worker();
		if (read(sup_rdy[0], &c, 1) != 1)
			_exit(1);
		_exit(0);	/* the supervisor goes away: the worker gets SIGTERM from the kernel */
	}
	CHECK(waitpid(s, &st, 0) == s && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	pf.fd = sup_up[0];
	pf.events = POLLIN;
	CHECK(poll(&pf, 1, 5000) == 1);
	CHECK(read(sup_up[0], &c, 1) == 1 && c == 'b');	/* the handler of the worker ran */
}

/* the other direction: a sandboxed parent cannot deliver its death signal to a child outside its domain */
static void
t_sup_pdeathsig_from_scoped_parent(void)
{
	pid_t p;
	int st;
	struct pollfd pf;
	char buf[32];
	pid_t cpid = 0;
	int cp[2];

	need_scope();
	sup_mk();
	CHECK(pipe(cp) == 0);
	fflush(NULL);
	p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		pid_t c = fork();	/* made before the pledge: outside the domain */

		if (c == 0) {
			struct sigaction sa;

			prctl(PR_SET_PDEATHSIG, SIGTERM);
			memset(&sa, 0, sizeof sa);
			sa.sa_handler = on_term;
			sigaction(SIGTERM, &sa, NULL);
			{
				int me = getpid();

				(void)!write(cp[1], &me, sizeof me);
			}
			if (write(sup_rdy[1], "r", 1) != 1)
				_exit(1);
			{
				char x;

				(void)read(sup_dn[0], &x, 1);
			}
			_exit(0);
		}
		{
			char x;

			if (read(sup_rdy[0], &x, 1) != 1)
				_exit(1);
		}
		if (pledge("stdio", NULL) != 0)
			_exit(2);
		_exit(0);	/* a sandboxed parent exits */
	}
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	CHECK(read(cp[0], &cpid, sizeof cpid) == sizeof cpid);
	pf.fd = sup_up[0];
	pf.events = POLLIN;
	CHECK(poll(&pf, 1, 1500) == 0);	/* nothing arrived: the child is still alive */
	CHECK(kill(cpid, 0) == 0);
	CHECK(kill(cpid, SIGKILL) == 0);	/* we are outside every domain: we may clean up */
	(void)buf;
}

/* kill(0) and kill(-pgid): the call succeeds because the caller is a member, the others are not signalled */
static void
t_scope_group_signal(void)
{
	pid_t u, pg;
	struct pollfd pf;
	char c;
	int spin;

	need_scope();
	sup_mk();
	set_handler();
	CHECK(setpgid(0, 0) == 0);
	pg = getpgrp();	/* getpgrp is not in stdio */
	fflush(NULL);
	u = fork();
	CHECK(u >= 0);
	if (u == 0) {
		struct sigaction sa;

		memset(&sa, 0, sizeof sa);
		sa.sa_handler = on_term;	/* any signal it receives is reported */
		sigaction(SIGUSR1, &sa, NULL);
		if (write(sup_rdy[1], "r", 1) != 1)
			_exit(1);
		(void)read(sup_dn[0], &c, 1);
		_exit(0);
	}
	CHECK(read(sup_rdy[0], &c, 1) == 1);
	pls("stdio");
	got = 0;
	CHECK(kill(0, SIGUSR1) == 0);	/* success says nothing about the others */
	for (spin = 0; spin < 50000000 && got != SIGUSR1; spin++)
		;
	CHECK(got == SIGUSR1);		/* delivered to the caller, a member of the domain */
	got = 0;
	CHECK(kill(-pg, SIGUSR1) == 0);
	for (spin = 0; spin < 50000000 && got != SIGUSR1; spin++)
		;
	CHECK(got == SIGUSR1);
	errno = 0;
	CHECK(kill(u, SIGUSR1) == -1 && errno == EPERM);	/* aimed at it directly it is refused */
	usleep(300000);
	pf.fd = sup_up[0];
	pf.events = POLLIN;
	CHECK(poll(&pf, 1, 0) == 0);	/* the member outside the domain never got a signal */
}


/* the always-allowed calls only take flags that tighten and that vow itself uses */
static void
k_seccomp_spec_allow(void)
{
	pl("stdio");
	syscall(VOW_NR_seccomp, VOW_SECCOMP_SET_MODE_FILTER, 4 /* SPEC_ALLOW */, NULL);
	_exit(0);
}

static void
k_seccomp_listener(void)
{
	pl("stdio");
	syscall(VOW_NR_seccomp, VOW_SECCOMP_SET_MODE_FILTER, 8 /* NEW_LISTENER */, NULL);
	_exit(0);
}

static void
k_landlock_log_flag(void)
{
	pl("stdio");
	syscall(VOW_SYS_landlock_restrict_self, -1, 4 /* LOG_SUBDOMAINS_OFF */);
	_exit(0);
}


/* a sibling thread has a stricter domain of its own: stdio is refused and the sibling keeps what it had */
static volatile int sib_stage, sib_res = -9;
static char sib_path[8192];

static void *
sib_thread(void *arg)
{
	struct vow_ruleset_attr attr;
	int rs;

	(void)arg;
	memset(&attr, 0, sizeof attr);
	attr.handled_access_fs = VOW_LL_FS_READ_FILE;	/* handled, nothing granted */
	rs = (int)syscall(VOW_SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
	if (rs < 0 || prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
	    syscall(VOW_SYS_landlock_restrict_self, rs, 0) != 0) {
		sib_stage = -1;
		return NULL;
	}
	sib_stage = 1;
	while (sib_stage != 2)
		;
	{
		int fd = open(sib_path, O_RDONLY);

		sib_res = fd < 0 ? errno : 0;
	}
	return NULL;
}

static void
t_scope_refused_keeps_sibling_domain(void)
{
	pthread_t t;

	need_scope();
	pdir("sib1");
	snprintf(sib_path, sizeof sib_path, "%s", pp("f"));
	CHECK(pthread_create(&t, NULL, sib_thread, NULL) == 0);
	while (sib_stage == 0)
		;
	CHECK(sib_stage == 1);
	ERR(pledge("stdio", NULL), EBUSY);	/* would have replaced the domain of the sibling */
	CHECK(vow_test_scope_state() == 0 && vow_test_promises() == 0xffff);
	nothing_installed();
	CHECK(kill(getppid(), 0) == 0);	/* no scope was entered: the caller can still signal the process that started it */
	{
		int fd = open(pp("f"), O_RDONLY);	/* this thread was never restricted */

		CHECK(fd >= 0);
		close(fd);
	}
	sib_stage = 2;
	CHECK(pthread_join(t, NULL) == 0);
	CHECK(sib_res == EACCES);	/* the sibling is as restricted as it was */
}

/* an outside domain on the one thread is kept: the scope is a layer on top of it */
static void
t_scope_stacks_on_existing_domain(void)
{
	struct vow_ruleset_attr attr;
	struct vow_path_beneath pb;
	int rs, fd, pfd;

	need_scope();
	pdir("sib2");
	memset(&attr, 0, sizeof attr);
	attr.handled_access_fs = VOW_LL_FS_READ_FILE | VOW_LL_FS_READ_DIR;
	rs = (int)syscall(VOW_SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
	CHECK(rs >= 0);
	memset(&pb, 0, sizeof pb);
	pb.allowed_access = VOW_LL_FS_READ_FILE | VOW_LL_FS_READ_DIR;
	fd = open(pp("d"), O_PATH | O_DIRECTORY);
	pb.parent_fd = fd;
	CHECK(fd >= 0 && syscall(VOW_SYS_landlock_add_rule, rs, VOW_LL_RULE_PATH_BENEATH, &pb, 0) == 0);
	pfd = open("/proc", O_PATH | O_DIRECTORY);
	pb.parent_fd = pfd;
	CHECK(pfd >= 0 && syscall(VOW_SYS_landlock_add_rule, rs, VOW_LL_RULE_PATH_BENEATH, &pb, 0) == 0);
	CHECK(prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	CHECK(syscall(VOW_SYS_landlock_restrict_self, rs, 0) == 0);
	errno = 0;
	CHECK(open(pp("f"), O_RDONLY) == -1 && errno == EACCES);
	pl("stdio rpath");
	errno = 0;
	CHECK(open(pp("f"), O_RDONLY) == -1 && errno == EACCES);	/* still */
}

static void
k_landlock_tsync_flag(void)
{
	pl("stdio");
	syscall(VOW_SYS_landlock_restrict_self, -1, VOW_LL_RESTRICT_TSYNC);	/* would replace sibling domains */
	_exit(0);
}

/* the thread list belongs to the process: a child must not look at the one it inherited */
static void *
fork_list_thread(void *arg)
{
	while (!sc_stop)
		;
	return arg;
}

static void
child_creates_thread_then_asks(void)
{
	pthread_t t;

	sc_stop = 0;
	if (pthread_create(&t, NULL, fork_list_thread, NULL) != 0)
		_exit(1);
	/* the parent had one thread when the list was opened: a stale list would say one here too */
	if (vow_threads_single() != 0)
		_exit(2);
	sc_stop = 1;
	pthread_join(t, NULL);
}

static void
t_thread_list_is_not_inherited(void)
{
	pthread_t t;
	int st;
	pid_t p;

	need_scope();
	vow_atfork_register();	/* what the first call of pledge or unveil does: handlers, and the list */
	CHECK(vow_threads_single() == 1);
	CHECK(child_status(child_creates_thread_then_asks) == 0);
	/* and the other way round: the parent has two threads, the child (one thread, by fork) is one */
	sc_stop = 0;
	CHECK(pthread_create(&t, NULL, fork_list_thread, NULL) == 0);
	CHECK(vow_threads_single() == 0);
	fflush(NULL);
	p = fork();
	CHECK(p >= 0);
	if (p == 0)
		_exit(vow_threads_single() == 1 ? 0 : 1);
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0);
	sc_stop = 1;
	CHECK(pthread_join(t, NULL) == 0);
}

/* a thread that was just joined is gone for good: the list may lag for a moment, the answer must not */
static void *
quick_thread(void *arg)
{
	return arg;
}

static void
t_joined_threads_do_not_linger(void)
{
	int i;

	for (i = 0; i < 3000; i++) {
		pthread_t t;

		CHECK(pthread_create(&t, NULL, quick_thread, NULL) == 0);
		CHECK(pthread_join(t, NULL) == 0);
		CHECK(vow_threads_single() == 1);
	}
}


/* a thread made right after the scope was entered (only a signal handler of this thread could): reported */
static pthread_t ld_t;
static volatile int ld_go;

static void *
ld_fn(void *arg)
{
	while (!ld_go)
		;
	return arg;
}

static void
ld_spawn(void)
{
	pthread_create(&ld_t, NULL, ld_fn, NULL);
}

static void
t_scope_reports_late_thread(void)
{
	pid_t other;

	need_scope();
	other = spawn_unrelated();
	vow_test_after_restrict = ld_spawn;
	ERR(pledge("stdio", NULL), EBUSY);
	vow_test_after_restrict = NULL;
	CHECK(vow_test_promises() == 0xffff);
	nothing_installed();	/* no filter... */
	errno = 0;
	CHECK(kill(other, 0) == -1 && errno == EPERM);	/* ...but the scope is in force on this thread, and the caller was told */
	ld_go = 1;
	pthread_join(ld_t, NULL);
}

/* ---- raw fork versus the library locks, and fork stress ---- */

static void *
unveil_in_thread2(void *arg)
{
	(void)arg;
	(void)unveil(atfork_dir, "r");
	return NULL;
}

/* a raw fork runs no handlers: the child inherits the lock another thread holds, and waits for it forever */
static void
t_raw_fork_keeps_lock(void)
{
	pthread_t t;
	pid_t p;
	int st;

	pdir("af2");
	atfork_dir = strdup(pp("d"));
	win_in = 0;
	vow_test_window = slow_window;
	CHECK(pthread_create(&t, NULL, unveil_in_thread2, NULL) == 0);
	while (!win_in)
		;
	p = (pid_t)syscall(57 /* fork */);
	CHECK(p >= 0);
	if (p == 0) {
		alarm(2);
		vow_test_window = NULL;
		(void)unveil(NULL, NULL);	/* never returns: the lock was taken by a thread that is not here */
		_exit(0);
	}
	CHECK(waitpid(p, &st, 0) == p);
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGALRM);
	pthread_join(t, NULL);
}

/* fork from a thread that is not the main one: the child has only that thread, and the library works in it */
static void *
fork_in_thread(void *arg)
{
	int *res = arg;
	pid_t p;
	int st;

	fflush(NULL);
	p = fork();
	if (p == 0) {
		alarm(10);
		if (unveil(atfork_dir, "r") != 0 || pledge(NULL, NULL) != 0 || unveil(NULL, NULL) != 0)
			_exit(1);
		if (try_open_dir(atfork_dir) != 0 || try_open_dir(root) != EACCES)
			_exit(2);
		_exit(0);
	}
	*res = p > 0 && waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0;
	return NULL;
}

static void
t_fork_from_thread(void)
{
	pthread_t t;
	int res = 0;

	pdir("af4");
	atfork_dir = strdup(pp("d"));
	CHECK(pthread_create(&t, NULL, fork_in_thread, &res) == 0);
	CHECK(pthread_join(t, NULL) == 0);
	CHECK(res == 1);
}

static volatile int hammer_stop;

static void *
hammer(void *arg)
{
	(void)arg;
	while (!hammer_stop)
		(void)unveil(atfork_dir, "r");	/* the same inode again: a replace, cheap and always locked */
	return NULL;
}

static void
t_fork_stress(void)
{
	pthread_t t;
	int i, bad = 0;

	pdir("af3");
	atfork_dir = strdup(pp("d"));
	CHECK(pthread_create(&t, NULL, hammer, NULL) == 0);
	for (i = 0; i < 150; i++) {
		pid_t p;
		int st;

		fflush(NULL);
		p = fork();
		CHECK(p >= 0);
		if (p == 0) {
			alarm(5);
			/* the library works in the child, whatever the other thread was doing at the fork */
			if (unveil(atfork_dir, "r") != 0 || pledge(NULL, NULL) != 0)
				_exit(1);
			_exit(0);
		}
		CHECK(waitpid(p, &st, 0) == p);
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
			bad++;
	}
	hammer_stop = 1;
	pthread_join(t, NULL);
	CHECK(bad == 0);
}


/* ------------------------------------------------------------------ */
/* milestone 3, third part: inet                                       */
/* ------------------------------------------------------------------ */

static int
sockaddr_path(struct sockaddr_un *a, const char *path)
{
	memset(a, 0, sizeof *a);
	a->sun_family = AF_UNIX;
	if (strlen(path) >= sizeof a->sun_path)
		return -1;
	strcpy(a->sun_path, path);
	return (int)sizeof *a;
}

/* a unix server made before the sandbox, outside any domain */
static int
srv(const char *path, int type)
{
	struct sockaddr_un a;
	int fd = socket(AF_UNIX, type, 0);

	if (fd < 0 || sockaddr_path(&a, path) < 0 || bind(fd, (struct sockaddr *)&a, sizeof a) != 0)
		_exit(2);
	if (type == SOCK_STREAM && listen(fd, 8) != 0)
		_exit(2);
	return fd;
}

static struct sockaddr_in
loop4(unsigned port)
{
	struct sockaddr_in a;

	memset(&a, 0, sizeof a);
	a.sin_family = AF_INET;
	a.sin_port = htons((unsigned short)port);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return a;
}

static int
bound4(int type, unsigned *port)
{
	struct sockaddr_in a = loop4(0);
	socklen_t l = sizeof a;
	int one = 1;
	int s = socket(AF_INET, type | SOCK_CLOEXEC, 0);

	if (s < 0 || setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0 ||
	    bind(s, (struct sockaddr *)&a, sizeof a) != 0 || getsockname(s, (struct sockaddr *)&a, &l) != 0)
		_exit(2);
	*port = ntohs(a.sin_port);
	return s;
}

static void
t_inet_tcp(void)
{
	unsigned port;
	struct sockaddr_in a;
	struct pollfd pf;
	socklen_t l = sizeof a;
	int one = 1, srv, cl, ac, err = -1;
	char buf[16];
	socklen_t el = sizeof err;

	pl("stdio inet");
	srv = bound4(SOCK_STREAM, &port);
	CHECK(listen(srv, 4) == 0);
	cl = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	CHECK(cl >= 0);
	/* the options that tune a connection */
	CHECK(setsockopt(cl, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) == 0);
	CHECK(setsockopt(cl, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one) == 0);
	CHECK(setsockopt(cl, SOL_SOCKET, SO_RCVBUF, &(int){ 65536 }, sizeof(int)) == 0);
	CHECK(setsockopt(cl, IPPROTO_IP, IP_TOS, &(int){ 0x10 }, sizeof(int)) == 0);
	a = loop4(port);
	errno = 0;
	CHECK(connect(cl, (struct sockaddr *)&a, sizeof a) == 0 || errno == EINPROGRESS);
	pf.fd = cl;
	pf.events = POLLOUT;
	CHECK(poll(&pf, 1, 2000) == 1);
	CHECK(getsockopt(cl, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0);
	ac = accept4(srv, (struct sockaddr *)&a, &l, SOCK_CLOEXEC);
	CHECK(ac >= 0);
	CHECK(getpeername(cl, (struct sockaddr *)&a, &l) == 0);
	CHECK(send(cl, "hello", 5, 0) == 5);
	CHECK(recv(ac, buf, sizeof buf, 0) == 5 && memcmp(buf, "hello", 5) == 0);
	CHECK(shutdown(cl, SHUT_WR) == 0);
	CHECK(recv(ac, buf, sizeof buf, 0) == 0);
}

static void
t_inet_udp(void)
{
	unsigned p1, p2;
	struct sockaddr_in to;
	struct msghdr mh;
	struct iovec iv;
	char buf[16];
	int u1, u2;
	pl("stdio inet");
	u1 = bound4(SOCK_DGRAM, &p1);
	u2 = bound4(SOCK_DGRAM, &p2);
	to = loop4(p1);
	/* an address on sendto and on sendmsg: both are available with inet */
	CHECK(sendto(u2, "one", 3, 0, (struct sockaddr *)&to, sizeof to) == 3);
	CHECK(recv(u1, buf, sizeof buf, 0) == 3);
	memset(&mh, 0, sizeof mh);
	iv.iov_base = (void *)"two";
	iv.iov_len = 3;
	mh.msg_name = &to;
	mh.msg_namelen = sizeof to;
	mh.msg_iov = &iv;
	mh.msg_iovlen = 1;
	CHECK(sendmsg(u2, &mh, 0) == 3);
	CHECK(recv(u1, buf, sizeof buf, 0) == 3);
	CHECK(setsockopt(u1, SOL_SOCKET, SO_REUSEPORT, &(int){ 1 }, sizeof(int)) == 0);
	CHECK(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) >= 0);
	CHECK(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) >= 0);
}

static void
t_inet6(void)
{
	struct sockaddr_in6 a, b;
	socklen_t l = sizeof b;
	int s, c, ac, v6only = 1;
	char buf[8];

	/* probe before the pledge: some systems have no ::1 */
	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s < 0)
		SKIP("no ipv6");
	memset(&a, 0, sizeof a);
	a.sin6_family = AF_INET6;
	a.sin6_addr = in6addr_loopback;
	if (bind(s, (struct sockaddr *)&a, sizeof a) != 0)
		SKIP("no ::1");
	close(s);
	pl("stdio inet");
	s = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	CHECK(s >= 0);
	CHECK(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only) == 0);
	CHECK(bind(s, (struct sockaddr *)&a, sizeof a) == 0 && listen(s, 2) == 0);
	CHECK(getsockname(s, (struct sockaddr *)&b, &l) == 0);
	c = socket(AF_INET6, SOCK_STREAM, 0);
	CHECK(c >= 0 && connect(c, (struct sockaddr *)&b, sizeof b) == 0);
	ac = accept(s, NULL, NULL);
	CHECK(ac >= 0 && send(c, "v6", 2, 0) == 2 && recv(ac, buf, sizeof buf, 0) == 2);
}

/* addresses written as numbers need no files */
static void
t_inet_numeric_lookup(void)
{
	struct addrinfo hints, *res = NULL;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
	pl("stdio inet");
	CHECK(getaddrinfo("127.0.0.1", "80", &hints, &res) == 0 && res != NULL);
}

/* a name needs /etc/hosts (and maybe resolv.conf): under inet alone musl opens a file and is killed */
static void
t_inet_name_lookup_needs_files(void)
{
	struct addrinfo hints, *res = NULL;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	pl("stdio inet");
	(void)getaddrinfo("localhost", "80", &hints, &res);
	_exit(0);
}

/* with rpath, and unveil limited to the two files, the lookup works */
static void
t_inet_name_lookup_with_files(void)
{
	struct addrinfo hints, *res = NULL;

	if (access("/etc/hosts", R_OK) != 0)
		SKIP("no /etc/hosts");
	OK(unveil("/etc/hosts", "r"));
	OK(unveil(NULL, NULL));
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	pl("stdio rpath inet");
	if (getaddrinfo("localhost", "80", &hints, &res) != 0)
		SKIP("localhost is not in /etc/hosts");
	CHECK(res != NULL);
	/* and the rest of the filesystem stayed closed */
	errno = 0;
	CHECK(open("/etc/passwd", O_RDONLY) == -1 && errno == EACCES);
}

#define SKILL(name, stmt) \
static void \
name(void) \
{ \
	int ns = socket(AF_INET, SOCK_DGRAM, 0); \
	int ts = socket(AF_INET, SOCK_STREAM, 0); \
	(void)ns; (void)ts; \
	pl("stdio inet"); \
	stmt; \
	_exit(0); \
}

SKILL(n_unix, (void)socket(AF_UNIX, SOCK_STREAM, 0))
SKILL(n_packet, (void)socket(AF_PACKET, SOCK_RAW, 0))
SKILL(n_netlink, (void)socket(AF_NETLINK, SOCK_RAW, 0))
SKILL(n_raw, (void)socket(AF_INET, SOCK_RAW, IPPROTO_RAW))
SKILL(n_seqpacket, (void)socket(AF_INET, SOCK_SEQPACKET, 0))
SKILL(n_sctp, (void)socket(AF_INET, SOCK_STREAM, 132))
SKILL(n_icmp, (void)socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP))
SKILL(n_udplite, (void)socket(AF_INET, SOCK_DGRAM, 136))
SKILL(n_mptcp, (void)socket(AF_INET, SOCK_STREAM, 262))
SKILL(n_flagbit, (void)socket(AF_INET, SOCK_STREAM | 0x1000, 0))
SKILL(n_filter, (void)setsockopt(ns, SOL_SOCKET, 26 /* SO_ATTACH_FILTER */, &(int){ 0 }, sizeof(int)))
SKILL(n_bpf, (void)setsockopt(ns, SOL_SOCKET, 50 /* SO_ATTACH_BPF */, &(int){ 0 }, sizeof(int)))
SKILL(n_bindtodev, (void)setsockopt(ns, SOL_SOCKET, 25 /* SO_BINDTODEVICE */, "lo", 3))
SKILL(n_mark, (void)setsockopt(ns, SOL_SOCKET, 36 /* SO_MARK */, &(int){ 1 }, sizeof(int)))
SKILL(n_ulp, (void)setsockopt(ts, IPPROTO_TCP, 31 /* TCP_ULP */, "tls", 4))
SKILL(n_ipoptions, (void)setsockopt(ns, IPPROTO_IP, 4 /* IP_OPTIONS */, &(int){ 0 }, sizeof(int)))
SKILL(n_mcast, (void)setsockopt(ns, IPPROTO_IP, 32 /* IP_MULTICAST_IF */, &(int){ 0 }, sizeof(int)))
SKILL(n_congestion, (void)setsockopt(ts, IPPROTO_TCP, 13 /* TCP_CONGESTION */, "reno", 5))

/* sockets that exist before the pledge, and what the promises do and do not do to them */
static void
t_pre_connected_stdio(void)
{
	unsigned port;
	struct sockaddr_in a;
	socklen_t l = sizeof a;
	int srv, cl, ac, err = -1;
	socklen_t el = sizeof err;
	char buf[16];

	srv = bound4(SOCK_STREAM, &port);
	CHECK(listen(srv, 2) == 0);
	cl = socket(AF_INET, SOCK_STREAM, 0);
	a = loop4(port);
	CHECK(cl >= 0 && connect(cl, (struct sockaddr *)&a, sizeof a) == 0);
	ac = accept(srv, NULL, NULL);
	CHECK(ac >= 0);
	pl("stdio");	/* no inet */
	/* a connected socket keeps working: reading, writing, queries and the harmless options */
	CHECK(send(cl, "pre", 3, 0) == 3 && recv(ac, buf, sizeof buf, 0) == 3);
	CHECK(write(ac, "ack", 3) == 3 && read(cl, buf, sizeof buf) == 3);
	CHECK(getpeername(cl, (struct sockaddr *)&a, &l) == 0);
	CHECK(getsockopt(cl, SOL_SOCKET, SO_ERROR, &err, &el) == 0);
	CHECK(setsockopt(cl, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int)) == 0);
	CHECK(shutdown(cl, SHUT_RDWR) == 0);
}

static void
k_pre_connect_setup(void)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = loop4(9);

	CHECK(s >= 0);
	pl("stdio");
	(void)connect(s, (struct sockaddr *)&a, sizeof a);	/* an unconnected socket from before: no inet, no connect */
	_exit(0);
}

/* the sendmsg limit: with only stdio an existing datagram socket can still send anywhere */
static void
t_pre_udp_sendmsg_gap(void)
{
	unsigned p1;
	struct sockaddr_in to;
	struct msghdr mh;
	struct iovec iv;
	char buf[16];
	int u1, u2;

	u1 = bound4(SOCK_DGRAM, &p1);
	u2 = socket(AF_INET, SOCK_DGRAM, 0);	/* made before, never connected */
	CHECK(u2 >= 0);
	pl("stdio");
	to = loop4(p1);
	memset(&mh, 0, sizeof mh);
	iv.iov_base = (void *)"gap";
	iv.iov_len = 3;
	mh.msg_name = &to;
	mh.msg_namelen = sizeof to;
	mh.msg_iov = &iv;
	mh.msg_iovlen = 1;
	CHECK(sendmsg(u2, &mh, 0) == 3);	/* the destination is in a struct: not visible to the filter */
	CHECK(recv(u1, buf, sizeof buf, 0) == 3);
}

static void
t_pre_udp_sendto_addr(void)
{
	struct sockaddr_in to = loop4(9);
	int u = socket(AF_INET, SOCK_DGRAM, 0);

	CHECK(u >= 0);
	pl("stdio");
	(void)sendto(u, "x", 1, 0, (struct sockaddr *)&to, sizeof to);	/* sendto's address is visible: killed */
	_exit(0);
}

/* connect and bind do not look at the family of the socket: pathname unix sockets through an inet pledge */
static void
t_inet_unix_gap_no_unveil(void)
{
	struct sockaddr_un a;
	int server, us, us2;
	const char *name;

	pdir("ng1");
	name = pp("s.sock");
	server = srv(name, SOCK_STREAM);
	CHECK(server >= 0);
	us = socket(AF_UNIX, SOCK_STREAM, 0);
	us2 = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(us >= 0 && us2 >= 0);
	pl("stdio inet");
	CHECK(sockaddr_path(&a, name) > 0);
	/* an unconnected unix socket from before can be connected: inet allows connect on any descriptor */
	CHECK(connect(us, (struct sockaddr *)&a, sizeof a) == 0);
	/* and bound, which creates a file in the filesystem without cpath */
	CHECK(sockaddr_path(&a, pp("made.sock")) > 0);
	CHECK(bind(us2, (struct sockaddr *)&a, sizeof a) == 0);
}

static void
t_inet_unix_with_unveil(void)
{
	struct sockaddr_un a;
	int server, us, us2, us3;

	if (vow_landlock_abi() < VOW_UNIX_ABI)
		SKIP("kernel landlock abi < 9");
	pdir("ng2");
	server = srv(pp("s.sock"), SOCK_STREAM);
	CHECK(server >= 0);
	us = socket(AF_UNIX, SOCK_STREAM, 0);
	us2 = socket(AF_UNIX, SOCK_STREAM, 0);
	us3 = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(us >= 0 && us2 >= 0 && us3 >= 0);
	OK(unveil(P, "rw"));	/* no s, no c */
	OK(unveil(NULL, NULL));
	pl("stdio inet");
	CHECK(sockaddr_path(&a, pp("s.sock")) > 0);
	errno = 0;
	CHECK(connect(us, (struct sockaddr *)&a, sizeof a) == -1 && errno == EACCES);	/* landlock closes it */
	CHECK(sockaddr_path(&a, pp("made.sock")) > 0);
	errno = 0;
	CHECK(bind(us2, (struct sockaddr *)&a, sizeof a) == -1 && errno == EACCES);	/* no c: no socket file */
	(void)us3;
}

static void
t_inet_unix_with_s(void)
{
	struct sockaddr_un a;
	int server, us;

	if (vow_landlock_abi() < VOW_UNIX_ABI)
		SKIP("kernel landlock abi < 9");
	pdir("ng3");
	server = srv(pp("s.sock"), SOCK_STREAM);
	CHECK(server >= 0);
	us = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(us >= 0);
	OK(unveil(P, "s"));
	OK(unveil(NULL, NULL));
	pl("stdio inet");
	CHECK(sockaddr_path(&a, pp("s.sock")) > 0);
	CHECK(connect(us, (struct sockaddr *)&a, sizeof a) == 0);
}

/* unveil limits files; the network is not touched by it */
static void
t_inet_with_unveil(void)
{
	unsigned port;
	struct sockaddr_in a;
	int srv_, cl, ac;
	char buf[8];

	pdir("ng4");
	OK(unveil(pp("d"), "r"));
	OK(unveil(NULL, NULL));
	pl("stdio rpath inet");
	srv_ = bound4(SOCK_STREAM, &port);
	CHECK(listen(srv_, 2) == 0);
	cl = socket(AF_INET, SOCK_STREAM, 0);
	a = loop4(port);
	CHECK(cl >= 0 && connect(cl, (struct sockaddr *)&a, sizeof a) == 0);	/* any port: nothing filters it */
	ac = accept(srv_, NULL, NULL);
	CHECK(ac >= 0 && send(cl, "net", 3, 0) == 3 && recv(ac, buf, sizeof buf, 0) == 3);
	errno = 0;
	CHECK(open(pp("f"), O_RDONLY) == -1 && errno == EACCES);
}

PKILL(inet_no_rpath, "stdio inet", (void)0, (void)open(pp("f"), O_RDONLY))
PKILL(inet_no_exec, "stdio inet", (void)0, (void)execl("/bin/true", "true", (char *)NULL))
PKILL(stdio_no_socket, "stdio", (void)0, (void)socket(AF_INET, SOCK_STREAM, 0))
PKILL(stdio_no_bind, "stdio", (void)0, { struct sockaddr_in a = loop4(0); (void)bind(0, (struct sockaddr *)&a, sizeof a); })
PKILL(stdio_no_listen, "stdio", (void)0, (void)listen(0, 1))
PKILL(stdio_no_accept, "stdio", (void)0, (void)accept4(0, NULL, NULL, 0))

/* ------------------------------------------------------------------ */
/* milestone 3, fourth part: exec                                      */
/* ------------------------------------------------------------------ */

static char hs[4096], hd[4096], interp[512];

/* the interpreter a dynamic executable asks for, read from its program headers */
static int
find_interp(const char *path, char *out, size_t max)
{
	Elf64_Ehdr eh;
	Elf64_Phdr ph;
	int fd = open(path, O_RDONLY), i, ok = -1;

	if (fd < 0)
		return -1;
	if (pread(fd, &eh, sizeof eh, 0) == sizeof eh)
		for (i = 0; i < eh.e_phnum; i++) {
			if (pread(fd, &ph, sizeof ph, (off_t)(eh.e_phoff + (size_t)i * eh.e_phentsize)) != sizeof ph)
				break;
			if (ph.p_type == PT_INTERP && ph.p_filesz < max &&
			    pread(fd, out, ph.p_filesz, (off_t)ph.p_offset) == (ssize_t)ph.p_filesz) {
				out[ph.p_filesz] = 0;
				ok = 0;
				break;
			}
		}
	close(fd);
	return ok;
}

extern char **environ;

/* run a program in a child; the status is the wait status, or a code that says execve failed */
static int
run_prog_ex(const char *path, const char *a1, const char *a2, int nest)
{
	pid_t p;
	int st = -1;

	fflush(NULL);
	p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		char *av[4];

		if (nest && vow_scope_enter_child() != 0)
			_exit(99);
		av[0] = (char *)path;
		av[1] = (char *)a1;
		av[2] = (char *)a2;
		av[3] = NULL;
		execve(path, av, environ);
		_exit(60 + (errno & 0x1f));	/* 73 is EACCES */
	}
	CHECK(waitpid(p, &st, 0) == p);
	return st;
}

static int
run_prog(const char *path, const char *a1, const char *a2)
{
	return run_prog_ex(path, a1, a2, 0);
}

#define EXITED(st, code) (WIFEXITED(st) && WEXITSTATUS(st) == (code))
#define EXEC_EACCES (60 + EACCES)

static void
t_exec_static_ok(void)
{
	enable_fork();
	pl("stdio exec");	/* no rpath, no unveil: a static program needs nothing from the pledge but exec */
	CHECK(EXITED(run_prog(hs, "ok", NULL), 0));
	CHECK(EXITED(run_prog(hs, "print", NULL), 0));
}

/* the new program runs under the filter it inherited: its first violation kills it */
static void
t_exec_filter_inherited(void)
{
	int st;

	enable_fork();
	pl("stdio exec");
	st = run_prog(hs, "socket", NULL);
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
}

static void
t_exec_status(void)
{
	enable_fork();
	pl("stdio rpath exec");
	/* no_new_privs and a seccomp filter in the new image, as the kernel reports them */
	CHECK(EXITED(run_prog(hs, "status", NULL), 0));
}

static void
t_exec_not_promised(void)
{
	int st;

	enable_fork();
	pl("stdio rpath");
	st = run_prog(hs, "ok", NULL);	/* the child's execve is a violation */
	CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS);
}

static void
t_exec_with_unveil(void)
{
	enable_fork();
	OK(unveil(hs, "rx"));
	OK(unveil(NULL, NULL));
	pl("stdio rpath exec");
	CHECK(EXITED(run_prog(hs, "ok", NULL), 0));
	/* the domain came along: the new program cannot open what the old one could not */
	CHECK(EXITED(run_prog(hs, "open", "/etc/passwd"), 0));
	CHECK(EXITED(run_prog(hs, "open", hs), 10));
	/* and executables that were not unveiled are refused by landlock with an error, not a kill */
	CHECK(EXITED(run_prog(hd, "ok", NULL), EXEC_EACCES));
	CHECK(EXITED(run_prog(self, "--child", NULL), EXEC_EACCES));
}

static void
t_exec_dynamic(void)
{
	CHECK(find_interp(hd, interp, sizeof interp) == 0);
	enable_fork();
	OK(unveil(hd, "rx"));
	{
		char dir[512], *sl;

		snprintf(dir, sizeof dir, "%s", interp);
		sl = strrchr(dir, '/');
		if (sl)
			*sl = 0;
		OK(unveil(dir, "rx"));	/* the directory of the interpreter */
	}
	OK(unveil(NULL, NULL));
	pl("stdio rpath exec");
	CHECK(EXITED(run_prog(hd, "ok", NULL), 0));
	CHECK(EXITED(run_prog(hd, "print", NULL), 0));
	CHECK(EXITED(run_prog(hd, "status", NULL), 3));	/* /proc is not unveiled: landlock closes it for the new program too */
}

/* the interpreter is a second executable: it needs its own x, landlock checks it separately */
static void
t_exec_dynamic_interp_not_unveiled(void)
{
	CHECK(find_interp(hd, interp, sizeof interp) == 0);
	enable_fork();
	OK(unveil(hd, "rx"));
	OK(unveil(NULL, NULL));
	pl("stdio rpath exec");
	CHECK(EXITED(run_prog(hd, "ok", NULL), EXEC_EACCES));
}

/* a dynamic program that links only the libc needs no file access to start (a program with other libraries would open them) */
static void
t_exec_dynamic_needs_rpath(void)
{
	int st;

	enable_fork();
	pl("stdio exec");
	st = run_prog(hd, "ok", NULL);
	/* musl keeps its libc in the interpreter, so a program with no other library opens nothing */
	CHECK(EXITED(st, 0));
}

static void
t_exec_fexecve(void)
{
	int fd, st;

	fd = open(hs, O_RDONLY | O_CLOEXEC);
	CHECK(fd >= 0);
	enable_fork();
	pl("stdio exec");
	fflush(NULL);
	{
		pid_t p = fork();
		char *av[3] = { (char *)hs, (char *)"ok", NULL };

		CHECK(p >= 0);
		if (p == 0) {
			syscall(VOW_NR_execveat, fd, "", av, environ, VOW_AT_EMPTY_PATH);
			_exit(60 + (errno & 0x1f));
		}
		CHECK(waitpid(p, &st, 0) == p);
	}
	CHECK(EXITED(st, 0));	/* running a descriptor is allowed by exec as running a path is */
}

/* landlock judges the file again at execveat, so a descriptor does not get around the exec rule */
static void
t_exec_fexecve_with_unveil(void)
{
	int fd, st;

	fd = open(hs, O_RDONLY | O_CLOEXEC);
	CHECK(fd >= 0);
	enable_fork();
	OK(unveil(self, "rx"));	/* not the helper */
	OK(unveil(NULL, NULL));
	pl("stdio exec");
	fflush(NULL);
	{
		pid_t p = fork();
		char *av[3] = { (char *)hs, (char *)"ok", NULL };

		CHECK(p >= 0);
		if (p == 0) {
			syscall(VOW_NR_execveat, fd, "", av, environ, VOW_AT_EMPTY_PATH);
			_exit(60 + (errno & 0x1f));
		}
		CHECK(waitpid(p, &st, 0) == p);
	}
	CHECK(EXITED(st, EXEC_EACCES));
}

/* descriptors cross exec: an untrusted program inherits everything not marked close-on-exec */
static void
t_exec_inherited_descriptors(void)
{
	char num[16];
	int fd, fdc;

	pdir("ex_fd");
	fd = open(pp("f"), O_WRONLY);	/* not close-on-exec */
	fdc = open(pp("g"), O_WRONLY | O_CLOEXEC);
	CHECK(fd >= 0 && fdc >= 0);
	enable_fork();
	OK(unveil(hs, "rx"));	/* the file the descriptor names is not reachable by path any more */
	OK(unveil(NULL, NULL));
	pl("stdio exec");
	errno = 0;
	snprintf(num, sizeof num, "%d", fd);
	/* the descriptor crosses into the new program, which writes to a file it could not open */
	CHECK(EXITED(run_prog(hs, "writefd", num), 0));
	snprintf(num, sizeof num, "%d", fdc);
	/* close-on-exec closes it: the helper sees a bad descriptor */
	CHECK(!EXITED(run_prog(hs, "writefd", num), 0));
}

static void
exec_after_close_range(void)
{
	char *av[4];
	char num[16];

	syscall(VOW_NR_close_range, 3, ~0u, 0);	/* allowed by stdio: everything but 0, 1, 2 */
	snprintf(num, sizeof num, "%d", 3);
	av[0] = (char *)hs;
	av[1] = (char *)"writefd";
	av[2] = num;
	av[3] = NULL;
	execve(hs, av, environ);
	_exit(60 + (errno & 0x1f));
}

static void
t_exec_close_range_before(void)
{
	int fd, st;
	pid_t p;

	pdir("ex_cr");
	fd = open(pp("f"), O_WRONLY);
	CHECK(fd == 3 || fd > 3);
	if (fd != 3) {
		CHECK(dup2(fd, 3) == 3);
	}
	enable_fork();
	pl("stdio exec");
	fflush(NULL);
	p = fork();
	CHECK(p >= 0);
	if (p == 0)
		exec_after_close_range();
	CHECK(waitpid(p, &st, 0) == p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) != 0);	/* nothing left to write to */
}



/* the signal domain goes into the new program too: it is the domain of the parent unless the child nested one */
static void
t_exec_signal_domain(void)
{
	char num[16];
	pid_t other;

	other = spawn_unrelated();
	enable_fork();
	pls("stdio exec");
	snprintf(num, sizeof num, "%d", (int)getpid());
	CHECK(EXITED(run_prog(hs, "sig", num), 10));	/* same domain as the parent that sent it: allowed */
	CHECK(EXITED(run_prog_ex(hs, "sig", num, 1), 0));	/* nested by the child before the exec: refused */
	snprintf(num, sizeof num, "%d", (int)other);
	CHECK(EXITED(run_prog(hs, "sig", num), 0));	/* unrelated: refused either way */
	CHECK(EXITED(run_prog_ex(hs, "sig", num, 1), 0));
}

static void
t_exec_promise_strings(void)
{
	OK(pledge("stdio rpath exec", "stdio rpath exec"));
	ERR(pledge("stdio rpath", "stdio rpath exec"), ENOTSUP);
	ERR(pledge("stdio rpath", "stdio"), ENOTSUP);
	OK(pledge("stdio rpath", NULL));
}

PKILL(x_no_socket, "stdio rpath exec", (void)0, (void)socket(AF_INET, SOCK_STREAM, 0))
PKILL(x_no_write, "stdio rpath exec", (void)0, (void)open(pp("f"), O_WRONLY))
PKILL(x_no_create, "stdio rpath exec", (void)0, (void)mkdir(pp("nd"), 0700))

/* ------------------------------------------------------------------ */

static const struct test tests[] = {
	{ "kernel differential, stdio", t_kdiff_stdio, 0 },
	{ "kernel differential, empty set", t_kdiff_empty, 0 },
	{ "kernel differential, path promises", t_kdiff_paths, 0 },
	{ "argument errors, nothing installed", t_args, 0 },
	{ "execpromises must equal promises", t_exec_promises_equal, 0 },
	{ "widening refused", t_widen_refused, 0 },
	{ "narrowing takes effect", t_narrow_then_dead, SIGSYS },
	{ "empty set still allows exit", t_empty_exit_ok, 0 },
	{ "empty set kills getpid", t_empty_getpid, SIGSYS },
	{ "extra filter cannot widen", t_intersection, SIGSYS },
	{ "failed install changes nothing", t_install_failure, 0 },
	{ "unveil locked by pledge", t_unveil_locked, 0 },
	{ "filter and nnp survive exec", t_exec_inherits, 0 },
	{ "musl smoke test under stdio", t_smoke, 0 },
	{ "clone3 answers enosys", t_clone3_answer, 0 },
	{ "abort in the main thread is SIGABRT", t_abort_dies, SIGABRT },
	{ "fork", t_fork, SIGSYS },
	{ "mprotect w+x", t_mprotect_wx, SIGSYS },
	{ "mmap w+x", t_mmap_wx, SIGSYS },
	{ "thread violation ends process", t_thread_violation, SIGSYS },
	{ "thread existing at pledge time", t_existing_thread, SIGSYS },
	{ "thread created after pledge", t_new_thread, SIGSYS },
	{ "socket", t_socket, SIGSYS },
	{ "open", t_open, SIGSYS },
	{ "sendto with address", t_sendto_addr, SIGSYS },
	{ "setrlimit", t_setrlimit, SIGSYS },
	{ "prlimit of another process", t_prlimit_other, SIGSYS },
	{ "ioctl tiocsti", t_tiocsti, SIGSYS },
	{ "fcntl setown", t_setown, SIGSYS },
	{ "x32 call", t_x32, SIGSYS },
	{ "32-bit int 0x80", t_int80, SIGSYS },
	{ "w^x is not enforced over time", t_wx_transitions, 0 },
	{ "injected code is still filtered", t_injected_code, SIGSYS },
	{ "mprotect w+x with high bits", t_mprotect_wx_high_bits, SIGSYS },
	{ "mprotect w+x with growsdown", t_mprotect_growsdown_wx, SIGSYS },
	{ "failed install keeps no_new_privs", t_failed_install_keeps_nnp, 0 },
	{ "scope entered once over failed installs", t_scope_entered_once_over_failed_installs, 0 },
	{ "a refused promise string changes nothing", t_bad_promise_changes_nothing, 0 },
	{ "tsync conflict returns a thread id", t_tsync_conflict, 0 },
	{ "concurrent pledge calls", t_pledge_race, 0 },
	{ "kernel: how open flags really behave", t_kernel_open_truths, 0 },
	{ "rpath: reading works", t_rpath_works, 0 },
	{ "rpath: O_WRONLY", k_wronly, SIGSYS },
	{ "rpath: O_RDWR", k_rdwr, SIGSYS },
	{ "rpath: access mode 3", k_mode3, SIGSYS },
	{ "rpath: O_RDONLY|O_CREAT", k_creat_rd, SIGSYS },
	{ "rpath: O_RDONLY|O_TRUNC", k_trunc_rd, SIGSYS },
	{ "rpath: O_TMPFILE", k_tmpfile, SIGSYS },
	{ "rpath: creat()", k_creat_call, SIGSYS },
	{ "rpath: openat O_WRONLY", k_openat_wr, SIGSYS },
	{ "rpath: O_WRONLY with junk above 32 bits", k_junk_wr, SIGSYS },
	{ "rpath: unlink", k_unlink, SIGSYS },
	{ "rpath: mkdir", k_mkdir, SIGSYS },
	{ "rpath: rename", k_rename, SIGSYS },
	{ "rpath: truncate", k_truncate, SIGSYS },
	{ "rpath: chmod", k_chmod, SIGSYS },
	{ "rpath: socket", k_socket, SIGSYS },
	{ "stdio without rpath: stat", t_stdio_only_stat, SIGSYS },
	{ "unveil then rpath", t_unveil_then_rpath, 0 },
	{ "unveil write, pledge read only", t_unveil_write_pledge_read, SIGSYS },
	{ "rpath then unveil", t_rpath_then_unveil, 0 },
	{ "unveil denial under rpath", t_rpath_unveil_denied_path_kills_nothing, 0 },
	{ "signal handler calls pledge inside pledge", t_reentrant_pledge, 0 },
	{ "signal handler calls unveil inside pledge", t_reentrant_pledge_into_unveil, 0 },
	{ "signal handler calls unveil inside unveil", t_reentrant_unveil, 0 },
	{ "fork while another thread is in unveil", t_atfork_unveil, 0 },
	{ "fork while another thread is in pledge", t_atfork_pledge, 0 },
	{ "descriptors from before the sandbox", t_descriptor_exposure, 0 },
	{ "seccomp flag SPEC_ALLOW is refused", k_seccomp_spec_allow, SIGSYS },
	{ "seccomp flag NEW_LISTENER is refused", k_seccomp_listener, SIGSYS },
	{ "landlock log flags are refused", k_landlock_log_flag, SIGSYS },
	{ "landlock tsync flag is refused", k_landlock_tsync_flag, SIGSYS },
	{ "thread list is not inherited by a child", t_thread_list_is_not_inherited, 0 },
	{ "scope reports a thread made during it", t_scope_reports_late_thread, 0 },
	{ "joined threads do not linger in the list", t_joined_threads_do_not_linger, 0 },
	{ "scope refused, a stricter sibling keeps its domain", t_scope_refused_keeps_sibling_domain, 0 },
	{ "scope stacks on an existing domain", t_scope_stacks_on_existing_domain, 0 },
	{ "S2: abi 5 refuses stdio", t_s2_old_abi_refused, 0 },
	{ "S2: no landlock refuses stdio", t_s2_no_landlock_refused, 0 },
	{ "S2: stdio refused with other threads, any abi", t_s2_abi7_threads_refused, 0 },
	{ "S2: abi 7 single threaded works", t_s2_abi7_single_thread_ok, 0 },
	{ "S2: a real error is not hidden", t_s2_error_not_hidden, 0 },
	{ "S2: the filter has no ids in it", t_s2_filter_has_no_ids, 0 },
	{ "fork: libc fork shares the domain", t_fork_libc_shares_domain, 0 },
	{ "fork: raw fork shares the domain", t_fork_raw_shares_domain, 0 },
	{ "fork: explicit nesting isolates the child", t_fork_explicit_nesting, 0 },
	{ "fork: nesting down the generations", t_fork_nesting_generations, 0 },
	{ "fork: the layer limit of nesting", t_nesting_layer_limit, 0 },
	{ "supervisor signals a pledged worker", t_sup_signals_worker, 0 },
	{ "normal shutdown of a worker", t_sup_normal_shutdown, 0 },
	{ "worker cannot signal its supervisor", t_sup_worker_cannot_signal_supervisor, 0 },
	{ "parent-death signal from outside arrives", t_sup_pdeathsig_from_outside, 0 },
	{ "parent-death signal from a scoped parent is blocked", t_sup_pdeathsig_from_scoped_parent, 0 },
	{ "group signals reach only the domain", t_scope_group_signal, 0 },
	{ "scope: main thread, confined and working", t_scope_main_thread, 0 },
	{ "scope: threads after the pledge, confined, cancellable", t_scope_threads, 0 },
	{ "scope: thread created after the pledge", t_scope_new_thread, 0 },
	{ "scope: abort in the main thread", t_scope_abort_main, SIGABRT },
	{ "scope: abort in a secondary thread", t_scope_abort_thread, SIGABRT },
	{ "scope: two pledged processes are siblings", t_scope_siblings, 0 },
	{ "scope: unveil first", t_scope_unveil_first, 0 },
	{ "scope: pledge first", t_scope_pledge_first, 0 },
	{ "raw fork keeps a lock held by another thread", t_raw_fork_keeps_lock, 0 },
	{ "fork stress against a busy thread", t_fork_stress, 0 },
	{ "fork from a secondary thread", t_fork_from_thread, 0 },
	{ "inet: tcp on loopback, options, nonblocking connect", t_inet_tcp, 0 },
	{ "inet: udp on loopback, sendto and sendmsg with addresses", t_inet_udp, 0 },
	{ "inet: ipv6 on loopback", t_inet6, 0 },
	{ "inet: numeric address lookup needs no files", t_inet_numeric_lookup, 0 },
	{ "inet: a name needs files, killed without rpath", t_inet_name_lookup_needs_files, SIGSYS },
	{ "inet: a name with rpath and unveil of /etc/hosts", t_inet_name_lookup_with_files, 0 },
	{ "inet: AF_UNIX", n_unix, SIGSYS },
	{ "inet: AF_PACKET", n_packet, SIGSYS },
	{ "inet: AF_NETLINK", n_netlink, SIGSYS },
	{ "inet: SOCK_RAW", n_raw, SIGSYS },
	{ "inet: SOCK_SEQPACKET", n_seqpacket, SIGSYS },
	{ "inet: sctp", n_sctp, SIGSYS },
	{ "inet: icmp datagram", n_icmp, SIGSYS },
	{ "inet: udplite", n_udplite, SIGSYS },
	{ "inet: mptcp", n_mptcp, SIGSYS },
	{ "inet: unknown type flag", n_flagbit, SIGSYS },
	{ "inet: SO_ATTACH_FILTER", n_filter, SIGSYS },
	{ "inet: SO_ATTACH_BPF", n_bpf, SIGSYS },
	{ "inet: SO_BINDTODEVICE", n_bindtodev, SIGSYS },
	{ "inet: SO_MARK", n_mark, SIGSYS },
	{ "inet: TCP_ULP", n_ulp, SIGSYS },
	{ "inet: IP_OPTIONS", n_ipoptions, SIGSYS },
	{ "inet: IP_MULTICAST_IF", n_mcast, SIGSYS },
	{ "inet: TCP_CONGESTION", n_congestion, SIGSYS },
	{ "inet: no rpath", inet_no_rpath, SIGSYS },
	{ "inet: no exec", inet_no_exec, SIGSYS },
	{ "stdio: no socket", stdio_no_socket, SIGSYS },
	{ "stdio: no bind", stdio_no_bind, SIGSYS },
	{ "stdio: no listen", stdio_no_listen, SIGSYS },
	{ "stdio: no accept", stdio_no_accept, SIGSYS },
	{ "existing connected socket under stdio", t_pre_connected_stdio, 0 },
	{ "existing unconnected socket cannot connect under stdio", k_pre_connect_setup, SIGSYS },
	{ "existing udp socket: sendmsg to anywhere (gap)", t_pre_udp_sendmsg_gap, 0 },
	{ "existing udp socket: sendto with address", t_pre_udp_sendto_addr, SIGSYS },
	{ "inet: connect and bind take unix sockets (gap)", t_inet_unix_gap_no_unveil, 0 },
	{ "inet: unix sockets with unveil, no s, no c", t_inet_unix_with_unveil, 0 },
	{ "inet: unix sockets with unveil s", t_inet_unix_with_s, 0 },
	{ "inet: with unveil, network untouched", t_inet_with_unveil, 0 },
	{ "exec: static program, no rpath needed", t_exec_static_ok, 0 },
	{ "exec: new program under the inherited filter", t_exec_filter_inherited, 0 },
	{ "exec: no_new_privs and filter in the new image", t_exec_status, 0 },
	{ "exec: not promised", t_exec_not_promised, 0 },
	{ "exec: with unveil, domain inherited", t_exec_with_unveil, 0 },
	{ "exec: dynamic program", t_exec_dynamic, 0 },
	{ "exec: interpreter must be unveiled too", t_exec_dynamic_interp_not_unveiled, 0 },
	{ "exec: dynamic program, libc only, without rpath", t_exec_dynamic_needs_rpath, 0 },
	{ "exec: execveat on a descriptor", t_exec_fexecve, 0 },
	{ "exec: execveat on a descriptor with unveil", t_exec_fexecve_with_unveil, 0 },
	{ "exec: descriptors cross exec", t_exec_inherited_descriptors, 0 },
	{ "exec: close_range before exec", t_exec_close_range_before, 0 },
	{ "exec: signal domain goes into the new program", t_exec_signal_domain, 0 },
	{ "exec: execpromises must equal promises", t_exec_promise_strings, 0 },
	{ "exec: still no socket", x_no_socket, SIGSYS },
	{ "exec: still no write", x_no_write, SIGSYS },
	{ "exec: still no create", x_no_create, SIGSYS },
	{ "wpath works", t_wpath_works, 0 },
	{ "cpath works", t_cpath_works, 0 },
	{ "rpath+cpath", t_rpath_cpath, 0 },
	{ "wpath+cpath", t_wpath_cpath, 0 },
	{ "rpath+wpath", t_rpath_wpath, 0 },
	{ "all three", t_all_three, 0 },
	{ "unveil rw, all promises", t_unveil_rw_all_promises, 0 },
	{ "unveil rwc, all promises", t_unveil_rwc_all_promises, 0 },
	{ "pledge then unveil, with paths", t_unveil_after_pledge_paths, 0 },
	{ "wpath: O_RDONLY", w_rdonly, SIGSYS },
	{ "wpath: O_RDWR", w_rdwr, SIGSYS },
	{ "wpath: O_CREAT", w_creat, SIGSYS },
	{ "wpath: creat()", w_creat_call, SIGSYS },
	{ "wpath: mkdir", w_mkdir, SIGSYS },
	{ "wpath: unlink", w_unlink, SIGSYS },
	{ "wpath: rename", w_rename, SIGSYS },
	{ "wpath: stat", w_stat, SIGSYS },
	{ "wpath: O_PATH", w_opath, SIGSYS },
	{ "wpath: O_TMPFILE", w_tmpfile, SIGSYS },
	{ "wpath: symlink", w_symlink, SIGSYS },
	{ "cpath: O_RDONLY", c_rdonly, SIGSYS },
	{ "cpath: O_WRONLY", c_wronly, SIGSYS },
	{ "cpath: O_CREAT|O_WRONLY", c_creat_wr, SIGSYS },
	{ "cpath: O_CREAT|O_RDONLY", c_creat_rd, SIGSYS },
	{ "cpath: creat()", c_creat_call, SIGSYS },
	{ "cpath: truncate", c_truncate, SIGSYS },
	{ "cpath: stat", c_stat, SIGSYS },
	{ "cpath: mkfifo", c_mkfifo, SIGSYS },
	{ "cpath: renameat2 WHITEOUT", c_whiteout, SIGSYS },
	{ "cpath: renameat2 WHITEOUT, junk above bit 31", c_whiteout_junk, SIGSYS },
	{ "cpath: linkat AT_EMPTY_PATH", c_empty_path, SIGSYS },
	{ "cpath: linkat AT_EMPTY_PATH, junk above bit 31", c_empty_path_junk, SIGSYS },
	{ "cpath: chmod", c_chmod, SIGSYS },
	{ "cpath: exec", c_exec, SIGSYS },
	{ "rpath+cpath: O_WRONLY|O_CREAT", rc_wr, SIGSYS },
	{ "rpath+cpath: O_RDONLY|O_TRUNC", rc_trunc, SIGSYS },
	{ "rpath+cpath: O_RDONLY|O_CREAT|O_TRUNC", rc_creat_trunc, SIGSYS },
	{ "wpath+cpath: O_RDWR|O_CREAT", wc_rdwr_creat, SIGSYS },
	{ "wpath+cpath: O_RDONLY", wc_rdonly, SIGSYS },
	{ "wpath+cpath: stat", wc_stat, SIGSYS },
	{ "rpath+wpath: O_CREAT", rw_creat, SIGSYS },
	{ "rpath+wpath: mkdir", rw_mkdir, SIGSYS },
	{ "rpath+wpath: unlink", rw_unlink, SIGSYS },
	{ "rpath+wpath: O_TMPFILE", rw_tmpfile, SIGSYS },
	{ "all three: mkfifo", a_mkfifo, SIGSYS },
	{ "all three: renameat2 WHITEOUT", a_whiteout, SIGSYS },
	{ "all three: linkat AT_EMPTY_PATH", a_empty_path, SIGSYS },
	{ "all three: chmod", a_chmod, SIGSYS },
	{ "all three: utimensat", a_utimens, SIGSYS },
	{ "all three: setxattr", a_setxattr, SIGSYS },
	{ "all three: exec", a_exec, SIGSYS },
	{ "all three: socket", a_socket, SIGSYS },
	{ "all three: mount", a_mount, SIGSYS },
	{ "unveil allows write, pledge has rpath only", u_write_seccomp_wins, SIGSYS },
	{ "unveil allows create, pledge lacks cpath", u_mkdir_seccomp_wins, SIGSYS },
};

int
main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "--probe") == 0) {
		/* the exec-ed program: still judged by the filter, still no_new_privs */
		errno = 0;
		if (socket(AF_INET, SOCK_DGRAM, 0) != -1 || errno != (int)SENTINEL)
			return 1;
		return prctl(39 /* PR_GET_NO_NEW_PRIVS */, 0, 0, 0, 0) == 1 ? 0 : 2;
	}
	if (realpath(argv[0], self) == NULL) {
		perror("realpath");
		return 1;
	}
	{
		char dir[4096];
		char *slash;

		snprintf(dir, sizeof dir, "%s", self);
		slash = strrchr(dir, '/');
		if (slash)
			*slash = 0;
		snprintf(hs, sizeof hs, "%s/hlp_static", dir);
		snprintf(hd, sizeof hd, "%s/hlp_dyn", dir);
	}
	{
		const char *tmp = getenv("TMPDIR");
		char tpl[4096], cmd[4200];
		int rc;

		snprintf(tpl, sizeof tpl, "%s/vowp.XXXXXX", tmp ? tmp : "/tmp");
		if (mkdtemp(tpl) == NULL || realpath(tpl, root) == NULL) {
			perror("mkdtemp");
			return 1;
		}
		rc = t_main(tests, (int)(sizeof tests / sizeof *tests), 215);
		snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
		if (system(cmd) != 0)
			rc = 1;
		return rc;
	}
}
