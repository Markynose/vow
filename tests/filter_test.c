/* SPDX-License-Identifier: LGPL-3.0-only */
#include <errno.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "filter.h"
#include "oracle.h"
#include "t.h"

/* syscalls the policy must refuse or treat specially; numbers from the x86-64 table, not vendored by the library */
#define NR_open 2
#define NR_socket 41
#define NR_connect 42
#define NR_fork 57
#define NR_vfork 58
#define NR_execve 59
#define NR_ptrace 101
#define NR_openat 257
#define NR_newfstatat 262
#define NR_bpf 321
#define NR_statx 332
#define NR_io_uring_setup 425
#define NR_openat2 437
#define NR_unlink 87
#define NR_mkdir 83
#define NR_rename 82
#define NR_truncate 76
#define NR_chmod 90
#define NR_mknod 133
#define NR_mknodat 259
#define NR_stat 4
#define NR_sendto 44
#define NR_setsockopt 54

#define JUNK 0xdeadbeef00000000ull

static const struct vow_ctx ctx = { VOW_SECCOMP_RET_ERRNO | 1001 };

static unsigned sets[] = {
	0, P_STDIO, P_RPATH, P_STDIO | P_RPATH, P_WPATH, P_CPATH, P_RPATH | P_WPATH, P_RPATH | P_CPATH,
	P_WPATH | P_CPATH, P_RPATH | P_WPATH | P_CPATH, P_STDIO | P_RPATH | P_WPATH | P_CPATH,
	P_INET, P_STDIO | P_INET, P_EXEC, P_STDIO | P_RPATH | P_EXEC, P_STDIO | P_INET | P_EXEC,
	P_STDIO | P_RPATH | P_WPATH | P_CPATH | P_INET | P_EXEC
};

static uint64_t rng = 0x9e3779b97f4a7c15ull;

static uint64_t
rnd(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return rng;
}

static void
t_syscall_numbers(void)
{
	int bad = 0;

	/* every vendored number must equal the one this libc ships, where the libc has it */
#define X(n) \
	if (VOW_NR_##n != SYS_##n) { fprintf(stderr, "    %s: %d != %d\n", #n, VOW_NR_##n, SYS_##n); bad = 1; }
#include "nr_list.h"
#undef X
	CHECK(!bad);
}

static void
t_structure(void)
{
	struct vow_insn p[VOW_MAX_INSNS];
	struct vow_insn tiny[10];
	size_t n, i;

	for (i = 0; i < sizeof sets / sizeof *sets; i++) {
		n = vow_build(sets[i], &ctx, p, VOW_MAX_INSNS);
		CHECK(n > 0 && n < VOW_MAX_INSNS);
		CHECK(bpf_validate(p, n));
		printf("    promises 0x%x: %zu instructions\n", sets[i], n);
		{
			struct vow_table t[VOW_MAX_TABLES];
			struct vow_policy pol;

			vow_tables(sets[i], &pol, t);
			CHECK(pol.nrule + 4 < VOW_POLICY_RULES && pol.ncond + 4 < VOW_POLICY_CONDS);
		}
		/* too small a buffer fails closed instead of truncating */
		errno = 0;
		CHECK(vow_build(sets[i], &ctx, tiny, 10) == 0 && errno == E2BIG);
		errno = 0;
		CHECK(vow_build(sets[i], &ctx, p, n - 1) == 0 && errno == E2BIG);
		CHECK(vow_build(sets[i], &ctx, p, n) == n);
	}
	/* the production deny action is a kill of the whole process */
	{
		struct vow_ctx k = { VOW_SECCOMP_RET_KILL_PROCESS };
		struct sdata d;

		n = vow_build(P_STDIO, &k, p, VOW_MAX_INSNS);
		memset(&d, 0, sizeof d);
		d.arch = VOW_AUDIT_ARCH_X86_64;
		d.nr = NR_socket;
		CHECK(bpf_run(p, n, &d) == VOW_SECCOMP_RET_KILL_PROCESS);
	}
}

/* expectations written by hand, independent of the tables and of the oracle */
struct exp {
	unsigned promises;
	uint32_t nr;
	uint64_t a[6];
	uint32_t want;
	const char *why;
};

#define AL VOW_SECCOMP_RET_ALLOW
#define DN (VOW_SECCOMP_RET_ERRNO | 1001)
#define ER(e) (VOW_SECCOMP_RET_ERRNO | (e))
#define THREAD 0x3d0f00ull	/* what glibc passes to clone for a thread */
#define MUSLTHREAD 0x7d0f00ull	/* musl, with the detached bit */

static const struct exp exps[] = {
	/* nothing at all is allowed with no promises except leaving */
	{ 0, VOW_NR_exit_group, { 0 }, AL, "exit_group" },
	{ 0, VOW_NR_exit, { 0 }, AL, "exit" },
	{ 0, VOW_NR_rt_sigreturn, { 0 }, AL, "sigreturn" },
	{ 0, VOW_NR_write, { 1, 0, 1 }, DN, "write with no promises" },
	{ 0, VOW_NR_getpid, { 0 }, DN, "getpid with no promises" },
	{ 0, VOW_NR_seccomp, { 1, 0, 0 }, AL, "seccomp set_mode_filter" },
	{ 0, VOW_NR_seccomp, { 0, 0, 0 }, DN, "seccomp strict" },
	{ 0, VOW_NR_seccomp, { 1 | JUNK, 0, 0 }, AL, "seccomp op, junk above 32 bits" },
	{ 0, VOW_NR_seccomp, { 2, 0, 0 }, DN, "seccomp get_action_avail" },
	{ 0, VOW_NR_seccomp, { 1, 1, 0 }, AL, "seccomp with tsync" },
	{ 0, VOW_NR_seccomp, { 1, 4, 0 }, DN, "seccomp with SPEC_ALLOW switches off a mitigation" },
	{ 0, VOW_NR_seccomp, { 1, 8, 0 }, DN, "seccomp with NEW_LISTENER" },
	{ 0, VOW_NR_seccomp, { 1, 2, 0 }, DN, "seccomp with LOG" },
	{ 0, VOW_NR_seccomp, { 1, 16, 0 }, DN, "seccomp with TSYNC_ESRCH" },
	{ 0, VOW_NR_seccomp, { 1, 1 | JUNK, 0 }, AL, "seccomp flags are an unsigned int" },
	{ 0, VOW_NR_seccomp, { 1, 4 | JUNK, 0 }, DN, "seccomp flags: junk does not hide SPEC_ALLOW" },
	{ 0, VOW_NR_landlock_restrict_self, { 3, 0 }, AL, "landlock_restrict_self, plain" },
	{ 0, VOW_NR_landlock_restrict_self, { 3, 8 }, DN, "landlock_restrict_self with tsync would replace sibling domains" },
	{ 0, VOW_NR_landlock_restrict_self, { 3, 8 | JUNK }, DN, "tsync: junk above bit 31 does not hide it" },
	{ 0, VOW_NR_landlock_restrict_self, { 3, 1 }, DN, "landlock_restrict_self: log flags" },
	{ 0, VOW_NR_landlock_restrict_self, { 3, 4 }, DN, "landlock_restrict_self: subdomain log off" },
	{ 0, VOW_NR_landlock_restrict_self, { 3, 16 }, DN, "landlock_restrict_self: unknown flag" },
	{ 0, VOW_NR_prctl, { 38, 1 }, AL, "prctl no_new_privs" },
	{ 0, VOW_NR_prctl, { 38, 0 }, DN, "prctl no_new_privs value 0" },
	{ 0, VOW_NR_prctl, { 38, 1 | (1ull << 32) }, DN, "prctl nnp value is unsigned long: high bits count" },
	{ 0, VOW_NR_prctl, { 38 | JUNK, 1 }, AL, "prctl option is int: high bits ignored" },
	{ 0, VOW_NR_prctl, { 15 }, DN, "set_name needs stdio" },
	{ 0, VOW_NR_landlock_restrict_self, { 0 }, AL, "landlock_restrict_self" },
	/* stdio, plain */
	{ P_STDIO, VOW_NR_read, { 0 }, AL, "read" },
	{ P_STDIO, VOW_NR_fstat, { 0 }, AL, "fstat" },
	{ P_STDIO, NR_newfstatat, { 0 }, DN, "newfstatat is rpath" },
	{ P_STDIO, NR_statx, { 0 }, DN, "statx is rpath" },
	{ P_STDIO, NR_open, { 0 }, DN, "open" },
	{ P_STDIO, NR_openat, { 0 }, DN, "openat" },
	{ P_STDIO, NR_socket, { 2, 1, 0 }, DN, "socket" },
	{ P_STDIO, NR_connect, { 0 }, DN, "connect" },
	{ P_STDIO, NR_execve, { 0 }, DN, "execve" },
	{ P_STDIO, NR_ptrace, { 0 }, DN, "ptrace" },
	{ P_STDIO, NR_fork, { 0 }, DN, "fork" },
	{ P_STDIO, NR_vfork, { 0 }, DN, "vfork" },
	{ P_STDIO, NR_io_uring_setup, { 0 }, DN, "io_uring_setup" },
	{ P_STDIO, NR_bpf, { 0 }, DN, "bpf" },
	{ P_STDIO, NR_openat2, { 0 }, DN, "openat2" },
	/* inet */
	{ P_INET, VOW_NR_socket, { 2, 1, 0 }, AL, "inet: tcp socket" },
	{ P_INET, VOW_NR_socket, { 2, 1, 6 }, AL, "inet: tcp socket, protocol named" },
	{ P_INET, VOW_NR_socket, { 2, 2, 0 }, AL, "inet: udp socket" },
	{ P_INET, VOW_NR_socket, { 2, 2, 17 }, AL, "inet: udp socket, protocol named" },
	{ P_INET, VOW_NR_socket, { 10, 1, 0 }, AL, "inet: ipv6 tcp" },
	{ P_INET, VOW_NR_socket, { 10, 2, 17 }, AL, "inet: ipv6 udp" },
	{ P_INET, VOW_NR_socket, { 2, 1 | 0x80000, 0 }, AL, "inet: SOCK_CLOEXEC" },
	{ P_INET, VOW_NR_socket, { 2, 2 | 0x800 | 0x80000, 0 }, AL, "inet: SOCK_NONBLOCK|SOCK_CLOEXEC" },
	{ P_INET, VOW_NR_socket, { 2 | JUNK, 1 | JUNK, 0 | JUNK }, AL, "inet: all three are ints" },
	{ P_INET, VOW_NR_socket, { 1, 1, 0 }, DN, "inet: AF_UNIX" },
	{ P_INET, VOW_NR_socket, { 16, 3, 0 }, DN, "inet: AF_NETLINK" },
	{ P_INET, VOW_NR_socket, { 17, 3, 0 }, DN, "inet: AF_PACKET" },
	{ P_INET, VOW_NR_socket, { 2, 3, 0 }, DN, "inet: SOCK_RAW" },
	{ P_INET, VOW_NR_socket, { 2, 5, 0 }, DN, "inet: SOCK_SEQPACKET" },
	{ P_INET, VOW_NR_socket, { 2, 1, 132 }, DN, "inet: sctp" },
	{ P_INET, VOW_NR_socket, { 2, 1, 262 }, DN, "inet: mptcp" },
	{ P_INET, VOW_NR_socket, { 2, 2, 1 }, DN, "inet: ping socket (icmp)" },
	{ P_INET, VOW_NR_socket, { 2, 2, 136 }, DN, "inet: udplite" },
	{ P_INET, VOW_NR_socket, { 2, 1, 17 }, DN, "inet: tcp with the udp protocol" },
	{ P_INET, VOW_NR_socket, { 2, 2, 6 }, DN, "inet: udp with the tcp protocol" },
	{ P_INET, VOW_NR_socket, { 2, 1 | 0x1000, 0 }, DN, "inet: an unknown type flag" },
	{ P_INET, VOW_NR_socket, { 2, 0, 0 }, DN, "inet: type 0" },
	{ P_INET, VOW_NR_socket, { 2, 1 | 0x100000000ull, 0 }, AL, "inet: bit 32 is not a type flag" },
	{ P_STDIO, VOW_NR_socket, { 2, 1, 0 }, DN, "stdio alone: no sockets" },
	{ P_INET, VOW_NR_connect, { 3 }, AL, "inet: connect" },
	{ P_INET, VOW_NR_bind, { 3 }, AL, "inet: bind" },
	{ P_INET, VOW_NR_listen, { 3, 5 }, AL, "inet: listen" },
	{ P_INET, VOW_NR_accept, { 3 }, AL, "inet: accept" },
	{ P_INET, VOW_NR_accept4, { 3, 0, 0, 0x80800 }, AL, "inet: accept4" },
	{ P_INET, VOW_NR_sendmmsg, { 3 }, AL, "inet: sendmmsg" },
	{ P_INET, VOW_NR_recvmmsg, { 3 }, AL, "inet: recvmmsg" },
	{ P_INET, NR_sendto, { 3, 0, 1, 0, 0x1000, 16 }, AL, "inet: sendto with an address" },
	{ P_STDIO, VOW_NR_connect, { 3 }, DN, "stdio alone: no connect" },
	{ P_STDIO, VOW_NR_bind, { 3 }, DN, "stdio alone: no bind" },
	{ P_STDIO, VOW_NR_accept4, { 3 }, DN, "stdio alone: no accept" },
	{ P_STDIO | P_RPATH | P_WPATH | P_CPATH, VOW_NR_connect, { 3 }, DN, "path promises give no network" },
	/* setsockopt: only options that tune a connection */
	{ P_STDIO, NR_setsockopt, { 3, 1, 2 }, AL, "setsockopt SO_REUSEADDR" },
	{ P_STDIO, NR_setsockopt, { 3, 1, 9 }, AL, "setsockopt SO_KEEPALIVE" },
	{ P_STDIO, NR_setsockopt, { 3, 1, 15 }, AL, "setsockopt SO_REUSEPORT" },
	{ P_STDIO, NR_setsockopt, { 3, 6, 1 }, AL, "setsockopt TCP_NODELAY" },
	{ P_STDIO, NR_setsockopt, { 3, 41, 26 }, AL, "setsockopt IPV6_V6ONLY" },
	{ P_STDIO, NR_setsockopt, { 3, 0, 1 }, AL, "setsockopt IP_TOS" },
	{ P_STDIO, NR_setsockopt, { 3, 17, 1 }, AL, "setsockopt UDP_CORK" },
	{ P_STDIO, NR_setsockopt, { 3, 1 | JUNK, 2 | JUNK }, AL, "setsockopt level and option are ints" },
	{ P_STDIO, NR_setsockopt, { 3, 1, 26 }, DN, "setsockopt SO_ATTACH_FILTER" },
	{ P_STDIO, NR_setsockopt, { 3, 1, 50 }, DN, "setsockopt SO_ATTACH_BPF" },
	{ P_STDIO, NR_setsockopt, { 3, 1, 25 }, DN, "setsockopt SO_BINDTODEVICE" },
	{ P_STDIO, NR_setsockopt, { 3, 1, 36 }, DN, "setsockopt SO_MARK" },
	{ P_STDIO, NR_setsockopt, { 3, 6, 31 }, DN, "setsockopt TCP_ULP" },
	{ P_STDIO, NR_setsockopt, { 3, 6, 14 }, DN, "setsockopt TCP_MD5SIG" },
	{ P_STDIO, NR_setsockopt, { 3, 6, 13 }, DN, "setsockopt TCP_CONGESTION" },
	{ P_STDIO, NR_setsockopt, { 3, 0, 4 }, DN, "setsockopt IP_OPTIONS" },
	{ P_STDIO, NR_setsockopt, { 3, 0, 3 }, DN, "setsockopt IP_HDRINCL is 3 at level ip, not allowed" },
	{ P_STDIO, NR_setsockopt, { 3, 0, 32 }, DN, "setsockopt IP_MULTICAST_IF" },
	{ P_STDIO, NR_setsockopt, { 3, 255, 2 }, DN, "setsockopt unknown level" },
	{ P_STDIO, NR_setsockopt, { 3, 1 | (1ull << 32), 2 }, AL, "setsockopt bit 32 of level is ignored" },
	{ P_INET, NR_setsockopt, { 3, 1, 2 }, DN, "inet alone: setsockopt is stdio" },
	{ P_STDIO, VOW_NR_getsockopt, { 3, 6, 31 }, AL, "getsockopt stays open" },
	/* exec */
	{ P_EXEC, VOW_NR_execve, { 0 }, AL, "exec: execve" },
	{ P_EXEC, VOW_NR_execveat, { 0 }, AL, "exec: execveat" },
	{ P_STDIO | P_RPATH | P_WPATH | P_CPATH | P_INET, VOW_NR_execve, { 0 }, DN, "everything else: still no exec" },
	{ P_EXEC, VOW_NR_socket, { 2, 1, 0 }, DN, "exec alone: no sockets" },
	{ P_EXEC, NR_open, { 0, 0 }, DN, "exec alone: no open" },
	{ P_EXEC, VOW_NR_read, { 0 }, DN, "exec alone: no read" },
	/* signals: the filter lets the five calls through with stdio, any arguments; the landlock scope that pledge() enters first does the confining */
	{ P_STDIO, VOW_NR_kill, { 1, 9 }, AL, "kill any pid (the scope confines it)" },
	{ P_STDIO, VOW_NR_kill, { 0, 9 }, AL, "kill process group" },
	{ P_STDIO, VOW_NR_kill, { 0xffffffffull, 9 }, AL, "kill -1" },
	{ P_STDIO, VOW_NR_tgkill, { 1, 1, 9 }, AL, "tgkill any" },
	{ P_STDIO, VOW_NR_tkill, { 99, 9 }, AL, "tkill any thread" },
	{ P_STDIO, VOW_NR_rt_sigqueueinfo, { 1, 9 }, AL, "rt_sigqueueinfo" },
	{ P_STDIO, VOW_NR_rt_tgsigqueueinfo, { 1, 1, 9 }, AL, "rt_tgsigqueueinfo" },
	{ 0, VOW_NR_kill, { 1, 9 }, DN, "no stdio, no kill" },
	{ P_RPATH | P_WPATH | P_CPATH | P_INET | P_EXEC, VOW_NR_tkill, { 1, 9 }, DN, "no stdio, no tkill" },
	{ P_RPATH, VOW_NR_rt_sigqueueinfo, { 1, 9 }, DN, "no stdio, no sigqueue" },
	/* rpath: reading paths, and what the open flags need */
	{ P_STDIO, VOW_NR_stat, { 0 }, DN, "stat needs rpath" },
	{ P_RPATH, VOW_NR_stat, { 0 }, AL, "stat with rpath" },
	{ P_RPATH, VOW_NR_newfstatat, { 0 }, AL, "newfstatat with rpath" },
	{ P_RPATH, VOW_NR_statx, { 0 }, AL, "statx with rpath" },
	{ P_RPATH, VOW_NR_readlink, { 0 }, AL, "readlink with rpath" },
	{ P_RPATH, VOW_NR_getdents64, { 0 }, AL, "getdents64 with rpath" },
	{ P_RPATH, VOW_NR_getcwd, { 0 }, AL, "getcwd with rpath" },
	{ P_RPATH, VOW_NR_chdir, { 0 }, AL, "chdir with rpath" },
	{ P_RPATH, VOW_NR_read, { 0 }, DN, "rpath alone does not read descriptors (that is stdio)" },
	{ P_RPATH, NR_socket, { 2, 1, 0 }, DN, "rpath does not give sockets" },
	{ P_RPATH, NR_unlink, { 0 }, DN, "unlink is cpath" },
	{ P_RPATH, NR_mkdir, { 0 }, DN, "mkdir is cpath" },
	{ P_RPATH, NR_rename, { 0 }, DN, "rename is cpath" },
	{ P_RPATH, NR_truncate, { 0 }, DN, "truncate is wpath" },
	{ P_RPATH, NR_chmod, { 0 }, DN, "chmod is fattr" },
	{ P_RPATH, NR_execve, { 0 }, DN, "execve is exec" },
	{ P_RPATH, NR_openat2, { 0 }, ER(38), "openat2 answers enosys by policy" },
	{ P_STDIO, NR_openat2, { 0 }, DN, "openat2 without a path promise" },
	{ P_RPATH, VOW_NR_creat, { 0 }, DN, "creat is create+write" },
	{ P_RPATH, NR_open, { 0, 0 }, AL, "open O_RDONLY" },
	{ P_RPATH, NR_open, { 0, 1 }, DN, "open O_WRONLY" },
	{ P_RPATH, NR_open, { 0, 2 }, DN, "open O_RDWR" },
	{ P_RPATH, NR_open, { 0, 0x200 }, DN, "open O_RDONLY|O_TRUNC truncates, so it writes" },
	{ P_RPATH, NR_open, { 0, 0x40 }, DN, "open O_RDONLY|O_CREAT" },
	{ P_RPATH, NR_open, { 0, 0x410000 }, DN, "open O_TMPFILE" },
	{ P_RPATH, NR_open, { 0, 0x200000 }, AL, "open O_PATH" },
	{ P_RPATH, NR_open, { 0, 0x200000 | 0x241 }, AL, "open O_PATH, the kernel drops the rest" },
	{ P_RPATH, NR_open, { 0, 0x88000 }, AL, "open with O_CLOEXEC|O_LARGEFILE (musl)" },
	{ P_RPATH, NR_open, { 0, 0x10000 | 0x80000 }, AL, "open O_DIRECTORY|O_CLOEXEC" },
	{ P_RPATH, NR_open, { 0, JUNK }, AL, "open flags are an int" },
	{ P_RPATH, NR_open, { 0, 1 | JUNK }, DN, "open O_WRONLY with junk above 32 bits" },
	{ P_RPATH, NR_openat, { 0, 0, 0 }, AL, "openat O_RDONLY" },
	{ P_RPATH, NR_openat, { 0, 0, 1 }, DN, "openat O_WRONLY" },
	{ P_RPATH, NR_openat, { 0, 0, 0x200000 | 1 }, AL, "openat O_PATH|O_WRONLY" },
	{ P_RPATH, NR_openat, { 0, 1, 0 }, AL, "openat flags are argument 2, not 1" },
	{ P_RPATH, NR_open, { 0, 0, 1 }, AL, "open flags are argument 1, not 2" },
	{ P_WPATH, NR_open, { 0, 1 }, AL, "wpath: O_WRONLY" },
	{ P_WPATH, NR_open, { 0, 0 }, DN, "wpath: O_RDONLY" },
	{ P_WPATH, NR_open, { 0, 1 | 0x200 }, AL, "wpath: O_WRONLY|O_TRUNC" },
	{ P_WPATH, NR_open, { 0, 2 }, DN, "wpath: O_RDWR needs rpath too" },
	{ P_WPATH, NR_open, { 0, 1 | 0x40 }, DN, "wpath: O_CREAT needs cpath" },
	{ P_WPATH, NR_open, { 0, 0x200000 }, DN, "wpath: O_PATH needs rpath" },
	{ P_WPATH | P_CPATH, NR_open, { 0, 1 | 0x40 | 0x200 }, AL, "wpath+cpath: create and truncate" },
	{ P_WPATH | P_CPATH, NR_open, { 0, 0x410000 | 1 }, AL, "wpath+cpath: O_TMPFILE" },
	{ P_WPATH | P_CPATH, NR_open, { 0, 0x410000 | 2 }, DN, "wpath+cpath: O_TMPFILE|O_RDWR needs rpath" },
	{ P_WPATH | P_CPATH, VOW_NR_creat, { 0 }, AL, "wpath+cpath: creat" },
	{ P_WPATH, VOW_NR_creat, { 0 }, DN, "wpath alone: creat creates" },
	{ P_CPATH, VOW_NR_creat, { 0 }, DN, "cpath alone: creat writes" },
	{ P_RPATH | P_CPATH, VOW_NR_creat, { 0 }, DN, "rpath+cpath: creat writes" },
	{ P_CPATH, NR_open, { 0, 0x40 }, DN, "cpath alone: O_CREAT|O_RDONLY needs rpath" },
	{ P_CPATH | P_RPATH, NR_open, { 0, 0x40 | 0x80 }, AL, "cpath+rpath: O_CREAT|O_EXCL read" },
	{ P_CPATH | P_RPATH, NR_open, { 0, 0x40 | 0x200 }, DN, "cpath+rpath: O_CREAT|O_TRUNC writes" },
	{ P_WPATH, NR_truncate, { 0 }, AL, "truncate with wpath" },
	{ P_WPATH, VOW_NR_ftruncate, { 0 }, AL, "ftruncate with wpath" },
	{ P_WPATH, VOW_NR_fallocate, { 0 }, AL, "fallocate with wpath" },
	{ P_STDIO | P_RPATH | P_CPATH, NR_truncate, { 0 }, DN, "truncate needs wpath, not rpath or cpath" },
	{ P_STDIO | P_RPATH | P_CPATH, VOW_NR_ftruncate, { 0 }, DN, "ftruncate needs wpath" },
	{ P_CPATH, VOW_NR_mkdir, { 0 }, AL, "mkdir with cpath alone" },
	{ P_RPATH | P_WPATH, VOW_NR_mkdir, { 0 }, DN, "mkdir needs cpath" },
	{ P_CPATH, VOW_NR_mkdirat, { 0 }, AL, "mkdirat with cpath alone" },
	{ P_RPATH | P_WPATH, VOW_NR_mkdirat, { 0 }, DN, "mkdirat needs cpath" },
	{ P_CPATH, VOW_NR_rmdir, { 0 }, AL, "rmdir with cpath alone" },
	{ P_RPATH | P_WPATH, VOW_NR_rmdir, { 0 }, DN, "rmdir needs cpath" },
	{ P_CPATH, VOW_NR_unlink, { 0 }, AL, "unlink with cpath alone" },
	{ P_RPATH | P_WPATH, VOW_NR_unlink, { 0 }, DN, "unlink needs cpath" },
	{ P_CPATH, VOW_NR_unlinkat, { 0 }, AL, "unlinkat with cpath alone" },
	{ P_RPATH | P_WPATH, VOW_NR_unlinkat, { 0 }, DN, "unlinkat needs cpath" },
	{ P_CPATH, VOW_NR_rename, { 0 }, AL, "rename with cpath alone" },
	{ P_RPATH | P_WPATH, VOW_NR_rename, { 0 }, DN, "rename needs cpath" },
	{ P_CPATH, VOW_NR_renameat, { 0 }, AL, "renameat with cpath alone" },
	{ P_RPATH | P_WPATH, VOW_NR_renameat, { 0 }, DN, "renameat needs cpath" },
	{ P_CPATH, VOW_NR_link, { 0 }, AL, "link with cpath alone" },
	{ P_RPATH | P_WPATH, VOW_NR_link, { 0 }, DN, "link needs cpath" },
	{ P_CPATH, VOW_NR_symlink, { 0 }, AL, "symlink with cpath alone" },
	{ P_RPATH | P_WPATH, VOW_NR_symlink, { 0 }, DN, "symlink needs cpath" },
	{ P_CPATH, VOW_NR_symlinkat, { 0 }, AL, "symlinkat with cpath alone" },
	{ P_RPATH | P_WPATH, VOW_NR_symlinkat, { 0 }, DN, "symlinkat needs cpath" },
	{ P_CPATH, VOW_NR_renameat2, { 0, 0, 0, 0, 0 }, AL, "renameat2 no flags" },
	{ P_CPATH, VOW_NR_renameat2, { 0, 0, 0, 0, 1 }, AL, "renameat2 NOREPLACE" },
	{ P_CPATH, VOW_NR_renameat2, { 0, 0, 0, 0, 2 }, AL, "renameat2 EXCHANGE" },
	{ P_CPATH, VOW_NR_renameat2, { 0, 0, 0, 0, 4 }, DN, "renameat2 WHITEOUT leaves a device node" },
	{ P_CPATH, VOW_NR_renameat2, { 0, 0, 0, 0, 5 }, DN, "renameat2 NOREPLACE|WHITEOUT" },
	{ P_CPATH, VOW_NR_renameat2, { 0, 0, 0, 0, 4 | JUNK }, DN, "renameat2 flags: junk does not hide WHITEOUT" },
	{ P_CPATH, VOW_NR_renameat2, { 0, 0, 0, 0, 1 | JUNK }, AL, "renameat2 flags are 32 bits" },
	{ P_CPATH, VOW_NR_renameat2, { 0, 0, 0, 0, 0x100000000ull }, AL, "renameat2 bit 32 is not a flag" },
	{ P_CPATH, VOW_NR_linkat, { 0, 0, 0, 0, 0 }, AL, "linkat no flags" },
	{ P_CPATH, VOW_NR_linkat, { 0, 0, 0, 0, 0x400 }, AL, "linkat AT_SYMLINK_FOLLOW" },
	{ P_CPATH, VOW_NR_linkat, { 0, 0, 0, 0, 0x1000 }, DN, "linkat AT_EMPTY_PATH names a descriptor" },
	{ P_CPATH, VOW_NR_linkat, { 0, 0, 0, 0, 0x1400 }, DN, "linkat AT_EMPTY_PATH|AT_SYMLINK_FOLLOW" },
	{ P_CPATH, VOW_NR_linkat, { 0, 0, 0, 0, 0x1000 | JUNK }, DN, "linkat flags: junk does not hide AT_EMPTY_PATH" },
	{ P_CPATH, VOW_NR_linkat, { 0, 0, 0, 0, 0x400 | JUNK }, AL, "linkat flags are an int" },
	{ P_CPATH, VOW_NR_unlinkat, { 0, 0, 0x200 }, AL, "unlinkat AT_REMOVEDIR" },
	{ P_CPATH, NR_chmod, { 0 }, DN, "cpath does not chmod" },
	{ P_CPATH, NR_mknod, { 0 }, DN, "cpath does not mknod" },
	{ P_CPATH, NR_mknodat, { 0 }, DN, "cpath does not mknodat" },
	{ P_CPATH, NR_open, { 0, 0 }, DN, "cpath alone: open O_RDONLY needs rpath" },
	{ P_CPATH, NR_stat, { 0 }, DN, "cpath does not stat" },
	{ P_WPATH, NR_mkdir, { 0 }, DN, "wpath does not mkdir" },
	{ P_RPATH, VOW_NR_symlink, { 0 }, DN, "rpath does not symlink" },
	/* x32 and wrong architecture */
	{ P_STDIO, VOW_NR_read | VOW_X32_BIT, { 0 }, DN, "x32 read" },
	{ P_STDIO, VOW_NR_exit_group | VOW_X32_BIT, { 0 }, DN, "x32 exit_group" },
	/* memory: w^x */
	{ P_STDIO, VOW_NR_mprotect, { 0, 4096, 1 }, AL, "mprotect r" },
	{ P_STDIO, VOW_NR_mprotect, { 0, 4096, 3 }, AL, "mprotect rw" },
	{ P_STDIO, VOW_NR_mprotect, { 0, 4096, 5 }, AL, "mprotect rx" },
	{ P_STDIO, VOW_NR_mprotect, { 0, 4096, 4 }, AL, "mprotect x" },
	{ P_STDIO, VOW_NR_mprotect, { 0, 4096, 6 }, DN, "mprotect wx" },
	{ P_STDIO, VOW_NR_mprotect, { 0, 4096, 7 }, DN, "mprotect rwx" },
	{ P_STDIO, VOW_NR_mmap, { 0, 4096, 7 }, DN, "mmap rwx" },
	{ P_STDIO, VOW_NR_mmap, { 0, 4096, 3 }, AL, "mmap rw" },
	/* threads only */
	{ P_STDIO, VOW_NR_clone, { THREAD }, AL, "clone glibc thread flags" },
	{ P_STDIO, VOW_NR_clone, { MUSLTHREAD }, AL, "clone musl thread flags" },
	{ P_STDIO, VOW_NR_clone, { THREAD | JUNK }, AL, "clone flags are read as 32 bits" },
	{ P_STDIO, VOW_NR_clone, { 17 }, DN, "clone as fork (SIGCHLD)" },
	{ P_STDIO, VOW_NR_clone, { 0x50f00 | 0x20000 }, DN, "thread plus newns" },
	{ P_STDIO, VOW_NR_clone, { 0x50f00 | 0x10000000 }, DN, "thread plus newuser" },
	{ P_STDIO, VOW_NR_clone, { 0x50f00 | 0x2000 }, DN, "thread plus ptrace" },
	{ P_STDIO, VOW_NR_clone, { 0x50f00 | 17 }, DN, "thread plus exit signal" },
	{ P_STDIO, VOW_NR_clone, { 0x10f00 }, DN, "thread without sysvsem" },
	{ P_STDIO, VOW_NR_clone, { 0x40000100 }, DN, "newnet only" },
	{ P_STDIO, VOW_NR_clone3, { 0 }, ER(38), "clone3 answers enosys by policy" },
	/* signals */
	/* sockets */
	{ P_STDIO, VOW_NR_socketpair, { 1, 1, 0 }, AL, "socketpair unix" },
	{ P_STDIO, VOW_NR_socketpair, { 1 | JUNK, 1, 0 }, AL, "socketpair domain is int" },
	{ P_STDIO, VOW_NR_socketpair, { 2, 1, 0 }, DN, "socketpair inet" },
	{ P_STDIO, VOW_NR_sendto, { 3, 0, 1, 0, 0, 0 }, AL, "sendto without address" },
	{ P_STDIO, VOW_NR_sendto, { 3, 0, 1, 0, 0, 16 }, AL, "sendto null address, any length" },
	{ P_STDIO, VOW_NR_sendto, { 3, 0, 1, 0, 0x1000, 16 }, DN, "sendto with address" },
	{ P_STDIO, VOW_NR_sendto, { 3, 0, 1, 0, 1ull << 32, 16 }, DN, "sendto address is a pointer: high bits count" },
	/* fcntl, ioctl, prctl, arch_prctl, prlimit */
	{ P_STDIO, VOW_NR_fcntl, { 3, 1 }, AL, "fcntl getfd" },
	{ P_STDIO, VOW_NR_fcntl, { 3, 1030 }, AL, "fcntl dupfd_cloexec" },
	{ P_STDIO, VOW_NR_fcntl, { 3, 8 }, DN, "fcntl setown" },
	{ P_STDIO, VOW_NR_fcntl, { 3, 1031 }, DN, "fcntl setpipe_sz" },
	{ P_STDIO, VOW_NR_fcntl, { 3, 1 | JUNK }, AL, "fcntl cmd is unsigned int" },
	{ P_STDIO, VOW_NR_ioctl, { 1, 0x5413 }, AL, "ioctl tiocgwinsz" },
	{ P_STDIO, VOW_NR_ioctl, { 1, 0x5412 }, DN, "ioctl tiocsti" },
	{ P_STDIO, VOW_NR_prctl, { 15 }, AL, "prctl set_name" },
	{ P_STDIO, VOW_NR_prctl, { 4, 1 }, DN, "prctl set_dumpable" },
	{ P_STDIO, VOW_NR_arch_prctl, { 0x1002 }, AL, "arch_prctl set_fs" },
	{ P_STDIO, VOW_NR_arch_prctl, { 0x1001 }, DN, "arch_prctl set_gs" },
	{ P_STDIO, VOW_NR_prlimit64, { 0, 7, 0, 0x1000 }, AL, "prlimit get self" },
	{ P_STDIO, VOW_NR_prlimit64, { 0, 7, 0x1000, 0 }, DN, "prlimit set" },
	{ P_STDIO, VOW_NR_prlimit64, { 1, 7, 0, 0x1000 }, DN, "prlimit get other process" },
	{ P_STDIO, VOW_NR_prlimit64, { 0, 7, 1ull << 32, 0 }, DN, "prlimit new pointer high bits" },
};

static void
t_expectations(void)
{
	struct vow_insn p[VOW_MAX_INSNS];
	size_t n, i, j;
	int bad = 0;

	for (i = 0; i < sizeof exps / sizeof *exps; i++) {
		struct sdata d;
		uint32_t gen, orc;

		n = vow_build(exps[i].promises, &ctx, p, VOW_MAX_INSNS);
		CHECK(n > 0);
		memset(&d, 0, sizeof d);
		d.arch = VOW_AUDIT_ARCH_X86_64;
		d.nr = exps[i].nr;
		for (j = 0; j < 6; j++)
			d.args[j] = exps[i].a[j];
		gen = bpf_run(p, n, &d);
		orc = oracle(exps[i].promises, &ctx, &d);
		if (gen != exps[i].want || orc != exps[i].want) {
			fprintf(stderr, "    %s: want 0x%x, bytecode 0x%x, oracle 0x%x\n",
			    exps[i].why, exps[i].want, gen, orc);
			bad = 1;
		}
	}
	/* wrong architecture: every number is denied, including those that are allowed natively */
	for (i = 0; i < 512; i++) {
		struct sdata d;

		memset(&d, 0, sizeof d);
		d.nr = (uint32_t)i;
		d.arch = 0x40000003;	/* AUDIT_ARCH_I386 */
		n = vow_build(P_STDIO, &ctx, p, VOW_MAX_INSNS);
		if (bpf_run(p, n, &d) != ctx.deny) {
			fprintf(stderr, "    i386 nr %zu not denied\n", i);
			bad = 1;
		}
		d.arch = 0xc00000b7;	/* AUDIT_ARCH_AARCH64 */
		if (bpf_run(p, n, &d) != ctx.deny)
			bad = 1;
	}
	CHECK(!bad);
}

static void
pool_add(uint64_t *pool, size_t *np, uint64_t v)
{
	if (*np < 4096)
		pool[(*np)++] = v;
}

/* bytecode interpreter against the oracle over random and structured arguments */
static void
t_interpreter_vs_oracle(void)
{
	uint64_t pool[4096];
	struct vow_insn p[VOW_MAX_INSNS];
	size_t np = 0, n, si, nt, i, j, k, round;
	unsigned long allow = 0, deny = 0, errs = 0, cases = 0;

	pool_add(pool, &np, 0);
	pool_add(pool, &np, 1);
	pool_add(pool, &np, 0xffffffffull);
	pool_add(pool, &np, 0x100000000ull);
	pool_add(pool, &np, ~0ull);
	for (si = 0; si < sizeof sets / sizeof *sets; si++) {
		struct vow_table t[VOW_MAX_TABLES];
		struct vow_policy pol;

		nt = vow_tables(sets[si], &pol, t);
		for (i = 0; i < nt; i++)
			for (j = 0; j < t[i].n; j++)
				for (k = 0; k < t[i].r[j].ncond; k++) {
					const struct vow_cond *c = &t[i].r[j].cond[k];
					unsigned s;

					pool_add(pool, &np, c->v);
					pool_add(pool, &np, c->m);
					pool_add(pool, &np, c->v | JUNK);
					pool_add(pool, &np, c->v ^ 1);
					pool_add(pool, &np, c->v ^ (1ull << 32));
					pool_add(pool, &np, c->v | 0x2000);
					pool_add(pool, &np, c->v & 0x50f00);
					for (s = 0; s < c->nset; s++) {
						pool_add(pool, &np, c->set[s]);
						pool_add(pool, &np, c->set[s] | JUNK);
						pool_add(pool, &np, c->set[s] + 1);
					}
				}
	}
	for (si = 0; si < sizeof sets / sizeof *sets; si++) {
		struct vow_table t[VOW_MAX_TABLES];
		struct vow_policy pol;

		n = vow_build(sets[si], &ctx, p, VOW_MAX_INSNS);
		CHECK(n > 0 && bpf_validate(p, n));
		nt = vow_tables(sets[si], &pol, t);
		/* every number the tables name, and a sweep over the whole range around them */
		for (round = 0; round < 480 + 20000; round++) {
			struct sdata d;
			uint32_t g, o;

			memset(&d, 0, sizeof d);
			d.arch = VOW_AUDIT_ARCH_X86_64;
			if (round < 480) {
				d.nr = (uint32_t)round;
			} else {
				const struct vow_table *tb = &t[rnd() % nt];

				d.nr = tb->r[rnd() % tb->n].nr;
				if (rnd() % 16 == 0)
					d.nr |= VOW_X32_BIT;
			}
			for (i = 0; i < 6; i++)
				d.args[i] = rnd() % 8 ? pool[rnd() % np] : rnd();
			g = bpf_run(p, n, &d);
			o = oracle(sets[si], &ctx, &d);
			cases++;
			if (g != o) {
				fprintf(stderr, "    mismatch set 0x%x nr %u: bytecode 0x%x oracle 0x%x args "
				    "%llx %llx %llx %llx\n", sets[si], d.nr, g, o,
				    (unsigned long long)d.args[0], (unsigned long long)d.args[1],
				    (unsigned long long)d.args[2], (unsigned long long)d.args[3]);
				_exit(1);
			}
			if (g == VOW_SECCOMP_RET_ALLOW)
				allow++;
			else if (g == ctx.deny)
				deny++;
			else
				errs++;
		}
	}
	printf("    %lu cases: %lu allow, %lu deny, %lu errno\n", cases, allow, deny, errs);
	CHECK(allow > 1000 && deny > 1000 && errs > 10);
}

/* a promise set may only be a stricter filter than a bigger one: stdio allows all that none allows */
static void
t_core_in_every_set(void)
{
	struct vow_insn p0[VOW_MAX_INSNS], p1[VOW_MAX_INSNS];
	size_t n0 = vow_build(0, &ctx, p0, VOW_MAX_INSNS);
	size_t n1 = vow_build(P_STDIO, &ctx, p1, VOW_MAX_INSNS);
	uint32_t nr;

	CHECK(n0 > 0 && n1 > 0);
	for (nr = 0; nr < 512; nr++) {
		struct sdata d;

		memset(&d, 0, sizeof d);
		d.arch = VOW_AUDIT_ARCH_X86_64;
		d.nr = nr;
		d.args[0] = 38;
		d.args[1] = 1;
		if (bpf_run(p0, n0, &d) == VOW_SECCOMP_RET_ALLOW)
			CHECK(bpf_run(p1, n1, &d) == VOW_SECCOMP_RET_ALLOW);
	}
}


/* the architecture and x32 checks are the first instructions, spelled out */
static void
t_preamble(void)
{
	struct vow_insn p[VOW_MAX_INSNS];
	size_t n = vow_build(P_STDIO, &ctx, p, VOW_MAX_INSNS);

	CHECK(n > 6);
	CHECK(p[0].code == (VOW_BPF_LD | VOW_BPF_W | VOW_BPF_ABS) && p[0].k == VOW_SD_ARCH);
	CHECK(p[1].code == (VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K) && p[1].k == VOW_AUDIT_ARCH_X86_64 &&
	    p[1].jt == 1 && p[1].jf == 0);
	CHECK(p[2].code == (VOW_BPF_RET | VOW_BPF_K) && p[2].k == ctx.deny);
	CHECK(p[3].code == (VOW_BPF_LD | VOW_BPF_W | VOW_BPF_ABS) && p[3].k == VOW_SD_NR);
	CHECK(p[4].code == (VOW_BPF_JMP | VOW_BPF_JSET | VOW_BPF_K) && p[4].k == VOW_X32_BIT &&
	    p[4].jt == 0 && p[4].jf == 1);
	CHECK(p[5].code == (VOW_BPF_RET | VOW_BPF_K) && p[5].k == ctx.deny);
	/* and the last instruction is the default deny */
	CHECK(p[n - 1].code == (VOW_BPF_RET | VOW_BPF_K) && p[n - 1].k == ctx.deny);
}


/*
 * the policy matrix for opening files, as data. need is what the call asks of the promise set.
 * these rows are written by hand from the kernel rules (DESIGN.md section 2.5) and are checked
 * against the oracle and the generated bytecode for every subset of rpath, wpath and cpath.
 */
#define NR_ 1u
#define NW_ 2u
#define NC_ 4u
#define O_WR 0x1u
#define O_RW 0x2u
#define O_CREAT_ 0x40u
#define O_EXCL_ 0x80u
#define O_NOCTTY_ 0x100u
#define O_TRUNC_ 0x200u
#define O_APPEND_ 0x400u
#define O_NONBLOCK_ 0x800u
#define O_DIRECT_ 0x4000u
#define O_LARGEFILE_ 0x8000u
#define O_DIRECTORY_ 0x10000u
#define O_NOFOLLOW_ 0x20000u
#define O_NOATIME_ 0x40000u
#define O_CLOEXEC_ 0x80000u
#define O_PATH_ 0x200000u
#define O_TMPBIT_ 0x400000u
#define O_TMPFILE_ (O_TMPBIT_ | O_DIRECTORY_)
#define O_SYNC_ 0x101000u

static const struct {
	const char *what;
	uint32_t flags;
	unsigned need;
} matrix[] = {
	{ "O_RDONLY", 0, NR_ },
	{ "O_RDONLY|O_DIRECTORY (opendir)", O_DIRECTORY_, NR_ },
	{ "O_RDONLY|O_CLOEXEC|O_LARGEFILE (musl fopen)", O_CLOEXEC_ | O_LARGEFILE_, NR_ },
	{ "O_RDONLY with every neutral flag", O_NOCTTY_ | O_NONBLOCK_ | O_DIRECT_ | O_NOFOLLOW_ | O_NOATIME_ | O_CLOEXEC_ | O_SYNC_, NR_ },
	{ "O_RDONLY|O_EXCL (no O_CREAT: nothing created)", O_EXCL_, NR_ },
	{ "unknown flag bits", 0x80000000u | 0x40000000u | 0x20u, NR_ },
	{ "O_WRONLY", O_WR, NW_ },
	{ "O_WRONLY|O_APPEND", O_WR | O_APPEND_, NW_ },
	{ "O_WRONLY|O_TRUNC", O_WR | O_TRUNC_, NW_ },
	{ "O_RDWR", O_RW, NR_ | NW_ },
	{ "access mode 3 (kernel checks read and write)", 3, NR_ | NW_ },
	{ "O_RDWR|O_TRUNC", O_RW | O_TRUNC_, NR_ | NW_ },
	{ "O_RDONLY|O_TRUNC (truncates anyway)", O_TRUNC_, NR_ | NW_ },
	{ "O_RDONLY|O_CREAT", O_CREAT_, NR_ | NC_ },
	{ "O_RDONLY|O_CREAT|O_EXCL", O_CREAT_ | O_EXCL_, NR_ | NC_ },
	{ "O_RDONLY|O_CREAT|O_TRUNC", O_CREAT_ | O_TRUNC_, NR_ | NW_ | NC_ },
	{ "O_WRONLY|O_CREAT", O_WR | O_CREAT_, NW_ | NC_ },
	{ "O_WRONLY|O_CREAT|O_TRUNC (creat)", O_WR | O_CREAT_ | O_TRUNC_, NW_ | NC_ },
	{ "O_WRONLY|O_CREAT|O_EXCL|O_APPEND", O_WR | O_CREAT_ | O_EXCL_ | O_APPEND_, NW_ | NC_ },
	{ "O_RDWR|O_CREAT", O_RW | O_CREAT_, NR_ | NW_ | NC_ },
	{ "O_TMPFILE|O_WRONLY", O_TMPFILE_ | O_WR, NW_ | NC_ },
	{ "O_TMPFILE|O_RDWR", O_TMPFILE_ | O_RW, NR_ | NW_ | NC_ },
	{ "O_TMPFILE|O_RDONLY (kernel: EINVAL; still a read mode)", O_TMPFILE_, NR_ | NW_ | NC_ },
	{ "O_TMPFILE bit without O_DIRECTORY (kernel: EINVAL)", O_TMPBIT_ | O_WR, NW_ | NC_ },
	{ "O_TMPFILE|O_CREAT (kernel: EINVAL)", O_TMPFILE_ | O_CREAT_ | O_WR, NW_ | NC_ },
	{ "O_PATH", O_PATH_, NR_ },
	{ "O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC", O_PATH_ | O_DIRECTORY_ | O_NOFOLLOW_ | O_CLOEXEC_, NR_ },
	{ "O_PATH|O_WRONLY (the kernel drops it)", O_PATH_ | O_WR, NR_ },
	{ "O_PATH|O_RDWR|O_CREAT|O_TRUNC (the kernel drops it)", O_PATH_ | O_RW | O_CREAT_ | O_TRUNC_, NR_ },
	{ "O_PATH|O_TMPFILE (the kernel drops it)", O_PATH_ | O_TMPFILE_, NR_ },
};

static void
set_args(struct sdata *d, uint32_t nr, uint64_t flags)
{
	memset(d, 0, sizeof *d);
	d->arch = VOW_AUDIT_ARCH_X86_64;
	d->nr = nr;
	d->args[0] = (uint64_t)-100;	/* AT_FDCWD */
	d->args[1] = 0x1000;		/* a path */
	if (nr == VOW_NR_openat)
		d->args[2] = flags;
	else
		d->args[1] = flags;
}

static void
t_open_matrix(void)
{
	struct vow_insn p[VOW_MAX_INSNS];
	size_t row, sub, n;
	int bad = 0;

	for (sub = 0; sub < 8; sub++) {
		unsigned have = ((sub & 1) ? NR_ : 0) | ((sub & 2) ? NW_ : 0) | ((sub & 4) ? NC_ : 0);
		unsigned promises = ((sub & 1) ? P_RPATH : 0) | ((sub & 2) ? P_WPATH : 0) | ((sub & 4) ? P_CPATH : 0);

		n = vow_build(promises, &ctx, p, VOW_MAX_INSNS);
		CHECK(n > 0 && bpf_validate(p, n));
		for (row = 0; row < sizeof matrix / sizeof *matrix; row++) {
			uint32_t want = (matrix[row].need & ~have) == 0 ? VOW_SECCOMP_RET_ALLOW : ctx.deny;
			static const uint32_t nrs[2] = { VOW_NR_open, VOW_NR_openat };
			unsigned k, j;

			for (k = 0; k < 2; k++)
				for (j = 0; j < 2; j++) {
					struct sdata d;
					uint32_t g, o;

					set_args(&d, nrs[k], matrix[row].flags | (j ? JUNK : 0));
					g = bpf_run(p, n, &d);
					o = oracle(promises, &ctx, &d);
					if (g != want || o != want) {
						fprintf(stderr, "    %s with promises 0x%x (nr %u, junk %u): want 0x%x, bytecode 0x%x, oracle 0x%x\n",
						    matrix[row].what, promises, nrs[k], j, want, g, o);
						bad = 1;
					}
				}
		}
	}
	CHECK(!bad);
}

/* every combination of the flags that matter and of a spread of neutral ones, for every subset */
static void
t_open_exhaustive(void)
{
	static const uint32_t bits[] = {
		0x1, 0x2, 0x40, 0x80, 0x200, 0x400, 0x10000, 0x200000, 0x400000,
		0x8000, 0x20000, 0x80000, 0x800, 0x100, 0x40000, 0x80000000u
	};
	struct vow_insn p[VOW_MAX_INSNS];
	size_t sub, n;
	unsigned long cases = 0;
	uint32_t m;

	for (sub = 0; sub < 8; sub++) {
		unsigned promises = ((sub & 1) ? P_RPATH : 0) | ((sub & 2) ? P_WPATH : 0) | ((sub & 4) ? P_CPATH : 0);

		n = vow_build(promises, &ctx, p, VOW_MAX_INSNS);
		CHECK(n > 0);
		for (m = 0; m < (1u << (sizeof bits / sizeof *bits)); m++) {
			uint32_t flags = 0, nr;
			size_t i;

			for (i = 0; i < sizeof bits / sizeof *bits; i++)
				if (m & (1u << i))
					flags |= bits[i];
			for (nr = 0; nr < 2; nr++) {
				struct sdata d;
				uint32_t g, o;

				set_args(&d, nr ? VOW_NR_openat : VOW_NR_open, flags);
				g = bpf_run(p, n, &d);
				o = oracle(promises, &ctx, &d);
				cases++;
				if (g != o) {
					fprintf(stderr, "    promises 0x%x flags 0x%x nr %u: bytecode 0x%x oracle 0x%x\n",
					    promises, flags, d.nr, g, o);
					_exit(1);
				}
			}
		}
	}
	printf("    %lu open and openat flag sets compared\n", cases);
}


/*
 * the other path calls, as data: what each asks of the set. N is never granted by rpath, wpath
 * or cpath, whatever the combination: those calls belong to other promises or to none.
 */
#define NN_ 8u
#define NF_ 0u	/* no flags argument matters */

static const struct {
	const char *what;
	uint32_t nr;
	unsigned need;
} pathcalls[] = {
	{ "stat", VOW_NR_stat, NR_ }, { "lstat", VOW_NR_lstat, NR_ }, { "newfstatat", VOW_NR_newfstatat, NR_ },
	{ "statx", VOW_NR_statx, NR_ }, { "access", VOW_NR_access, NR_ }, { "faccessat", VOW_NR_faccessat, NR_ },
	{ "faccessat2", VOW_NR_faccessat2, NR_ }, { "readlink", VOW_NR_readlink, NR_ },
	{ "readlinkat", VOW_NR_readlinkat, NR_ }, { "getdents", VOW_NR_getdents, NR_ },
	{ "getdents64", VOW_NR_getdents64, NR_ }, { "getcwd", VOW_NR_getcwd, NR_ }, { "chdir", VOW_NR_chdir, NR_ },
	{ "fchdir", VOW_NR_fchdir, NR_ }, { "statfs", VOW_NR_statfs, NR_ }, { "fstatfs", VOW_NR_fstatfs, NR_ },
	{ "truncate", VOW_NR_truncate, NW_ }, { "ftruncate", VOW_NR_ftruncate, NW_ },
	{ "fallocate", VOW_NR_fallocate, NW_ },
	{ "mkdir", VOW_NR_mkdir, NC_ }, { "mkdirat", VOW_NR_mkdirat, NC_ }, { "rmdir", VOW_NR_rmdir, NC_ },
	{ "unlink", VOW_NR_unlink, NC_ }, { "unlinkat", VOW_NR_unlinkat, NC_ }, { "rename", VOW_NR_rename, NC_ },
	{ "renameat", VOW_NR_renameat, NC_ }, { "renameat2", VOW_NR_renameat2, NC_ }, { "link", VOW_NR_link, NC_ },
	{ "linkat", VOW_NR_linkat, NC_ }, { "symlink", VOW_NR_symlink, NC_ }, { "symlinkat", VOW_NR_symlinkat, NC_ },
	/* never granted by a path promise */
	{ "mknod", 133, NN_ }, { "mknodat", 259, NN_ }, { "chmod", 90, NN_ }, { "fchmod", 91, NN_ },
	{ "fchmodat", 268, NN_ }, { "chown", 92, NN_ }, { "lchown", 94, NN_ }, { "fchownat", 260, NN_ },
	{ "utime", 132, NN_ }, { "utimes", 235, NN_ }, { "futimesat", 261, NN_ }, { "utimensat", 280, NN_ },
	{ "setxattr", 188, NN_ }, { "getxattr", 191, NN_ }, { "listxattr", 194, NN_ }, { "removexattr", 197, NN_ },
	{ "mount", 165, NN_ }, { "umount2", 166, NN_ }, { "chroot", 161, NN_ }, { "pivot_root", 155, NN_ },
	{ "inotify_add_watch", 254, NN_ }, { "name_to_handle_at", 303, NN_ }, { "open_by_handle_at", 304, NN_ },
	{ "memfd_create", 319, NN_ }, { "flock", 73, NN_ }, { "sendfile", 40, NN_ }, { "splice", 275, NN_ },
	{ "copy_file_range", 326, NN_ }, { "execve", 59, NN_ }, { "execveat", 322, NN_ },
	{ "socket", 41, NN_ }, { "mkfifo-by-mknod", 133, NN_ }, { "open_tree", 428, NN_ }, { "fsopen", 430, NN_ },
};

static void
t_path_call_matrix(void)
{
	struct vow_insn p[VOW_MAX_INSNS];
	size_t sub, row, n;
	int bad = 0;

	for (sub = 0; sub < 8; sub++) {
		unsigned have = ((sub & 1) ? NR_ : 0) | ((sub & 2) ? NW_ : 0) | ((sub & 4) ? NC_ : 0);
		unsigned promises = ((sub & 1) ? P_RPATH : 0) | ((sub & 2) ? P_WPATH : 0) | ((sub & 4) ? P_CPATH : 0);

		n = vow_build(promises, &ctx, p, VOW_MAX_INSNS);
		CHECK(n > 0 && bpf_validate(p, n));
		for (row = 0; row < sizeof pathcalls / sizeof *pathcalls; row++) {
			unsigned need = pathcalls[row].need;
			uint32_t want = (need != NN_ && (need & ~have) == 0) ? VOW_SECCOMP_RET_ALLOW : ctx.deny;
			struct sdata d;
			uint32_t g, o;
			int j;

			for (j = 0; j < 3; j++) {
				memset(&d, 0, sizeof d);
				d.arch = VOW_AUDIT_ARCH_X86_64;
				d.nr = pathcalls[row].nr;
				/* junk in every argument, then in every 32-bit argument slot except flags */
				if (j == 1) {
					d.args[0] = JUNK; d.args[1] = JUNK; d.args[2] = JUNK; d.args[3] = JUNK;
				} else if (j == 2) {
					d.args[0] = ~0ull; d.args[1] = ~0ull; d.args[2] = ~0ull; d.args[3] = ~0ull;
				}
				if (d.nr == VOW_NR_renameat2 || d.nr == VOW_NR_linkat)
					d.args[4] = 0;	/* flags argument: the plain call */
				g = bpf_run(p, n, &d);
				o = oracle(promises, &ctx, &d);
				if (g != want || o != want) {
					fprintf(stderr, "    %s with promises 0x%x (variant %d): want 0x%x, bytecode 0x%x, oracle 0x%x\n",
					    pathcalls[row].what, promises, j, want, g, o);
					bad = 1;
				}
			}
		}
	}
	CHECK(!bad);
}

/* the two flags that change what a call is: every value of their relevant bits, with and without junk */
static void
t_path_call_flags(void)
{
	struct vow_insn p[VOW_MAX_INSNS];
	uint32_t flags;
	size_t n;
	unsigned promises;
	int bad = 0, k;

	for (promises = 0; promises < 16; promises += 1) {
		unsigned pr = ((promises & 1) ? P_RPATH : 0) | ((promises & 2) ? P_WPATH : 0) | ((promises & 4) ? P_CPATH : 0) |
		    ((promises & 8) ? P_STDIO : 0);

		n = vow_build(pr, &ctx, p, VOW_MAX_INSNS);
		CHECK(n > 0);
		for (flags = 0; flags < 0x20000; flags++)
			for (k = 0; k < 2; k++) {
				uint32_t nr = k ? VOW_NR_linkat : VOW_NR_renameat2, bit = k ? 0x1000 : 0x4;
				uint64_t junk;

				for (junk = 0; junk < 2; junk++) {
					struct sdata d;
					uint32_t want, g;

					memset(&d, 0, sizeof d);
					d.arch = VOW_AUDIT_ARCH_X86_64;
					d.nr = nr;
					d.args[4] = flags | (junk ? JUNK : 0);
					want = ((pr & P_CPATH) && !(flags & bit)) ? VOW_SECCOMP_RET_ALLOW : ctx.deny;
					g = bpf_run(p, n, &d);
					if (g != want || oracle(pr, &ctx, &d) != want) {
						fprintf(stderr, "    nr %u flags 0x%x: want 0x%x got 0x%x\n", nr, flags, want, g);
						bad = 1;
					}
				}
			}
	}
	CHECK(!bad);
}


/* socket(): every domain, type with flag bits, and protocol worth trying, bytecode against oracle */
static void
t_socket_grid(void)
{
	static const uint64_t doms[] = { 0, 1, 2, 3, 4, 9, 10, 11, 16, 17, 29, 31, 38, 40, 2 | JUNK, 10 | JUNK, 0xffffffffull, 1ull << 32, (1ull << 32) | 2 };
	static const uint64_t types[] = {
		0, 1, 2, 3, 4, 5, 6, 10, 1 | 0x80000, 1 | 0x800, 1 | 0x80800, 2 | 0x80000, 2 | 0x800, 2 | 0x80800,
		1 | 0x1000, 2 | 0x2000, 1 | 0x100000, 1 | JUNK, 2 | JUNK, 1ull << 32, 3 | 0x80000, 5 | 0x800
	};
	static const uint64_t protos[] = { 0, 1, 2, 6, 17, 41, 58, 132, 136, 255, 262, 6 | JUNK, 17 | JUNK, 0xffffffffull, 1ull << 32 };
	static const unsigned psets[] = { 0, P_INET, P_STDIO, P_STDIO | P_INET, P_EXEC | P_INET };
	struct vow_insn p[VOW_MAX_INSNS];
	unsigned long cases = 0, allowed = 0;
	size_t ps, a, b, c, n;

	for (ps = 0; ps < sizeof psets / sizeof *psets; ps++) {
		n = vow_build(psets[ps], &ctx, p, VOW_MAX_INSNS);
		CHECK(n > 0);
		for (a = 0; a < sizeof doms / sizeof *doms; a++)
			for (b = 0; b < sizeof types / sizeof *types; b++)
				for (c = 0; c < sizeof protos / sizeof *protos; c++) {
					struct sdata d;
					uint32_t g, o;

					memset(&d, 0, sizeof d);
					d.arch = VOW_AUDIT_ARCH_X86_64;
					d.nr = VOW_NR_socket;
					d.args[0] = doms[a]; d.args[1] = types[b]; d.args[2] = protos[c];
					g = bpf_run(p, n, &d);
					o = oracle(psets[ps], &ctx, &d);
					cases++;
					if (g == VOW_SECCOMP_RET_ALLOW)
						allowed++;
					if (g != o) {
						fprintf(stderr, "    set 0x%x socket(%llx, %llx, %llx): bytecode 0x%x oracle 0x%x\n", psets[ps],
						    (unsigned long long)doms[a], (unsigned long long)types[b], (unsigned long long)protos[c], g, o);
						_exit(1);
					}
				}
	}
	printf("    %lu socket calls compared, %lu allowed\n", cases, allowed);
	CHECK(allowed > 100);
}

static void
t_setsockopt_grid(void)
{
	struct vow_insn p[VOW_MAX_INSNS];
	size_t n;
	uint64_t level, opt;
	unsigned long allowed = 0;
	unsigned ps;
	static const unsigned psets[] = { 0, P_STDIO, P_STDIO | P_INET };

	for (ps = 0; ps < 3; ps++) {
		n = vow_build(psets[ps], &ctx, p, VOW_MAX_INSNS);
		for (level = 0; level < 300; level++)
			for (opt = 0; opt < 160; opt++) {
				uint64_t lv[3] = { level, level | JUNK, level | (1ull << 32) };
				int k;

				for (k = 0; k < 3; k++) {
					struct sdata d;
					uint32_t g, o;

					memset(&d, 0, sizeof d);
					d.arch = VOW_AUDIT_ARCH_X86_64;
					d.nr = NR_setsockopt;
					d.args[0] = 3; d.args[1] = lv[k]; d.args[2] = opt | (k == 1 ? JUNK : 0);
					g = bpf_run(p, n, &d);
					o = oracle(psets[ps], &ctx, &d);
					if (g == VOW_SECCOMP_RET_ALLOW)
						allowed++;
					if (g != o) {
						fprintf(stderr, "    set 0x%x setsockopt level %llu opt %llu: 0x%x vs 0x%x\n", psets[ps],
						    (unsigned long long)level, (unsigned long long)opt, g, o);
						_exit(1);
					}
				}
			}
	}
	CHECK(allowed == 49 * 3 * 2);	/* 49 allowed pairs, three spellings of the level, two sets with stdio */
}

static const struct test tests[] = {
	{ "vendored syscall numbers match libc", t_syscall_numbers, 0 },
	{ "program structure and limits", t_structure, 0 },
	{ "hand written expectations", t_expectations, 0 },
	{ "interpreter against oracle", t_interpreter_vs_oracle, 0 },
	{ "core is allowed in every set", t_core_in_every_set, 0 },
	{ "explicit arch and x32 checks", t_preamble, 0 },
	{ "open policy matrix, every subset", t_open_matrix, 0 },
	{ "open flags exhaustive, every subset", t_open_exhaustive, 0 },
	{ "path call matrix, every subset", t_path_call_matrix, 0 },
	{ "renameat2 and linkat flag bits", t_path_call_flags, 0 },
	{ "socket arguments, every class", t_socket_grid, 0 },
	{ "setsockopt level and option grid", t_setsockopt_grid, 0 },
};

int
main(void)
{
	return t_main(tests, (int)(sizeof tests / sizeof *tests), 12);
}
