/* SPDX-License-Identifier: LGPL-3.0-only */
#ifndef VOW_SYS_H
#define VOW_SYS_H

#include <stdint.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "vow supports linux x86-64 only"
#endif

/*
 * values copied from the linux uapi (include/uapi/linux/landlock.h,
 * checked against upstream master and the landlock userspace docs).
 * installed kernel headers may be older than the running kernel, so
 * vow never includes them. a missing header constant is a build
 * matter; whether the running kernel supports it is probed at runtime.
 */

#define VOW_SYS_landlock_create_ruleset 444
#define VOW_SYS_landlock_add_rule       445
#define VOW_SYS_landlock_restrict_self  446

#define VOW_LL_CREATE_VERSION   (1U << 0)
#define VOW_LL_RESTRICT_TSYNC   (1U << 3)   /* abi 8. the library never uses it (DESIGN.md 6); tests do */
#define VOW_LL_RULE_PATH_BENEATH 1

#define VOW_LL_FS_EXECUTE      (1ULL << 0)
#define VOW_LL_FS_WRITE_FILE   (1ULL << 1)
#define VOW_LL_FS_READ_FILE    (1ULL << 2)
#define VOW_LL_FS_READ_DIR     (1ULL << 3)
#define VOW_LL_FS_REMOVE_DIR   (1ULL << 4)
#define VOW_LL_FS_REMOVE_FILE  (1ULL << 5)
#define VOW_LL_FS_MAKE_CHAR    (1ULL << 6)
#define VOW_LL_FS_MAKE_DIR     (1ULL << 7)
#define VOW_LL_FS_MAKE_REG     (1ULL << 8)
#define VOW_LL_FS_MAKE_SOCK    (1ULL << 9)
#define VOW_LL_FS_MAKE_FIFO    (1ULL << 10)
#define VOW_LL_FS_MAKE_BLOCK   (1ULL << 11)
#define VOW_LL_FS_MAKE_SYM     (1ULL << 12)
#define VOW_LL_FS_REFER        (1ULL << 13)  /* abi 2 */
#define VOW_LL_FS_TRUNCATE     (1ULL << 14)  /* abi 3 */
#define VOW_LL_FS_RESOLVE_UNIX (1ULL << 16)  /* abi 9 */
#define VOW_LL_SCOPE_SIGNAL    (1ULL << 1)   /* abi 6: scoped, not an fs right */

/* the abi 3 set. ioctl_dev (abi 5) is not handled; resolve_unix is added at abi >= 9 */
#define VOW_LL_FS_HANDLED ((1ULL << 15) - 1)

#define VOW_MIN_ABI 3
#define VOW_SCOPE_ABI 6
#define VOW_UNIX_ABI 9
#define VOW_TSYNC_ABI 8

/* the kernel accepts a shorter struct; only the first field is used */
struct vow_ruleset_attr {
	uint64_t handled_access_fs;
};

/* the first three fields of the ruleset attribute: fs rights, net rights, scopes (abi 6) */
struct vow_ruleset_attr6 {
	uint64_t handled_access_fs;
	uint64_t handled_access_net;
	uint64_t scoped;
};

/* the kernel struct is packed (12 bytes); same offsets, trailing padding is never read */
struct vow_path_beneath {
	uint64_t allowed_access;
	int32_t parent_fd;
};

#define VOW_PR_SET_NO_NEW_PRIVS 38

/*
 * x86-64 syscall numbers, copied (not taken from libc headers, which may be
 * older than the kernel). tests/filter_test.c compares each one against the
 * running libc where it defines SYS_<name>.
 */
#define VOW_NR_read                       0
#define VOW_NR_write                      1
#define VOW_NR_readv                      19
#define VOW_NR_writev                     20
#define VOW_NR_pread64                    17
#define VOW_NR_pwrite64                   18
#define VOW_NR_preadv                     295
#define VOW_NR_pwritev                    296
#define VOW_NR_preadv2                    327
#define VOW_NR_pwritev2                   328
#define VOW_NR_lseek                      8
#define VOW_NR_close                      3
#define VOW_NR_close_range                436
#define VOW_NR_dup                        32
#define VOW_NR_dup2                       33
#define VOW_NR_dup3                       292
#define VOW_NR_fsync                      74
#define VOW_NR_fdatasync                  75
#define VOW_NR_sync_file_range            277
#define VOW_NR_fadvise64                  221
#define VOW_NR_fstat                      5
#define VOW_NR_fcntl                      72
#define VOW_NR_ioctl                      16
#define VOW_NR_mmap                       9
#define VOW_NR_mprotect                   10
#define VOW_NR_munmap                     11
#define VOW_NR_mremap                     25
#define VOW_NR_brk                        12
#define VOW_NR_madvise                    28
#define VOW_NR_mincore                    27
#define VOW_NR_msync                      26
#define VOW_NR_clock_gettime              228
#define VOW_NR_clock_getres               229
#define VOW_NR_gettimeofday               96
#define VOW_NR_time                       201
#define VOW_NR_nanosleep                  35
#define VOW_NR_clock_nanosleep            230
#define VOW_NR_getpid                     39
#define VOW_NR_getppid                    110
#define VOW_NR_gettid                     186
#define VOW_NR_getuid                     102
#define VOW_NR_geteuid                    107
#define VOW_NR_getgid                     104
#define VOW_NR_getegid                    108
#define VOW_NR_getgroups                  115
#define VOW_NR_getrlimit                  97
#define VOW_NR_prlimit64                  302
#define VOW_NR_uname                      63
#define VOW_NR_sysinfo                    99
#define VOW_NR_getrandom                  318
#define VOW_NR_sched_yield                24
#define VOW_NR_sched_getaffinity          204
#define VOW_NR_getrusage                  98
#define VOW_NR_times                      100
#define VOW_NR_rt_sigaction               13
#define VOW_NR_rt_sigprocmask             14
#define VOW_NR_rt_sigpending              127
#define VOW_NR_rt_sigsuspend              130
#define VOW_NR_rt_sigtimedwait            128
#define VOW_NR_sigaltstack                131
#define VOW_NR_pause                      34
#define VOW_NR_rt_sigreturn               15
#define VOW_NR_kill                       62
#define VOW_NR_tgkill                     234
#define VOW_NR_tkill                      200
#define VOW_NR_clone                      56
#define VOW_NR_clone3                     435
#define VOW_NR_futex                      202
#define VOW_NR_set_tid_address            218
#define VOW_NR_set_robust_list            273
#define VOW_NR_rseq                       334
#define VOW_NR_arch_prctl                 158
#define VOW_NR_prctl                      157
#define VOW_NR_poll                       7
#define VOW_NR_ppoll                      271
#define VOW_NR_select                     23
#define VOW_NR_pselect6                   270
#define VOW_NR_epoll_create               213
#define VOW_NR_epoll_create1              291
#define VOW_NR_epoll_ctl                  233
#define VOW_NR_epoll_wait                 232
#define VOW_NR_epoll_pwait                281
#define VOW_NR_eventfd                    284
#define VOW_NR_eventfd2                   290
#define VOW_NR_timerfd_create             283
#define VOW_NR_timerfd_settime            286
#define VOW_NR_timerfd_gettime            287
#define VOW_NR_pipe                       22
#define VOW_NR_pipe2                      293
#define VOW_NR_socketpair                 53
#define VOW_NR_sendmsg                    46
#define VOW_NR_recvmsg                    47
#define VOW_NR_recvfrom                   45
#define VOW_NR_sendto                     44
#define VOW_NR_shutdown                   48
#define VOW_NR_getsockname                51
#define VOW_NR_getpeername                52
#define VOW_NR_getsockopt                 55
#define VOW_NR_setsockopt                 54
#define VOW_NR_restart_syscall            219
#define VOW_NR_exit                       60
#define VOW_NR_exit_group                 231
#define VOW_NR_seccomp                    317
#define VOW_NR_landlock_create_ruleset    444
#define VOW_NR_landlock_add_rule          445
#define VOW_NR_landlock_restrict_self     446
#define VOW_NR_open                       2
#define VOW_NR_creat                      85
#define VOW_NR_openat                     257
#define VOW_NR_openat2                    437
#define VOW_NR_stat                       4
#define VOW_NR_lstat                      6
#define VOW_NR_newfstatat                 262
#define VOW_NR_statx                      332
#define VOW_NR_access                     21
#define VOW_NR_faccessat                  269
#define VOW_NR_faccessat2                 439
#define VOW_NR_readlink                   89
#define VOW_NR_readlinkat                 267
#define VOW_NR_getdents                   78
#define VOW_NR_getdents64                 217
#define VOW_NR_getcwd                     79
#define VOW_NR_chdir                      80
#define VOW_NR_fchdir                     81
#define VOW_NR_statfs                     137
#define VOW_NR_fstatfs                    138
#define VOW_NR_truncate                   76
#define VOW_NR_ftruncate                  77
#define VOW_NR_fallocate                  285
#define VOW_NR_mkdir                      83
#define VOW_NR_mkdirat                    258
#define VOW_NR_rmdir                      84
#define VOW_NR_unlink                     87
#define VOW_NR_unlinkat                   263
#define VOW_NR_rename                     82
#define VOW_NR_renameat                   264
#define VOW_NR_renameat2                  316
#define VOW_NR_link                       86
#define VOW_NR_linkat                     265
#define VOW_NR_symlink                    88
#define VOW_NR_symlinkat                  266
#define VOW_NR_rt_sigqueueinfo            129
#define VOW_NR_rt_tgsigqueueinfo          297
#define VOW_NR_accept                     43
#define VOW_NR_accept4                    288
#define VOW_NR_connect                    42
#define VOW_NR_bind                       49
#define VOW_NR_listen                     50
#define VOW_NR_sendmmsg                   307
#define VOW_NR_recvmmsg                   299
#define VOW_NR_socket                     41
#define VOW_NR_execve                     59
#define VOW_NR_execveat                   322

/* flags of the *at calls that change what a call can do */
#define VOW_RENAME_WHITEOUT    0x4	/* renameat2: leaves a character device behind */
#define VOW_AT_EMPTY_PATH      0x1000	/* linkat: name an inode through a descriptor */

/* open(2) flags, x86-64 values from asm-generic/fcntl.h */
#define VOW_O_ACCMODE  0x3
#define VOW_O_WRONLY   0x1
#define VOW_O_RDWR     0x2
#define VOW_O_CREAT    0x40
#define VOW_O_TRUNC    0x200
#define VOW_O_DIRECTORY 0x10000
#define VOW_O_PATH     0x200000
#define VOW_O_TMPFILE_BIT 0x400000	/* __O_TMPFILE; O_TMPFILE is this plus O_DIRECTORY */

/* seccomp and classic bpf, from linux/seccomp.h, linux/filter.h, linux/audit.h */
#define VOW_SYS_seccomp_nr             VOW_NR_seccomp
#define VOW_SECCOMP_SET_MODE_FILTER    1
#define VOW_SECCOMP_FILTER_FLAG_TSYNC  1U
#define VOW_SECCOMP_RET_KILL_PROCESS   0x80000000U
#define VOW_SECCOMP_RET_ERRNO          0x00050000U
#define VOW_SECCOMP_RET_ALLOW          0x7fff0000U
#define VOW_AUDIT_ARCH_X86_64          0xc000003eU  /* EM_X86_64 | 64BIT | LE */
#define VOW_X32_BIT                    0x40000000U

#define VOW_BPF_LD   0x00
#define VOW_BPF_ALU  0x04
#define VOW_BPF_JMP  0x05
#define VOW_BPF_RET  0x06
#define VOW_BPF_W    0x00
#define VOW_BPF_ABS  0x20
#define VOW_BPF_AND  0x50
#define VOW_BPF_JA   0x00
#define VOW_BPF_JEQ  0x10
#define VOW_BPF_JSET 0x40
#define VOW_BPF_K    0x00

/* struct sock_filter */
struct vow_insn {
	uint16_t code;
	uint8_t jt, jf;
	uint32_t k;
};

/* struct sock_fprog */
struct vow_prog {
	uint16_t len;
	struct vow_insn *filter;
};

/* struct seccomp_data offsets */
#define VOW_SD_NR   0
#define VOW_SD_ARCH 4
#define VOW_SD_ARG(i) (16 + 8 * (i))	/* low word; +4 for the high word */

/* the largest program the generator may emit; the kernel limit is 4096 */
#define VOW_MAX_INSNS 1024

#endif
