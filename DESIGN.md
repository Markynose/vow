<!-- SPDX-License-Identifier: LGPL-3.0-only -->
# vow design

status: milestones 1 to 3 are implemented and tested: `unveil()` with `s`, the seccomp generator and installer, and the promises `stdio`, `rpath`, `wpath`, `cpath`, `inet`, `exec`. signal isolation follows alternative S2 (section 2.7): `pledge` with `stdio` requires a landlock signal scope and fails otherwise; there is no pid based fallback. no further promise is planned for v0.1; the next work is a broader security review, tests across kernels and glibc compatibility (section 14).

vow is a small static library giving linux programs two openbsd-style calls: `pledge()` and `unveil()`. it is built on landlock (filesystem) and seccomp classic bpf (syscalls). it is not a port of openbsd semantics. where linux cannot enforce the same thing, vow rejects the request instead of pretending.

## 0. verification record

facts below were checked, not assumed. "run" means executed on the dev machine (kernel 7.2.9, musl, x86-64, landlock abi 10, errata mask 15). "read" means read from a primary source but not executed.

landlock (read from the kernel userspace-api docs, docs.kernel.org/userspace-api/landlock.html, and upstream `include/uapi/linux/landlock.h`):

| abi | adds |
|---|---|
| 1 | base filesystem rights |
| 2 | `FS_REFER` |
| 3 | `FS_TRUNCATE` |
| 4 | tcp bind and connect rights |
| 5 | `FS_IOCTL_DEV` |
| 6 | scopes (abstract unix socket, signal) |
| 7 | audit logging flags |
| 8 | `LANDLOCK_RESTRICT_SELF_TSYNC` = `1U << 3` |
| 9 | `FS_RESOLVE_UNIX` = `1ULL << 16` |
| 10 | udp rights and quiet rules |
| 11 | `LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS` = `1U << 4` |

- the earlier draft guessed abi 8 to 10 wrongly (it did not know them). abi numbers and constants above replace it.
- not controlled by landlock, per the docs: `chdir`, `stat`, `flock`, `chmod`, `chown`, `setxattr`, `utime`, `fcntl`, `access`.
- stacked layers are limited to 16.
- `TSYNC` "applies the new Landlock configuration atomically to all threads of the current process"; it overrides sibling domains and enables no_new_privs on siblings if the caller has it.
- `LANDLOCK_CREATE_RULESET_VERSION` fails with `ENOSYS` (no landlock) or `EOPNOTSUPP` (disabled).
- the installed `/usr/include/linux/landlock.h` here predates abi 8 (no `TSYNC`, no `RESOLVE_UNIX`). vow treats a missing header constant as a build issue (it carries its own copy in `src/sys.h`, with values from upstream) and a missing kernel feature as a runtime issue (abi probe). the two are never mixed.
- (run) executing a file needs `FS_READ_FILE` as well as `FS_EXECUTE`: a rule with only execute gave `EACCES` on `execve`. the draft assumed execute alone was enough. this changes the meaning of `x` (section 2.6).

openbsd (read from man.openbsd.org and the openbsd src repo, `pledge.2`, `unveil.2`):

- `unveil`: first call hides the rest of the filesystem; `r`, `w`, `x`, `c` map to `rpath`; `chown`+`fattr`+`wpath`; `exec`; `cpath`+`dpath`+`unix`. so on openbsd `w` also covers attribute changes and `c` covers create and remove.
- `unveil(NULL, NULL)` or a pledge without the `unveil` promise locks it. unveil after lock gives `EPERM`; so does an attempt to increase permissions or an inaccessible path. paths with no matching unveil give `ENOENT` on use, wrong permission gives `EACCES`.
- a directory rule applies "if and only if no more specific matching unveil exists at a lower level": narrowing is real on openbsd.
- the man page says nothing about `unveil` across `fork` or `execve`. the draft claimed it resets on exec; that claim is removed. vow does not rely on it.
- `pledge`: `NULL` means "do not change". widening gives `EPERM`. with `execpromises` set, the new program starts with them; setuid or setgid execs are blocked with `EACCES`; otherwise the new program runs without pledge. violation kills with an uncatchable `SIGABRT`.
- `stdio` includes `fstat`, `fcntl`, `close`, `dup`, memory calls with `mmap` and `mprotect` only without `PROT_EXEC`, `sendmsg`, `recvmsg`, `recvfrom`, `sendto` (only with a NULL destination address). `kill` is part of `proc`. `proc` also holds `fork` and `vfork`.

libc behavior for the stdio policy:

- (run, musl) `fstat(fd)`, `fstatat(fd, "", AT_EMPTY_PATH)` and `isatty` use syscalls `fstat` and `ioctl(TIOCGWINSZ)` (strace). path `stat` uses `stat`.
- (read, glibc) `fstat64.c` calls `fstat` directly on x86-64 (`INLINE_SYSCALL_CALL (fstat, ...)`); `fstatat` uses `statx` or `newfstatat`. glibc is not installed on this machine so this was not executed. a glibc run stays on the milestone 3 test list.
- result: `stdio` allows syscall `fstat` only. `newfstatat` and `statx` belong to `rpath`.
- (run, musl) `raise()`, `pthread_kill()` and `abort()` use `tkill(tid, sig)`. `kill(getpid(), sig)` uses `getpid` then `kill`. thread creation is `clone` with `CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID`. `send(fd, buf, 1, 0)` is `sendto(..., NULL, 0)`.
- (read, glibc) `pthread_kill` uses `tgkill(getpid(), tid, sig)`.

landlock `FS_RESOLVE_UNIX` (read from upstream `landlock.h` and the kernel docs): "look up pathname UNIX domain sockets. On UNIX domain sockets, this restricts both calls to connect(2) as well as calls to sendmsg(2) with an explicit recipient address." it applies only to servers "created outside of the newly created Landlock domain"; servers created inside the same domain stay reachable. denial gives `EACCES` (abstract sockets, by contrast, are covered only by the separate scope flag). the right is file-applicable (it can sit on the socket file or on a directory above it). the docs do not say what happens to already connected sockets or `socketpair()`; the tests show they are not affected.

executing a file (run, `tests/unveil_test.c`, raw syscalls with no vow code): with `READ_FILE` handled, a rule granting only `EXECUTE` makes `execve` of a fully static musl binary fail with `EACCES`; `EXECUTE|READ_FILE` works; handling only `EXECUTE` works. so the kernel opens the executed file for reading and landlock judges that open with the read right even when no interpreter is involved. for a dynamic musl binary (run, scratch experiment): the executable needs `rx`, the interpreter `/lib/ld-musl-x86_64.so.1` also needs `rx` (read only fails, execute only fails); musl keeps libc in the same file, so no other library was involved. libraries that a loader maps later need read access (the loader opens them), not execute. this is the concrete limitation behind refusing a bare `x` (section 2.6).

seccomp and the kernel (run, `tests/seccomp_test.c`, kernel 7.2.9):

- argument widths: the kernel truncates `int`, `unsigned int` and `pid_t` arguments to 32 bits (a call with junk in the upper half behaves exactly as one without) and reads pointers and `prctl`'s `unsigned long` arguments in full (a high bit changes the result). the filter must follow the kernel in both directions, so each comparison in the policy tables carries a kind, and the tests probe the bare kernel to check every declared kind (section 5). the first draft of this document had it backwards (it wanted the high half checked for ints).
- exempt calls: syscall 335 (`uretprobe`) and 336 (`uprobe`) are not subject to seccomp filters. called from ordinary code they end the caller with `SIGILL` (335) or return `EPROTO` (336). this is not an escape, but a filter can never turn them into a kill, and the kernel differential skips them.
- x32 numbers: the bit `0x40000000` makes the number match no rule, so an x32 call is denied even without the explicit check. the explicit check stays as a second line.
- `SECCOMP_RET_ERRNO` accepts values up to 4095; the tests use 1001 as an errno no real call returns.

## 1. public api (m1)

```c
#include <vow.h>

int unveil(const char *path, const char *permissions);
int pledge(const char *promises, const char *execpromises);
```

both return 0 on success and -1 with `errno` set. names match openbsd so existing code compiles. there is no other public function and no public abi probe (decided). the header also defines `VOW_VERSION_MAJOR`, `VOW_VERSION_MINOR` and `VOW_VERSION`.

### lifecycle

```
process start
  open everything that needs broad access (config, sockets, log files, output dirs)
  unveil(path, perms) ...            # collect rules, nothing enforced yet
  unveil(NULL, NULL)                 # commit: landlock enforced, unveil sealed
  pledge("stdio rpath inet", NULL)   # install seccomp filter (not yet implemented)
  main loop
  pledge("stdio", NULL)              # tighten further whenever possible
```

### failure contract

- a failed call leaves the sandbox *policy* as it was: the kernel installs a landlock domain or a seccomp filter atomically, and userspace state changes only after success. it can leave one irreversible side effect: `no_new_privs` is set before the kernel call that may fail, and cannot be cleared. a failed `pledge()` or `unveil(NULL, NULL)` therefore may leave the process with `no_new_privs` on (tested), which matters to programs that rely on setuid helpers.
- a program that gets a failure after an earlier successful sandbox call is partly sandboxed. callers must treat every failure as fatal (`_exit`). examples and README do.
- nothing is ever downgraded silently. unknown or unrepresentable input is an error.
- `pledge()` and `unveil()` are safe to call from several threads at once: each takes a spin lock (no system call, so it works under any pledge) around its whole body. the order of two concurrent calls is arbitrary, but the library state and the kernel state always agree (tested with a deliberately widened race window; without the lock both race tests fail).
- fork: `pthread_atfork` handlers, registered on the first call, take both locks before `fork()` and give them back in parent and child, so a child never inherits a lock held by a thread that does not exist in it, nor a half-updated table (tested: a thread sits inside `unveil()` or `pledge()` while another forks; without the handlers the child waits for a lock nobody can release). they do nothing else: no landlock domain is created in the child (section 2.7). fork from a signal handler that interrupted one of the calls is not supported.
- signal handlers: neither call is async-signal-safe. a handler that interrupts `pledge()` or `unveil()` and calls either one gets `-1` with `EDEADLK` instead of waiting for the thread it interrupted (tested; the interrupted call finishes normally). a thread-local flag marks "inside"; handlers that run on another thread simply wait for the lock.

### errno values

| errno | meaning |
|---|---|
| `EINVAL` | malformed or unknown promise or permission character, `NULL` path with permissions or the reverse |
| `ENOTSUP` | recognised openbsd concept that linux cannot enforce as asked (bare `x`, `c` on a non-directory, `s` below landlock abi 9, a narrowing rule, unrepresentable `execpromises`, promise names not implemented yet) |
| `EPERM` | request would widen privilege, or unveil is already sealed |
| `ENOSYS` | kernel lacks landlock or seccomp, or landlock abi below 3 |
| `EOPNOTSUPP` | landlock compiled in but disabled at boot (passed through from the kernel) |
| `ENOSYS`, `EOPNOTSUPP`, `EBUSY` from `pledge` | with `stdio`: no landlock signal scope can be entered. `ENOSYS`: no landlock or abi below 6; `EOPNOTSUPP`: landlock disabled; `EBUSY`: abi 6 or 7 and the process is not provably single threaded (a scope binds only the calling thread there). nothing is installed |
| `EBUSY` | `unveil(NULL, NULL)` or the first `pledge` with `stdio` refused because the kernel does not list exactly one thread for the process (or the list cannot be read), on every abi (section 6, X2); or seccomp could not synchronize a thread that carries an unrelated filter (`TSYNC` returned the id of that thread; nothing was installed) |
| `ESTALE` | the path changed between opening it and resolving it |
| `ENOENT`, `EACCES`, `ELOOP`, ... | passed through from path resolution |
| `ENOMEM`, `EMFILE`, `ENFILE` | allocation or descriptor limits (one descriptor per rule until commit) |

## 2. semantics

### 2.1 pledge promise strings (m2)

space separated, case sensitive, at most 1023 characters (`EINVAL` beyond). empty string means "nothing but exit". implemented: `stdio`, `rpath`, `wpath`, `cpath`, `inet`, `exec`. `NULL` means "leave unchanged". unknown tokens give `EINVAL`, and `EINVAL` wins over `ENOTSUP` when both occur. known openbsd tokens that are not enforced (`proc`, `dns`, `unix`, `tty`, `fattr`, `flock`, `recvfd`, `sendfd`, `unveil`, ... later or never) give `ENOTSUP`. promises are independent bits as on openbsd: `rpath` alone does not include `read(2)`; that is `stdio`.

### 2.2 repeated calls (m2)

the current promise set `P` lives in userspace. a call with new set `N` must satisfy `N` subset of `P` (or `P` unset on the first call), otherwise `EPERM`. each successful call builds a filter for the full set `N` and stacks it. the kernel takes the most restrictive result of all stacked filters, so even corrupted userspace state could not widen.

### 2.3 pledge and unveil together (m2)

- a pledge that does not include `rpath` also locks unveil, as a pledge without the `unveil` promise does on openbsd: every form of `unveil()` returns `EPERM` before touching the kernel. this also prevents an in-library pledge kill, since unveil needs `openat` (with `O_PATH`), `fstat`, `readlink` (musl `realpath`) and, on old kernels, `/proc/self/task`. with `rpath` in the set all of those are allowed, and `pledge("stdio rpath")` followed by `unveil()` and the commit is tested. recommended order is still unveil, commit, then pledge.
- landlock syscalls, `seccomp(SECCOMP_SET_MODE_FILTER)` and `prctl(PR_SET_NO_NEW_PRIVS, 1)` are allowed in every filter because they can only tighten.

### 2.4 execpromises (m2)

filters and landlock domains survive `execve` and cannot be swapped at exec time. therefore:

- `NULL`: accepted. the exec-ed image inherits the current filter and domain. this is stricter than openbsd, where the new program starts unrestricted. documented deviation.
- non-NULL and equal as a set to the resulting `promises`: accepted, since inheritance is exactly that.
- anything else: `ENOTSUP`. never ignored.

openbsd blocks setuid and setgid execs with `EACCES` when execpromises are set. vow sets `no_new_privs`, which makes setuid exec succeed but without privilege. also a documented deviation.

in v0.1 `exec` means `execve` and `execveat` only. fork-like clones are the unimplemented `proc` promise.

### 2.5 promises (m2: stdio and the core set; the rest is design)

default denial action is `SECCOMP_RET_KILL_PROCESS` (decided). `clone3` and `openat2` are answered with `ENOSYS` by policy because their arguments live in a struct the filter cannot read. that answer is a choice, not a guarantee that every caller copes: glibc 2.34 and later fall back from `clone3` to `clone`, musl never calls `clone3`, but another runtime might treat the error as fatal. the tests show the answer with raw calls; nothing relies on a fallback existing. same for `tkill` below, which is answered with `EPERM`.

every filter starts with: check `arch == AUDIT_ARCH_X86_64` else deny; check `nr & 0x40000000` (x32) else deny; then rule blocks; then a final deny. each block is `load nr; jeq nr else skip block; conditions (each failing = skip block); ret`. so rules for the same number are alternatives (the first whose conditions hold wins), and no jump leaves its block, which keeps every offset under the 8-bit limit (the builder fails with `E2BIG` instead of truncating).

always allowed (the core table, also in the empty set): `exit`, `exit_group`, `rt_sigreturn`, `restart_syscall`, the three landlock syscalls, `seccomp` with op `SECCOMP_SET_MODE_FILTER` (as an `unsigned int`, so junk above 32 bits is ignored like in the kernel), `prctl` with option `PR_SET_NO_NEW_PRIVS` and an `unsigned long` value of exactly 1.

#### stdio

- io on existing descriptors: `read write readv writev pread64 pwrite64 preadv pwritev preadv2 pwritev2 lseek close close_range dup dup2 dup3 fsync fdatasync sync_file_range fadvise64`. `fstat` only (not `newfstatat` or `statx`, section 0).
- `fcntl` with cmd in `F_GETFD F_SETFD F_GETFL F_SETFL F_DUPFD F_DUPFD_CLOEXEC F_GETLK F_SETLK F_SETLKW F_OFD_*`; not `F_SETOWN`, `F_SETSIG`, `F_SETPIPE_SZ`.
- `ioctl` with cmd in `FIONREAD FIONBIO FIOCLEX FIONCLEX TCGETS TIOCGWINSZ`.
- memory: `mmap mprotect munmap mremap brk madvise mincore msync`. `mmap` and `mprotect` are killed when `prot` has both `PROT_WRITE` and `PROT_EXEC`. `PROT_EXEC` alone stays allowed, unlike openbsd, which forbids it in stdio: a vow policy is inherited across exec and a dynamic child needs executable mappings. documented deviation. **this does not enforce w^x**: the filter only refuses a region that is writable and executable at the same moment. code can be written to a writable page and then made executable with a second `mprotect` (read-write to read-exec to read-write again all work; tested by running generated code). what limits such code is the syscall filter, which applies to it like to any other (tested: injected machine code that calls `socket` is killed). junk above bit 31 of `prot` cannot hide a write+exec request, because the filter reads the low word (tested), and `PROT_GROWSDOWN` does not either.
- time, ids and info: `clock_gettime clock_getres gettimeofday time nanosleep clock_nanosleep getpid getppid gettid getuid geteuid getgid getegid getgroups getrlimit prlimit64 (new_limit NULL only) uname sysinfo getrandom sched_yield sched_getaffinity`.
- signals handling: `rt_sigaction rt_sigprocmask rt_sigpending rt_sigsuspend rt_sigtimedwait sigaltstack pause`.
- signals: `kill`, `tgkill`, `tkill`, `rt_sigqueueinfo` and `rt_tgsigqueueinfo` pass the filter with any arguments. the filter contains no pid and no thread id. what makes this safe is not in the filter: `pledge()` does not install a filter with `stdio` before the process is inside a landlock signal scope, which confines every signal the process sends to its own domain (section 2.7). a filter built without that step is not safe and the library never builds one.
- threads: `clone` only when the low 32 bits of the flags contain `CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM` and nothing outside those plus `SETTLS`, `PARENT_SETTID`, `CHILD_CLEARTID`, `CHILD_SETTID` and the obsolete `DETACHED` bit (musl sets it), so no namespace flags, no ptrace, no exit signal; anything else is killed. real musl `pthread_create` flags were checked under the filter; `futex set_tid_address set_robust_list rseq arch_prctl(ARCH_SET_FS)`; `prctl` with `PR_SET_NAME PR_GET_NAME`. `clone3` returns `ENOSYS`.
- waiting and pipes: `poll ppoll select pselect6 epoll_create1 epoll_ctl epoll_wait epoll_pwait eventfd2 timerfd_* pipe pipe2`.
- sockets on existing descriptors: `socketpair` with domain `AF_UNIX`, `sendmsg recvmsg recvfrom shutdown getsockname getpeername getsockopt`, and `setsockopt` for a list of options that only tune a connection (below). `sendto` only when the destination address pointer (argument 5) is NULL, as on openbsd. this is checkable because the filter sees the pointer value, not its target.

descriptor passing: `sendmsg` and `recvmsg` are allowed and the filter cannot look into the message, so `SCM_RIGHTS` passing is not restrictable with seccomp (decided: do not claim otherwise). a process can pass any descriptor it holds over any socket it holds, and can receive descriptors from any peer it is connected to. openbsd has separate promises for this; vow has none. the consequence is listed with the other open descriptor gaps in section 6. `sendmsg` also carries an optional destination address that cannot be checked, which matters only for inherited unconnected sockets, since stdio cannot create ip sockets.

not in stdio: `socket`, `connect`, `bind`, `open*`, path `stat`, `fork`, `vfork`, `execve`, `ptrace`, `process_vm_*`, `io_uring_*`, `mount`, `bpf`, `userfaultfd`, `keyctl`, `personality`, `setns`, `unshare`, `perf_event_open`, `memfd_create`, `chroot`.

#### rpath (m3)

reading paths and their metadata: `stat lstat newfstatat statx access faccessat faccessat2 readlink readlinkat getdents getdents64 getcwd chdir fchdir statfs fstatfs`, plus the open classes below. `fstat` on an open descriptor is `stdio`. `rpath` alone does not read from the descriptors it opens (`read` is `stdio`).

#### how open, openat and creat are classified (m3, all three path promises)

one matrix, written in terms of what a call needs from the promise set. `R` read, `W` write, `C` create. the flags are an `int` (the kernel truncates them to 32 bits, tested), and flags the matrix does not name are neutral.

| flags (f, with `O_PATH` clear) | needs |
|---|---|
| access mode `O_RDONLY` | R |
| access mode `O_WRONLY` | W |
| access mode `O_RDWR`, and mode 3 | R and W |
| `O_TRUNC`, with any mode | W (the kernel truncates a file opened read-only; tested) |
| `O_CREAT`, with any mode | C |
| `O_TMPFILE` bit (`0x400000`), valid or not | W and C |
| `O_PATH` (open, openat) | R, and nothing else is looked at: the kernel drops every other flag for these two calls (tested: no truncation, no creation) |
| `creat(2)` | W and C |
| `openat2(2)` | refused with `ENOSYS`: the flags are in a struct the filter cannot read |
| `O_CLOEXEC O_LARGEFILE O_NONBLOCK O_NOCTTY O_DIRECTORY O_NOFOLLOW O_NOATIME O_APPEND O_EXCL O_DIRECT O_SYNC O_DSYNC`, unknown bits | nothing |

a call is allowed when all it needs is in the set, so for example `O_RDWR|O_CREAT` needs `rpath`, `wpath` and `cpath`, and `O_RDONLY|O_CREAT|O_TRUNC` needs all three too. a combination the kernel rejects with `EINVAL` (such as `O_TMPFILE` with a read-only mode) is classified by the same rules, conservatively. mode 3 (`O_WRONLY|O_RDWR`) is classified as read and write because the kernel checks both permissions for it (tested with files of mode 0200 and 0400).

deviations from openbsd that this matrix makes on purpose: `O_RDONLY|O_TRUNC` needs write (linux truncates), `O_PATH` is allowed with `rpath`, `O_TMPFILE` needs write and create, and the create bit alone is not enough to create (`O_CREAT|O_WRONLY` needs `wpath` as well as `cpath`). where this matrix and openbsd differ, this matrix is what is enforced.

generation: the matrix is split into cubes over the five flags that change the need (access bit 0, access bit 1, `O_CREAT`, `O_TRUNC`, `O_TMPFILE`), every cube is a rule `(flags & mask) == value` on argument 1 (open) and argument 2 (openat), plus an `O_PATH` rule when `R` is in the set. no more than 8 rules per set are produced today; the table has room for 48 and a test fails if a set comes near it.

#### wpath (m3)

changing the contents of files without opening them anew: `truncate`, `ftruncate`, `fallocate` (which also punches holes and collapses ranges: all of it changes contents). opening for writing is in the open matrix above. `wpath` alone does not read, create or remove anything.

#### cpath (m3)

making and removing names: `mkdir mkdirat rmdir unlink unlinkat rename renameat renameat2 link linkat symlink symlinkat`, plus the create class of the open matrix (`O_CREAT`, `O_TMPFILE`, `creat`). two flags change what a call is, and are refused:

- `renameat2` with `RENAME_WHITEOUT` (0x4) leaves a character device node behind, which needs `CAP_MKNOD`: this is a device-node creation by another name. `RENAME_NOREPLACE` and `RENAME_EXCHANGE` are allowed. the flags are an `unsigned int` (argument 4), tested with junk above bit 31 that must neither hide the bit nor add one.
- `linkat` with `AT_EMPTY_PATH` (0x1000) names an inode through a descriptor and needs `CAP_DAC_READ_SEARCH`; refused so that a privileged process cannot give names to inodes it only holds descriptors for. `AT_SYMLINK_FOLLOW` is allowed; it is how an `O_TMPFILE` file is published through `/proc/self/fd/N` (tested when `/proc` is there).

not part of `cpath`: `mknod` and `mknodat` (device nodes, fifos, sockets; `mkfifo` is killed), `chmod`, `chown`, `utimensat`, extended attributes. `unlinkat` with or without `AT_REMOVEDIR`, and `rename` that replaces an existing name, are creation or removal of names and need only `cpath`.

#### operation to promise matrix (m3, as tested)

one row per call; `R`, `W`, `C` are `rpath`, `wpath`, `cpath`; "no path promise" means no combination of the three allows it.

| call | needs | notes |
|---|---|---|
| `open`, `openat` | by flags, see the open matrix | flags are an `int`; `openat2` answers `ENOSYS` |
| `creat` | W and C | |
| `stat lstat newfstatat statx access faccessat faccessat2 readlink readlinkat getdents getdents64 getcwd chdir fchdir statfs fstatfs` | R | |
| `truncate ftruncate fallocate` | W | an already writable descriptor is enough for the content; the open decided that |
| `mkdir mkdirat rmdir unlink unlinkat rename renameat link symlink symlinkat` | C | |
| `renameat2` | C | except `RENAME_WHITEOUT` |
| `linkat` | C | except `AT_EMPTY_PATH` |
| `mknod mknodat chmod fchmod fchmodat chown lchown fchownat utime utimes futimesat utimensat setxattr getxattr listxattr removexattr` | no path promise | metadata and special files |
| `mount umount2 chroot pivot_root open_tree fsopen name_to_handle_at open_by_handle_at memfd_create inotify_add_watch flock sendfile splice copy_file_range` | no path promise | |
| `execve execveat socket` | no path promise | `exec` and `inet` |

the table is also data in `tests/filter_test.c`, checked for every subset of the three promises (the oracle states it separately). a call that needs only R, W or C is allowed by that promise alone: `cpath` does not need `rpath` to `unlink` or `rename`, `wpath` does not need `rpath` to `truncate`.

deviations from openbsd that this matrix makes on purpose are listed in the open matrix section and in section 12; where this matrix and openbsd differ, this matrix is what is enforced.

#### descriptors, O_PATH and the *at calls: what they expose (m3 review)

- `O_PATH` (allowed with `rpath`): the descriptor can be given to `fstat`, `fchdir`, `readlinkat`, `statx(AT_EMPTY_PATH)`, used as the base of `openat` (still subject to the open matrix: relative opens are classified by their flags like any other) and `*at` calls. it cannot read or write (`EBADF`). `linkat(AT_EMPTY_PATH)` would turn it into a new name, and is refused (above). reopening it through `/proc/self/fd/N` is an ordinary `open` and classified as such. linking through `/proc/self/fd/N` with `AT_SYMLINK_FOLLOW` is allowed with `cpath` and gives a new name to any inode the process holds a descriptor for (subject to the hard link protection of the kernel); documented, not blocked.
- the *at calls take a directory descriptor and a relative name, so a descriptor opened before the pledge is a capability for that directory: seccomp cannot tell it from `AT_FDCWD`. observed (tests, linux 7.2.9): with an unveil rule that does not cover the directory behind such a descriptor, landlock refuses `mkdirat`, `unlinkat`, `symlinkat`, `renameat` and `openat(O_WRONLY)` through it with `EACCES`, and refuses to link an inode in from outside through `/proc/self/fd`. so unveil compensates for path creation and removal reached through a directory descriptor. it does **not** compensate for a descriptor that is already open for writing: `ftruncate`, `fallocate` and `write` on it keep working after the commit (landlock judges at open time). without unveil nothing compensates for anything: `cpath` can create and remove names anywhere the uid can.
- landlock does not cover metadata (section 6); `wpath` and `cpath` do not include any metadata call, so for a pledged process seccomp is what closes `chmod`, `utimensat` and `setxattr`; for an unpledged one nothing does.
- a rename or link across an unveil boundary needs `REFER` on both sides in landlock, which `c` grants; the `cpath` filter has no notion of it, so the two layers answer separately (tested both ways).

#### inet (m3)

IP sockets. the rules, as tested (the oracle states them again on its own):

| call | allowed when |
|---|---|
| `socket(domain, type, protocol)` | domain `AF_INET` or `AF_INET6`; type, after taking off `SOCK_NONBLOCK` and `SOCK_CLOEXEC`, is `SOCK_STREAM` with protocol 0 or 6, or `SOCK_DGRAM` with protocol 0 or 17. all three are ints (junk above bit 31 is ignored, as by the kernel; probed) |
| `connect bind listen accept accept4 sendmmsg recvmmsg` | always, on any descriptor |
| `sendto` | with any address (stdio allows only a null address) |

refused, and tested with a kill: `AF_UNIX`, `AF_PACKET`, `AF_NETLINK` and every other family; `SOCK_RAW`, `SOCK_SEQPACKET`, type 0; protocols sctp (132), mptcp (262), udplite (136), icmp ping sockets (1), and tcp on a datagram socket or udp on a stream; any type flag other than the two the kernel accepts. these protocols open more kernel code than a tcp/udp client or server needs.

`setsockopt` (in `stdio`, so it also applies to sockets that exist already) is limited to an allowlist of 49 level and option pairs: `SOL_SOCKET` reuseaddr, dontroute, broadcast, sndbuf, rcvbuf, keepalive, oobinline, linger, reuseport, passcred, rcvlowat, send/receive timeouts, timestamp; `IPPROTO_IP` tos, ttl, pktinfo, mtu discover, recverr, recvttl, recvtos; `IPPROTO_IPV6` unicast hops, mtu discover, recverr, v6only, recvpktinfo, recvhoplimit, dontfrag, recvtclass, tclass; `IPPROTO_TCP` nodelay, maxseg, cork, keepalive idle/interval/count, syncnt, linger2, defer accept, window clamp, quickack, user timeout, fastopen, fastopen connect, notsent lowat; `IPPROTO_UDP` cork. level and option are ints. everything else is a violation, among it: `SO_ATTACH_FILTER`, `SO_ATTACH_BPF`, `SO_BINDTODEVICE`, `SO_MARK`, `IP_OPTIONS` (source routing), `IP_HDRINCL`, the multicast options, `TCP_ULP` (loads a kernel module), `TCP_MD5SIG`, `TCP_REPAIR`, `TCP_CONGESTION`. `getsockopt` stays open. this restriction is new in milestone 3: milestone 2 let `stdio` call `setsockopt` freely.

what `inet` cannot do, all of it documented and in the tests:

- **addresses and ports.** `connect`, `bind`, `sendto` and `sendmsg` carry the address in memory, which the filter cannot read. any host and any port can be reached, including privileged ports a process may bind and other local services. landlock has network rules (tcp bind and connect by port from abi 4, udp from abi 10); they are not used in v0.1. unveil does not touch the network at all (tested: with an unveil rule set, loopback connections to arbitrary ports still work).
- **descriptors that exist.** `connect`, `bind`, `listen`, `accept` take any descriptor, whatever its family. a pathname unix socket made before the pledge can be connected or bound under `inet`: `connect` reaches any unix server and `bind` creates a socket file without `cpath` (both tested without unveil). with an unveil rule set that lacks `s` or `c`, landlock refuses both (`EACCES`, abi >= 9 for the connect; the socket file needs `c`). abstract sockets are never covered. the same descriptors can be used the same way after `stdio` alone, minus `connect`/`bind`/`listen`/`accept`.
- **datagram destinations.** under `stdio` alone, an existing unconnected datagram socket can still send anywhere with `sendmsg` (the destination is in the message); only `sendto` with an address is refused (both tested). connect such sockets before the pledge.
- **already connected sockets** keep working under `stdio`: read, write, send, recv, shutdown, the queries and the allowed options (tested).
- **names.** no `dns` promise: a numeric address needs no file (tested under `stdio inet`); a name makes musl open `/etc/hosts` and maybe `/etc/resolv.conf`, which is a violation without `rpath` (tested, killed) and works with `rpath` plus an unveil of just those files (tested). glibc may load nss modules through `dlopen`, which fails inside a pledge.
- **ipv6** is covered by the same rules and tested on loopback (skipped where there is no `::1`).

#### exec (m3)

`execve` and `execveat`, nothing else (no fork-like call: that is the unimplemented `proc`). what a successful exec means:

- **everything inherited, nothing widened.** the new image runs under all seccomp filters of the old one (tested: a static helper that calls `socket` is killed with `SIGSYS`; `/proc/self/status` of the new image shows `NoNewPrivs: 1` and `Seccomp: 2`), under the landlock domain (tested: it cannot open what the old image could not, and the exec rule of unveil decides which programs can start: a program that was not unveiled `rx` fails to start with `EACCES`, not a kill), and in the signal domain. `no_new_privs` keeps setuid and file capabilities from taking effect (the kernel reports it in the new image; a setuid-root exec could not be exercised without root).
- **no `execpromises`.** the policy cannot change at exec: it is neither narrower nor wider in the new image. `pledge(p, e)` therefore accepts `e` only when it equals `p` as a set (or is `NULL`), and returns `ENOTSUP` otherwise (tested). a launcher that wants the child narrower must pledge that narrower set in itself before the exec, which also narrows itself.
- **descriptors cross exec.** every descriptor that is not close-on-exec is in the new image, with the rights it had. tested: a file opened for writing before an unveil that hides it is still writable by the new program; the same descriptor opened with `O_CLOEXEC` is gone; `close_range(3, ~0, 0)` before the exec (allowed by `stdio`) removes the rest. **running an untrusted binary means giving it all descriptors you did not close**, all rights of the pledge (an `rpath` without unveil is the whole readable filesystem), the environment, and the signal domain; what it cannot do is exceed the filters. it can, for example, use an inherited socket, signal anything in its domain, and write to any inherited writable descriptor.
- **environment.** the dynamic loader of musl honours `LD_LIBRARY_PATH` and `LD_PRELOAD`; a caller that executes a trusted dynamic program with an environment an attacker can influence lets the attacker choose code to load (inside the same filters). clear or rebuild the environment before the exec.
- **dynamic programs.** a dynamic executable needs `rx` on the interpreter as well as on itself (tested: with only the program unveiled the exec fails with `EACCES`); libraries the loader opens need read access, so a program with libraries other than the libc needs `rpath` in the pledge. a musl program that links only the libc starts without `rpath` (tested, since musl keeps libc in the interpreter). `/proc` is closed to the new program by the same unveil (tested).
- **`execveat` with `AT_EMPTY_PATH`** (running a descriptor) is allowed like running a path; landlock judges the file again at that point, so an unveil rule that does not cover the file refuses it (tested, `EACCES`), and without unveil nothing is compensated.
- scripts need `x` and `r` on the script and `rx` on the interpreter named in `#!`.
- **after the exec the library is gone**: the new image has its own state; there is no library call that can lift anything.

### 2.6 unveil (m1)

```
unveil(path, perms)   add or replace a rule; path is resolved now
unveil(NULL, NULL)    commit and seal
```

`perms` is a string of `r w x c s`, duplicates ignored, empty allowed. anything else is `EINVAL`.

| perm | landlock rights | notes |
|---|---|---|
| `r` | `READ_FILE`, plus `READ_DIR` on directories | |
| `w` | `WRITE_FILE`, `TRUNCATE` | existing files only; does not cover `chmod`, `chown`, `utime` (section 6) |
| `x` | `EXECUTE` | must be combined with `r` or the call fails with `ENOTSUP`; evidence in section 0 and in two kernel tests that use raw syscalls, so a kernel that changes this is noticed. a dynamic executable also needs `rx` on its interpreter |
| `s` | `RESOLVE_UNIX` | abi >= 9 only; `ENOTSUP` below. lets the process connect or `sendto` to pathname unix sockets at or below the path (a socket file or a directory) |
| `c` | `MAKE_REG MAKE_DIR MAKE_SYM MAKE_SOCK MAKE_FIFO REMOVE_FILE REMOVE_DIR REFER` | directories only; on a non-directory the call fails with `ENOTSUP` |

`MAKE_CHAR` and `MAKE_BLOCK` are never granted. creation rights belong to the parent directory in landlock, which is why `c` on a non-directory is refused: to let a program create `/tmp/f`, unveil `/tmp` (or a dedicated directory) with `c`, not the name. rights that do not apply to a file are dropped for file rules. a rule whose right set ends up empty (for example `""`) grants nothing and is not added to the ruleset, but still takes part in the conflict check.

the handled set is the abi 3 set (`EXECUTE` through `TRUNCATE`, bits 0 to 14) plus `RESOLVE_UNIX` when the kernel is at abi 9 or above. so on abi >= 9 a process cannot connect to any pathname unix socket unless a rule carries `s` for it (default deny); on abi 3 to 8 pathname unix sockets are not restricted at all, and only a request that needs `s` is refused (`ENOTSUP`). a program that must be sure unix sockets are closed cannot get that from unveil on an old kernel; it needs a pledge (no `socket` in `stdio`) and no open socket. other later rights (`IOCTL_DEV`) are not handled (section 6).

`s` limits, all tested (m1+): it covers `connect` and `sendto` with an explicit address (streams and datagrams); it does not cover abstract sockets (a separate namespace, reachable regardless); connections made before the commit keep working; a server created inside the sandbox domain stays reachable without `s` (kernel semantics); `socketpair` has no path and is unaffected; a denial is `EACCES`.

#### why unveil is deferred

openbsd enforces from the first call. landlock cannot: rules go into a ruleset before `landlock_restrict_self`, and later rulesets only intersect. so vow collects calls and enforces at `unveil(NULL, NULL)`. between the first call and the commit nothing is restricted. a program that never commits has no filesystem protection. with no path ever unveiled, `unveil(NULL, NULL)` only seals (decided, matches openbsd).

#### table and tocttou

each `unveil(path, perms)`:

1. check arguments, sealed state, abi (`ENOSYS` below 3).
2. grow the table if full (`realloc`, doubling from 16). failure gives `ENOMEM` and leaves earlier entries untouched (decided: no fixed limit).
3. `open(path, O_PATH | O_CLOEXEC)`, following the final symlink. the descriptor pins the inode; later renames and symlink swaps do not change what the rule refers to.
4. `fstat`; refuse `c` on a non-directory.
5. `realpath` and `stat` the result; dev and ino must equal the pinned inode (`ESTALE` otherwise). the string is used only for the conflict check.
6. same dev and ino already present: replace its permissions, close the new descriptor (openbsd replace semantics).
7. conflict check (below), then append `{fd, perms, dev, ino, path}`.

commit: if the table is empty, seal and return. otherwise require abi >= 3, create the ruleset (`handled_access_fs` only; the kernel accepts the short struct), add one `PATH_BENEATH` rule per entry, `prctl(PR_SET_NO_NEW_PRIVS)`, `landlock_restrict_self`, close descriptors, free the table, seal. on any failure the table stays intact and the sandbox is not sealed; `no_new_privs` may stay set, which is harmless.

#### threads at commit (X2: never process-wide)

the commit enters a landlock domain on the calling thread only, and only if the process has exactly one thread. it never uses `LANDLOCK_RESTRICT_SELF_TSYNC`, on any abi, because that flag *replaces* the domains of the other threads with the one of the caller (section 6): a thread that was more restricted than the caller would be widened. the rules:

- the kernel is asked, not the library: the list of threads is read from `/proc/self/task`. the directory is opened at the first call of `pledge` or `unveil` (while `/proc` can still be reached) and read again at the commit, before the domain is entered and once more right after (reading an open directory is not checked again by landlock). more than one entry, or a list that cannot be read, is `EBUSY`. a thread that has only just been joined can still be listed for a moment (measured: up to a few hundred microseconds idle), so a longer list is read again up to 2000 times before it counts (about ten milliseconds when another thread really exists).
- if the list taken after the domain shows another thread, the call returns `EBUSY` with the domain already in force on the caller (the only way is a thread made by a signal handler of this same thread during the call; the caller must treat it as fatal). tested.
- the list cannot be opened for lack of descriptors or memory: `EMFILE`, `ENFILE` or `ENOMEM`, not `EBUSY`.
- a process that is kept away from `/proc` before its first call by a landlock domain it did not make itself cannot commit (`EBUSY`): there is no proof, so no commit. tested. one that restricted itself after the first call can (the handle is already open). tested.
- the child of a fork opens its own list lazily (the inherited one belongs to the parent): a stale list would let a child that made threads pass, or refuse a single threaded child of a multithreaded parent. tested both ways. the handlers do not make system calls, because the child may be under a filter that allows none.
- a restriction the caller already has is kept: the new domain stacks on it (tested).
- threads made after the commit inherit the domain (tested).
- **lifecycle**: unveil, commit and the first `pledge` with `stdio` before creating threads; narrowing pledges later, from any thread (seccomp's `TSYNC` is verified by the kernel and refuses, with `EBUSY`, when a thread carries a filter that the caller does not).

#### the narrowing conflict

openbsd lets a more specific rule reduce what a parent granted. landlock only adds rights down a tree; there is no deny rule. so when a rule below another asks for less than the one above gives, the extra access would stay, and the call fails with `ENOTSUP` instead of leaving it. work around it by unveiling siblings instead of the parent. the ancestor test compares canonical path strings at component boundaries; bind mounts and hardlinks can defeat it, so it is a guard against honest mistakes, not a security boundary.

which letters count depends on what the object below is. measured on a real kernel (abi 10) for every pair of permission sets, with the outer rule on a directory and the inner rule on a directory, a regular file or a unix socket node (`t_conflict_matches_kernel`, 667 pairs, probing read, list, write, truncate, execute, create, mkdir, unlink and connect):

- 489 pairs leave extra access on the inner object and are refused. 178 do not and are accepted; every accepted pair is enforced exactly as asked.
- for a directory below, every letter of the rule above matters (`r w x c s`): no refused pair was harmless.
- for a regular file below, `s` does not matter (it is about connecting to a socket), so `rs` on the directory and `r` on a file in it is accepted. `c` does matter: the rule above lets the file be unlinked or renamed.
- for a socket node below, only `s` and `c` matter: nothing can read, write or execute a socket node, so `r`, `w` and `x` above it are accepted.
- v0.1.0 compared letters only and refused the last two kinds for nothing (27 of the 667 pairs). after the release the library reads the type of the inode it already pins. other types (fifos, devices) still use all letters, which is the safe side; they were not measured.
- the check has the same answer whichever of the two rules comes first (tested in both orders).

#### minimum abi

abi >= 3 (linux 6.2) is required (decided). below that, rename across directories and truncation could not be controlled, so `unveil()` returns `ENOSYS` rather than run with holes.

### 2.7 signal isolation: the scope is required (S2)

**decision.** vow prefers predictable security semantics to the widest kernel support. `pledge()` with `stdio` is the only promise that lets a process send signals, and it is available only inside a `LANDLOCK_SCOPE_SIGNAL` domain. if that domain cannot be entered the call fails and nothing is installed; there is no fallback to filter rules that look at pids. the earlier pid-bound rules (a pid captured when the filter was built; `tkill` only for tid == pid) are gone from the policy, from the code and from the tests.

**what the call does.** on the first `pledge` that includes `stdio`, before the filter is installed:

| kernel | result of `pledge("stdio ...")` |
|---|---|
| no landlock | `ENOSYS` (or `EOPNOTSUPP` when disabled), as the kernel says |
| landlock abi below 6 (before linux 6.12) | `ENOSYS` |
| abi 6 or later, one thread (the kernel's thread list, section 2.6) | works: the scope binds the calling thread, which is all of them; threads made later inherit it |
| abi 6 or later, more than one thread, or the thread list cannot be read | `EBUSY` |
| (abi 8 or later) | nothing different: `TSYNC` is not used, because it replaces the domains of other threads (section 6) |

any other error of the landlock calls (for example `EMFILE`) is returned unchanged. after a failure the process is not in a scope, no filter is installed and the state of the library is untouched; the exceptions are the ones that cannot be undone: `no_new_privs` may be set, and a scope entered successfully before a later step failed stays (the library remembers it). promises without `stdio` (for example `rpath` alone) do not need a scope, since the filter does not let them signal anything.

**what was measured** (run, raw syscalls first, then through the library; kernel 7.2.9, abi 10, static musl):

| question | result |
|---|---|
| unrelated same-user process, with a scope domain | `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo` and `pidfd_send_signal` all fail with `EPERM` |
| `kill(-1, sig)`, `kill(0, sig)`, `kill(-pgid, sig)` | reach only members of the domain; the call returns 0 when it reached anyone (the caller itself), **so success says nothing about the others**: a process outside the domain in the same group never gets the signal (tested) |
| `kill(1, sig)`, the process that started the program | refused (outside the domain) |
| existing secondary thread, scope made with `TSYNC` (abi 8) | confined, **and its own domain is replaced** (section 6): the reason `TSYNC` is not used |
| existing secondary thread, scope made without `TSYNC` | **not confined** (its `kill` of an unrelated process succeeds). hence the single thread requirement, on every abi |
| thread created after the scope | inherits it |
| musl `raise`, `pthread_kill`, `abort`, `pthread_cancel` of another thread | all work in the main thread and in secondary threads (`abort` gives `SIGABRT` in both) |
| two processes that each pledged | each has its own domain: siblings, neither can signal the other |
| a pledged supervisor and its unpledged worker, and the reverse | see "supervisors" below |

**same domain means signalling is allowed.** a signal passes if the target is in the same landlock domain as the sender or in a domain nested inside it. so **every process in the same domain may signal every other one**: all threads of a process, and every child that was made by `fork` (libc or raw), `clone`, `vfork` or `posix_spawn` and every program started by `exec`, because all of them inherit the domain and none gets a new one. nothing in vow changes that. what the scope gives is the boundary around the group: unrelated processes, the process that started the program, a supervisor, and siblings that pledged separately are out of reach.

**isolating a child from its parent is explicit, and vow does not do it for you.** earlier versions entered a new nested scope in the child of every libc `fork()` through `pthread_atfork`. that was removed:

- every nested scope is one more landlock layer and the kernel allows 16 in total (measured: sixteen scopes can be entered in a row, the seventeenth fails with `E2BIG`); unveil's domain and any layer the application made count too, so a program that forks in a chain or a loop of generations runs out in a way that cannot be seen from the code that forks;
- the only way to report a failure from a `pthread_atfork` handler is to do something to the process; the previous code exited with status 127. an internal sandbox operation must not terminate an application that did nothing wrong;
- a handler works for the libc `fork()` only, and a sandbox that holds for one way of creating a child and not for the others invites mistakes;
- it changes the behavior of every program that forks, including those that want the child to be able to signal the parent.

what is possible instead, with the code as it is: (a) **order**: make the child before the pledge, and let each process pledge for itself. each gets its own domain; siblings cannot signal each other (tested). this is the pattern for workers and sandboxed helpers. (b) **after the fork**, a child that must not reach its parent enters a nested scope of its own; the test suite does this with the internal `vow_scope_enter()` and shows the result: the child cannot signal the parent (`EPERM`), the parent can still signal the child, the child can signal itself, and the property holds down the generations (tested). there is no public function for it in v0.1, because a public entry point needs decisions about the error contract and the layer budget; one is listed for review in section 13 (X1). nothing is claimed for children whose creation bypasses (b).

**supervisors, parent-death signals and shutdown** (tested):

- a supervisor outside the domain can `SIGTERM`, `SIGKILL`, `SIGSTOP` and `SIGCONT` a pledged worker, and a handler for `SIGTERM` in the worker runs and can exit cleanly. the scope restricts the signals a pledged process *sends*, not those it receives.
- the worker cannot signal its supervisor: `kill`, `tkill` and `SIGTERM` to the parent give `EPERM`. it has to tell the supervisor something by a descriptor (a pipe or socket). a design that relies on the worker sending `SIGUSR1` or `SIGTERM` to its parent does not work under a pledge.
- `SIGCHLD` to the parent when the worker exits is generated by the kernel and arrives; so do `SIGPIPE`, `SIGALRM`, the signals of the terminal and `PR_SET_PDEATHSIG` signals sent by a parent that is *not* in a domain. `exit()` runs its handlers, flushes `stdio` buffers and the supervisor reads the exit status (tested). `abort()` is a real `SIGABRT` in any thread.
- **the reverse of `PR_SET_PDEATHSIG` is blocked**: when a pledged parent exits, the kernel's attempt to deliver its parent-death signal to a child that is outside the parent's domain is refused (tested: the child lives on). a pledged supervisor therefore cannot rely on `PDEATHSIG` for children it made before pledging; it must clean up itself, or give the children a way to notice (EOF on a pipe, a lock). a worker can set `PDEATHSIG` on itself before the pledge (`prctl` is not in `stdio`) and gets the signal when an unpledged supervisor dies (tested).
- process groups: `kill(0, sig)` from a pledged process signals itself and not the other members of the group outside the domain, and returns success (above). a supervisor that shuts down its group by signalling it from inside the sandbox does not shut down members outside it.

**what is claimed, and what is not.** demonstrated by tests: a pledged process (with `stdio`) cannot send a signal to an unrelated process of the same user, to the process that started it, to a supervisor, or to a sibling that pledged separately, by `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo` and `rt_tgsigqueueinfo` (the only signal-sending calls the filter allows), from the main thread, from existing and from new threads. **not claimed**: isolation between processes of the same domain (above); protection of the pledged process from signals sent to it; any limit on signals the kernel generates; anything before the first `pledge` that includes `stdio`; anything about threads whose landlock domain was set by someone else before `TSYNC` replaced it (section 6).

**alternatives that were considered** (kept for the record; S2 was chosen by review): S1 pid bound rules only (works everywhere, no thread or fork support); S3 scope with the pid rules as a silent fallback (two behaviors for the same call, one of them with an inherited pid that lets a child signal its parent and fail to signal itself); S4 both together.

## 3. internal architecture

```
include/vow.h        two prototypes, version macros, extern "C" guard                (m1)
src/sys.h            syscall numbers, landlock constants and structs, vendored        (m1)
src/unveil.c         abi probe, dynamic entry table, conflict check, commit           (m1)
src/lock.h           spin lock without system calls                                   (m2)
src/fork.c           pthread_atfork handlers that take and release both locks         (m3)
src/pledge.c         promise parsing, state, subset and execpromises rules, installer  (m2)
src/filter.[ch]      rule tables, open flag classes, bpf generator; pure              (m2, m3)
src/scope.c          enter a landlock domain that scopes signals                       (m3, S2)
```

state is file-scope static: `tab, n, cap, sealed` in `unveil.c` (guarded by `ulock`), `cur` and `have` in `pledge.c` (guarded by `plock`). heap is used only for the unveil table and its canonical path strings. the locks are the spin locks of `src/lock.h`; `unveil()` takes `plock` briefly through `vow_pledge_blocks_unveil()` while holding `ulock`, and `pledge()` never takes `ulock`, so the order is fixed. the open(2) rule classes are built into a `struct vow_policy` on the stack of the caller, not into shared state.

test hooks exist only under `-DVOW_TEST`: `vow_test_abi_cap` (pretend the kernel abi is lower, or absent), `vow_test_alloc_fail` (make the nth table allocation fail), `vow_test_seccomp_nr` (call a bogus number instead of `seccomp(2)`, to make the install fail), `vow_test_window` (a function called inside the locked region, to widen race windows) and `vow_test_promises` (what `pledge` believes is in force). the test binary compiles `src/unveil.c` itself with the hooks; `libvow.a` never contains them.

## 4. landlock details

- abi probe once, cached, errors as in section 1.
- ruleset attr: only `handled_access_fs`, size 8 (the kernel struct has grown since; it accepts the short one and zeroes the rest). net, scope and quiet fields stay zero. the handled set is bits 0 to 14, plus bit 16 (`RESOLVE_UNIX`) from abi 9.
- rules are `PATH_BENEATH` with the pinned `O_PATH` descriptor as `parent_fd`.
- `restrict_self` flags: always 0. `TSYNC` is never used by the library and is not allowed through the filter.
- the errata mask is not used in v0.1. the tests print the abi so failures can be tied to a kernel.

## 5. seccomp details (m2)

### rule tables and the generator

one policy, in `src/filter.c`: a table per promise (`core`, `stdio`) of `{ nr, err, conditions }`. `vow_build()` turns the tables selected by a promise set into a program; it has no side effects. conditions:

| op | meaning | kind |
|---|---|---|
| `VC_EQ` | argument equals a value | `VK_LO32` or `VK_FULL64` |
| `VC_EQ_PID` | argument equals the pid captured at build time | `VK_LO32` |
| `VC_IN` | argument is in a set | `VK_LO32` |
| `VC_ALLBITS`, `VC_NOTALLBITS`, `VC_ONLYBITS` | mask tests on the low 32 bits | low word only |
| `VC_MASKEQ` | `(arg & m) == v` on the low 32 bits (used for the open(2) flag classes, generated per promise set) | low word only |

the kind is how the *kernel* reads the register. `VK_LO32` covers `int`, `unsigned int`, `pid_t` and clone flags (the kernel truncates them, so the filter compares the low word and ignores the high one); `VK_FULL64` covers pointers and `unsigned long` values (both words are compared). mask tests only look at the bits they name; for example `mprotect(prot)` is read as an `unsigned long` by the kernel and junk above bit 31 makes the call fail with `EINVAL` anyway, so testing the low word for write+exec is enough.

program layout: arch check, x32 check, then the blocks of the selected tables in order, then the default action. size today: 42 instructions for the empty set, 117 for `rpath`, 69 for `wpath`, 144 for `cpath`, 391 for `stdio`, 469 for `stdio` with all three path promises (generator limit 1024, kernel 4096). a linear search over the blocks is fine at this size and is kept simple on purpose.

the default action is a parameter of `vow_build` so tests can use `ERRNO(1001)` instead of a kill; `pledge()` always passes `SECCOMP_RET_KILL_PROCESS`.

### installation (`vow_install`)

`prctl(PR_SET_NO_NEW_PRIVS)`, then `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, ...)`. a positive return (a thread could not be synchronized, and its id is the value) becomes `EBUSY` (tested with a real conflicting thread). a failure leaves the *filter stack* as it was, and `pledge()` changes its own state only after success (tested with an injected failure and with the thread conflict), but `no_new_privs` has already been set and stays set, so "as it was" does not include that. a kernel that rejects the program (for example one without `KILL_PROCESS`) makes `pledge` fail with the kernel errno; nothing is retried with a weaker action.

### monotonic restriction

two layers. in userspace `pledge()` accepts only a subset of the promises in force (`EPERM` otherwise, `ENOTSUP` for execpromises it cannot honour). in the kernel every filter is stacked and the strictest verdict wins; the tests install an allow-everything filter after `pledge("stdio")` through the always-allowed `seccomp` call and show the process still dies on `socket()`. the always-allowed set (landlock calls, `seccomp` with `SET_MODE_FILTER`, `prctl` no_new_privs) can only add restrictions.

### validation, three ways that must agree

1. an interpreter for the classic-bpf subset the generator may emit (`tests/bpfi.h`) with the checks the kernel makes at load time. an opcode outside the subset aborts the test, so the generator cannot drift unnoticed.
2. an oracle (`tests/oracle.h`) that decides from the rule tables with its own argument handling, independent of the bytecode.
3. the kernel: the same bytecode is installed with `ERRNO(1001)` as the deny action in a forked child, and 561 (empty set) to 1373 (largest set) real syscalls are made with chosen arguments, among them every unlisted number from 0 to 459 with zero arguments (calls that would be harmful if wrongly allowed are not run; see the exemption note in section 0), templates with harmless base arguments for every conditional rule, junk in the upper half of every 32-bit argument, and for the path promises all 32 combinations of the five flags that matter, with and without `O_PATH`, three neutral flag sets and a junk variant, on both `open` and `openat`, run against a directory so that nothing is damaged if a call slips through. each verdict is checked against the interpreter, which is checked against the oracle.

a differential test of a filter against itself cannot tell whether the declared *kinds* are true, so a fourth check goes straight to the kernel with no filter loaded: for every `VK_LO32` comparison the call with junk in the upper half must behave exactly like the one without (203 probes for `stdio`, 587 with the open flags added); for the exact value of a `VK_FULL64` equality, setting a high bit must change the behavior. mutation checks done by hand (each makes a test fail): wrong kind on `socketpair`, `prlimit64`, `sendto`, the `prctl` value; wrong mask in the clone flag test. one mutant is equivalent and not caught on purpose: removing the explicit x32 check changes nothing because an x32 number matches no rule.

## 6. security model and unenforced restrictions

attacker model: the program initializes correctly, then an attacker gets arbitrary code execution inside it. vow limits what the process can do afterwards. it does not protect against an attacker before the calls, kernel exploits, or programs that never call it.

### enforced (each backed by a test at its milestone)

- (m1, tested) after commit, opens of non-unveiled paths fail with `EACCES`, including via `..`, symlinks, `O_PATH` directory descriptors and `/proc/self/fd` reopen. creation, removal, rename and link across rule boundaries fail. rights cannot be widened afterwards (sealed). `no_new_privs` is set.
- (m1, tested) the commit refuses a process with more than one thread, on every abi, and leaves everything as it was; a stricter domain of another thread is untouched; threads made after the commit are restricted.
- (m2, tested) after `pledge("stdio")`, every syscall outside the set kills the whole process with `SIGSYS` (a violation in any thread, tested), on the native abi, the x32 numbers and the 32-bit `int 0x80` entry. threads that exist at the time of the call are covered (`TSYNC`), later threads inherit. a stricter second call takes effect; a looser one is refused in userspace and cannot be forced in the kernel. `no_new_privs` and the filter survive `execve` (tested through a real exec).
- (m2, tested) self signaling works with `kill(getpid())` and `tgkill` of the own group, and killing the parent, the process group or everything is a violation.

### known unenforced restrictions (m1 relevant ones are asserted by tests so a kernel change is noticed)

filesystem metadata operations, not covered by landlock (kernel docs): `stat`, `lstat`, `access`, `chdir`, `chmod`, `chown`, `utime` and friends, `setxattr`, `flock`, `fcntl`. after commit the test asserts that `stat`, `access`, `chmod` (same mode), `utime` and `chdir` still work on a non-unveiled path. effects: the existence, type, size and timestamps of any path stay observable; attributes of any file the uid owns stay changeable; unveil does not return `ENOENT` for hidden paths; directory listing of an unveiled directory shows all names. openbsd ties `w` to attribute changes (`fattr`, `chown`); vow cannot, and `w` does not imply them in either direction. a later pledge without `rpath` and without `fattr` closes the syscall side, but only inside a pledged process.

already open descriptors: landlock checks at open time and seccomp checks syscalls, not objects. a descriptor opened before sandboxing keeps its power: read, write, `sendmsg` over a connected socket, a listening socket, an inherited unix socket to a privileged daemon. the test asserts a read and a write through descriptors opened before commit. the descriptors a program should close, or never open, are listed in README.

landlock rights newer than abi 3 are not handled in v0.1, so they are unrestricted, even on kernels that support them:

- `FS_IOCTL_DEV` (abi 5): `ioctl` on opened device files.
- pathname unix sockets are now handled on abi >= 9 (`s` permission, section 2.6). on abi 3 to 8 they are still unrestricted: unveil alone does not stop a process from connecting to any unix socket its uid can reach there (a session bus, a display server, a container runtime socket). only a pledge without `socket` closes that, and only for sockets not already held. abstract sockets are never covered by unveil (they are a separate namespace; landlock has a scope flag for them that vow does not use), nor are connections that exist before the commit.
- tcp and udp bind and connect rights (abi 4, 10): no network restriction from unveil.
- scopes for abstract unix sockets and signals (abi 6): not set.

**landlock `TSYNC` replaces, it does not stack, on sibling threads (X2, resolved by refusing).** measured (raw syscalls, and as a test): a thread that restricted itself with a domain of its own (here: no file may be read) and a call of another thread with `TSYNC` leaves that thread with the domain of the caller plus the new layer; its own restriction is gone and it can do what the caller can. upstream says so ("overrides the Landlock configuration of sibling threads, irrespective of previously established Landlock domains"). a stricter domain is lost, a looser one is tightened. the questions asked and the answers:

- *can the domain of another thread be inspected or compared?* no. looked at on 7.2.9: `/proc/<pid>/status` has `NoNewPrivs` and `Seccomp` fields but nothing for landlock, `/proc/<pid>/attr` only the lsm names that have attributes (apparmor, smack, ...), and no syscall returns a domain identity. the library has no way to know whether two threads have the same history.
- *can it be proven that all threads share one history?* not in general: any thread of the program may have restricted itself at any time through the syscall.
- *so* vow refuses a process-wide commit rather than risk widening: the unveil commit and the signal scope of `pledge` need exactly one thread, on every abi, and use a plain `restrict_self` on it. a thread made later inherits and is never replaced. tested with independently restricted siblings for both the unveil commit and the pledge scope (both are refused and the sibling keeps its domain), with an outside restriction on the one thread (kept), with the thread list unavailable (refused), and with a late thread (reported).
- the filter does not let a pledged process use `TSYNC` either: the flags of `landlock_restrict_self` are limited to 0, so a compromised thread cannot replace the domains of its siblings.
- locks do not protect kernel state and are not used for this: `ulock` and `plock` only order the calls of the library. what makes the commit safe is the kernel's own thread list, read before and after, and the one thread rule: with a single thread nothing else can start one except a signal handler of this same thread, which the check after the call reports.
- what remains: a program that makes threads before its first vow call cannot use the `unveil` commit or `pledge("stdio")`; a program that restricted one thread through landlock and wants vow for the others cannot have it from one call. the alternative that would allow both, restricting each thread from its own context by a signal (as libpsx does for capabilities; it stacks and loses nothing), needs a signal handler in the application, thread enumeration, signal masks and races. it was not written for v0.1.

**flags of the always-allowed calls.** the calls that can only tighten (`seccomp` with `SET_MODE_FILTER`, `landlock_restrict_self`) are allowed in every filter, which would let a compromised thread use their flags. only the flags vow uses are accepted: seccomp 0 and `TSYNC`; landlock restrict 0 and `TSYNC`. not accepted (violation): `SECCOMP_FILTER_FLAG_SPEC_ALLOW` (switches off a speculation mitigation for the process), `NEW_LISTENER`, `LOG`, `TSYNC_ESRCH`, and the landlock flags that silence audit logging or any future flag (tested, and checked against the kernel with and without junk above bit 31).

pledge-related (also section 2.5, 2.7):

- **cpath, wpath without unveil.** `wpath` and `cpath` reach every file and directory the uid can write; with no unveil rule set nothing compensates (section 2.5).

- `rpath`/`wpath` without unveil span the whole filesystem the uid can reach, including `/proc/*/mem` of same-uid processes when ptrace policy allows. pair them with unveil.
- `inet` cannot restrict addresses or ports, applies to descriptors of any family (a pathname unix socket from before can be connected or bound through it; landlock closes this only with an unveil rule set, abi 9 for the connect), and an existing datagram socket can send anywhere by `sendmsg` even under `stdio` alone (section 2.5, inet).
- `exec` hands the new program every descriptor not marked close-on-exec and every right of the pledge; running an untrusted binary under a pledge is only as safe as the descriptors and rights it is given (section 2.5, exec).
- `SCM_RIGHTS` descriptor passing cannot be restricted (section 2.5).
- `sendmsg` carries its destination in a struct the filter cannot read, so a datagram socket that is already open (for example an udp socket made before the pledge) can still send to any address with `sendmsg`, although `sendto` with an address is refused. do not keep such sockets across a `pledge("stdio")`; `connect` them first.
- `PROT_EXEC` is allowed (only write+exec together is refused). this is **not** w^x: injected code can be written, made executable and run (tested). it runs under the same filter.
- `wpath` and `cpath` without unveil reach every file and directory the uid can write: create, remove, rename, truncate, link and symlink anywhere. unveil compensates for path-based creation and removal (also through directory descriptors held from before), but never for a descriptor that is already open for writing (`ftruncate`, `fallocate` and `write` keep working), and not at all without an unveil rule set. no layer compensates for what is outside both: metadata calls are not in these promises and are killed by seccomp, but only inside a pledged process.
- `cpath` can link and rename: a `rename` replaces an existing name silently, `link` and `linkat(AT_SYMLINK_FOLLOW)` through `/proc/self/fd/N` give a new name to any inode the process holds a descriptor for, `symlink` writes an arbitrary target string. none is blocked; `RENAME_WHITEOUT` and `AT_EMPTY_PATH` are.
- the open(2) classes treat `O_TRUNC` as write and `O_CREAT` as create, so `O_CREAT` alone never needs `wpath` to be refused: `O_WRONLY|O_CREAT` needs `wpath` and `cpath`, `O_RDONLY|O_CREAT` needs `rpath` and `cpath`.
- `rpath` is broad on purpose: it reads anything the uid can read, including `/proc/<pid>/environ` and `/proc/<pid>/mem` of same-uid processes where kernel policy allows, `/sys`, and device nodes. it must be paired with unveil, and even then `stat`, `lstat`, `access`, `readlink`, `statfs`, directory listing and `O_PATH` opens still work on paths that unveil hides (tested): existence, type, size, times and symlink targets of any path remain visible.
- `openat2` is answered with `ENOSYS` under any path promise. that is a policy choice, not a promise that callers cope; a program that requires `openat2` (some container runtimes and newer coreutils use it with a fallback, others do not) breaks.
- the open(2) classification depends on kernel behavior that is tested on 7.2.9 only (`O_PATH` dropping flags, `O_RDONLY|O_TRUNC` truncating, mode 3). `t_kernel_open_truths` asserts them so another kernel that behaves differently fails visibly; it does not make vow correct there.
- the filter cannot see paths, so the same `rpath` that allows reading `/etc/hostname` allows `/etc/shadow` if the uid can read it. only unveil limits paths.
- `uretprobe` and `uprobe` are exempt from every seccomp filter in the kernel (section 0); they are not usable by user code for anything beyond dying or failing.
- the policy answers `clone3` with `ENOSYS`; a runtime that treats that error as fatal breaks.
- **signals.** see section 2.7. in short: with `stdio` the process is inside a landlock signal scope or the pledge fails. unrelated processes, the starter of the program, a supervisor and separately pledged siblings are out of reach; **processes of the same domain (threads, every child made by fork, clone, vfork or posix_spawn, every program started by exec) may signal one another**; signals sent to the pledged process and signals generated by the kernel are not restricted; success of `kill(0)` or `kill(-1)` does not mean everyone was signalled; a pledged parent cannot deliver `PR_SET_PDEATHSIG` to children outside its domain.
- stdio `ioctl` allow-list is small but not empty.

other:

- seccomp never reads paths, so there is no path tocttou in the filter. landlock evaluates the real object at access time, not a string, so swapping symlinks does not help. the one string check (narrowing conflict) is advisory.
- `io_uring`, `ptrace`, `bpf`, `perf_event_open` and similar are absent from every promise, so a pledge kills them. this is why pledge is an allowlist.
- the process is not isolated from other processes: no pid or mount namespace is created.

## 7. threads, fork, exec, descriptors

- seccomp: `TSYNC` covers every current thread; new threads inherit. verified failure behavior (run): when another thread carries a filter that is not in the history of the caller, the call installs nothing and *returns the id of that thread* as a positive number (the test sees exactly the id of the conflicting thread). `vow_install` turns any positive return into `EBUSY`, `pledge()` changes nothing, and the same call works once that thread has gone. the `SECCOMP_FILTER_FLAG_TSYNC_ESRCH` flag would make this a plain error, but it needs linux 5.7 and is not used, so the positive-return path stays the one in use.
- concurrent calls: serialized by the locks (section 1). a thread that is inside `pledge()` while the `pledge()` of another thread finishes first simply sees the new state; the test hammers this with six threads for 40 rounds and checks, each round, that the promises the library believes in are exactly what the kernel enforces.
- landlock: section 2.6, threads at commit.
- fork: children inherit all landlock domains (the signal scope included), the seccomp filters, `no_new_privs` and the promise state of the library. nothing is added in the child: **a child made by fork, raw or not, is in the same signal domain as its parent and the two may signal each other** (tested). a pledged process cannot fork in v0.1 (a violation), so this concerns children made before the pledge (which pledge on their own and are then siblings, tested) and the tests, which add a test-only rule table that allows fork and wait. `pthread_atfork` handlers (registered on the first call) make the library locks safe across a libc `fork()`. verified: a thread inside `unveil()` or `pledge()` while another forks (the child gets consistent state and free locks); 150 forks against a thread that hammers `unveil()` (no child ever waited on a lock); `fork()` from a secondary thread. **raw `fork`, `clone`, `vfork` and `posix_spawn` run no handlers**: a raw-forked child inherits a lock that another thread held (tested: it waits for it forever). do not call the library in such a child while another thread may be inside it; `vfork` shares the address space, so a library call before the child exec changes the state of the parent too. musl adds a trap of its own: it keeps the thread id in memory and only its `fork()` updates it, so `raise()` in a raw-forked child signals the parent (tested; the signal passes because they share the domain).
- exec: inheritance is total (section 2.4). `unveil()` descriptors are `O_CLOEXEC`, and are closed at commit.
- vow never closes or inspects descriptors other than its own.
- a kill from seccomp is `SIGSYS` (core dump possible), not `SIGABRT` as on openbsd.

## 8. libc and static linking

- `src/` is c99 and uses `syscall()`, `open`, `fstat`, `stat`, `realpath`, `opendir`, `prctl`, `realloc`. no `dlopen`, no stdio, no locale. built with `-D_GNU_SOURCE -std=c99 -Wall -Wextra -Wpedantic -Werror`.
- **v0.1 supports musl only** (this machine is musl native). glibc is deferred: no glibc support, script or glibc-specific test code is kept in the tree. what a trial run showed is recorded in section 14 so that the later work starts from it. the glibc facts in section 0 were read from source or from those trial runs.
- (m1, run) the test binary is built with `-static`; `make static-check` fails if `readelf -d` shows `NEEDED`.

## 9. c89 to c23 header (m1)

only `const char *` and `int` in prototypes, no `//` comments, no declarations after statements, no inline, no `bool`, no `restrict`, `extern "C"` guard. `make check-header` compiles `tests/hdr.c` with `-pedantic -Wall -Wextra -Werror` as c89, c99, c11, c17, c2x and as c++11 (all pass).

## 10. testing

each test runs in a forked child, because restrictions are irreversible, with a 60 second alarm and core dumps off. exit 0 is a pass (or, for entries that name a signal, death by that signal), exit 77 a skip. the runner counts passes, failures and skips separately and fails if the table size is not the expected number, so a dropped test is noticed. skips are never counted as passes. all test binaries are linked `-static` against musl and `make static-check` verifies it.

### unveil (`tests/unveil_test.c`, 61 tests)

- arguments, rights (`r`, `rw`, `rwc`, `w` on a file, `r` on a file, `rx` exec of a static binary, exec without `x`, bare `x`/`wx`/`cx` refused, `c` on a file refused), lifecycle (sealed, seal-only, replace narrower and wider), conflict checks, escapes (symlink, `..`, `O_PATH` directory descriptor, `/proc/self/fd` reopen, cross-boundary rename and hardlink).
- documented gaps asserted so a kernel change is noticed: earlier descriptors keep working; metadata calls work on hidden paths.
- kernel side: `no_new_privs`; abi gate; commit refused with other threads, with a stricter sibling, without a thread list, with `/proc` hidden by an outside domain, with a thread made during the call; commit stacks on an outside domain; the thread list opened early and reopened by the child; raw `TSYNC` replaces a sibling domain (the reason for it all); failed commit does not seal and does not enforce; threads created after commit are restricted; 300 entries; forced allocation failures; `EMFILE`.
- pathname unix sockets (abi >= 9 only, else skipped): connect allowed under `s` and denied elsewhere, denied by default without `s`, `s` on a socket file only, datagram `sendto`, existing connection keeps working (limit), server created inside the domain stays reachable (limit), abstract socket reachable (gap), `s` refused on a simulated abi 8, conflict check with `s`.
- two raw-syscall tests prove why bare `x` is refused (execute alone fails, execute plus read works).

### filter (`tests/filter_test.c`, 12 tests, no kernel filter needed)

- vendored syscall numbers equal the libc ones (106 names).
- program structure: validity, size limits, `E2BIG` when the buffer is too small, kill action in the production build.
- 100 hand-written expectations, independent of the tables: x32, i386 and aarch64 architectures, w^x, thread-only `clone` (glibc and musl flag sets, fork-style, namespace, ptrace, exit-signal variants), self-only signals, socket domains, `sendto` address pointers, `fcntl`/`ioctl`/`prctl`/`arch_prctl`/`prlimit64`, junk in upper halves.
- 225280 random and structured argument sets over eleven promise sets, bytecode interpreter against oracle, with numbers drawn from the tables.
- the open matrix (30 hand-written flag rows) against the oracle and the bytecode for all eight subsets of `rpath`, `wpath`, `cpath`, each with and without junk in the upper half; and 1048576 flag combinations of 16 bits, again for all eight subsets, bytecode against oracle. the oracle states the open matrix on its own and does not read the generated classes.
- the first six instructions (architecture check, x32 check) and the final deny are spelled out.
- sockets: 37620 `socket` calls over domains, types with flag bits and protocols for six promise sets, and a grid of every level and option for `setsockopt` with three spellings of each (the count of allowed pairs is asserted to be exactly 49 times 3 times 2), bytecode against oracle.
- the path call matrix (56 calls: the read, write and create calls, 16 more that no path promise may allow, each with plain, junk and all-ones arguments) for all eight subsets; and every value of the low 17 bits of the `renameat2` and `linkat` flags, with and without junk above bit 31, for sixteen promise sets.

### seccomp (`tests/seccomp_test.c`, 215 tests)

- kernel differential for the `stdio` set and the empty set (section 5), including the argument-model probes.
- argument errors with proof that nothing was installed; execpromises rules; widening refused; narrowing takes effect; an extra allow-all filter cannot widen; a failed install changes nothing; unveil locked after a pledge; filter and `no_new_privs` inherited across a real `execve`.
- musl behavior under `pledge("stdio")`: a smoke test (printing, big `malloc`/`realloc`, four thread create/join rounds, clocks, `nanosleep`, `getrandom`, pipes, `poll`, `fcntl`, `dup`, a local socket pair with `sendmsg`/`recvmsg`, `getrlimit`, `sigaltstack`, `kill`/`tgkill` to self with handler return, `mmap`/`mprotect` read-write-then-read-exec); `raise` and `pthread_kill` fail; raw `tkill` gives `EPERM`; raw `clone3` gives `ENOSYS`; `abort()` ends in `SIGSEGV`.
- milestone 2 corrections: w^x transitions are allowed (generated code runs), injected code is still filtered, `PROT_WRITE|PROT_EXEC` with junk bits or `PROT_GROWSDOWN` still kills, a failed install keeps `no_new_privs` set, a real `TSYNC` conflict returns the id of the other thread and installs nothing, 40 rounds of six threads calling `pledge` at once with the kernel state compared to the library state, and (in the unveil binary) six threads adding 90 rules at once.
- milestone 3 (open flags): the differential covers every combination in the matrix against the kernel for nine path sets; a test of how the bare kernel treats these flags (`O_RDONLY|O_TRUNC` truncates, `O_PATH` drops the rest, mode 3 needs both permissions, `O_TMPFILE` combinations, unknown bits, `O_EXCL` without `O_CREAT`); reading works under `stdio rpath` with libc `open`, `fopen`, `opendir`, `stat`, `lstat`, `fstatat`, `statx`, `access`, `readlink`, `statfs`, `getcwd`, `chdir`, `fchdir`, `O_PATH`; fifteen operations that must kill (`O_WRONLY`, `O_RDWR`, mode 3, `O_CREAT`, `O_TRUNC` read-only, `O_TMPFILE`, `creat`, `openat` write, junk-high write, `unlink`, `mkdir`, `rename`, `truncate`, `chmod`, `socket`); `stat` without `rpath` kills; unveil in both orders with `rpath`, landlock `EACCES` versus seccomp kill, and the metadata/`O_PATH` gap.
- wpath and cpath (milestone 3, second part): each promise alone, in pairs and all three, with real operations (create, write, read back, `ftruncate`, `posix_fallocate`, `rename`, `link`, `symlink`, `renameat2` with `NOREPLACE` and `EXCHANGE`, the *at calls through a directory descriptor, `O_TMPFILE` published through `/proc`) and 44 operations that must kill (for example `wpath` with `O_RDONLY`, `O_CREAT`, `mkdir`, `unlink`; `cpath` with every open mode, `truncate`, `stat`, `mkfifo`, `chmod`, `exec`, `renameat2` with `RENAME_WHITEOUT` also with junk above bit 31, `linkat` with `AT_EMPTY_PATH` likewise; `rpath cpath` with write opens and `O_RDONLY|O_TRUNC`; all three with `mkfifo`, `chmod`, `utimensat`, `setxattr`, `exec`, `socket`, `mount`).
- with unveil: `rw` with all three promises (landlock `EACCES` for create, remove, rename, link, symlink and for everything outside); `rwc` (everything inside works, across the boundary in either direction is refused); unveil grants but the pledge lacks the promise (seccomp kills); pledge first, unveil after.
- descriptors: directory descriptors, `/proc` links and writable descriptors from before the commit (section 2.5, what they expose).
- tkill and fork (section 2.7): main thread, secondary threads, cancellation, `abort` in both, fork before the pledge, the forked child of a pledged process (with the test-only fork rule), signal handlers calling `pledge` and `unveil` inside both, fork while another thread is inside `unveil` or `pledge`.
- signal isolation (section 2.7): main thread and secondary threads with `raise`, `pthread_kill`, `abort`, `pthread_cancel`; unrelated same-user processes through all five calls; siblings that pledged separately; children made by libc fork and by raw fork share the domain; explicit nesting in the child isolates it from the parent, down the generations, and the layer limit (16) is measured; stdio refused on abi 5, without landlock, on abi 7 with threads, accepted on abi 7 single threaded, a real error (`EMFILE`) returned unchanged; unveil first and pledge first; the filter contains no pid or thread id; supervisor behavior (terminate, stop, continue, kill, graceful handler, worker cannot signal the supervisor, `SIGCHLD`, exit status and flushed output, parent-death signals both ways, group signals).
- inet: tcp and udp on loopback with options, nonblocking connect, `accept4`, addresses on `sendto` and `sendmsg`; ipv6; numeric and by-name lookups; 18 operations that must kill (families, types, protocols, flag bits, options); existing connected and unconnected sockets; the unix socket gap with and without unveil (`s`, no `s`, no `c`); the network with an unveil rule set.
- exec: static and dynamic helpers (one built static, one dynamic: the only dynamic program in the tree), the inherited filter, `no_new_privs` and seccomp mode read from the new image, not promised, landlock exec rules and interpreter, `execveat` on a descriptor with and without unveil, descriptors crossing exec and `close_range`, the signal scope and the pid rules in the new image, `execpromises`.
- locks: raw fork keeps a lock, fork stress, fork from a secondary thread.
- violations that must kill (`SIGSYS`): kill of parent, group, everything; foreign `tgkill`; `fork`; `mprotect`/`mmap` write+exec; a violation in a second thread; a thread that existed before the pledge; a thread created after; `socket`; `open`; `sendto` with an address; `setrlimit`; `prlimit64` of another process; `TIOCSTI`; `F_SETOWN`; an x32 number; `int 0x80`.

not done and not planned for v0.2: glibc (unsupported, section 14), runs on other kernels (untested), a build matrix.

## 11. repository and milestones

(v0.2: `tools/vow-run/` holds the command line tool and its profile format; its design is in `tools/vow-run/DESIGN.md`. the library does not depend on it. `dist/kiss/` holds the kiss recipe.)

```
vow/
├── DESIGN.md  ROADMAP.md  README.md  Makefile
├── include/vow.h
├── src/{sys.h, filter.h, filter.c, unveil.c, pledge.c, fork.c, scope.c, lock.h}
├── tests/{t.h, bpfi.h, oracle.h, nr_list.h, hdr.c, unveil_test.c, filter_test.c, seccomp_test.c}
└── examples/
```

`make` targets: `all` (libvow.a), `test`, `check-header`, `static-check`, `clean`. `CC` is overridable.

1. unveil end to end, `s` permission (done)
2. bpf generator, interpreter and oracle tests, kernel differential, installer, `pledge()` with `stdio` (done)
3. promises: `rpath`, `wpath`, `cpath`, the open flag classification, `inet`, `exec` and the signal scope (done); the glibc runs are still open
4. integration tests
5. static musl validation (done); other kernels (section 14). glibc is deferred
6. examples and docs (README not yet written)

## 12. where linux cannot match openbsd

| openbsd | vow on linux |
|---|---|
| unveil enforces from the first call | enforced at `unveil(NULL, NULL)` |
| a more specific unveil can narrow a parent | refused with `ENOTSUP` |
| hidden paths return `ENOENT`; metadata calls blocked | opens fail with `EACCES`; `stat`, `chmod`, `utime`, `chdir` still work |
| `x` alone is enough to execute | `x` needs `r` (kernel opens the file for reading); bare `x` refused |
| `rpath` hides nothing the process can name | `stat`, `access`, `readlink`, listing and `O_PATH` work on unveil-hidden paths |
| read-only open never writes | `O_RDONLY|O_TRUNC` truncates on linux, so it needs write |
| unix sockets follow the filesystem rules | `s` permission, abi >= 9 only; abstract sockets and existing connections are not covered |
| `c` works on a non-directory name | refused with `ENOTSUP` |
| `w` also covers `chown` and `fattr` | not enforceable |
| execpromises apply after exec | only `NULL` or equal to promises; else `ENOTSUP` |
| exec-ed program starts unrestricted if no execpromises | inherits the full policy |
| setuid exec blocked with `EACCES` | `no_new_privs`: runs without privilege |
| pledge sees argument contents | register values only; paths, sockaddr, message contents invisible |
| descriptor passing has its own promises | not restrictable; `sendmsg`/`recvmsg` allowed in stdio |
| `kill` only under `proc` | `kill`, `tgkill`, `tkill`, `rt_sigqueueinfo` in `stdio`, confined to the signal domain of the process (landlock scope) where the kernel has it, to the own pid and main thread otherwise |
| stdio forbids `PROT_EXEC` | only `PROT_WRITE|PROT_EXEC` is forbidden (exec inheritance) |
| `dns`, `proc`, `unix`, `tty`, `fattr`... | `ENOTSUP` (not planned for v0.1) |
| `inet` restricts what it can see | socket families, types and protocols; options by allowlist; not addresses, ports or the family of an existing descriptor |
| exec-ed program may get its own promises | none: the new image is under the same filters and domains, `execpromises` must equal `promises` |
| violation kills with `SIGABRT` | `SIGSYS` (`KILL_PROCESS`) |

## 13. decisions

resolved by review:

1. landlock abi >= 3 required.
2. `unveil(NULL, NULL)` with no paths is seal-only.
3. `stdio` allows `fstat` only (musl run, glibc read); no `newfstatat`/`statx`.
4. self-signaling: see section 2.7 (scope where possible, pid rules otherwise).
5. `SCM_RIGHTS` not claimed restrictable; documented.
6. landlock net, ioctl, scope (and `RESOLVE_UNIX`) out of v0.1; gaps documented in section 6.
7. superseded by X2: landlock `TSYNC` is never used; a multithreaded process is refused; the vendored constant exists for the tests.
8. no public `vow_abi()`.
9. no `dns` promise in v0.1.
10. default denial action `KILL_PROCESS`.
11. unveil storage grows dynamically; allocation failure handled.

resolved after milestone 1:

- N1: bare `x` stays `ENOTSUP`. the investigation (section 0) found a concrete kernel limitation: with `READ_FILE` handled, an executable file needs it, static or not, and a dynamic interpreter needs `rx`. read is never granted implicitly.
- N2: `c` on a non-directory stays `ENOTSUP`; creation rights belong to the parent directory.
- N3: `s` permission added (`RESOLVE_UNIX`, abi >= 9, default deny from abi 9, `ENOTSUP` for `s` below).

review of milestone 2, decided: keep the explicit x32 check (tested as spelled-out instructions); keep `PROT_EXEC` allowed in `stdio`, documented as not w^x and tested; keep the sendmsg, existing-descriptor and seccomp-exempt limitations; failure contract corrected for `no_new_privs`; `TSYNC` failure verified; concurrent calls serialized.

signal isolation: **decided, S2** (the scope is required; no pid based fallback; no automatic nested domain in `pthread_atfork` handlers). see section 2.7 and X1 below.

decisions of the review after milestone 3: S2; the nested domain in the fork child is removed and isolation of a child is explicit (section 2.7); the always-allowed `seccomp` and `landlock_restrict_self` calls accept only the flags vow uses (section 5).

**open for review**

- X1 (decided: keep internal): child isolation stays an internal helper (`vow_scope_enter_child()`, with its tests) and is documented as a future api design problem. the questions a public function would have to answer: whether it nests a scope or does more; what it reports at the 16 layer limit (`E2BIG`) and whether the caller may continue; how it interacts with `exec` and with a future `proc` promise; whether it belongs to the child or to the code that forks. v0.1 does not expose it. until then: (a) order, (b) the internal call.
- X2 (resolved, release blocker closed): see sections 2.6 and 6.

milestone 2 findings, decisions taken (open to review):

- M2-1: the explicit x32 check stays although exact matching already denies x32 numbers (second line of defence).
- M2-2: superseded for `tkill` by section 2.7; `clone3` still answers `ENOSYS` by policy, with no claim that callers cope.
- M2-3: `PROT_EXEC` alone is allowed in `stdio` (openbsd forbids it), because of exec inheritance; this makes w^x a weak measure.
- M2-4: `sendmsg` destination addresses cannot be checked; documented, with the advice to `connect` datagram sockets before pledging.
- M2-5: superseded: `rpath` is enforced since milestone 3; a pledge without `rpath` still locks unveil.

milestone 3 findings (inet, exec, signals), decisions taken (open to review):

- M3-9: superseded by S2 and X2 (sections 2.6, 2.7): `stdio` requires the signal scope, entered once, with one thread, on abi 6 or later; the pid rules are removed.
- M3-10: `setsockopt` in `stdio` is an allowlist of 49 level and option pairs (it was unrestricted in milestone 2).
- M3-11: `inet` allows only tcp and udp over ipv4 and ipv6; other protocols, raw, packet, netlink, unix are refused.
- M3-12: `exec` is `execve` and `execveat` and nothing else; the new image inherits everything; `execpromises` must equal `promises`.
- M3-13: the pthread_atfork handlers take and release the library locks and do nothing else; the raw calls are documented as unsupported while another thread may be inside the library.

milestone 3 findings (path promises), decisions taken (open to review):

- M3-1: `O_RDONLY|O_TRUNC` needs write (linux truncates); `O_PATH` needs only read; mode 3 needs read and write; `O_TMPFILE` needs write and create; creating needs write as well as cpath.
- M3-2: `openat2` answers `ENOSYS` under any path promise.
- M3-3: `stat` family, `access`, `readlink`, `statfs`, listing and `chdir` are part of `rpath` and are not hidden by unveil.
- M3-4: superseded: `wpath` and `cpath` are enforced.
- M3-5: `renameat2` with `RENAME_WHITEOUT` and `linkat` with `AT_EMPTY_PATH` are refused under `cpath`; `mknod`, `mknodat`, metadata calls and extended attributes belong to no path promise.
- M3-6: `truncate`, `ftruncate` and `fallocate` are `wpath`.
- M3-7: pledge and unveil are serialized by spin locks, fork-safe through `pthread_atfork`, and refuse reentry from a signal handler with `EDEADLK`.
- M3-8: unveil does not compensate for descriptors that are already writable, nor for anything when no unveil rule exists; documented in section 2.5 and section 6.

## 14. security review, cross-kernel and glibc work (glibc and other kernels: out of scope, unsupported or untested)

the work after milestone 3 is a review, not new features. this section is the list and what has been found so far.

### review done so far

read through with fresh eyes: the rule tables, the generator, `pledge.c`, `scope.c`, `fork.c`, `lock.h`, and the always-allowed set. findings, all fixed or documented:

| finding | status |
|---|---|
| `seccomp` and `landlock_restrict_self` are allowed in every filter and took any flags; `SPEC_ALLOW` switches off a speculation mitigation, `NEW_LISTENER` and the landlock log flags are not needed to tighten | fixed: only flags vow uses are accepted; tests and kernel differential cover them |
| landlock `TSYNC` replaces the domain of sibling threads | **resolved (X2)**: never used; the commit and the scope need exactly one thread, proven by the kernel's list; documented in section 6 |
| a nested scope created in `pthread_atfork` could exhaust the 16 layers and killed the child with 127 | removed (section 2.7) |
| `kill(0)` and `kill(-1)` succeed when only the caller was reached | documented, tested |
| a scoped parent cannot deliver `PR_SET_PDEATHSIG` to children outside the domain | documented, tested |
| musl `raise()` in a raw-forked child signals the parent (stale thread id in memory) | documented, tested |
| `vow_tables` wrote past its output array when a set selected more than eight tables | fixed earlier (the differential test found it); the limit is 12 |
| the stdio `setsockopt` was unrestricted | fixed: allowlist |
| `sigqueue` was said to work and was not in the table | fixed |

not found, checked: lock order cannot cycle (`unveil` takes `plock` inside `ulock`, never the reverse; `fork` handlers take them in that order); a failed `pledge` leaves the library state alone (the irreversible exceptions are listed in section 1); `policy_rule` drops a rule rather than overflow, which only denies more; the generator fails with `E2BIG` rather than emit a jump that does not fit.

### to do

- **glibc: unsupported, not planned for v0.2** (it was deferred past v0.1). the trial notes below are information only, nothing is claimed for glibc; the tree has no glibc build and no glibc-only test code. a trial was run once, on the musl host, with the host compiler against the headers and libraries of the debian 12 (glibc 2.36) and debian 13 (glibc 2.41) packages in a scratch directory (static, and dynamic with the loader of the sysroot as interpreter), the whole suite compiled unchanged except for the points below. result: all of it passed in the four configurations once these were handled. the points, for whoever does the real work:
  - glibc `fork()` is `clone` with the flags `SIGCHLD|CHILD_SETTID|CHILD_CLEARTID`, not the `fork` system call: the test-only rule table that lets the tests fork needs that `clone` too.
  - glibc programs read `/proc/self/exe` while they start, static ones too (`readlinkat`): a program started by `exec` under a pledge needs `rpath` in it (a static musl program needs nothing).
  - a name lookup (`getaddrinfo`) goes through nss modules loaded with `dlopen`: impossible under a pledge, and a static glibc `getaddrinfo` still needs the shared libraries at run time. numeric addresses are fine.
  - dynamic glibc loads `libgcc_s.so.1` with `dlopen` the first time a thread is cancelled (or exits through the unwinder): an `open` under a pledge, a violation unless a thread was cancelled before the pledge; without the library installed it aborts with "libgcc_s.so.1 must be installed".
  - one compiler warning (`strncpy` truncation) in a test; the `pthread_atfork` link needs no extra library on 2.34 and later (older glibc not tried).
  - the claims from section 0 (`fstat` is `fstat`, `raise` is `tgkill`) were seen to hold; the signal scope no longer depends on the second.
  also needed then: a `make` target, the matrix, and the documentation of these caveats in the user documentation.
  - (older note kept for the record) no glibc was on the development machine at first; known questions at that time: does glibc `fstat` use `fstat`, does `raise` use `tgkill`, which syscalls glibc startup and `pthread_create` need beyond the `clone` flags `0x3d0f00`. all answered by the trial.
- **other kernels (untested, not planned for v0.2).** the suite skips by landlock abi (`SKIP` is counted apart from passes) and simulates lower abis with the `vow_test_abi_cap` hook, but a hook is not a kernel. needed: runs on real kernels, at least linux 6.2 (abi 3, the minimum for `unveil`), 6.7 or 6.8 (abi 4), 6.10 (abi 5), 6.12 (abi 6, the minimum for `stdio`) and 6.15 or later (abi 7), and the first kernel with abi 8 for `TSYNC`. expected: abi 3 to 5 refuse `stdio` (`ENOSYS`, tested through the hook), abi 6 or later accepts `stdio` for a process that provably has one thread (the same on every abi, since `TSYNC` is never used). the tests that need `s` (abi 9) skip below it. a kernel without seccomp, without landlock, or with landlock disabled at boot is simulated only.
- **tests that assume 7.2.9 behavior**: the open(2) flag semantics, the `uprobe` exemptions, the exact errno of several refusals, the 16 layer limit. each is asserted so a different kernel reports it.
- **review items, state now**:
  - hostile symlinks, mounts and races: done, see the next subsection.
  - the `stdio` rule table against newer syscalls: not done. v0.1 ships without that comparison.
  - fuzz of the generator against the interpreter and the kernel: done (`tests/fuzz_test.c`, six seeds clean).
  - existing seccomp filters and restricted environments: see "restricted environments" below.

### hostile filesystem audit (tests in `tests/unveil_test.c`, 61 tests)

- the path given to `unveil` is opened once (`O_PATH`, the inode is pinned by the descriptor) and then resolved a second time to a string for the conflict check. if the two disagree (a symlink swapped between them) the call fails with `ESTALE` and records nothing. tested deterministically (hook after the open) and under a thread that swaps a link all the time (about 400 recorded and 1600 refused out of 2000 calls; every recorded rule was for one of the two targets). mutant 31 removes the check and is caught.
- loops (`ELOOP`), a trailing slash on a file (`ENOTDIR`), names too long, missing middle components, an unreadable directory, names with blanks and newlines, `/proc/self/cwd` and device files behave as plain paths.
- rules are keyed on inodes: a rule on a file covers every hard link to it; a rule on a directory does not cover a hard link to a file in it made at another place (tested both ways). limitation: a hard link created before the commit to something inside an allowed tree, from outside, is not a way in; the opposite, a link from an allowed tree to a secret file, is only possible if the caller could already write there.
- mounts (user and mount namespace of the test, skipped where unavailable): a bind mount made before the commit under an allowed path shows its content through that path (the rule follows the path, not the origin) while the origin by its own name stays denied; a rule on a mount point is a rule on the mounted root; after the commit `mount`, `umount` and `pivot_root` fail (landlock denies them). `chroot` is not denied by landlock and works, it only moves the root to a place already granted. limitation: anything mounted or bound under an allowed path later by someone else outside the sandbox is visible through it.
- limitation, not fixable: landlock does not cover `stat`, `chmod`, `chdir`, `utime` and similar; `rpath` stops them only through seccomp classification, not per path.

### restricted environments

- the whole suite passes in a user namespace as root (`unshare -Ur`): 60, 12 and 213 tests (before the last two tests were added to the unveil and seccomp binaries; not rerun there).
- with a low descriptor limit (`ulimit -n 12` or `24`) only the tests that open many descriptors on purpose fail (`many entries`, `emfile`, `allocation failure`, `concurrent unveil calls`), and the library reports `EMFILE`: every `unveil` pins one descriptor until the commit, so a program with a tight limit gets a clean error, not a partial rule set. this is a documented property, not a fixed one.
- a filter installed before vow (container runtime, systemd): stacking works; `TSYNC` fails with `EBUSY` if sibling threads carry different filters, and pledge then reports `EBUSY` with nothing installed. a seccomp profile that blocks `landlock_*` or `seccomp` makes `unveil` or `pledge` fail with `EPERM` or `ENOSYS`; vow does not try to work around it. not run against a real container runtime or a systemd service: none was available and the maintainer chose not to. only simulated.

### failure states: what stays changed after an error

| step | on failure | stays changed |
|---|---|---|
| `unveil` add (open, fstat, resolve) | `-1`, errno from the step | nothing; the descriptor is closed |
| `unveil` add, table or memory full | `EMFILE`, `ENOMEM`, `E2BIG`-class | rules added earlier stay; this call adds nothing |
| `unveil(NULL, NULL)` ruleset creation or rule add | `-1` | no domain; the process is still unrestricted and the list is kept, the call can be repeated |
| `unveil` commit, `restrict_self` fails | `-1` | `no_new_privs` is set; no domain |
| `unveil` commit, a second thread appeared | `EBUSY` | **the domain is in force** (irreversible); the caller is told the sandbox exists but was not provably process wide |
| `pledge`, parse, promise check | `EINVAL`, `ENOTSUP`, `EPERM` | nothing |
| `pledge("stdio")` scope entry fails before the domain | `ENOSYS`, `EOPNOTSUPP`, `EBUSY`, `EMFILE` | nothing, or `no_new_privs` |
| `pledge("stdio")` scope entered, then the filter fails | the error of the install | **the signal scope stays** (irreversible); `scoped` is remembered, so a retry does not enter a second layer; the promises are not recorded |
| `pledge` filter install fails | `-1`, `EBUSY` for a sibling that could not be synchronized | `no_new_privs` is set; no filter was added by that call |
| atfork registration | never fails visibly | the handlers stay registered for the life of the process |
| thread-list descriptor | opened on the first call | one cached descriptor for the life of the process; `EMFILE` there is returned as `EMFILE` |

the rows come from reading `unveil.c`, `scope.c` and `pledge.c`; the rows with a test: thread at commit, scope then filter failure (the scope is entered once over twenty failed installs), a failed add keeps the earlier rules, a refused promise string changes nothing, a failed commit enforces nothing, and `EMFILE`. the rest are not asserted by a test. nothing is rolled back because the kernel offers no way to. the two irreversible partial states are the unveil domain after a late thread and the scope after a failed filter; both only make the process more restricted, never less.


