# vow roadmap

status: v0.1 milestones 1 to 3 are implemented and tested (`unveil()`, `pledge()` with `stdio`, `rpath`, `wpath`, `cpath`, `inet`, `exec`). signal isolation follows alternative S2: `pledge` with `stdio` requires a landlock signal scope (abi 6 for one thread, abi 8 for several) and fails otherwise, with no pid based fallback. no further promise is planned for v0.1. the current work is a security review, tests on other kernels and glibc compatibility (DESIGN.md section 14).

rule for every stage: no feature without a test that shows the kernel enforcing it, and no claim in the docs that a test does not back.

## v0.1: core userspace library

goal: a small, auditable `libvow.a` that an application opts into by including `<vow.h>`.

scope:

- `libvow.a` and `include/vow.h` (c89 to c23 compatible header, checked in the build).
- landlock based `unveil()` with `r w x c s` permissions (`x` needs `r`, `s` needs abi 9), deferred commit at `unveil(NULL, NULL)`, abi probe, abi >= 3 required, `TSYNC` on abi >= 8, dynamic rule storage, seal-only `unveil(NULL, NULL)` with no paths. no network, ioctl or scope rights in v0.1; the resulting gaps are listed in DESIGN.md section 6.
- seccomp-bpf based `pledge()` with promises `stdio`, `rpath`, `wpath`, `cpath`, `inet`, `exec`; subset-only repeated calls; strict `execpromises` rules; `KILL_PROCESS` as the denial action; no `dns`; no claim of `SCM_RIGHTS` restriction.
- fully static musl builds. glibc is not part of v0.1 (deferred, DESIGN.md section 14).
- tests: positive, negative, adversarial, bpf oracle, build matrix. skips reported, never counted as passes.
- examples: simple cli, file processor, network client, progressive privilege reduction, static link builds.
- README (lifecycle, what to open before sandboxing, how to handle setup failure, limitations table) and DESIGN.md kept in sync.

milestones (details in DESIGN.md section 11):

1. unveil end to end. **done**: 45 unveil tests pass on abi 10 (including the `s` permission), static musl build, header checks c89 to c23 and c++.
2. bpf generator and seccomp install. **done**: rule tables, interpreter, oracle and kernel differential (606 real syscalls plus 203 argument-model probes), installer with `TSYNC`, monotonic `pledge()`, `stdio` verified with static musl. 85 tests in total.
3. promises one at a time. **all done**: the path promises, `inet`, `exec`. signals: `stdio` requires the landlock signal scope (S2); the pid rules and the nested domain in the fork child are gone; fork-safe and reentrancy-safe locks; 207 seccomp tests plus the filter (12) and unveil (47) suites. next: **security review, cross-kernel tests, glibc** (below).
4. integration tests.
5. static musl validation. **done.** glibc deferred.
6. examples and docs.

explicitly not in v0.1: `proc`, `dns`, `unix`, `tty`, `fattr` and other promises; landlock net and scope rules; other architectures; any cli; any config file; any init integration.

exit criteria: every row of the "enforced" list in DESIGN.md section 6 has a passing kernel test on the primary matrix; the open items N1 to N3 in DESIGN.md section 13 are resolved; the glibc `fstat` and `tgkill` findings are confirmed by running a glibc build, not only by reading source.

## review stage between v0.1 milestones and release (current)

no new promises. work, in this order (details in DESIGN.md section 14):

1. glibc: deferred past v0.1. a trial run passed (DESIGN.md section 14 lists the points); real support needs a build target, a matrix and the caveats in the user documentation.
2. other kernels: run the suite on real kernels at abi 3, 6, 7 and 8 or later at least; confirm what skips and what fails; keep the tests that assume 7.2.9 honest.
3. security review: unveil path logic against hostile layouts, the stdio table against newer syscalls, a generator fuzz against the interpreter and the kernel, behavior inside containers and under existing seccomp filters.
4. README with the lifecycle, the failure handling and the limitations table, the examples, and the release checklist.

## v0.2: system integration

goal: use vow on programs whose source is not changed, and from a service supervisor. the library stays independent of any distro or init system. everything here lives in separate directories or repos, and nothing here changes the v0.1 api.

candidates, in rough order:

1. `vow-run`: a small cli that applies a policy and then `execve`s a program. covers the same ground as the library from outside. depends on the library, not the other way round.
2. profiles: optional reusable sandbox profiles and a plain config file format (one line per unveil and one for the promise set, no templating, no includes at first). the library never reads config; only `vow-run` does.
3. wren integration: wren is a minimal linux init and service supervisor. it would apply a profile between `fork` and `exec` of a service, either by calling libvow or by running `vow-run`. design question: wren needs `exec` in the promise set of the profile, and the service then inherits that whole policy (see below).
4. kiss linux packaging: a package recipe for `libvow.a`, headers and `vow-run`, and the install layout. kiss is only a packaging target; no kiss specific code in the library.
5. violation reporting. a pledge violation kills the process (`KILL_PROCESS`, uncatchable), so it cannot say what it did. two ways to see it, neither changes the default behavior of the library:
   - `vow-run` as the observer: it runs the program, sees `SIGSYS`, and prints the syscall name and which promise would have allowed it, from the same rule tables the filter is built from. no change to the library.
   - a trap mode for debugging: the filter uses `SECCOMP_RET_TRAP`, a handler prints `vow: pledge violation: openat (needs rpath)` and exits. off by default, switched on explicitly (an environment variable or a `vow-run` flag), never the default because a handler inside the process is weaker than a kill. open question: whether it needs any public api; if it does, it waits for the api review.
   a log-only mode (`SECCOMP_RET_LOG`, find out what a program needs) was also considered and is not planned: the program stays unsandboxed while it runs.
5. investigations that must come before promising anything:
   - executable loading: what a dynamically linked child needs (ld.so, libs, `mmap` with `PROT_EXEC`, `openat`) and whether a policy can be both useful and tight. static children are the baseline.
   - exec-time policy change: because filters and domains survive `execve` and cannot be swapped, `execpromises` that differ from `promises` cannot be done by the library. options to evaluate: a launcher stub that stays below the target, or accepting only inherit-everything profiles. do not hide the limitation, document it.
   - subprocess behavior and the `proc` promise: fork-like clones, `wait4`, process groups and how to allow them without opening `kill`.
   - inherited capabilities and descriptors: what leaks through exec, `no_new_privs` consequences for setuid helpers, ambient caps.
   - the promises most requested by real programs, first `dns`, then `proc`, `unix`, `fattr`; for each, an enforceability statement before any code.
   - re-evaluate landlock net (abi 4, 10), ioctl_dev (abi 5), scope (abi 6) and resolve_unix (abi 9) rights against measured breakage. resolve_unix is the largest filesystem-adjacent gap left by v0.1 (connecting to pathname unix sockets is not restricted by unveil).
   - signal isolation beyond v0.1: a public way to isolate a child from its parent (DESIGN.md X1: nested scope, explicit, with the error contract and the 16 layer budget decided); a `proc` promise must answer how its children get their own domain; the `TSYNC` replacement of sibling domains (X2) and a per-thread alternative.
   - the network: landlock net rules (tcp from abi 4, udp from abi 10) against the address and port blindness of `inet`.
   - `exec`: a launcher that narrows the child before the exec, the environment of the child, and what to do about descriptors without close-on-exec.
   - whether `x` without `r` can ever be offered (landlock needs read to execute).

exit criteria: `vow-run` sandboxes a real static program from a profile with kernel verified denials; wren runs a service under a profile in a documented example; every investigation above ends in a written conclusion, even if the conclusion is "not feasible".

## future: native kernel integration (experimental research, not a release)

this is a research direction only. there is no commitment to build it, ship it, or keep the api stable around it.

questions to answer first:

- would a linux security module or kernel patch give openbsd-like pledge and unveil natively? what would actually be gained over landlock plus seccomp:
  - real exec-time policy change (execpromises), the biggest gap in the userspace design.
  - deny rules and narrowing below a granted parent, which landlock cannot express.
  - path hiding (`ENOENT`) and metadata control (`stat`, `chmod` and friends).
  - argument inspection beyond registers (paths, sockaddr).
- hooks and state: which lsm hooks cover it (`file_open`, `inode_*`, `path_*`, `socket_*`, `task_alloc`, `cred_prepare`, `bprm_creds_for_exec`, `bprm_committed_creds`), where per-process restriction state lives (cred blob), how it is inherited by fork and clone and transformed by exec, and how irreversible reduction is guaranteed (only monotonic transitions).
- how it coexists with other lsms (blob allocation, stacking order) and with landlock itself.
- smaller alternative: a minimal kernel change to existing interfaces (for example exec-time seccomp or landlock policy swapping) might deliver most of the benefit with far less to maintain. evaluate before any lsm work.
- cost: out of tree maintenance, upstream acceptance (new lsm needs a very strong case when landlock exists), security review burden, support for distros that compile their own kernels.
- api: keep `pledge()` and `unveil()` identical on both backends, selected at build time or at runtime by capability probe, with differing guarantees documented per backend. only if the research shows meaningful benefit.

deliverable of this stage: a written evaluation (design notes, a prototype only if justified, and a recommendation including "do not do this"). nothing from here enters v0.1 or v0.2.

## how this file changes

milestones and priorities change only through a reviewed edit to this file. each completed v0.1 milestone updates DESIGN.md and marks the matching item here.
