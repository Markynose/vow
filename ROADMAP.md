<!-- SPDX-License-Identifier: LGPL-3.0-only -->
# vow roadmap

status: v0.1.0 is tagged. v0.2 is in development (version `0.2.0-dev`): `vow-run` with profiles and `--check`, the wren integration design, a kiss package, and licensing (libvow LGPL-3.0-only, vow-run GPL-3.0-only). `unveil()` and `pledge()` (`stdio`, `rpath`, `wpath`, `cpath`, `inet`, `exec`) are implemented and tested; signal isolation follows alternative S2 and landlock `TSYNC` is never used (X2). **platform scope: x86-64 linux with musl, static, and nothing else is claimed.** glibc, other architectures and other kernels are unsupported or untested and are not part of the release requirements (RELEASE.md, section 14 of DESIGN.md).

rule for every stage: no feature without a test that shows the kernel enforcing it, and no claim in the docs that a test does not back.

## v0.1: core userspace library

goal: a small, auditable `libvow.a` that an application opts into by including `<vow.h>`.

scope:

- `libvow.a` and `include/vow.h` (c89 to c23 compatible header, checked in the build).
- landlock based `unveil()` with `r w x c s` permissions (`x` needs `r`, `s` needs abi 9), deferred commit at `unveil(NULL, NULL)`, abi probe, abi >= 3 required, one thread required at the commit and `TSYNC` never used (X2), dynamic rule storage, seal-only `unveil(NULL, NULL)` with no paths. no network, ioctl or scope rights in v0.1; the resulting gaps are listed in DESIGN.md section 6.
- seccomp-bpf based `pledge()` with promises `stdio`, `rpath`, `wpath`, `cpath`, `inet`, `exec`; subset-only repeated calls; strict `execpromises` rules; `KILL_PROCESS` as the denial action; no `dns`; no claim of `SCM_RIGHTS` restriction.
- fully static musl builds on x86-64. glibc and other architectures are unsupported (DESIGN.md section 14).
- tests: positive, negative, adversarial, bpf oracle, build matrix. skips reported, never counted as passes.
- examples: simple cli, file processor, network client, progressive privilege reduction, static link builds.
- README (lifecycle, what to open before sandboxing, how to handle setup failure, limitations table) and DESIGN.md kept in sync.

milestones (details in DESIGN.md section 11):

1. unveil end to end. **done**: 61 unveil tests (the count grew with later milestones) pass on abi 10 (including the `s` permission), static musl build, header checks c89 to c23 and c++.
2. bpf generator and seccomp install. **done**: rule tables, interpreter, oracle and kernel differential (606 real syscalls plus 203 argument-model probes), installer with `TSYNC`, monotonic `pledge()`, `stdio` verified with static musl. 85 tests in total.
3. promises one at a time. **all done**: the path promises, `inet`, `exec`. signals: `stdio` requires the landlock signal scope (S2); the pid rules and the nested domain in the fork child are gone; fork-safe and reentrancy-safe locks; 215 seccomp tests plus the filter (12) and unveil (47) suites. next: **security review, cross-kernel tests, glibc** (below).
4. integration tests. **done**: 61 unveil, 12 filter, 3 fuzz and 215 seccomp tests, kernel differential, 32 mutants caught, fuzz seeds clean, `tests/examples.sh`.
5. static musl validation. **done.** glibc unsupported.
6. examples and docs. **done**: README, four examples, DESIGN.md, RELEASE.md.

explicitly not in v0.1: `proc`, `dns`, `unix`, `tty`, `fattr` and other promises; landlock net and scope rules; other architectures; any cli; any config file; any init integration.

exit criteria: every row of the "enforced" list in DESIGN.md section 6 has a passing kernel test on the dev machine (kernel 7.2.9); the open items N1 to N3 in DESIGN.md section 13 are resolved. met for 0.1.0. not required: the same rows on other kernels and any glibc run are out of scope (unsupported or untested), not open items.

## review stage between v0.1 milestones and release (done; what was left open is listed as unsupported or untested)

no new promises. work, in this order (details in DESIGN.md section 14):

1. glibc: **unsupported**, not planned for v0.2 or v0.3. a trial run once passed (notes in DESIGN.md section 14, for information only); nothing is claimed and no work is scheduled.
2. other kernels: **untested**, not planned for v0.2. the suite was run on kernel 7.2.9 (landlock abi 10) only; lower abis are simulated with a test hook, which is not a kernel. `tests/kernel_matrix.sh` runs the suite on one kernel for anyone who wants to try; its results would be information, not a requirement.
3. security review: **done as far as it goes**. hostile paths and mounts, generator fuzz against the interpreter and the kernel, user namespace and low descriptor limit runs, and the failure-state table are done. untested and not required: the stdio table against newer syscalls, a real container, systemd.
4. README, examples and the release checklist: **done** (RELEASE.md).

## v0.2: system integration

platform scope of v0.2: x86-64 linux, musl, static linking. other platforms are unsupported or untested and are not release requirements. licensing of v0.2: libvow LGPL-3.0-only, vow-run GPL-3.0-only, the example programs 0BSD, texts in `LICENSES/`, the musl notice in `third-party/`, everything explained in `LICENSING.md` (static relinking duties, what goes with a binary package).

goal: use vow on programs whose source is not changed, and from a service supervisor. the library stays independent of any distro or init system. everything here lives in separate directories or repos, and nothing here changes the v0.1 api.

candidates, in rough order:

1. `vow-run`: a small cli that applies a policy and then `execve`s a program. covers the same ground as the library from outside. depends on the library, not the other way round. **static and dynamic executables done**: `tools/vow-run/DESIGN.md` (approved decisions D1 to D5), `tools/vow-run/vow-run.c`, `tests/vow_run.sh`, mutants 32 to 43; dynamic executables take the interpreter from the elf (checked, then unveiled) and the libraries from `-u`; profiles, wren, packaging and the new promises are not started. design: (c99, static musl, in this repository, `libvow` unchanged). the first version runs static executables only; dynamic needs the interpreter, the libraries and `rpath` (measured table in the design); `execpromises` stays unsupported (the stub idea gives nothing over inheriting; an interposer is a new trusted component); a post-exec restriction without trusting the program is not possible with landlock and seccomp.
2. profiles: **done**: `vow-run --profile file.vow`, a strict line format (one `pledge` line, any number of `unveil = path:perms` lines, comments, no includes, variables or inheritance), validated completely before any sandbox step; cannot be combined with `-p` or `-u`. review of the nested rule check against the kernel (667 permission pairs, `t_conflict_matches_kernel`) found the library check right except for two harmless cases it refused, now fixed in `src/unveil.c` (behavior only, no api change, accepts more than v0.1.0 did); the parser leaves that check to the library. design in `tools/vow-run/DESIGN.md` section 13; the library never reads config.
3. wren integration: **design approved, run-script based, no change in wren**: `tools/vow-run/WREN.md`. a run script ending in `exec vow-run --profile /etc/wren/vow/name.vow -- daemon` works with wren as it is (checked in a scratch copy of wren in dev mode: pid and process group, restarts and backoff, stopping on purpose, shutdown, failures 125/126/127 and pledge kills). a persistent vow-run failure is a restart every 30 seconds, accepted and documented. `vow-run --check file.vow` (parser only, status 0 or 125, no guarantee of enforceability) exists so a package can reject a bad profile. the real limit is the promise set: none of the kiss services of wren (sshd, dhcpcd, syslogd, mdev, getty) can be sandboxed until `proc`, `unix` and a few more promises exist. not tested: wren as pid 1, a real boot, a kernel without landlock.
4. kiss linux packaging: **done** in `dist/kiss/` (recipe `vow`, `mkpkg.sh`, `README.md`): installs `vow-run`, `libvow.a`, `vow.h`, the license texts, the musl notice, the examples and the documents; static, x86-64, musl; no dependency on wren. the package is `0.2.0-dev 1` (nerd compares versions by string inequality, so the release number is bumped when another revision is packaged); `mkpkg.sh outdir revision` packages one explicit commit with `git archive`, from any directory, and never the uncommitted working tree. tested with nerd in a scratch repository and by `tests/package.sh`. installing on a real root and upgrading remain untested. kiss is only a packaging target; no kiss specific code in the library.
5. violation reporting. a pledge violation kills the process (`KILL_PROCESS`, uncatchable) and `waitpid` gives only "signal 31". **measured** (tools/vow-run/DESIGN.md section 8): a ptrace parent with `PTRACE_O_TRACEEXIT` reads the syscall number from `orig_rax` at the exit event, also with threads (the culprit is found by checking each thread against the policy, since every thread reports status 31). kernel audit and `dmesg` are not available to an ordinary user here; core dumps, `SECCOMP_RET_TRAP` and user notification were rejected. implemented as the opt-in `vow-run -v` using ptrace; the library does not change and the default stays the plain kill.
   a log-only mode (`SECCOMP_RET_LOG`, find out what a program needs) was also considered and is not planned: the program stays unsandboxed while it runs.
6. investigations that must come before promising anything:
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
