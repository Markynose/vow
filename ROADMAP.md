<!-- SPDX-License-Identifier: LGPL-3.0-only -->
# vow roadmap

status: v0.1.0 is tagged. **v0.2.0 is frozen and prepared for release** (version `0.2.0`, not tagged yet): no new promise, no new public api, no major feature. v0.2 added the launcher `vow-run` (profiles, `--check`, `-v`), the example of a wren service, a kiss package, licenses (libvow LGPL-3.0-only, vow-run GPL-3.0-only, examples 0BSD) and a release procedure. the library changed in one way since v0.1.0: the narrowing check of `unveil` knows the type of the object it checks and accepts 27 of 667 pairs of permission sets that v0.1.0 refused (each shown harmless on a real kernel); `pledge`, the prototypes, the promises, the signal scope (S2) and the refusal of a multithreaded commit (X2) are unchanged. **platform scope: x86-64 linux with musl, static; nothing else is claimed.** glibc, other architectures and other kernels are unsupported or untested and are not release requirements. new promises and the unfinished security investigations are in the section v0.3 below.

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

## v0.2: system integration (frozen)

version `0.2.0`. platform scope: x86-64 linux, musl, static linking. other platforms are unsupported or untested and are not release requirements. licensing: libvow LGPL-3.0-only, vow-run GPL-3.0-only, the example programs 0BSD, texts in `LICENSES/`, the musl notice in `third-party/`, everything explained in `LICENSING.md` (static relinking duties, what goes with a binary package).

goal: use vow on programs whose source is not changed, and from a service supervisor. the library stays independent of any distro or init system. everything here lives in separate directories, and nothing here changes the v0.1 api.

what v0.2 contains, all done:

1. `vow-run`: a small cli that applies a policy and then `execve`s a program, static and dynamic executables (the interpreter is checked and unveiled, shared libraries are listed with `-u`), `-v` to name the syscall that killed the program (ptrace on the exit event). `tools/vow-run/DESIGN.md` (decisions D1 to D5), `tools/vow-run/vow-run.c`, `tests/vow_run.sh`. depends on the library, not the other way round.
2. profiles: `vow-run --profile file.vow`, a strict line format (one `pledge` line, any number of `unveil = path:perms` lines, comments, no includes, variables or inheritance), validated completely before any sandbox step; cannot be combined with `-p` or `-u`. `vow-run --check file.vow` validates a profile and nothing else (status 0 or 125; no guarantee of enforceability). the nested-rule check was reviewed against the kernel (667 permission pairs, `t_conflict_matches_kernel`) and made type-aware in `src/unveil.c`; the parser leaves that check to the library.
3. wren integration: no change in wren. a run script ending in `exec vow-run --profile /etc/wren/vow/name.vow -- daemon` works with wren as it is. design and findings in `tools/vow-run/WREN.md`; a minimal example (a daemon, a run script, a profile, a readme) in `examples/wren/`, tested by `tests/wren_example.sh` under a scratch build of wren in its dev mode (pid and process group, the sandbox, restart after a kill, backoff for a broken profile, shutdown). a persistent vow-run failure is a restart every 30 seconds, accepted and documented. not tested: wren as pid 1, a real boot, a kernel without landlock. none of the services that ship with wren on kiss linux (sshd, dhcpcd, syslogd, mdev, getty) can be sandboxed with v0.2: that needs promises from v0.3.
4. kiss linux packaging: `dist/kiss/` (recipe `vow`, `mkpkg.sh`, `README.md`): installs `vow-run`, `libvow.a`, `vow.h`, the license texts, the musl notice, the examples and the documents; static, x86-64, musl; no dependency on wren. the recipe sets umask 022 itself. the supported workflow is nerd with umask 022 for building and installing; the original kiss is not a supported installer. tested with nerd in an isolated root (`tests/kiss_install.sh`) and as root of a disposable user and mount namespace with the real system read-only (`tests/kiss_install_ns.sh`: files installed as root are `0:0` although the archive records 1000:1000, nerd makes no `chown`, and it matches the original kiss on modes and trees). **installing on the real root and upgrading an installed copy there were not tested, and are not a release requirement.**
5. violation reporting: `vow-run -v`, a ptrace parent reading the syscall number at the exit event (measured also with threads); the library does not change and the default stays the plain kill.
6. the release procedure (`RELEASE.md`, `tests/release_check.sh`): a release commit with the final version and nothing derived from itself, checks on that commit, a signed tag afterwards, a source archive that is `git archive` of the commit the tag names. no hash, tag name or tarball checksum is stored in the repository, so nothing can disagree with the commit.

exit criteria, as met: `vow-run` sandboxes a real static program from a profile with kernel verified denials (met: `tests/vow_run.sh`); wren runs a service under a profile in a documented, tested example (met in dev mode: `examples/wren/`); the package builds from the exact release commit and installs in an isolated root and a disposable namespace (met); full regression, fuzz, mutation, license and package tests pass on the release commit (to be run on that commit: `RELEASE.md`). the criterion of v0.2 that every investigation ends in a written conclusion is not required for v0.2.0: it moved to v0.3 by decision.

not in v0.2: new promises, new public api, anything below.

## v0.3: new promises and the unfinished security investigations (planned, nothing started)

moved here from v0.2 by decision on 2026-10-10. none of it is in v0.2.0. the known limits of v0.2.0 stay documented as they are (DESIGN.md section 6, `RELEASE.md`) until an item here changes one. no new promise gets code before it has a written enforceability statement.

proposed promises: `dns`, `proc`, `unix`, `fattr`, and the ones that the services of wren would need (a terminal promise, an id promise for dropping privileges). without `proc` and `unix` none of the services that ship with wren on kiss linux can be sandboxed.

concluded in v0.2 (written, not repeated here): executable loading (`tools/vow-run/DESIGN.md` sections 3 and 12), exec-time policy change and the launcher stub (section 6 there: not worth it, an interposer is a new trusted component), `x` without `r` (not offered, DESIGN.md N1), the finding that a post-exec restriction without trusting the program is not possible with landlock and seccomp.

open investigations, each to end in a written conclusion, even "not feasible":

- subprocess behavior and the `proc` promise: fork-like clones, `wait4`, process groups and how to allow them without opening `kill`.
- inherited capabilities and descriptors: what leaks through exec, `no_new_privs` consequences for setuid helpers, ambient caps (the launcher closes descriptors above 2; the rest is not written).
- the promises most requested by real programs, first `dns`, then `proc`, `unix`, `fattr`; for each, an enforceability statement before any code.
- re-evaluate landlock net (abi 4, 10), ioctl_dev (abi 5), scope (abi 6) and resolve_unix (abi 9) rights against measured breakage. resolve_unix is the largest filesystem-adjacent gap left (connecting to pathname unix sockets is not restricted by unveil below abi 9).
- signal isolation beyond v0.2: a public way to isolate a child from its parent (DESIGN.md X1: nested scope, explicit, with the error contract and the 16 layer budget decided); a `proc` promise must answer how its children get their own domain; a per-thread alternative to the refusal of X2.
- the network: landlock net rules (tcp from abi 4, udp from abi 10) against the address and port blindness of `inet`.
- `exec`: a launcher that narrows the child before the exec, the environment of the child, and what to do about descriptors without close-on-exec.
- an option to name the interpreter of a dynamic program instead of trusting the one the program file names (the remaining exposure of the launcher, `tools/vow-run/DESIGN.md` section 12), and finding the shared libraries of a program without running its loader.
- the services of wren: which of them can be sandboxed once the promises exist, and a run of the example with wren as pid 1 in a vm.

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
