<!-- SPDX-License-Identifier: LGPL-3.0-only -->
# release checklist and procedure

v0.1.0 is tagged. v0.2.0 is prepared: the tree says `0.2.0`, nothing is tagged yet. v0.2 is frozen (no new promise, no new public api, no major feature); what was left over is in `ROADMAP.md` under v0.3.

## supported platform

x86-64 linux with musl libc, static. this is the only configuration built and tested: one machine, kiss linux, kernel 7.2.9, landlock abi 10. everything else is unsupported or untested (below) and is **not** a requirement for a release. no portability is claimed beyond it.

## what changed since v0.1.0 (the seed of the release notes)

- **library.** the prototypes of `pledge` and `unveil`, the promises, the signal scope (S2) and the refusal of a multithreaded commit (X2) are unchanged. the only change in the code: the narrowing check of `unveil` knows the type of the object it checks. a rule below another that asks for less than the one above gives is still refused when the kernel would leave the extra access, but the check no longer refuses what cannot matter: `s` above a regular file, and `r`, `w` or `x` above a socket node (27 of the 667 pairs of permission sets that were measured on a real kernel, `t_conflict_matches_kernel`). it accepts more than v0.1.0 did and refuses nothing new. also: the version macros, and an SPDX license line in every file.
- **new in v0.2.** the launcher `vow-run` (static and dynamic programs, profiles, `--check`, `-v`); the example of a wren service (`examples/wren/`); a kiss package (`dist/kiss/`); licenses (libvow LGPL-3.0-only, vow-run GPL-3.0-only, examples 0BSD, the musl notice); the release procedure and checks below.

## the procedure (no circular dependency)

the rule that keeps it simple: **nothing committed names the hash of a commit, a tag, or the checksum of a tarball.** the version is the only thing the release commit says about itself.

1. work on `main` until the tree is what is to be released. the final version is the same in four places, and a check enforces it: `VOW_VERSION` and the two macros in `include/vow.h`, the first field of `dist/kiss/vow/version` (the second is the release counter of the package), `dist/kiss/vow/sources` (`vow-VERSION.tar.gz`), and the documents name it.
2. commit that as the release commit **R**, signed. R holds no hash of itself, no tag name, no checksum.
3. on R, with a clean tree: `sh tests/release_gate.sh`. every step must pass (the commit facts, the clean build and all tests, six seeds of both fuzzers, the install tests with nerd, the wren example, every mutant, a rebuild). `--worktree` runs it before R exists; that is a rehearsal, not the gate.
4. only then make the tag, signed, on R: `git tag -s v0.2.0 -m "vow 0.2.0" R`. the tag names R. R does not name the tag, so the tag cannot disagree with R.
5. build the source archive and the package directory from the tag: `dist/kiss/mkpkg.sh OUTDIR v0.2.0`. `mkpkg.sh` refuses a tag whose version differs from the recipe in it, and refuses a development version from a tag. the archive is `git archive` of R: its content is a function of the tree of R, it records the id of R (`git get-tar-commit-id`), and making it twice gives the same bytes.
6. checksums: `nerd c vow` (or `kiss c vow`) in OUTDIR writes them next to the recipe, outside the repository. the release notes carry the sha256 of the tarball and the sha256 of the uncompressed tar (`tests/release_check.sh` prints both; the second does not depend on the gzip program that made the first).
7. push R and the tag to both remotes (Forgejo and GitHub) and check that both name R and that the tag points at R.
8. if anything is found after the tag and before the push: delete the local tag, fix on a new commit S, run the gate again, tag S (S replaces R). a tag that has been pushed is never moved. afterwards `main` goes on with the next development version (the same three places, with a dev suffix), in a later commit.

why nothing is circular: the tarball is made from R, so it cannot be inside R; the tag is made from R, so R does not hold it; the checksum is made from the tarball, so it is published beside it and not in git. each arrow goes one way. a file that tried to embed its own commit id (`export-subst`) would make the archive differ from the commit, and `tests/release_check.sh` fails on it.

## what must hold, all run by `tests/release_gate.sh` on R

- [ ] the commit: the tree is clean and R is `HEAD`; the version is the same in the header, the macros, the recipe and the sources file, with no development string left; the tag, if it exists, names R and is signed (`tests/release_check.sh --release`)
- [ ] `make all tools check-header test static-check` on a clean build: the four test binaries, `tests/examples.sh`, `tests/vow_run.sh`, `tests/package.sh`, `tests/license.sh`, `tests/release_check_test.sh` (which also tests `tests/docs_check.sh`), the profile fuzz; the header compiles as c89 to c2x and from c++, and `pledge` and `unveil` are unchanged
- [ ] fuzz: `VOW_FUZZ_SEED` 1 to 6 with `VOW_FUZZ_N=20000 VOW_FUZZ_KN=600` for the library; `tests/profile_fuzz.py` 1 to 6
- [ ] the package: `dist/kiss/mkpkg.sh` from R, the archive is exactly the files of R byte for byte and holds no binary, the recipe builds from it under an inherited umask 077, `vow-run` is a static x86-64 executable with no interpreter and no shared library, the compiler targets musl, the modes are 755 / 644
- [ ] install, reinstall, upgrade, conflict and removal with nerd: `tests/kiss_install.sh` in an isolated root and `tests/kiss_install_ns.sh` as root of a disposable user and mount namespace with the real system read-only; ownership `0:0` although the archive records 1000:1000, and the package database of the real system is unchanged
- [ ] the example of a wren service runs under a scratch build of wren: `tests/wren_example.sh`
- [ ] every mutant is caught: `python3 tests/mutate.py` (132 mutants), after a preflight that runs the judging tests on the unmutated tree; the script removes `build/` when it ends, the gate rebuilds. a mutant that is caught only sometimes (a race in what the test looks at) is a weak test: the report of a waiting thread by `vow-run -v` was one, and the test now uses eight waiting threads and three runs
- [ ] licenses: `LICENSE`, `LICENSES/`, `LICENSING.md` and `third-party/` agree with the tree (`tests/license.sh`); the copyright holder is `mark <mark@65x64.xyz>` (confirmed); the musl notice is the one of the musl the binaries are built with (musl 1.2.6; the recipe warns otherwise)
- [ ] this file, `ROADMAP.md`, `README.md`, `DESIGN.md` and the documents of vow-run agree with the source (the gate cannot read documents: a person checks this one)
- [ ] the signed tag, made in step 4, only when asked

## not required: unsupported

- glibc and any libc but musl; architectures other than x86-64; a shared libvow; dynamic linking of `vow-run` itself; the original kiss as the installer of the package (its tar restores the owner recorded in the archive, nerd does not; the result as real root was not observed).

## not required: untested (nothing is claimed)

- **installing the package on the real root, and upgrading an installed copy there.** the install tests above never touch the real root or its package database. a procedure for it exists (`tests/real_root_install.sh`: preflight, backup, install, verification, rollback; described in `dist/kiss/README.md`) and its preflight has been run against the real root, read only; until an install has been done and verified there, this stays the largest untested part of the packaging.
- kernels other than 7.2.9; lower landlock abis beyond what the `vow_test_abi_cap` hook simulates (`tests/kernel_matrix.sh` exists for anyone who wants to try)
- containers with a default seccomp profile; systemd services with `SystemCallFilter`
- the `stdio` rule table against syscalls added to linux after 5.x
- wren as pid 1, a real boot with vow-run services, a kernel without landlock

## known limits that ship (do not hide)

- threads before the first vow call: the unveil commit and `pledge("stdio")` refuse with `EBUSY`
- processes in the same landlock domain can signal each other; raw fork children share the domain and the locks
- `wpath` and `cpath` without unveil are broad; descriptors opened before the sandbox keep their power
- `sendmsg` destinations and `inet` addresses and ports are not filtered; the landlock layer limit is 16
- `uprobe` and `uretprobe` are exempt from seccomp; `PROT_EXEC` is not w^x
- failure-state table rows without a test are from reading the code
- no promise allows `fork`, unix sockets, terminals or `setuid`, so the services of wren on kiss linux (sshd, dhcpcd, syslogd, mdev, getty) cannot be sandboxed
- every profile needs `exec`; a program file chooses its own interpreter (checked, then unveiled `rx`); a profile is trusted configuration; `--check` does not promise enforceability; `-v` traces the program and is not for services of wren; a persistent vow-run failure under wren is a restart every 30 seconds (the full list is in DESIGN.md section 6)
- the package is built and installed with nerd under umask 022 (a strict umask gives unreadable files, in nerd and in the original kiss alike); the recipe sets umask 022 itself so that the payload does not depend on the builder, but the database skeleton that the package manager adds does

## history

v0.1.0 (tagged) was checked on kernel 7.2.9 only; it was released with the platform items above open, which are now stated as unsupported or untested instead.
