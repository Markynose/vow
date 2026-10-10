<!-- SPDX-License-Identifier: LGPL-3.0-only -->
# release checklist

v0.1.0 is tagged. v0.2 is in development as `0.2.0-dev`; no release is tagged for it yet. each line is checked by hand and the result written next to it.

## supported platform

x86-64 linux with musl libc, static. this is the only configuration built and tested: one machine, kiss linux, kernel 7.2.9, landlock abi 10. everything else is unsupported or untested (below) and is **not** a requirement for a release.

## required for a v0.2 release

- [ ] `make all tools check-header test static-check` passes on a clean build: the four test binaries, `tests/examples.sh`, `tests/vow_run.sh`, `tests/package.sh`, `tests/license.sh`, the profile fuzz
- [ ] `python3 tests/mutate.py`: every mutant CAUGHT (the x32 check is an equivalent mutant, see the file); run `make clean` and rebuild afterwards, the script removes `build/`
- [ ] fuzz: `VOW_FUZZ_SEED` over at least six seeds, `VOW_FUZZ_N=20000 VOW_FUZZ_KN=600` for the library; `tests/profile_fuzz.py` seeds 1 to 6
- [ ] the header compiles as c89 to c2x and from c++ (`make check-header`); no change of `pledge` or `unveil`
- [ ] licenses: `LICENSE`, `LICENSES/`, `LICENSING.md` and `third-party/` agree with the tree (`tests/license.sh`); the copyright holder is `mark <mark@65x64.xyz>` (confirmed); the musl notice is the one of the musl the binaries are built with
- [x] the package builds from an exact commit (`dist/kiss/mkpkg.sh outdir <commit>`, `nerd c`, `nerd b`; done for `02a86d8`); the version in `include/vow.h` and `dist/kiss/vow/version` agree
- [x] install, reinstall, upgrade, conflict and removal with nerd in an isolated root: `sh tests/kiss_install.sh` (44 checks and one skip; results and findings in `dist/kiss/README.md`)
- [x] the same as root of a disposable user and mount namespace with the real system read-only: `sh tests/kiss_install_ns.sh` (49 checks): ownership `0:0` while the archive records 1000:1000, modes, metadata, removal, upgrade, hook, nerd against the original kiss
- [ ] the install on the **real root**, by root, with your explicit approval: the real database and a real upgrade of an installed copy. not done; the namespace tests do not replace it (one mapped id, no real database)
- [ ] DESIGN.md, ROADMAP.md, README.md, the documents of vow-run and this list agree with the source
- [ ] tag: signed, only when asked

## not required: unsupported

- glibc and any libc but musl; architectures other than x86-64; a shared libvow; dynamic linking of vow-run itself; the original kiss as the installer of the package (its tar restores the owner recorded in the archive, nerd does not; the result as real root was not observed).

## not required: untested (nothing is claimed)

- kernels other than 7.2.9; lower landlock abis beyond what the `vow_test_abi_cap` hook simulates (`tests/kernel_matrix.sh` exists for anyone who wants to try)
- containers with a default seccomp profile, systemd services with `SystemCallFilter`
- the `stdio` rule table against syscalls added to linux after 5.x
- wren as pid 1, a real boot with vow-run services, a kernel without landlock

## known limits that ship (do not hide)

- threads before the first vow call: unveil commit and pledge stdio refuse with EBUSY
- processes in the same landlock domain can signal each other; raw fork children share the domain and locks
- wpath and cpath without unveil are broad; descriptors opened before the sandbox keep their power
- sendmsg destinations and inet addresses and ports are not filtered; the landlock layer limit is 16
- uprobe and uretprobe are exempt from seccomp; PROT_EXEC is not w^x
- failure-state table rows without a test are from reading the code
- the kiss package is built and installed with nerd under umask 022 (a strict umask gives a wrong archive and unreadable files); the recipe does not set a umask itself
- no promise allows `fork`, unix sockets, terminals or `setuid`, so the kiss services of wren cannot be sandboxed yet

## history

v0.1.0 (tagged) was checked on kernel 7.2.9 only; it was released with the platform items above open, which are now stated as unsupported or untested instead. test counts at the time: 61 unveil, 12 filter, 3 fuzz, 215 seccomp.
