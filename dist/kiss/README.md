<!-- SPDX-License-Identifier: LGPL-3.0-only -->
# vow on kiss linux

a package recipe for vow: the launcher `vow-run`, the static library, the header, the license texts, the musl notice, the examples and the documents. it is a separate package from wren and does not depend on it, and wren does not depend on it.

## build and install

```sh
dist/kiss/mkpkg.sh /path/to/outdir HEAD   # recipe plus source tarball, from that commit
KISS_PATH=/path/to/outdir:$KISS_PATH
kiss c vow && kiss b vow && kiss i vow    # or nerd c, b, i
```

- **a revision is required.** `mkpkg.sh` packages the commit you name (`HEAD`, a tag, a hash) with `git archive`, and the recipe files are read from that commit as well. uncommitted changes are never packaged; if the working tree has any, `mkpkg.sh` says so. the commit id is recorded in the tarball (`gzip -dc vow-VERSION.tar.gz | git get-tar-commit-id`).
- it works from any directory (it finds the checkout from its own location) and uses no gnu tar option: `git archive` writes the tar, `gzip` packs it.
- it refuses a commit whose `dist/kiss/vow/version` differs from `VOW_VERSION` in `include/vow.h`, or whose `sources` file names another tarball.
- `kiss c` writes the checksums, which are not kept in the repository.

**the supported workflow, and the umask.** the supported way to build and install this package is with **nerd**, with **umask 022** in the shell that runs `nerd b` and `nerd i` (check with `umask`; 022 is the usual default). this is a requirement, not advice:
- *installing.* the copy into the root applies the umask. under `umask 077` an install by root gives files that other users cannot read (files 700 and 600, directories 755), so `/usr/bin/vow-run` would be usable by root only. found and checked in the namespace test below; the original kiss does exactly the same, so this is how both package managers work, not a defect of nerd (nerd was not changed).
- *building.* under `umask 077` the archive records the top-level directory `./usr` as mode 700 (observed), because the directories that the recipe creates with `install -D` follow the umask of the builder. a package built that way would create `/usr` with that mode in an empty root. the recipe sets no umask of its own, so the builder must; a `umask 022` at the top of `dist/kiss/vow/build` would remove the dependence (not done: it is a change of the recipe, left to a decision).

**nerd and the original kiss are not interchangeable for this package.** with nerd, a root install creates root-owned files whatever owner the archive records: nerd makes no `chown` (traced, and a failing check if one appears). the original kiss restores the owner that the archive records: its `tar` was seen calling `chown(..., 1000, 1000)` for every entry when it ran as uid 1000. every archive nerd builds records the builder (uid and gid 1000), so what the original kiss leaves behind when root installs such an archive was **not observed** (the one-id namespace cannot show it) and may be files owned by uid 1000. only the nerd workflow is tested and supported; installing this package with the original kiss as root is unsupported and its ownership result is unverified.

## version

the package is `0.2.0-dev 1`. the first field is the version of the library (`VOW_VERSION` in `include/vow.h`); a development version carries `-dev` until a release is tagged, and no release is tagged yet. the second field is the release counter of the package. `nerd U` and `kiss u` decide that a package changed by comparing both fields as strings, not by order, so **bump the release counter whenever another commit is packaged under the same version**, or an installed copy will not be seen as outdated.

## what it installs

| file | what |
|---|---|
| `/usr/bin/vow-run` | the launcher, static, GPL-3.0-only |
| `/usr/lib/libvow.a` | the library, static, LGPL-3.0-only |
| `/usr/include/vow.h` | the header (`pledge`, `unveil`), c89 clean |
| `/usr/share/licenses/vow/` | `LICENSE`, `GPL-3.0-only.txt`, `LGPL-3.0-only.txt`, `0BSD.txt`, `musl-COPYRIGHT` |
| `/usr/share/doc/vow/` | `README.md`, `DESIGN.md`, `ROADMAP.md`, `LICENSING.md`, `vow-run.md` (design of the launcher and the profile format), `vow-run-wren.md` (running services under wren) |
| `/usr/share/doc/vow/examples/` | the four example programs, 0BSD |

nothing is installed under `/etc`. profiles live where the administrator puts them; `vow-run-wren.md` proposes `/etc/wren/vow/`, and creating it is up to whoever installs the first profile.

## licenses, and what has to go with a binary

`vow-run` is GPL-3.0-only, `libvow.a` is LGPL-3.0-only and the examples are 0BSD (`LICENSE`). a binary package of vow carries:

- **the license texts** (`/usr/share/licenses/vow/`), and **the musl notice** (`musl-COPYRIGHT`): the binaries are linked statically against musl (MIT), whose copyright and permission notice has to be included with copies of the parts that are in them. the file is the `COPYRIGHT` of musl 1.2.6, unchanged; `build` warns when the musl of the build machine is another version, and then `third-party/musl/COPYRIGHT` has to be replaced by the one of that release.
- **the corresponding source** of `vow-run` (GPL-3.0 section 6), which includes the source of the libvow inside it and the build scripts: kiss and nerd keep the source tarball and the recipe inside the binary package, in `/var/db/kiss/installed/vow/`, so the package is accompanied by its source. the tarball records the exact commit. anyone who passes on the binary some other way has to give the source, or a written offer valid for three years, or offer both from the same place.
- for **a program that links `libvow.a`** (the LGPL): it is static only, so whoever passes such a program on has to let the recipient relink it with a modified libvow (the application source, or its object files and the link command), say that libvow is used, and include the license texts and the musl notice. `LICENSING.md` has the whole list, also for devices (installation information).

## tested

`tests/package.sh` (run by `make test`): a throwaway git repository is made from the tree, `mkpkg.sh` is run from another directory on explicit commits, with uncommitted changes, with a revision that does not exist, with a commit whose version, `sources` or recipe is wrong; then the recipe builds from the unpacked tarball into a staging directory the way the package manager runs it; exactly the files above are installed, with the license texts, the 0BSD text, the unchanged musl notice and the examples of the tree; `vow-run` is static and checks a profile; a program links against the installed header and library and runs under `pledge`; the recipe refuses a compiler for another architecture and says that a libc other than musl is unsupported. also built and run once with `nerd c`, `nerd b` in a scratch repository on this machine, and the packaged binary was run from an extracted copy.

## install, upgrade and removal test (isolated root)

`sh tests/kiss_install.sh [revision]` (or `make kiss-test`) builds the package from a commit (default `HEAD`) and runs it through nerd in a throwaway root. it is not part of `make test`, because it needs nerd, git, python3 and (for the audit) strace.

**isolation.** the root is a directory under `build/tmp` that the test user owns (`KISS_ROOT`), so nerd never needs a privilege tool (it escalates only for a root the user does not own); `KISS_SU` points at a stub that records an attempt and fails, and none was recorded. nerd runs in a clean environment (`env -i`) with its own `KISS_PATH`, cache (`XDG_CACHE_HOME`) and temp directories (`KISS_TMPDIR`, `TMPDIR`) inside the scratch directory. every nerd call runs under `strace`; afterwards each call that could write is checked against the scratch directory (3404 writes in one run, covering nerd and the original kiss, none outside; the audit follows the working directory and the `chroot` of every process, is shown to flag a synthetic write outside, and fails if it sees fewer than 100 writes or if its script crashes, so a missing trace cannot pass). the 202 packages of the real package database were unchanged (sha256 over all its files, before and after) and so was the checkout. nerd documents this mode (its own tests use throwaway roots the same way); nothing here depends on a trick.

**what ran, and the result** (kiss linux, nerd 0.3.0, kernel 7.2.9, as the unprivileged user; 44 checks passed and one skipped: the hook test needs root):

| step | result |
|---|---|
| install `0.2.0-dev 1` next to an unrelated package and two unowned files | 24 files, `installed (24 files)`; exactly the 18 packaged files plus the 6 database files; binary 755, files 644, directories 755; `nerd l`, `owns`, `verify` (`39 files: all there`) agree |
| package database entry | `var/db/kiss/installed/vow/` holds `build`, `checksums`, `manifest`, `sources`, `version` and the source tarball with the commit id; the manifest names the files, the database files and the directories (directories with a trailing slash, shared ones such as `/usr/share/doc/` included) |
| the installed program and library | `vow-run` is static; `--check` accepts a profile and refuses a bad one with 125; it runs a static program under a pledge and passes its status back; a program links statically against the installed `libvow.a` and runs under `pledge` |
| reinstall the same version | succeeds, same manifest, same file hashes, neighbours unchanged |
| upgrade `0.2.0-dev 1` to `0.2.0-dev 2` (one example dropped, one file added), by `nerd U` | `U -n` lists `vow 0.2.0-dev-1 => 0.2.0-dev-2`; the dropped file is gone, the new file is there, the files on disk equal the manifest (no stale file), the database entry is replaced, the unowned note and the other package are unchanged |
| a changed package under the same release | not seen as newer: nerd compares version and release as strings, so the release number must be bumped when another commit is packaged (as documented above) |
| a second package that ships `/usr/include/vow.h` | no overwrite: nerd warns `/usr/include/vow.h is now a choice of vowclash (see nerd a)`, vow stays the owner and keeps its header, the other file is parked in `var/db/kiss/choices`; the file only the other package owns is installed next to of vow; removing it cleans the choice and leaves vow complete |
| remove vow | `removed (24 files)`; every file gone, the database entry gone, no empty directory left behind that vow created; every directory that existed before still exists; the unowned note inside `usr/share/doc/vow/` is kept (so is the directory), and the unrelated package and files are identical by path, mode and content |
| install again after the removal | works, same files |

**findings and packaging problems.**
- no problem was found in the vow package or in what nerd does with it. the points below are facts to know, not defects of the recipe.
- **ownership:** the unprivileged test installs files owned by that user; every archive nerd builds records the numeric owner of the builder (uid and gid 1000, no names), which is also true of vow, libcap, xinit and nerd itself. the privileged test shows that a root install by nerd still produces `0:0` (below).
- **hooks:** the vow package has no hook. the `chroot` path of nerd for hooks was exercised with a probe package in the privileged test (it works), not with vow.
- **`/etc` handling is not exercised by vow** (it installs nothing under `/etc`); the unrelated test package has an `/etc` file, which was left alone.
- an isolated build still writes the temporary files of the compiler to `/tmp` unless `TMPDIR` is set; the test sets it. harmless, noted because it is a write outside a root.
- `nerd l` on an empty database exits 1 with `'*' not found`; it works once a package is installed. a quirk of nerd, nothing to do with vow.
- the 48 write calls that an earlier version of the audit could not attribute were temporary files of `make` itself (`build.ninja`, `.ninja_log`, `.make-shin.*`), written relative to the build directory that nerd makes in the scratch tree. the audit now tracks `chdir`, `fchdir`, `chroot` and every fork, so each relative path is resolved: none is left unresolved, and the `make` files resolve to `$T/tmp/<pid>/build/vow/` inside the scratch directory.
- the install tests are not in the mutation set; their checks include controls against silent passes (a non-empty baseline of the neighbours, the audit control, a failing audit script, a check that the cache was not rebuilt). while writing them i found and fixed three silent passes of my own: an `awk` pitfall that made the neighbour snapshot empty, installs run in subshells whose log counter did not advance (logs overwritten), and a stale line that overwrote the audit result.

## privileged installation test (user and mount namespace)

`sh tests/kiss_install_ns.sh [revision]` (or `make kiss-test-root`) runs the same flow as root, without touching the host.

**how it is isolated.** phase 1 runs as the ordinary user: it builds every package (so the archives record the builder, uid and gid 1000, as they do when a package is built as a user) and runs the unprivileged test above. phase 2 runs the test again inside `unshare -Urm`, a disposable user and mount namespace in which the user is root (uid 0 inside is the uid of the user outside; only that one id is mapped, because the host has no subuid range, no `newuidmap` and no qemu). inside it `/home`, `/var/db/kiss` (the real package database) and the checkout are bind-mounted read-only, and the run is refused if a probe write to any of them succeeds. the root of the test is a directory owned by namespace-root in `/tmp`, `LOGNAME` is `root`, and `KISS_SU` is the failing stub. nothing is escalated on the host (no sudo, doas or su); if user namespaces are missing the test is skipped. phase 2 installs from the cache of phase 1 and checks that the archives were not rebuilt there.

**what ran** (nerd 0.3.0, kiss linux, kernel 7.2.9; 49 checks, all passed): the whole flow of the first test (install, reinstall, upgrade, conflict, removal, the installed program and library) and, only as root:

| check | result |
|---|---|
| the archive against what is installed | the archive records `1000:1000`; every installed path and every database file belongs to `0:0`; the same after the reinstall and after the upgrade (including the new file of release 2) |
| the `chown` family | nerd makes no call of it, in any run (strace, a failing check if one appears); the original kiss makes 80 (its `tar` restores the owner recorded in the archive) |
| modes and the umask | installed as root under umask 022, binary 755 and files 644; under umask 077 files come out 700 and 600, directories 755 |
| nerd against the original kiss | the same tarball installed by both gives the same tree (modes, owners, content, manifest and version of the database entry) under umask 022 and under 077 |
| a `post-install` hook | runs in a chroot of the root as uid 0 with `/` as its directory; the hook file is kept in the database; the package is removable |
| the real system | the 202 packages of the real database are unchanged (checked from inside the run and again from outside), nothing was written outside the scratch directories |

**what this establishes.**
- a root install by nerd creates root-owned files whatever the archive records. four independent lines agree: the tar and install code of nerd contains no `chown`; not one `chown` call appears in the traces; in the namespace the archive says `1000:1000` and the installed files are `0:0` (had nerd applied the recorded ids the call would have failed with `EINVAL`, ids being unmapped); and on the live root, read only, `/usr/bin/nerd` and `/usr/bin/hop` (packages built by this nerd and installed by it) are `0:0` and `/usr` holds no file that root does not own.
- modes, package metadata, removal and upgrade behave as in the unprivileged test, also as root.
- the hook path (`chroot`, run as root) works.

**the umask finding, and why nerd is unchanged.** installing as root under a strict umask gives files that other users cannot read (700 and 600 under 077). i first took that for a nerd defect, because the extraction step gives root the exact modes of the archive. it is not: the second step, the copy into the root, applies the umask, and the original kiss does exactly the same (busybox `cp`); the differential above shows identical trees. nerd matches its reference, so nerd was not changed. the consequence for anyone installing as root is plain: **install packages with umask 022** (a root shell with a strict umask would make `/usr/bin/vow-run` mode 700, usable by root only).

**what stays unverified.**
- a real root. the namespace has one mapped id, so a `chown` to the id 1000 fails here instead of succeeding; the argument above (no `chown` is made) does not depend on that, but this was not seen on a real root. no other capability of real root was exercised (device nodes, setuid files: the package has neither).
- the original kiss as real root. its `tar` restores the owner recorded in the archive (seen as `chown(".", 1000, 1000)` and the like when it ran as uid 1000); what it leaves behind on a real root, installing a tarball built by an ordinary user, was not observed, because the namespace cannot show it. that concerns kiss, not nerd or vow; it means a nerd-built tarball should not be assumed safe to install with kiss as real root.
- the real database and a real upgrade of an installed copy. the install on the live root was not done and needs your explicit approval; nothing in the tests touches it.
- a kernel without landlock, other kernels, other musl distributions (see below).

## unsupported and untested

- **supported:** x86-64, musl, static. this is the one configuration that was built and run, on one machine (kiss linux, kernel 7.2.9, landlock abi 10).
- **unsupported:** other architectures (the build script refuses them), glibc and any other libc (the build script warns and goes on, nothing is claimed), a shared library (only `libvow.a` is built).
- **untested:** `kiss i` or `nerd i` on the **real root** (the two tests above cover nerd for this package in an unprivileged root and as root of a namespace, with the real system read-only; they do not touch the real database, and the namespace cannot show everything a real root can), the original kiss as real root, a cross build, other kernels, containers, systemd, other musl distributions.
- **no `depends`:** a c compiler, `make`, `readelf` and (for `mkpkg.sh`) `git` and `gzip` are assumed. `WARN` is set on the `make` line without `-Werror`, so a newer compiler with a new warning does not stop the build.
- **the kernel:** the package does not check it. `vow-run` needs landlock abi 3 or later for `unveil` and abi 6 or later for `stdio`, and one thread in the process; a kernel without landlock gives `vow-run` setup failures (status 125), not a package error.
- **no man pages:** the documents are markdown.
