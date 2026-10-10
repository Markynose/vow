<!-- SPDX-License-Identifier: LGPL-3.0-only -->
# vow

pledge() and unveil() for linux x86-64, in c99. landlock for the filesystem and signals, seccomp classic bpf for syscalls. no dependencies, no libseccomp. built and tested static against musl. the header is c89 clean and works from c++.

```c
int unveil(const char *path, const char *permissions);
int pledge(const char *promises, const char *execpromises);
```

version 0.2.0-dev (the last release, tagged v0.1.0, has no `vow-run`). read the limits below before trusting it.

## use

```c
#include <vow.h>

if (unveil("/srv/data", "r") < 0 || unveil("/tmp/out", "rwc") < 0)
	err(1, "unveil");
if (unveil(NULL, NULL) < 0)		/* seal: from here the list is fixed */
	err(1, "unveil");
if (pledge("stdio rpath wpath cpath", NULL) < 0)
	err(1, "pledge");
```

- unveil permissions: `r` `w` `x` `c` `s` (unix sockets). `x` needs `r`. `c` only on directories.
- pledge promises: `stdio rpath wpath cpath inet exec`. other openbsd promises give `ENOTSUP`. `execpromises` must be the same as `promises` or `NULL`, because filters and domains survive `execve`.
- a pledge violation kills the process (`SECCOMP_RET_KILL_PROCESS`).
- promises only shrink. asking for more than you have gives `EPERM`.

## requirements

- linux x86-64. landlock abi 3 or later for `unveil`, abi 6 or later for `pledge("stdio")` (signal scope). the signal scope is required, there is no pid fallback.
- the unveil commit and the first `pledge("stdio")` need the process to have exactly one thread, proven from `/proc/self/task`. otherwise `EBUSY`. call them before starting threads.

## platform

- **supported:** x86-64 linux with musl libc, linked statically. this is the only configuration that is built and tested: one machine (kiss linux, musl, kernel 7.2.9, landlock abi 10).
- **unsupported** (the code is not written for it and no work is planned for v0.2): other architectures (syscall numbers, the seccomp architecture check and the landlock calls are x86-64), glibc, a shared `libvow` (only `libvow.a` is built).
- **untested, nothing claimed:** other kernel versions (the stated minimums are landlock abi 3 for `unveil` and abi 6 for `pledge("stdio")`; lower abis are simulated with a test hook, not run), containers and their default seccomp profiles, systemd services, other musl distributions, installing the kiss package on a real root by root and upgrading it there (install, upgrade and removal were tested in an isolated root and as root of a disposable namespace, never on the real root: `dist/kiss/README.md`).

## build and test

```sh
make                 # build/libvow.a
make test            # unveil, filter, fuzz and seccomp tests (needs landlock and seccomp)
make examples        # the programs in examples/, static, into build/
make check-header    # c89 to c2x and c++
make static-check
python3 tests/mutate.py   # mutation check, every mutant must be caught
```

link `build/libvow.a` and `-pthread`. use musl and `-static`.

## examples

small programs in `examples/`, built with `make examples` from the repo root (output in `build/`). by hand, also from the root:

```sh
cc -std=c99 -D_GNU_SOURCE -Iinclude -static -o cli examples/cli.c build/libvow.a -pthread
```

the programs:

- `cli`: a cat that can only read the files named on its command line
- `fileproc`: read one file, write an upper cased copy into one directory
- `netclient`: send a line to an ipv4 address and port (no name lookup, that needs files)
- `progressive`: drop `rpath` after loading a config, then get killed on purpose by opening a file

## vow-run

`build/vow-run` (`make tools`) sandboxes a static or dynamic program without changing it:

```sh
vow-run -p "stdio rpath exec" -u /srv/data:r ./prog args...
```

or from a profile file:

```sh
vow-run --profile editor.vow -- ./prog args...
```

```
# editor.vow
pledge = stdio rpath wpath cpath exec
unveil = /home/mark/docs:rwc
unveil = /tmp:rwc
```

`vow-run --check editor.vow` only validates a profile (status 0, or 125 with the file and line) and installs and starts nothing; a pass does not promise that the profile can be enforced on a given machine or that the program runs under it.

the profile format is strict (one `pledge`, any number of `unveil` lines, comments on their own line, absolute canonical paths, no includes or variables) and is checked completely before the sandbox is built; `--profile` cannot be combined with `-p` or `-u`. `-p` is the pledge string and must contain `exec`; `-u path:perms` is an unveil rule (the program itself is unveiled `rx` for you); `-i` clears the environment; `-v` stays as the parent and says which syscall killed the program. the loader of a dynamic program is unveiled for you; its shared libraries are not, list them with `-u` (and add `rpath`). scripts are refused for now. see `tools/vow-run/DESIGN.md`.

## packages

`dist/kiss/` has a recipe for kiss linux: `dist/kiss/mkpkg.sh outdir HEAD` packages one commit (never uncommitted changes), then `kiss c vow` or `nerd c vow`, then `b` and `i`. it installs `vow-run`, `libvow.a`, `vow.h`, the license texts and the documents. see `dist/kiss/README.md`. the supported workflow is **nerd, with umask 022 for both `nerd b` and `nerd i`** (a strict umask gives unreadable files and a wrong archive); the original kiss is not a supported installer for this package, because it restores the owner recorded in the archive and nerd does not. installing on the real root has not been tested.

## license

libvow is LGPL-3.0-only, vow-run is GPL-3.0-only, and the example programs are 0BSD; see `LICENSE`. a program that links `libvow.a` statically has to let its recipients relink it against a modified libvow when it is distributed, and a binary that is passed on carries the musl notice: `LICENSING.md` says what that means in practice, also for packagers of binaries.

## limits

read DESIGN.md sections 6, 12 and 14 for the full list. the main ones:

- threads started before the first vow call make the commit and `stdio` fail with `EBUSY`.
- processes in the same landlock domain can signal each other.
- `wpath` and `cpath` without `unveil` are broad. descriptors opened before the sandbox keep their power.
- `inet` cannot filter addresses or ports, `sendmsg` destinations are not filtered.
- landlock allows at most 16 layers. `PROT_EXEC` is not w^x. `uprobe` bypasses seccomp.
- see "platform" for what is supported, unsupported and untested.

## files

- LICENSE, LICENSES/, LICENSING.md: which part is under which license, the texts, what they ask of you
- DESIGN.md: how it works and why, decisions, security model
- ROADMAP.md: stages
- RELEASE.md: v0.1 checklist
- include/vow.h, src/: the library
- examples/: the programs above
- tools/vow-run/: the launcher, its profile parser, its design (`DESIGN.md`) and the wren integration (`WREN.md`)
- dist/kiss/: the kiss recipe
- tests/: tests, independent oracle, bpf interpreter, fuzzer, mutation script
