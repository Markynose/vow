# vow

pledge() and unveil() for linux x86-64, in c99. landlock for the filesystem and signals, seccomp classic bpf for syscalls. no dependencies, no libseccomp. built and tested static against musl. the header is c89 clean and works from c++.

```c
int unveil(const char *path, const char *permissions);
int pledge(const char *promises, const char *execpromises);
```

version 0.1.0. read the limits below before trusting it. it has been run on one kernel (linux 7.2.9) only.

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

## limits

read DESIGN.md sections 6, 12 and 14 for the full list. the main ones:

- threads started before the first vow call make the commit and `stdio` fail with `EBUSY`.
- processes in the same landlock domain can signal each other.
- `wpath` and `cpath` without `unveil` are broad. descriptors opened before the sandbox keep their power.
- `inet` cannot filter addresses or ports, `sendmsg` destinations are not filtered.
- landlock allows at most 16 layers. `PROT_EXEC` is not w^x. `uprobe` bypasses seccomp.
- kernel behavior was verified on linux 7.2.9 only. glibc is not supported yet.

## files

- DESIGN.md: how it works and why, decisions, security model
- ROADMAP.md: stages
- RELEASE.md: v0.1 checklist
- include/vow.h, src/: the library
- examples/: the programs above
- tests/: tests, independent oracle, bpf interpreter, fuzzer, mutation script
