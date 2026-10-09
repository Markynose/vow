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

## unsupported and untested

- **supported:** x86-64, musl, static. this is the one configuration that was built and run, on one machine (kiss linux, kernel 7.2.9, landlock abi 10).
- **unsupported:** other architectures (the build script refuses them), glibc and any other libc (the build script warns and goes on, nothing is claimed), a shared library (only `libvow.a` is built).
- **untested:** `kiss i` or `nerd i` on a real root (file ownership, the alternatives system), upgrading an installed copy, a cross build, other kernels, containers, systemd, other musl distributions, installing without the compiler `readelf`, `make` and `git`.
- **no `depends`:** a c compiler, `make`, `readelf` and (for `mkpkg.sh`) `git` and `gzip` are assumed. `WARN` is set on the `make` line without `-Werror`, so a newer compiler with a new warning does not stop the build.
- **the kernel:** the package does not check it. `vow-run` needs landlock abi 3 or later for `unveil` and abi 6 or later for `stdio`, and one thread in the process; a kernel without landlock gives `vow-run` setup failures (status 125), not a package error.
- **no man pages:** the documents are markdown.
