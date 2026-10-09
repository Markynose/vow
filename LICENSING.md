<!-- SPDX-License-Identifier: LGPL-3.0-only -->
# licensing

this explains `LICENSE`; it is not legal advice and not a substitute for the license texts in `LICENSES/`.

## what is under what

- **libvow** (`include/vow.h`, `src/`) is LGPL-3.0-only. the makefile, the tests, the top level documents and `dist/kiss/` follow it, except two tests of the launcher.
- **vow-run** (`tools/vow-run/`, its documents, `tests/vow_run.sh`, `tests/profile_fuzz.py`) is GPL-3.0-only.
- **the examples** (`examples/*.c`) are 0BSD: copy them into your own programs under any terms, without conditions. what you build from them and link with `libvow.a` is still subject to the LGPL for the library part (below).
- `LICENSES/` holds the texts. the GPL-3.0 and LGPL-3.0 texts come from gnu.org (they match an independent copy byte for byte); the LGPL is written as additional permissions on top of the GPL, which is why the GPL text is there too. the 0BSD text is the one of the SPDX license list with the copyright line filled in.
- the `-only` is a choice of the author: version 3 and nothing later. a consequence is that a program under GPL-2.0-only cannot link libvow (version 2 and version 3 are not compatible with each other); programs under GPL-3.0, LGPL-3.0, permissive licenses or proprietary terms can, as below.

## using libvow in a program

- **using it yourself costs nothing.** the duties below start when you convey (distribute) a program that contains libvow, in source or binary form. running a program inside your own organization is not conveying.
- **only a static library is offered** (`libvow.a`; the project is static by design and builds no shared library). so a program that contains libvow is a statically linked combined work, and the LGPL (section 4) asks you, when you convey it, to do all of these:
  1. give prominent notice with each copy that libvow is used in it and covered by the LGPL;
  2. include a copy of the GPL-3.0 text and of the LGPL-3.0 text (`LICENSES/`);
  3. **let the recipient relink.** either convey the program in source form, or convey the minimal corresponding source of libvow (with your changes to it, under the LGPL) *and* your application in a form that lets someone relink it against a modified libvow: its source, or its object files and the link command. you do not have to publish your application source if you give the object files;
  4. if the program is a consumer "User Product" (GPL-3.0 section 6), also give the installation information a user needs to run a modified version on the device. other products do not need this;
  5. your own terms for the rest of the program must not forbid modifying libvow or reverse engineering to debug such modifications.
- **the header is harmless.** `include/vow.h` has two prototypes and version macros, which is within what section 3 allows an application to take from a header (parameters, layouts, small macros) without further duty. the duties above come from linking the library, not from including the header.
- the library has no obligation to anyone who only runs a program that links it, and the permissions you pass on are those of the LGPL.

## using vow-run

- running vow-run on any program, whatever its license, is free of conditions. a program started by vow-run is not a derivative of it, and neither is the profile you write. the interface to other software (wren, a shell script, a service manager) is exec, not linking, so vow-run does not change the license of what starts it.
- conveying a vow-run binary means conveying its source under the GPL-3.0 (the offer or the source itself, with the texts). the kiss package ships the binary and the license texts; where the source is, is the repository and the tarball made by `dist/kiss/mkpkg.sh`.
- code taken from `tools/vow-run/` into another program makes that program GPL-3.0. to call `pledge` and `unveil` from your own program, use libvow (LGPL), not vow-run.

## how the two fit

- vow-run is GPL-3.0-only and contains libvow (LGPL-3.0-only): it includes the internal header `src/filter.h` and links `libvow.a`. the LGPL allows a work to be combined and conveyed under the GPL-3.0, so the vow-run binary is GPL-3.0.
- the reverse must not happen: libvow must not contain GPL code. `tests/license.sh` fails if anything under `include/`, `src/` or `examples/` is not LGPL-3.0-only, or refers to `tools/`.

## third party material

- `src/sys.h` repeats numbers, flags and structure layouts of the Linux user space API (landlock, seccomp, bpf, system calls), because the library does not depend on the kernel headers being installed. these are interface definitions, not kernel code. the user space headers of the kernel carry the "Linux-syscall-note" exception that lets programs under any license use the interface.
- `tools/vow-run/sysnames.h` is a table of x86-64 system call names and numbers generated from those headers (`gen-sysnames.sh`).
- **musl libc (MIT).** `vow-run` and the test programs are linked statically against musl, so a binary contains parts of it, and the MIT license asks that its copyright notice and permission notice be included with copies of those parts. `third-party/musl/COPYRIGHT` is that notice, unchanged, from the musl 1.2.6 release (checked against the sha256 of the release tarball). **it has to go with every binary that is passed on**: the kiss package installs it as `/usr/share/licenses/vow/musl-COPYRIGHT`, and anyone who distributes `vow-run` or a program linked with `libvow.a` and musl in another way has to include it as well. `dist/kiss/vow/build` warns when it builds against a musl other than 1.2.6, because the file then has to be replaced by the one of that release.
- no other code is included.

## binary packages: what goes with a binary

this is for whoever passes on a build of vow (a package, an image, a disk). it summarizes the licenses and is not legal advice.

**the binary `vow-run` (GPL-3.0-only).** passing it on is "conveying" and GPL-3.0 section 6 applies. the corresponding source is the vow source of the exact build (this repository at one commit, `dist/kiss/mkpkg.sh` records the commit in the tarball), including the scripts that control the build and install (`dist/kiss/vow/build`, the `Makefile`) and the source of the libvow it contains. any one of these satisfies it:
- the source goes along with the binary. the kiss binary package does this: kiss keeps the source tarball and the recipe inside the package, under `/var/db/kiss/installed/vow/` (checked on the package built for this release; it is behavior of kiss and nerd, not of vow, so check it again for another package manager);
- a written offer, valid for at least three years, to give the source to anyone who has the binary;
- the binary and the source offered from the same place.
a vow-run that has been modified has to say so in its source, and the recipient gets the same rights.

**the library `libvow.a` and the header (LGPL-3.0-only).** passing on the library itself means giving the source of libvow with it and the license texts; the package does both. the library is not a "combined work" until someone links it into a program.

**a program built with `libvow.a` (the static linking duties of the LGPL).** whoever passes on such a program, in a package or on a device, has to:
1. say prominently that libvow is used and covered by the LGPL, and include the GPL-3.0 and LGPL-3.0 texts;
2. **let the recipient relink**: give the source of the libvow in the program (and any change to it, under the LGPL) and the application in a form from which it can be linked again with a modified libvow: its source, or its object files and the link command. because `libvow.a` is static there is no shared library alternative; this is the one duty that cannot be skipped by choosing a different packaging;
3. if the program is in a "User Product" (a consumer device), also give the installation information needed to run the modified version on it (GPL-3.0 section 6);
4. include the musl notice above.
the application source does not have to be published if the object files are given.

**what the kiss package carries, and what it does not.** it installs `LICENSE`, `GPL-3.0-only.txt`, `LGPL-3.0-only.txt`, `0BSD.txt` and `musl-COPYRIGHT` under `/usr/share/licenses/vow/`, the documents under `/usr/share/doc/vow/`, the examples under `/usr/share/doc/vow/examples/`, and carries the source tarball and recipe in its own database directory. it does not carry the source of musl: that is another package (`musl` of the kiss repository) and its source offer is its own.

## open points

- the history of the repository before the licensing change has no license files; the license applies to the files from the commit that adds it. the history is not rewritten.
- the copyright holder in `LICENSE` is `mark <mark@65x64.xyz>`, confirmed by the author.
