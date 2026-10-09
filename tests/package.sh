#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# tests for the kiss recipe (dist/kiss). a throwaway git repository is made from the current tree, so that
# mkpkg.sh can be tested on real commits: from another directory, on an explicit revision, with uncommitted
# changes, with a bad revision. the recipe is then built from the tarball into a staging directory the way
# the package manager runs it. no kiss, nerd or root needed. installing on a real root is not tested here.
set -u
cd "$(dirname "$0")/.." || exit 2
here=$PWD
fail=0
mkdir -p build/tmp
T=$(mktemp -d "$PWD/build/tmp/pk.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
ok() { echo "pass  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
chk() { if "$@"; then ok "$name"; else bad "$name"; fi; }

if ! command -v git >/dev/null || ! git rev-parse --git-dir >/dev/null 2>&1; then
	echo "SKIP  needs git and a git checkout"
	exit 0
fi
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
g() { git -C "$R" -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@"; }

# a repository with the current tree (tracked files and new ones that are not ignored) as its first commit
R=$T/repo
mkdir "$R"
(git ls-files; git ls-files --others --exclude-standard) | sort -u | while read -r f; do
	[ -f "$f" ] || continue
	mkdir -p "$R/$(dirname "$f")"
	cp -p "$f" "$R/$f"
done
git -C "$R" init -q 2>/dev/null
g add -A
g commit -q -m first
C1=$(g rev-parse HEAD)
ver=$(cut -d' ' -f1 dist/kiss/vow/version)
MK=$R/dist/kiss/mkpkg.sh

# ---- mkpkg ----
name="mkpkg works from another directory and names the commit"
if (cd / && sh "$MK" "$T/out" "$C1") >"$T/mk.log" 2>&1 && grep -q "$C1" "$T/mk.log" &&
    [ -x "$T/out/vow/build" ] && [ -s "$T/out/vow/version" ] && [ -s "$T/out/vow/sources" ] && [ -s "$T/out/vow/vow-$ver.tar.gz" ]; then ok "$name"; else bad "$name"; cat "$T/mk.log" | sed 's/^/    /'; fi
name="the commit id is recorded in the tarball"
if [ "$(gzip -dc "$T/out/vow/vow-$ver.tar.gz" | git get-tar-commit-id)" = "$C1" ]; then ok "$name"; else bad "$name"; fi
name="mkpkg uses no gnu tar option and no tar at all"
if grep -v "^#" "$R/dist/kiss/mkpkg.sh" | grep -qE "(^|[|;&(][ ]*)tar[ ]|--transform"; then bad "$name"; else ok "$name"; fi

gzip -dc "$T/out/vow/vow-$ver.tar.gz" | tar t >"$T/list" 2>/dev/null
for f in Makefile LICENSE LICENSES/GPL-3.0-only.txt LICENSES/LGPL-3.0-only.txt LICENSES/0BSD.txt third-party/musl/COPYRIGHT examples/cli.c LICENSING.md include/vow.h src/pledge.c src/unveil.c \
    src/filter.c tools/vow-run/vow-run.c tools/vow-run/profile.c tools/vow-run/profile.h tools/vow-run/sysnames.h README.md \
    DESIGN.md tools/vow-run/WREN.md; do
	name="the tarball holds $f"
	chk grep -q "^vow-$ver/$f\$" "$T/list"
done
name="the tarball holds no tests, no build output and no compiled example"
if grep -q "/tests/\|/build/\|/\.git\|/examples/cli\$" "$T/list"; then bad "$name"; else ok "$name"; fi

# uncommitted changes are left out and the user is told
echo "UNCOMMITTED-MARKER" >>"$R/README.md"
name="uncommitted changes are not packaged, and mkpkg says so"
if sh "$MK" "$T/out2" "$C1" >"$T/mk2.log" 2>&1 && grep -q "uncommitted" "$T/mk2.log" &&
    ! gzip -dc "$T/out2/vow/vow-$ver.tar.gz" | tar xO "vow-$ver/README.md" 2>/dev/null | grep -q UNCOMMITTED-MARKER; then ok "$name"; else bad "$name"; fi
g checkout -q -- README.md

# an explicit revision is what is packaged, not the newest
echo "SECOND-COMMIT-MARKER" >>"$R/README.md"; g commit -q -am second
C2=$(g rev-parse HEAD)
name="an older revision is packaged as it was"
if sh "$MK" "$T/out3" "$C1" >/dev/null 2>&1 && ! gzip -dc "$T/out3/vow/vow-$ver.tar.gz" | tar xO "vow-$ver/README.md" 2>/dev/null | grep -q SECOND-COMMIT-MARKER; then ok "$name"; else bad "$name"; fi
name="and the newer one has the change"
if sh "$MK" "$T/out4" "$C2" >/dev/null 2>&1 && gzip -dc "$T/out4/vow/vow-$ver.tar.gz" | tar xO "vow-$ver/README.md" 2>/dev/null | grep -q SECOND-COMMIT-MARKER; then ok "$name"; else bad "$name"; fi
name="a name like HEAD~1 is accepted and resolved"
if sh "$MK" "$T/out5" HEAD~1 >"$T/mk5.log" 2>&1 && grep -q "$C1" "$T/mk5.log"; then ok "$name"; else bad "$name"; fi

# refusals
name="mkpkg refuses a missing revision argument"
if sh "$MK" "$T/o" >"$T/neg.log" 2>&1; then bad "$name"; else if grep -q "usage" "$T/neg.log"; then ok "$name"; else bad "$name (no message)"; fi; fi
name="mkpkg refuses a revision that does not exist"
if sh "$MK" "$T/o" no-such-revision >"$T/neg.log" 2>&1; then bad "$name"; else if grep -q "no such revision" "$T/neg.log"; then ok "$name"; else bad "$name (no message)"; fi; fi
name="mkpkg refuses a version that is not the one of the header"
printf '0.9.9 1\n' >"$R/dist/kiss/vow/version"; g commit -q -am badversion
if sh "$MK" "$T/o" HEAD >"$T/neg.log" 2>&1; then bad "$name"; else if grep -q "include/vow.h says" "$T/neg.log"; then ok "$name"; else bad "$name (no message)"; fi; fi
printf '%s 1\n' "$ver" >"$R/dist/kiss/vow/version"; printf 'vow-9.tar.gz\n' >"$R/dist/kiss/vow/sources"; g commit -q -am badsources
name="mkpkg refuses a sources file that names another tarball"
if sh "$MK" "$T/o" HEAD >"$T/neg.log" 2>&1; then bad "$name"; else if grep -q "does not name" "$T/neg.log"; then ok "$name"; else bad "$name (no message)"; fi; fi
printf 'vow-%s.tar.gz\n' "$ver" >"$R/dist/kiss/vow/sources"; g commit -q -am fixed
g rm -q -r dist/kiss/vow; g commit -q -m norecipe
name="mkpkg refuses a revision that has no recipe"
if sh "$MK" "$T/o" HEAD >"$T/neg.log" 2>&1; then bad "$name"; else if grep -q "does not exist in" "$T/neg.log"; then ok "$name"; else bad "$name (no message)"; fi; fi
name="and the checkout is never changed by mkpkg"
if [ -z "$(git -C "$R" status --porcelain)" ]; then ok "$name"; else bad "$name"; fi

# ---- the recipe, built from the tarball the way the package manager does ----
mkdir "$T/x" "$T/dest"
gzip -dc "$T/out/vow/vow-$ver.tar.gz" | tar x -C "$T/x"
name="the recipe builds"
if (cd "$T/x/vow-$ver" && "$T/out/vow/build" "$T/dest") >"$T/build.log" 2>&1; then ok "$name"; else bad "$name"; sed 's/^/    /' "$T/build.log" | tail -5; fi

(cd "$T/dest" && find . -type f | sort) >"$T/files"
cat >"$T/expect" <<'X'
./usr/bin/vow-run
./usr/include/vow.h
./usr/lib/libvow.a
./usr/share/doc/vow/DESIGN.md
./usr/share/doc/vow/LICENSING.md
./usr/share/doc/vow/README.md
./usr/share/doc/vow/ROADMAP.md
./usr/share/doc/vow/examples/cli.c
./usr/share/doc/vow/examples/fileproc.c
./usr/share/doc/vow/examples/netclient.c
./usr/share/doc/vow/examples/progressive.c
./usr/share/doc/vow/vow-run-wren.md
./usr/share/doc/vow/vow-run.md
./usr/share/licenses/vow/0BSD.txt
./usr/share/licenses/vow/GPL-3.0-only.txt
./usr/share/licenses/vow/LGPL-3.0-only.txt
./usr/share/licenses/vow/LICENSE
./usr/share/licenses/vow/musl-COPYRIGHT
X
name="exactly these files are installed"
if cmp -s "$T/files" "$T/expect"; then ok "$name"; else bad "$name"; diff "$T/expect" "$T/files" | sed 's/^/    /'; fi
name="the license texts in the package are the ones of the tree"
if cmp -s "$T/dest/usr/share/licenses/vow/GPL-3.0-only.txt" LICENSES/GPL-3.0-only.txt &&
    cmp -s "$T/dest/usr/share/licenses/vow/LGPL-3.0-only.txt" LICENSES/LGPL-3.0-only.txt &&
    cmp -s "$T/dest/usr/share/licenses/vow/0BSD.txt" LICENSES/0BSD.txt; then ok "$name"; else bad "$name"; fi
name="the musl notice in the package is the one of musl 1.2.6, unchanged"
if cmp -s "$T/dest/usr/share/licenses/vow/musl-COPYRIGHT" third-party/musl/COPYRIGHT; then ok "$name"; else bad "$name"; fi
name="the examples in the package are the 0BSD ones"
if [ -s "$T/dest/usr/share/doc/vow/examples/cli.c" ] && head -n 1 "$T/dest/usr/share/doc/vow/examples/cli.c" | grep -q "SPDX-License-Identifier: 0BSD"; then ok "$name"; else bad "$name"; fi
name="vow-run is static"
if [ -x "$T/dest/usr/bin/vow-run" ] && ! readelf -d "$T/dest/usr/bin/vow-run" 2>/dev/null | grep -q NEEDED; then ok "$name"; else bad "$name"; fi
name="nothing of wren is needed: no file of the package outside the documents mentions a wren path"
if grep -rl "/etc/wren" "$T/dest/usr/bin" "$T/dest/usr/include" "$T/dest/usr/lib" "$T/dest/usr/share/licenses" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi

printf 'pledge = stdio exec\n' >"$T/p.vow"
name="the installed vow-run checks a profile"
chk "$T/dest/usr/bin/vow-run" --check "$T/p.vow"
printf 'pledge = stdio\n' >"$T/p.vow"
name="and refuses a bad one"
if "$T/dest/usr/bin/vow-run" --check "$T/p.vow" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi

cat >"$T/hello.c" <<'X'
#include <stdio.h>
#include <vow.h>
int main(void) { if (pledge("stdio", NULL) < 0) { perror("pledge"); return 1; } puts("ok"); return 0; }
X
name="a program builds against the installed header and library"
if cc -std=c99 -I"$T/dest/usr/include" -static -o "$T/hello" "$T/hello.c" "$T/dest/usr/lib/libvow.a" -pthread >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
name="and runs under pledge (skipped without landlock)"
out=$("$T/hello" 2>&1)
case $out in ok) ok "$name";; *"not implemented"*|*"not supported"*) echo "SKIP  $name";; *) bad "$name ($out)";; esac

# platforms: other architectures are refused, other libc is said to be unsupported
printf '#!/bin/sh\necho aarch64-unknown-linux-musl\n' >"$T/fakecc"; chmod +x "$T/fakecc"
name="the build refuses another architecture"
if (cd "$T/x/vow-$ver" && CC="$T/fakecc" "$T/out/vow/build" "$T/dest2") >"$T/arch.log" 2>&1; then bad "$name"; else
	if grep -q "x86-64 only" "$T/arch.log"; then ok "$name"; else bad "$name (no message)"; fi
fi
printf '#!/bin/sh\necho x86_64-pc-linux-gnu\n' >"$T/fakeglibc"; chmod +x "$T/fakeglibc"
name="the build says that a libc other than musl is unsupported"
(cd "$T/x/vow-$ver" && CC="$T/fakeglibc" "$T/out/vow/build" "$T/dest3") >"$T/libc.log" 2>&1
if grep -q "not musl" "$T/libc.log"; then ok "$name"; else bad "$name (no message)"; fi
exit $fail
