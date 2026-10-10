#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# checks that a commit can be released: the version is the same everywhere, the tag (if there is one) names this
# commit, the source archive is exactly the commit, and the binaries built from the archive are static.
#
# usage: sh tests/release_check.sh [--release] [--fast] [revision | WORKTREE]      (default: HEAD)
#
# --release makes the facts a release needs into failures: a development version, a dirty tree, a revision that is not
# HEAD, a missing or wrong signature of an existing tag, stale development strings in the documents. without it the same
# things are reported as information, so that the checks can run on the way to a release. WORKTREE takes a throwaway
# commit of the working tree (for a tree that is not committed; not allowed with --release). --fast stops after the
# version and tag checks: it does not make or build the archive.
#
# the procedure behind it (RELEASE.md): the release commit R holds the final version and nothing derived from itself, no
# hash, no tag name, no checksum of a tarball. all checks run on R. the signed tag vX.Y.Z is made afterwards and names R.
# the source archive is `git archive` of that commit, so it is a function of the tree of R, and it records the id of R.
# its checksum is made from the tarball and published with the release, outside git. nothing feeds back into R.
set -u
cd "$(dirname "$0")/.." || exit 2
here=$PWD
mode=check; rev=HEAD; fast=
for a in "$@"; do
	case $a in --release) mode=release ;; --fast) fast=1 ;; *) rev=$a ;; esac
done
fail=0
ok() { echo "pass  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
info() { echo "info  $1"; }
base=${KI_BASE:-$PWD/build/tmp}
mkdir -p "$base"
T=$(mktemp -d "$base/rc.XXXXXX") || exit 2
trap 'case $T in "$base"/rc.*) rm -rf "$T" ;; esac' EXIT

# ---- the commit ----
if [ "$rev" = WORKTREE ]; then
	[ $mode = release ] && { bad "a release is made from a commit, not from WORKTREE"; exit 1; }
	gd=$T/snap
	sha=$(sh "$here/tests/snapshot.sh" "$gd") || { echo "snapshot failed"; exit 2; }
	info "checking a throwaway commit of the working tree"
else
	gd=$here
	sha=$(git rev-parse --verify "$rev^{commit}") || { echo "no such revision: $rev"; exit 2; }
	info "checking $sha"
	dirty=$(git status --porcelain | wc -l)
	if [ "$dirty" != 0 ]; then
		if [ $mode = release ]; then bad "the working tree is not clean ($dirty changes): the tests would have run on something that is not the commit"; else info "the working tree has $dirty uncommitted changes (a release needs none)"; fi
	elif [ $mode = release ]; then ok "the working tree is clean"; fi
	if [ "$sha" != "$(git rev-parse HEAD)" ]; then
		if [ $mode = release ]; then bad "the revision is not HEAD"; else info "the revision is not HEAD"; fi
	fi
fi
show() { git -C "$gd" show "$sha:$1" 2>/dev/null; }

# ---- the version, everywhere ----
hdr=$(show include/vow.h | sed -n 's/^#define VOW_VERSION[[:space:]]*"\(.*\)"/\1/p')
maj=$(show include/vow.h | sed -n 's/^#define VOW_VERSION_MAJOR[[:space:]]*\([0-9]*\).*/\1/p')
min=$(show include/vow.h | sed -n 's/^#define VOW_VERSION_MINOR[[:space:]]*\([0-9]*\).*/\1/p')
ver=$(show dist/kiss/vow/version | cut -d' ' -f1)
rel=$(show dist/kiss/vow/version | cut -d' ' -f2)
srcn=$(show dist/kiss/vow/sources)
name="the version is the same in include/vow.h, in the recipe and in the sources file ($hdr / $ver / $srcn)"
[ -n "$ver" ] && [ "$hdr" = "$ver" ] && [ "$srcn" = "vow-$ver.tar.gz" ] && ok "$name" || bad "$name"
name="the major and minor macros agree with the version (${maj:-?}.${min:-?} in $ver)"
case $ver in "$maj.$min."*) ok "$name" ;; *) bad "$name" ;; esac
name="the release number of the package is a positive integer ($rel)"
case $rel in ''|*[!0-9]*|0) bad "$name" ;; *) ok "$name" ;; esac
case $ver in
*-dev*)
	if [ $mode = release ]; then bad "$ver is a development version: a release has none"; else info "$ver is a development version: not releasable"; fi ;;
*)
	ok "$ver is a release version"
	stale=$(git -C "$gd" grep -nE '[0-9]+\.[0-9]+\.[0-9]+-dev' "$sha" -- . ':!tests/release_check.sh' ':!tests/release_check_test.sh' 2>/dev/null | head -3)
	name="no document or file still names a development version"
	if [ -z "$stale" ]; then ok "$name"; else
		if [ $mode = release ]; then bad "$name"; else info "$name: $(echo "$stale" | head -1 | cut -c1-110)"; fi
	fi ;;
esac
name="README.md, ROADMAP.md and RELEASE.md name the version $ver"
miss=""
for f in README.md ROADMAP.md RELEASE.md; do show $f | grep -qF -- "$ver" || miss="$miss $f"; done
[ -z "$miss" ] && ok "$name" || { if [ $mode = release ]; then bad "$name (not in:$miss)"; else info "$name (not in:$miss)"; fi; }

# ---- the tag ----
tag=v$ver
if git -C "$gd" rev-parse -q --verify "refs/tags/$tag" >/dev/null 2>&1; then
	tsha=$(git -C "$gd" rev-parse "refs/tags/$tag^{commit}")
	name="the tag $tag names this commit"
	[ "$tsha" = "$sha" ] && ok "$name" || bad "$name (it names $tsha)"
	if command -v gpg >/dev/null; then
		name="the tag $tag has a good signature"
		git -C "$gd" tag -v "$tag" >/dev/null 2>&1 && ok "$name" || { if [ $mode = release ]; then bad "$name"; else info "the tag $tag has no good signature"; fi; }
	fi
else
	info "the tag $tag does not exist yet: it is made after this check passes, and names this commit"
fi

[ -n "$fast" ] && { info "the archive and the binaries are not checked (--fast)"; exit $fail; }

# ---- the source archive is the commit ----
mk=$gd/dist/kiss/mkpkg.sh
name="mkpkg builds the package directory from $sha"
if (cd / && sh "$mk" "$T/pkg" "$sha") >"$T/mk.log" 2>&1; then ok "$name"; else bad "$name"; sed 's/^/    /' "$T/mk.log"; exit 1; fi
tb=$T/pkg/vow/vow-$ver.tar.gz
name="the archive records the id of the commit"
[ "$(gzip -dc "$tb" | git get-tar-commit-id)" = "$sha" ] && ok "$name" || bad "$name"
paths="Makefile LICENSE LICENSES LICENSING.md README.md DESIGN.md ROADMAP.md include src tools examples third-party"
git -C "$gd" ls-tree -r "$sha" -- $paths >"$T/tree.txt"
awk '{ $1 = $2 = $3 = ""; sub(/^ +/, ""); print }' "$T/tree.txt" | sort >"$T/want.txt"
gzip -dc "$tb" | tar t | sed "s|^vow-$ver/||" | grep -v '/$' | grep -v '^$' | sort >"$T/got.txt"
name="the archive holds exactly the files of the commit that the package lists ($(wc -l <"$T/want.txt") files)"
if cmp -s "$T/want.txt" "$T/got.txt"; then ok "$name"; else bad "$name"; diff "$T/want.txt" "$T/got.txt" | head -6 | sed 's/^/    /'; fi
mkdir "$T/x" && gzip -dc "$tb" | tar x -C "$T/x"
badc=0
while read -r m t h f; do
	git -C "$gd" cat-file blob "$h" | cmp -s - "$T/x/vow-$ver/$f" || { badc=1; echo "    differs: $f"; }
	if [ "$m" = 100755 ]; then [ -x "$T/x/vow-$ver/$f" ] || { badc=1; echo "    not executable: $f"; }; fi
done <"$T/tree.txt"
name="every file in the archive is byte for byte the file of the commit, with its executable bit"
[ $badc = 0 ] && ok "$name" || bad "$name"
name="the archive holds no binary file"
nbin=0; for f in $(cd "$T/x/vow-$ver" && find . -type f); do [ "$(head -c 4 "$T/x/vow-$ver/$f")" = "$(printf '\177ELF')" ] && nbin=$((nbin+1)); done
[ $nbin = 0 ] && ok "$name" || bad "$name ($nbin)"
(cd / && sh "$mk" "$T/pkg2" "$sha") >/dev/null 2>&1
name="making the archive again gives the same bytes (it is a function of the commit)"
cmp -s "$tb" "$T/pkg2/vow/vow-$ver.tar.gz" && ok "$name" || bad "$name"
info "source tarball vow-$ver.tar.gz: sha256 $(sha256sum "$tb" | cut -d' ' -f1)"
info "its tar, uncompressed (does not depend on the gzip program): sha256 $(gzip -dc "$tb" | sha256sum | cut -d' ' -f1)"

# ---- the binaries built from the archive, under a strict umask ----
mkdir "$T/dest"
name="the recipe builds from the archive (under an inherited umask 077)"
if (umask 077; cd "$T/x/vow-$ver" && "$T/pkg/vow/build" "$T/dest") >"$T/build.log" 2>&1; then ok "$name"; else bad "$name"; sed 's/^/    /' "$T/build.log" | tail -4; exit 1; fi
V=$T/dest/usr/bin/vow-run
name="vow-run is a fully static x86-64 executable: no interpreter, no shared library, no dynamic section"
if readelf -h "$V" 2>/dev/null | grep -q 'Machine:.*X86-64' && ! readelf -lW "$V" 2>/dev/null | grep -q INTERP && ! readelf -d "$V" 2>/dev/null | grep -q NEEDED; then ok "$name"; else bad "$name"; fi
name="libvow.a holds the library objects and nothing of the launcher"
if ar t "$T/dest/usr/lib/libvow.a" | sort | tr '\n' ' ' | grep -q 'filter.o fork.o pledge.o scope.o unveil.o' && ! ar t "$T/dest/usr/lib/libvow.a" | grep -q 'profile\|vow-run'; then ok "$name"; else bad "$name"; fi
cm=$(${CC:-cc} -dumpmachine)
name="the compiler targets musl ($cm)"
case $cm in x86_64-*musl*) ok "$name" ;; *) if [ $mode = release ]; then bad "$name"; else info "$name: it does not"; fi ;; esac
name="the installed files carry the intended modes (755 for the binary and the directories, 644 for the rest)"
badm=$(cd "$T/dest" && find . | while read -r f; do
	m=$(stat -c %a "$f"); if [ "$f" = ./usr/bin/vow-run ] || [ -d "$f" ]; then w=755; else w=644; fi
	[ "$m" = "$w" ] || echo "$f is $m, wanted $w"; done)
[ -z "$badm" ] && ok "$name" || { bad "$name"; echo "$badm" | head -3 | sed 's/^/    /'; }
exit $fail
