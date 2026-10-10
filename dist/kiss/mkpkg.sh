#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
set -e
# make a kiss package directory for vow from one commit of this repository.
#
# usage: mkpkg.sh outdir revision      (from any directory)
#
# outdir/vow gets the recipe and a source tarball, both taken from the commit named by revision. uncommitted
# changes are not packaged, on purpose, and the commit is the one on the label: the tarball is made by
# git archive, which records the commit id in it (git get-tar-commit-id shows it). add outdir to KISS_PATH, run
# 'kiss c vow' (or 'nerd c vow') once to write the checksums, then 'kiss b vow' and 'kiss i vow'.
# no gnu tar: git archive writes the tar, gzip packs it, the checkout is never touched.
# a revision that is a release tag (v0.2.0) must match the version of the recipe in it, see RELEASE.md.

die() { echo "mkpkg: $*" >&2; exit 1; }

[ $# -eq 2 ] || die "usage: mkpkg.sh outdir revision   (for example: mkpkg.sh /tmp/repo HEAD)"
out=$1
rev=$2
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null) || die "not inside a git checkout of vow"
sha=$(git -C "$root" rev-parse --verify --quiet "$rev^{commit}") || die "no such revision: $rev"

# everything below is read from that commit, never from the working tree
show() { git -C "$root" show "$sha:$1" 2>/dev/null || die "$1 does not exist in $sha"; }
ver=$(show dist/kiss/vow/version | cut -d' ' -f1)
src=$(show dist/kiss/vow/sources)
hdr=$(show include/vow.h | sed -n 's/^#define VOW_VERSION[[:space:]]*"\(.*\)"/\1/p')

[ -n "$ver" ] || die "dist/kiss/vow/version of $sha is empty"

# a release tag is a statement about the version: v0.2.0 must hold a recipe for 0.2.0, and a development version
# is never a release. nothing in the commit names its own hash, the tag or the checksum of the tarball, so
# tagging after the commit and packaging from the tag cannot disagree with the commit
case $rev in
v[0-9]*)
    [ "$rev" = "v$ver" ] || die "the tag $rev does not match the version $ver of the recipe in it"
    case $ver in *-dev*) die "the tag $rev holds a development version ($ver), not a release" ;; esac ;;
esac
[ "$hdr" = "$ver" ] || die "include/vow.h says $hdr but dist/kiss/vow/version says $ver (in $sha)"
[ "$src" = "vow-$ver.tar.gz" ] || die "dist/kiss/vow/sources of $sha does not name vow-$ver.tar.gz"

if [ -n "$(git -C "$root" status --porcelain 2>/dev/null)" ]; then
    echo "mkpkg: note: the working tree has uncommitted changes; they are not in the package" >&2
fi

mkdir -p "$out/vow"
for f in build version sources; do
    show "dist/kiss/vow/$f" >"$out/vow/$f"
done
chmod 755 "$out/vow/build"
git -C "$root" archive --format=tar --prefix="vow-$ver/" "$sha" -- \
    Makefile LICENSE LICENSES LICENSING.md README.md DESIGN.md ROADMAP.md include src tools examples third-party |
    gzip -n >"$out/vow/vow-$ver.tar.gz"

printf 'packaged commit %s as vow %s into %s/vow, next: kiss c vow\n' "$sha" "$ver" "$out"
