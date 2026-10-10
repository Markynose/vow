#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# tests of tests/release_check.sh: it passes on a consistent release and fails, with a message, on each way a release can be
# wrong. the cases are throwaway git repositories made from the working tree (tests/snapshot.sh) and then spoiled.
set -u
cd "$(dirname "$0")/.." || exit 2
here=$PWD
fail=0
ok() { echo "pass  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
base=${KI_BASE:-$PWD/build/tmp}
mkdir -p "$base"
T=$(mktemp -d "$base/rt.XXXXXX") || exit 2
trap 'case $T in "$base"/rt.*) rm -rf "$T" ;; esac' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
n=0
newrepo() { n=$((n+1)); R=$T/r$n; sh "$here/tests/snapshot.sh" "$R" >/dev/null; }
g() { git -C "$R" -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@"; }
rc() { (cd "$R" && sh tests/release_check.sh "$@") >"$T/out" 2>&1; }
# want STATUS TEXT NAME: the last run exited with STATUS (0 or not 0) and printed TEXT
want() {
	st=$?; code=$1; text=$2; name=$3
}
expect_fail() { # name, text: the run failed and a FAIL line says text (a pass line with the same words does not count)
	if [ $rcode != 0 ] && grep -q -- "^FAIL  .*$2" "$T/out"; then ok "$1"; else bad "$1 (status $rcode)"; sed 's/^/    /' "$T/out" | grep -E "FAIL|info" | head -4; fi
}
expect_only() { # name, text: the run failed, with exactly one FAIL line, and it says text
	if [ $rcode != 0 ] && [ "$(grep -c '^FAIL' "$T/out")" = 1 ] && grep -q -- "^FAIL  .*$2" "$T/out"; then ok "$1"; else bad "$1 (status $rcode)"; grep -E "^FAIL" "$T/out" | head -4 | sed 's/^/    /'; fi
}
expect_pass() { # name
	if [ $rcode = 0 ] && ! grep -q '^FAIL' "$T/out"; then ok "$1"; else bad "$1 (status $rcode)"; grep '^FAIL' "$T/out" | head -4 | sed 's/^/    /'; fi
}
# set the version of a repository to V everywhere it is named: the header and its two macros, the recipe, the sources file and
# the documents (whatever the version of the tree was), and commit
set_version() {
	v=$1
	old=$(cut -d' ' -f1 "$R/dist/kiss/vow/version"); oldre=$(printf '%s' "$old" | sed 's/\./\\./g')
	maj=${v%%.*}; rest=${v#*.}; min=${rest%%.*}
	(cd "$R" && git ls-files | while read -r f; do [ -f "$f" ] && sed -i "s/$oldre/$v/g" "$f"; done
	 sed -i "s/^#define VOW_VERSION_MAJOR .*/#define VOW_VERSION_MAJOR $maj/; s/^#define VOW_VERSION_MINOR .*/#define VOW_VERSION_MINOR $min/" include/vow.h
	 printf '%s 1\n' "$v" >dist/kiss/vow/version; printf 'vow-%s.tar.gz\n' "$v" >dist/kiss/vow/sources)
	g add -A; g commit -q -m "version $v"
}
release_version() { set_version 9.9.9; }
dev_version() { set_version 9.9.9-dev; }

# ---- a development version: fine as a check, not as a release ----
newrepo; dev_version
rc --fast; rcode=$?
expect_pass "a development version passes a plain check"
rc --release --fast; rcode=$?
expect_fail "a development version fails --release" "development version"
rc --release --fast WORKTREE; rcode=$?
expect_fail "--release refuses the working tree (a release is a commit)" "not from WORKTREE"

# ---- a consistent release ----
newrepo; release_version
rc --release --fast; rcode=$?
expect_pass "a consistent clean release version passes --release"
grep -q "tag v9.9.9 does not exist yet" "$T/out" && ok "and says that the tag is made afterwards" || bad "and says that the tag is made afterwards"

# the version spoiled in one place at a time
for spoil in header recipe sources minor; do
	newrepo; release_version
	case $spoil in
	header) sed -i 's/^#define VOW_VERSION .*/#define VOW_VERSION "9.9.8"/' "$R/include/vow.h" ;;
	recipe) printf '9.9.8 1\n' >"$R/dist/kiss/vow/version" ;;
	sources) printf 'vow-9.9.8.tar.gz\n' >"$R/dist/kiss/vow/sources" ;;
	minor) sed -i 's/^#define VOW_VERSION_MINOR .*/#define VOW_VERSION_MINOR 8/' "$R/include/vow.h" ;;
	esac
	g commit -q -am spoil
	rc --release --fast; rcode=$?
	case $spoil in minor) text="the major and minor macros" ;; *) text="the version is the same" ;; esac
	expect_fail "the version differs in the $spoil" "$text"
done
newrepo; release_version
printf 'a document that still says 1.2.3-dev\n' >>"$R/README.md"; g commit -q -am stale
rc --release --fast; rcode=$?
expect_fail "a release with a development version string left in a file fails" "no document or file still names a development version"
rc --fast; rcode=$?
[ $rcode = 0 ] && ok "and the same is only information in a plain check" || bad "and the same is only information in a plain check"

# ---- the state of the repository ----
newrepo; release_version
echo change >>"$R/README.md"
rc --release --fast; rcode=$?
expect_fail "a dirty tree fails --release" "working tree is not clean"
rc --fast; rcode=$?; [ $rcode = 0 ] && ok "and is information in a plain check" || bad "and is information in a plain check"
g checkout -q -- README.md
echo "a later commit" >>"$R/DESIGN.md"; g commit -q -am later
rc --release --fast HEAD~1; rcode=$?
expect_only "a revision that is not HEAD fails --release, and nothing else is wrong with it" "the revision is not HEAD"

# ---- the tag ----
newrepo; release_version
g tag v9.9.9 HEAD~1
rc --release --fast; rcode=$?
expect_fail "a tag on another commit fails" "names this commit"
g tag -d v9.9.9 >/dev/null; g tag v9.9.9
rc --release --fast; rcode=$?
if command -v gpg >/dev/null; then expect_fail "an unsigned tag fails --release" "good signature"; else echo "SKIP  no gpg for the signature of the tag"; fi

# ---- the archive and the binaries (the slow part) ----
newrepo; release_version
rc --release; rcode=$?
expect_pass "the full check passes on a consistent release: archive, byte comparison, static binary"
for want in "records the id of the commit" "exactly the files" "byte for byte" "again gives the same bytes" "fully static x86-64" "carry the intended modes"; do
	grep -q "^pass  .*$want" "$T/out" && ok "  it checked: $want" || bad "  it checked: $want"
done
grep -q "^info  source tarball vow-9.9.9.tar.gz: sha256 [0-9a-f]\{64\}" "$T/out" && ok "  and printed the checksums of the tarball for the release notes" || bad "  and printed the checksums of the tarball"
newrepo
sed -i 's/examples third-party |/examples third-party tests |/' "$R/dist/kiss/mkpkg.sh"; g commit -q -am extra
rc; rcode=$?
expect_fail "an archive that holds files the package does not list fails" "exactly the files"
newrepo
printf 'README.md export-subst\n' >"$R/.gitattributes"; printf 'built from commit $Format:%%H$\n' >>"$R/README.md"; g add -A; g commit -q -m selfref
rc; rcode=$?
expect_fail "a file that would embed the id of its own commit (export-subst) is not the file of the commit" "byte for byte"
newrepo
sed -i 's/-Itools\/vow-run -static/-Itools\/vow-run/' "$R/Makefile"; g commit -q -am dynamic
rc; rcode=$?
expect_fail "a vow-run that is not static fails the build from the archive" "the recipe builds"

# ---- the documents against the tree (tests/docs_check.sh) ----
newrepo
(cd "$R" && sh tests/docs_check.sh) >"$T/out" 2>&1; rcode=$?
[ $rcode = 0 ] && ok "the documents of the tree name only things that exist" || { bad "the documents of the tree name only things that exist"; cat "$T/out" | sed 's/^/    /'; }
printf 'run `make nonesuch-target` first\n' >>"$R/README.md"; g commit -q -am badtarget
(cd "$R" && sh tests/docs_check.sh) >"$T/out" 2>&1; rcode=$?
[ $rcode != 0 ] && grep -q "no such make target" "$T/out" && ok "a make target that does not exist is found" || bad "a make target that does not exist is found"
g reset -q --hard HEAD~1
printf 'see `tests/nonesuch.sh`\n' >>"$R/README.md"; g commit -q -am badpath
(cd "$R" && sh tests/docs_check.sh) >"$T/out" 2>&1; rcode=$?
[ $rcode != 0 ] && grep -q "tests/nonesuch.sh.*no such file" "$T/out" && ok "a path that does not exist is found" || bad "a path that does not exist is found"
exit $fail
