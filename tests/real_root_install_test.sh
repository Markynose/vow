#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# tests of tests/real_root_install.sh against scratch roots (never the real one): the preflight says yes and no for the right
# reasons and changes nothing, the install adds exactly the package, a spoiled install is detected and undone, the rollback
# restores the root entry for entry, the backup is a real backup. needs nerd, git, python3; nothing is escalated: the scratch
# root belongs to the user and KISS_SU is a stub that records any attempt.
set -u
cd "$(dirname "$0")/.." || exit 2
here=$PWD
for c in nerd git python3 tar cc; do command -v $c >/dev/null || { echo "SKIP  needs $c"; exit 0; }; done
fail=0
ok() { echo "pass  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
base=${KI_BASE:-$PWD/build/tmp}
mkdir -p "$base"
T=$(mktemp -d "$base/ri.XXXXXX") || exit 2
trap 'case $T in "$base"/ri.*) rm -rf "$T" ;; esac' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
mkdir -p "$T/su" "$T/home"
printf '#!/bin/sh\necho "escalation attempt: $*" >>%s/su/attempts\nexit 1\n' "$T" >"$T/su/stub"; chmod +x "$T/su/stub"

# a snapshot repository of the working tree, and a second one whose recipe lacks the umask line
sha=$(sh tests/snapshot.sh "$T/repo") || { echo "snapshot failed"; exit 2; }
g() { git -C "$T/repo" -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@"; }
sed -i '/^umask 022$/d' "$T/repo/dist/kiss/vow/build"; g commit -q -am "no umask"; sha_noumask=$(g rev-parse HEAD)
g reset -q --hard "$sha"
printf '\nprintf "x\\n" | install -Dm644 /dev/stdin "$1/etc/wren/vow/intruder"\n' >>"$T/repo/dist/kiss/vow/build"; g commit -q -am "etc"; sha_etc=$(g rev-parse HEAD)
g reset -q --hard "$sha"

# a scratch root that looks like a small live one: a package database with one package, a fake /etc/wren with a service
newroot() { # name
	R=$T/$1; rm -rf "$R"
	mkdir -p "$R/var/db/kiss" "$R/usr/bin" "$R/usr/lib" "$R/usr/include" "$R/usr/share/doc" "$R/usr/share/licenses" "$R/etc/wren/services" "$R/etc/wren/sv/exampled"
	printf '#!/bin/sh\nexec sleep 1\n' >"$R/etc/wren/sv/exampled/run"; chmod 755 "$R/etc/wren/sv/exampled/run"
	ln -s /etc/wren/sv/exampled "$R/etc/wren/services/exampled"
	rm -rf "$T/baserepo"; mkdir -p "$T/baserepo/base"; printf '1.0 1\n' >"$T/baserepo/base/version"
	printf '#!/bin/sh -e\ninstall -Dm644 /dev/null "$1/usr/lib/libother.a"\nprintf "other\\n" | install -Dm644 /dev/stdin "$1/usr/share/doc/other/README"\ninstall -Dm755 /dev/null "$1/usr/bin/other"\ninstall -Dm644 /dev/null "$1/usr/include/other.h"\ninstall -Dm644 /dev/null "$1/usr/share/licenses/other/LICENSE"\n' >"$T/baserepo/base/build"; chmod +x "$T/baserepo/base/build"
	env -i PATH="$PATH" HOME="$T/home" LOGNAME="$(id -un)" USER="$(id -un)" TERM=dumb KISS_ROOT="$R" XDG_CACHE_HOME="$T/basecache" KISS_TMPDIR="$T/tmp" TMPDIR="$T/tmp" KISS_PATH="$T/baserepo" KISS_SU="$T/su/stub" KISS_PROMPT=0 KISS_COLOR=0 NERD_ANIM=0 sh -c 'nerd b base && nerd i base' >/dev/null 2>&1
	mkdir -p "$T/tmp"
}
listing() { python3 "$here/tests/tree_listing.py" "$R"; }
# the script under test
rri() { # args...: runs it against the current scratch root, output in $T/out
	env VOW_ROOT="$R" VOW_STATE="$T/state" VOW_REPO="$T/repo" KISS_PATH="$T/baserepo" KISS_SU="$T/su/stub" HOME="$T/home" sh tests/real_root_install.sh "$@" >"$T/out" 2>&1
}
wantfail() { # name text: exit status not 0 and a FAIL line with text
	if [ $rc != 0 ] && grep -q -- "^FAIL .*$2" "$T/out"; then ok "$1"; else bad "$1 (status $rc)"; grep -E "^FAIL" "$T/out" | head -3 | sed 's/^/    /'; fi
}

newroot r1
[ "$(cd "$R" && ls var/db/kiss/installed)" = base ] && [ -L "$R/etc/wren/services/exampled" ] && ok "the scratch root is set up: one package, a fake /etc/wren with a service" || bad "the scratch root is set up"
listing >"$T/l0"
[ "$(wc -l <"$T/l0")" -ge 10 ] && ok "the listing used for the comparisons is not empty ($(wc -l <"$T/l0") entries): the comparisons below compare something" || bad "the listing used for the comparisons is empty"

# ---- the revision must be exact ----
rri preflight HEAD; rc=$?;                       wantfail "HEAD is refused: it moves" "full commit id or a release tag"
rri preflight main; rc=$?;                       wantfail "a branch name is refused" "full commit id or a release tag"
rri preflight "$(echo $sha | cut -c1-12)"; rc=$?; wantfail "an abbreviated commit id is refused" "full 40 digit"
rri preflight 0000000000000000000000000000000000000000; rc=$?; wantfail "a commit id that does not exist is refused" "no such commit"
rri preflight "$sha_noumask"; rc=$?;             wantfail "a commit whose recipe lacks umask 022 is refused" "does not set umask 022"
rri preflight "$sha_etc"; rc=$?;                 wantfail "a package that would install under /etc or touch wren is refused" "touches etc or wren\|outside /usr\|installs nothing under"
listing >"$T/l1"; cmp -s "$T/l0" "$T/l1" && ok "none of the refused preflights changed the root" || bad "a refused preflight changed the root"

# ---- the good preflight changes nothing ----
rri preflight "$sha"; rc=$?
if [ $rc = 0 ] && grep -q "^PREFLIGHT: SAFE TO INSTALL ($sha" "$T/out"; then ok "the preflight of the exact commit says: safe to install"; else bad "the preflight of the exact commit says: safe to install"; sed 's/^/    /' "$T/out" | grep -E "FAIL|PREFLIGHT" | head -5; fi
for what in "the revision is the exact commit $sha" "the recipe of this commit sets umask 022" "vow is not installed" "the whole package database can be archived" "disk:" "the tarball: only paths under /usr" "the source tarball records the commit $sha" "none of the .* files of the package is in the manifest" "the package installs nothing under /etc and nothing of wren"; do
	grep -q "^pass  .*$what" "$T/out" && ok "  it checked: $what" || bad "  it checked: $what"
done
listing >"$T/l2"; cmp -s "$T/l0" "$T/l2" && ok "the preflight left the root exactly as it was" || bad "the preflight changed the root"
[ -f "$R/usr/bin/vow-run" ] && bad "the preflight installed something" || ok "and installed nothing"
[ ! -e "$T/su/attempts" ] && ok "and asked for no privilege" || bad "the preflight asked for privilege"

# ---- a root where a directory is empty: the rollback could not restore it ----
newroot r1b; rm -f "$R/usr/include/other.h"; (cd "$R" && sed -i '/usr\/include\/other.h$/d' var/db/kiss/installed/base/manifest)
rri preflight "$sha"; rc=$?; wantfail "an empty directory that the package adds to is refused" "/usr/include is empty"

# ---- a root where the target exists ----
newroot r2; printf 'mine\n' >"$R/usr/lib/libvow.a"; listing >"$T/l3"
rri preflight "$sha"; rc=$?; wantfail "a target file that already exists stops the preflight" "/usr/lib/libvow.a already exists"
rri install "$sha"; rc=$?; wantfail "and the install does not go on" "already exists"
listing >"$T/l4"; cmp -s "$T/l3" "$T/l4" && [ ! -d "$T/state/latest" ] && ok "nothing was installed, nothing changed" || bad "the root changed although the preflight said no"
grep -q "BACKUP\|backup of the package database" "$T/out" && bad "a backup was made although the preflight said no" || ok "and no backup was made"

# ---- install, verify, rollback on a clean root ----
newroot r3; listing >"$T/l5"
rri install "$sha"; rc=$?
if [ $rc = 0 ] && grep -q "^VERIFIED" "$T/out"; then ok "install: exit 0 and VERIFIED"; else bad "install: exit 0 and VERIFIED (status $rc)"; grep -E "FAIL|VERIF" "$T/out" | head -5 | sed 's/^/    /'; fi
for what in "backup of the package database" "nerd i vow exited 0" "every entry that existed before is unchanged" "the only new paths are those of the package" "every path of the package is there" "belongs to the owner of the install" "nerd lists vow" "nerd verify vow" "/etc/wren is identical" "the installed vow-run is static" "accepts a good profile" "sandboxes a static program\|no landlock here" "links statically against the installed header"; do
	grep -q "^\(pass\|info\)  .*$what" "$T/out" && ok "  it checked: $what" || bad "  it checked: $what"
done
S=$(cat "$T/state/latest")
[ -f "$S/var-db-kiss.tar" ] && (cd "$S" && sha256sum -c var-db-kiss.tar.sha256 >/dev/null 2>&1) && ok "the backup exists and its checksum matches" || bad "the backup exists and its checksum matches"
tar tf "$S/var-db-kiss.tar" | grep -q '^var/db/kiss/installed/base/manifest$' && ! tar tf "$S/var-db-kiss.tar" | grep -q 'installed/vow' && ok "the backup is of the state before: it has the other package and not vow" || bad "the backup is of the state before"
[ -x "$R/usr/bin/vow-run" ] && [ "$(stat -c %a "$R/usr/bin/vow-run")" = 755 ] && ok "vow-run is installed, mode 755" || bad "vow-run is installed"
rri verify; rc=$?; [ $rc = 0 ] && grep -q "^VERIFIED" "$T/out" && ok "verify on its own repeats the verification and passes" || bad "verify on its own"
rri install "$sha"; rc=$?; wantfail "installing again is refused (vow is installed)" "vow is already installed"
[ "$(cat "$T/state/latest")" = "$S" ] && ok "and the refused attempt did not replace the recorded install" || bad "and the refused attempt did not replace the recorded install"
rri rollback; rc=$?
if [ $rc = 0 ] && grep -q "^ROLLED BACK" "$T/out"; then ok "rollback: ROLLED BACK"; else bad "rollback: ROLLED BACK"; sed 's/^/    /' "$T/out" | tail -8; fi
listing >"$T/l6"; cmp -s "$T/l5" "$T/l6" && ok "after the rollback the root is entry for entry what it was before the install (type, mode, owner, size, path)" || { bad "after the rollback the root is what it was"; diff "$T/l5" "$T/l6" | head -5; }
[ ! -e "$R/usr/bin/vow-run" ] && [ ! -d "$R/usr/share/licenses/vow" ] && ok "no file of vow is left" || bad "a file of vow is left"
rri rollback; rc=$?; [ $rc = 0 ] && grep -q "nothing to remove" "$T/out" && ok "a second rollback is harmless" || bad "a second rollback is harmless"

# ---- an install that is spoiled after the fact must be detected and undone ----
newroot r4; listing >"$T/l7"
export VOW_TEST_AFTER_INSTALL
VOW_TEST_AFTER_INSTALL='echo changed >>"$R/usr/lib/libother.a"'; rri install "$sha"; rc=$?
if [ $rc != 0 ] && grep -q "^VERIFICATION FAILED" "$T/out" && grep -q "removed or changed" "$T/out"; then ok "a pre-existing file that changed is detected"; else bad "a pre-existing file that changed is detected"; fi
grep -q "the install is being undone" "$T/out" && grep -q "^pass  nerd r vow exited 0" "$T/out" && [ ! -e "$R/usr/bin/vow-run" ] && ok "and the install is undone by the script itself (vow is gone)" || bad "and the install is undone by the script itself"
grep -q "^ROLLBACK INCOMPLETE" "$T/out" && grep -q "var-db-kiss.tar" "$T/out" && ok "the rollback says that the root is not what it was (the changed file) and prints the restore command" || bad "the rollback says that the root is not what it was"
newroot r5
VOW_TEST_AFTER_INSTALL='mkdir -p "$R/etc/wren/vow"; echo x >"$R/etc/wren/vow/intruder"'; rri install "$sha"; rc=$?
if [ $rc != 0 ] && grep -q "^FAIL  /etc/wren changed" "$T/out"; then ok "a change under /etc/wren is detected"; else bad "a change under /etc/wren is detected"; fi
newroot r6
VOW_TEST_AFTER_INSTALL='echo x >"$R/usr/lib/stray.a"'; rri install "$sha"; rc=$?
if [ $rc != 0 ] && grep -q "new paths that are not in the package" "$T/out"; then ok "a stray new file is detected"; else bad "a stray new file is detected"; fi
newroot r7; listing >"$T/l8"
VOW_TEST_AFTER_INSTALL='chmod 777 "$R/usr/bin/vow-run"'; rri install "$sha"; rc=$?
if [ $rc != 0 ] && grep -q "owner or mode of a package path is wrong" "$T/out"; then ok "a wrong mode of a package file is detected"; else bad "a wrong mode of a package file is detected"; fi
listing >"$T/l9"; cmp -s "$T/l8" "$T/l9" && ok "and because the spoil was inside the package, the undo restores the root exactly" || bad "the undo restores the root exactly"
grep -q "^THE INSTALL WAS REJECTED" "$T/out" && ok "a rejected install exits non-zero (status $rc) even though the undo itself succeeded" || bad "a rejected install says that it was rejected"
unset VOW_TEST_AFTER_INSTALL
# the owner of the package files is checked against the owner of the install: here a different one is expected, so every file is "wrong"
newroot r8; listing >"$T/l10"
VOW_TEST_EXPECT_OWNER=0:0 rri install "$sha"; rc=$?
if [ $rc != 0 ] && grep -q "owner or mode of a package path is wrong" "$T/out" && grep -q "^THE INSTALL WAS REJECTED" "$T/out"; then ok "a package file with an unexpected owner is detected and the install is rejected"; else bad "a package file with an unexpected owner is detected"; fi
listing >"$T/l11"; cmp -s "$T/l10" "$T/l11" && ok "and undone: the root is as before" || bad "and undone: the root is as before"
# pid 1 must be the same process after the install: here its start time is made to change after the install (a restart of the init)
newroot r10; listing >"$T/l12"
export VOW_TEST_AFTER_INSTALL='VOW_TEST_P1START=999999999'; rri install "$sha"; rc=$?
if [ $rc != 0 ] && grep -q "pid 1 changed" "$T/out" && grep -q "^THE INSTALL WAS REJECTED" "$T/out"; then ok "a pid 1 that restarted during the install is detected and the install is rejected"; else bad "a pid 1 that restarted during the install is detected"; fi
unset VOW_TEST_AFTER_INSTALL VOW_TEST_P1START
newroot r11
rri install "$sha"; rc=$?
[ $rc = 0 ] && grep -q "^pass  pid 1 is still the same process" "$T/out" && ok "and with an unchanged pid 1 the same-run verification reaches its end (this path once died on an unset variable)" || { bad "the same-run verification reaches its end"; tail -5 "$T/out" | sed 's/^/    /'; }
# a lister that finds nothing must stop the preflight: an empty listing compares nothing, and compared nothing passes everything
newroot r9
VOW_TEST_LISTER=/bin/true rri preflight "$sha"; rc=$?; wantfail "an empty listing of the root stops the preflight" "empty or lacks the package database"
VOW_TEST_LISTER=/bin/true rri install "$sha"; rc=$?; wantfail "and the install" "empty or lacks the package database"
[ ! -x "$R/usr/bin/vow-run" ] && ok "and nothing was installed" || bad "and nothing was installed"
[ ! -e "$T/su/attempts" ] && ok "no privilege was asked for in any scratch run" || bad "privilege was asked for"
[ "$(id -u)" != 0 ] && ok "(this test runs as the ordinary user)"
# it refuses to run as root
exit $fail
