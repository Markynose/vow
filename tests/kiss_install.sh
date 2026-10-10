#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# install, reinstall, upgrade, conflict and removal of the kiss package of vow with nerd, in an isolated root.
#
# usage: sh tests/kiss_install.sh [revision]      (default HEAD; the package is built from that commit)
#
# nothing here touches the real system. the root is a directory under build/tmp (KISS_ROOT), owned by the
# user, so nerd never needs a privilege tool; KISS_SU is a stub that records an attempt and fails. nerd runs
# in a clean environment (no KISS_PATH or KISS_ROOT of the real system), with its cache and temp directories
# in the same scratch directory. every nerd call runs under strace, and at the end every call that could
# write is checked against the scratch directory; the package database of the real system, and the
# checkout, are compared before and after. needs nerd, git and python3; strace is used when present.
# KEEP=1 keeps the scratch directory (the path is printed) for looking at it; delete it yourself.
# KI_BASE sets where the scratch directory is made (default build/tmp). KI_CACHE points nerd at a cache that
# already holds the built packages, so that they are not built again: the privileged test builds them as an
# ordinary user first, which is how the archives come to record the builder uid, and installs them as root.
#
# run as an ordinary user this is the unprivileged test. run as root of a disposable user and mount
# namespace (tests/kiss_install_ns.sh does that, with the real system mounted read-only) it is the privileged
# one: nerd then runs as uid 0, the root directory is owned by root, and the extra checks for ownership, the
# chown family of calls, the umask and the hook of a package are made.
set -u
cd "$(dirname "$0")/.." || exit 2
here=$PWD
rev=${1:-HEAD}
for c in nerd git python3; do
	command -v $c >/dev/null || { echo "SKIP  needs $c"; exit 0; }
done
fail=0
ok() { echo "pass  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
base=${KI_BASE:-$PWD/build/tmp}
mkdir -p "$base"
T=$(mktemp -d "$base/ki.XXXXXX") || exit 2
PRIV=0; [ "$(id -u)" = 0 ] && PRIV=1
ME=$(id -u):$(id -g)
[ -n "${KEEP:-}" ] || trap 'rm -rf "$T"' EXIT
root=$T/root; repo=$T/repo
cachedir=${KI_CACHE:-$T/cache}
[ -n "${KEEP:-}" ] && echo "info  kept $T"
mkdir -p "$root/var/db/kiss" "$cachedir" "$T/tmp" "$T/su" "$T/strace" "$T/home" "$repo"

# ---- the isolation ----
cat >"$T/su/stub" <<X
#!/bin/sh
echo "escalation attempt: \$*" >>"$T/su/attempts"
exit 1
X
chmod +x "$T/su/stub"
KP=$repo
n=0
k() { TOOL=nerd runtool "$@"; }
# with a given cache the packages are already built (by an ordinary user): install them as they are, do not build
build() { if [ -n "${KI_CACHE:-}" ]; then return 0; fi; k b "$@"; }
kk() { TOOL=kiss runtool "$@"; }
runtool() {
	n=$((n+1))
	if command -v strace >/dev/null; then
		strace -f -y -qq -e trace=openat,open,creat,unlink,unlinkat,rename,renameat,renameat2,mkdir,mkdirat,rmdir,symlink,symlinkat,link,linkat,chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown,truncate,ftruncate,utimensat,mknod,mknodat,chdir,fchdir,chroot,clone,clone3,fork,vfork \
		    -o "$(mktemp "$T/strace/$TOOL-XXXXXX")" env -i PATH="$PATH" HOME="$T/home" LOGNAME="$(id -un)" USER="$(id -un)" TERM=dumb TMPDIR="$T/tmp" \
		    KISS_ROOT="$root" XDG_CACHE_HOME="$cachedir" KISS_TMPDIR="$T/tmp" KISS_PATH="$KP" KISS_SU="$T/su/stub" \
		    KISS_PROMPT=0 KISS_COLOR=0 NERD_ANIM=0 "$TOOL" "$@"
	else
		env -i PATH="$PATH" HOME="$T/home" LOGNAME="$(id -un)" USER="$(id -un)" TERM=dumb TMPDIR="$T/tmp" KISS_ROOT="$root" \
		    XDG_CACHE_HOME="$cachedir" KISS_TMPDIR="$T/tmp" KISS_PATH="$KP" KISS_SU="$T/su/stub" KISS_PROMPT=0 \
		    KISS_COLOR=0 NERD_ANIM=0 "$TOOL" "$@"
	fi
}
real_fp() { find /var/db/kiss -type f 2>/dev/null | sort | xargs sha256sum 2>/dev/null | sha256sum | cut -d' ' -f1; }
FP0=$(real_fp)
export GIT_OPTIONAL_LOCKS=0
GIT0=$(git status --porcelain | sha256sum | cut -d' ' -f1)
[ $PRIV = 1 ] && echo "info  privileged mode: uid 0 in a disposable namespace (uid map: $(tr -s ' ' </proc/self/uid_map | tr '\n' ';'))"

# a snapshot of every file that the vow package does not own: path, mode, content
snap() {
	vow=$T/vowfiles; : >"$vow"
	[ -f "$root/var/db/kiss/installed/vow/manifest" ] && sed 's/\/$//' "$root/var/db/kiss/installed/vow/manifest" >"$vow"
	(cd "$root" && find . -type f | sed 's|^\./|/|' | sort | awk 'FILENAME==ARGV[1]{skip[$0]=1;next} !($0 in skip)' "$vow" - |
	    grep -v '^/var/db/kiss/installed/vow/' | grep -v '^/var/db/kiss/choices/' |
	    while read -r f; do printf '%s %s %s\n' "$f" "$(stat -c %a "$root$f")" "$(sha256sum "$root$f" | cut -d' ' -f1)"; done)
}
dirs() { (cd "$root" && find . -type d | sort); }
expect_files() {
	cat <<X
/usr/bin/vow-run
/usr/include/vow.h
/usr/lib/libvow.a
/usr/share/doc/vow/DESIGN.md
/usr/share/doc/vow/LICENSING.md
/usr/share/doc/vow/README.md
/usr/share/doc/vow/ROADMAP.md
/usr/share/doc/vow/examples/cli.c
/usr/share/doc/vow/examples/fileproc.c
/usr/share/doc/vow/examples/netclient.c
/usr/share/doc/vow/examples/progressive.c
/usr/share/doc/vow/vow-run-wren.md
/usr/share/doc/vow/vow-run.md
/usr/share/licenses/vow/0BSD.txt
/usr/share/licenses/vow/GPL-3.0-only.txt
/usr/share/licenses/vow/LGPL-3.0-only.txt
/usr/share/licenses/vow/LICENSE
/usr/share/licenses/vow/musl-COPYRIGHT
X
}
vowfiles_now() { (cd "$root" && find usr -type f 2>/dev/null | sed 's|^|/|' | sort | grep -E '^/usr/(bin/vow-run|include/vow.h|lib/libvow.a|share/doc/vow/|share/licenses/vow/)' | grep -v '/USER-NOTE$'); }

# ---- packages: vow from the commit, an unrelated one, a clashing one ----
sha=$(git rev-parse --verify "$rev^{commit}") || { echo "no such revision $rev"; exit 2; }
(cd / && sh "$here/dist/kiss/mkpkg.sh" "$repo" "$sha") >/dev/null 2>&1 || { bad "mkpkg from $sha"; exit 1; }
k c vow >/dev/null 2>&1
mkdir "$repo/base" "$repo/vowclash" "$repo/hookpkg"
printf '1.0 1\n' >"$repo/base/version"
cat >"$repo/base/build" <<'X'
#!/bin/sh -e
install -Dm644 /dev/null "$1/usr/lib/libother.a"
install -Dm644 /dev/null "$1/usr/include/other.h"
printf 'other doc\n' | install -Dm644 /dev/stdin "$1/usr/share/doc/other/README"
printf 'setting=1\n' | install -Dm644 /dev/stdin "$1/etc/other.conf"
X
printf '1.0 1\n' >"$repo/vowclash/version"
cat >"$repo/vowclash/build" <<'X'
#!/bin/sh -e
printf '/* not the header of vow */\n' | install -Dm644 /dev/stdin "$1/usr/include/vow.h"
printf 'clash doc\n' | install -Dm644 /dev/stdin "$1/usr/share/doc/vow/CLASH"
X
printf '1.0 1\n' >"$repo/hookpkg/version"
cat >"$repo/hookpkg/build" <<'X'
#!/bin/sh -e
printf 'hook package\n' | install -Dm644 /dev/stdin "$1/usr/share/doc/hookpkg/README"
X
cat >"$repo/hookpkg/post-install" <<'X'
#!/bin/sh
{ echo "uid=$(id -u)"; echo "cwd=$(pwd)"; } > /hook-ran
X
chmod +x "$repo/base/build" "$repo/vowclash/build" "$repo/hookpkg/build" "$repo/hookpkg/post-install"
if [ $PRIV = 1 ]; then
	mkdir -p "$root/bin" && cp /bin/busybox "$root/bin/busybox"
	for a in sh id pwd echo; do ln -s busybox "$root/bin/$a"; done
fi

name="the isolated root is used, not the real one"
build base >/dev/null 2>&1 && k i base >"$T/o" 2>&1
if [ "$(k l base 2>/dev/null)" = "base 1.0-1" ] && [ ! -e "$T/su/attempts" ]; then ok "$name"; else bad "$name"; fi
# an unowned file inside the directory that vow will use, and one next to the library
mkdir -p "$root/usr/share/doc/vow" "$root/usr/lib"
printf 'my own note\n' >"$root/usr/share/doc/vow/USER-NOTE"
printf 'not from a package\n' >"$root/usr/lib/unowned.a"
snap >"$T/snap0"; dirs >"$T/dirs0"
name="the baseline snapshot of the other files is not empty"
[ "$(wc -l <"$T/snap0")" -ge 5 ] && ok "$name" || bad "$name ($(wc -l <"$T/snap0") lines)"

# who owns what: every path of the package must belong to the user that ran nerd (root in the privileged mode),
# never to the builder uid that the archive records
owners_ok() {
	bad=0
	sed 's|/$||' "$root/var/db/kiss/installed/vow/manifest" | while read -r f; do
		o=$(stat -c %u:%g "$root$f"); [ "$o" = "$ME" ] || echo "    $f is $o, wanted $ME"
	done >"$T/owners.txt"
	[ -s "$T/owners.txt" ] && { cat "$T/owners.txt"; bad=1; }
	return $bad
}

# ---- install ----
name="vow builds and installs from the commit"
if build vow >"$T/o" 2>&1 && k i vow >>"$T/o" 2>&1 && [ "$(k l vow 2>/dev/null)" = "vow 0.2.0-dev-1" ]; then ok "$name"; else bad "$name"; tail -5 "$T/o"; fi
name="exactly the packaged files are installed"
if [ "$(vowfiles_now)" = "$(expect_files)" ]; then ok "$name"; else bad "$name"; expect_files >"$T/e1"; vowfiles_now >"$T/e2"; diff "$T/e1" "$T/e2" | head -8; fi
name="modes: the binary is 755, everything else 644, directories 755"
badm=0
for f in $(expect_files); do
	m=$(stat -c %a "$root$f"); want=644; [ "$f" = /usr/bin/vow-run ] && want=755
	[ "$m" = "$want" ] || { badm=1; echo "    $f is $m, wanted $want"; }
done
for d in usr/bin usr/include usr/lib usr/share/doc/vow usr/share/doc/vow/examples usr/share/licenses/vow; do
	[ "$(stat -c %a "$root/$d")" = 755 ] || { badm=1; echo "    /$d is $(stat -c %a "$root/$d"), wanted 755"; }
done
[ $badm = 0 ] && ok "$name" || bad "$name"
db=$root/var/db/kiss/installed/vow
name="every installed path and database file is owned by $ME (the user that ran nerd), not by the builder uid of the archive"
owners_ok && ok "$name" || bad "$name"
arch=$cachedir/kiss/bin/vow@0.2.0-dev-1.tar.gz
aown=$(python3 -c '
import sys, tarfile
t = tarfile.open(sys.argv[1])
print(" ".join(sorted(set("%d:%d" % (m.uid, m.gid) for m in t.getmembers()))))' "$arch" 2>/dev/null)
echo "info  the archive records the owner(s): $aown; the installed files belong to $ME"
if [ $PRIV = 1 ]; then
	name="the archive records a builder owner other than root ($aown) and the files installed as root belong to $ME all the same"
	if [ -n "$aown" ] && [ "$aown" != "0:0" ] && [ "$aown" != "$ME" ]; then
		if owners_ok; then ok "$name"; else bad "$name"; fi
	else echo "SKIP  $name (the archive was built as $aown: build it as an ordinary user first, see tests/kiss_install_ns.sh)"; fi
fi
name="the package database entry is complete"
if [ -f "$db/version" ] && [ "$(cat "$db/version")" = "0.2.0-dev 1" ] && [ -x "$db/build" ] && [ -s "$db/manifest" ] &&
    [ -s "$db/sources" ] && [ -s "$db/checksums" ] && [ -s "$db/vow-0.2.0-dev.tar.gz" ]; then ok "$name"; else bad "$name"; ls "$db"; fi
name="the manifest names exactly the packaged files, its own database files and its directories"
grep -v '/$' "$db/manifest" | grep -v '^/var/db/kiss/installed/vow/' | sort >"$T/man_files"
grep '^/var/db/kiss/installed/vow/' "$db/manifest" | grep -v '/$' | sort >"$T/man_db"
expect_files | sort >"$T/man_want"
printf '%s\n' /var/db/kiss/installed/vow/build /var/db/kiss/installed/vow/checksums /var/db/kiss/installed/vow/manifest \
    /var/db/kiss/installed/vow/sources /var/db/kiss/installed/vow/version /var/db/kiss/installed/vow/vow-0.2.0-dev.tar.gz | sort >"$T/man_dbwant"
if cmp -s "$T/man_files" "$T/man_want" && cmp -s "$T/man_db" "$T/man_dbwant" && grep -qx '/usr/share/doc/vow/' "$db/manifest" &&
    grep -qx '/usr/share/licenses/vow/' "$db/manifest" && grep -qx '/usr/share/doc/vow/examples/' "$db/manifest"; then ok "$name"; else bad "$name"; diff "$T/man_want" "$T/man_files" | head -5; diff "$T/man_dbwant" "$T/man_db" | head -5; fi
name="owns: the files belong to vow, the others to base"
if [ "$(k owns /usr/bin/vow-run 2>&1 | grep -o 'vow' | head -1)" = vow ] && k owns /usr/lib/libother.a 2>&1 | grep -q base; then ok "$name"; else bad "$name"; fi
name="the unowned files and the other package are untouched by the install"
snap >"$T/snap1"; if cmp -s "$T/snap0" "$T/snap1" && [ -f "$root/usr/share/doc/vow/USER-NOTE" ]; then ok "$name"; else bad "$name"; diff "$T/snap0" "$T/snap1" | head; fi
name="verify finds nothing wrong"
if k verify vow >"$T/o" 2>&1 && ! grep -qi "missing\|differ\|modified" "$T/o"; then ok "$name"; else bad "$name"; cat "$T/o" | head -5; fi

# ---- the installed program and library ----
V=$root/usr/bin/vow-run
cat >"$T/hello.c" <<'X'
#include <stdio.h>
#include <vow.h>
int main(void) { if (pledge("stdio", NULL) < 0) { perror("pledge"); return 1; } puts("ok"); return 0; }
X
name="the installed library and header link statically and the program runs under pledge"
if cc -std=c99 -I"$root/usr/include" -static -o "$T/hello" "$T/hello.c" "$root/usr/lib/libvow.a" -pthread >/dev/null 2>&1; then
	out=$("$T/hello" 2>&1); case $out in ok) ok "$name";; *"not implemented"*|*"not supported"*) echo "SKIP  $name (no landlock)";; *) bad "$name ($out)";; esac
else bad "$name (does not link)"; fi
name="the installed vow-run is static"
if ! readelf -d "$V" 2>/dev/null | grep -q NEEDED; then ok "$name"; else bad "$name"; fi
printf 'pledge = stdio exec\n' >"$T/p.vow"
name="the installed vow-run --check accepts a profile"
if "$V" --check "$T/p.vow"; then ok "$name"; else bad "$name"; fi
printf 'pledge = stdio\n' >"$T/p.vow"
name="and refuses a bad one with status 125"
"$V" --check "$T/p.vow" >/dev/null 2>&1; [ $? = 125 ] && ok "$name" || bad "$name"
name="the installed vow-run runs a static program under a pledge and gives its status back"
cat >"$T/st.c" <<'X'
int main(void) { return 3; }
X
cc -std=c99 -static -o "$T/st" "$T/st.c" >/dev/null 2>&1
"$V" -p "stdio exec" "$T/st" >/dev/null 2>&1; rc=$?
case $rc in 3) ok "$name";; 125) echo "SKIP  $name (no landlock)";; *) bad "$name (status $rc)";; esac

# ---- reinstall the same version ----
name="reinstalling the same package leaves the same files, the same entry and the neighbours alone"
cp "$db/manifest" "$T/manifest1"; (cd "$root" && find usr -type f -path '*vow*' | sort | xargs sha256sum) >"$T/h1"
if k i vow >"$T/o" 2>&1 && cmp -s "$db/manifest" "$T/manifest1" && [ "$(k l vow)" = "vow 0.2.0-dev-1" ] &&
    [ "$(cd "$root" && find usr -type f -path '*vow*' | sort | xargs sha256sum)" = "$(cat "$T/h1")" ]; then
	snap >"$T/snap2"; cmp -s "$T/snap0" "$T/snap2" && ok "$name" || { bad "$name (neighbours changed)"; diff "$T/snap0" "$T/snap2" | head -5; }
	name="the owner is still $ME after the reinstall"; owners_ok && ok "$name" || bad "$name"
else bad "$name"; tail -3 "$T/o"; fi

# ---- upgrade: release 2 with one example gone and one file new ----
repo2=$T/repo2; mkdir "$repo2"; cp -R "$repo/vow" "$repo2/vow"
printf '0.2.0-dev 2\n' >"$repo2/vow/version"
cat >>"$repo2/vow/build" <<'X'

rm -f "$1/usr/share/doc/vow/examples/progressive.c"
printf 'second release\n' | install -Dm644 /dev/stdin "$1/usr/share/doc/vow/CHANGES"
X
KP=$repo2:$repo
name="nerd U -n sees the newer release"
if k U -n 2>&1 | grep -q "vow.*0.2.0-dev-1.*=>.*0.2.0-dev-2\|vow 0.2.0-dev-1 => 0.2.0-dev-2"; then ok "$name"; else bad "$name"; k U -n 2>&1 | head -3; fi
name="the upgrade builds and installs release 2"
if k U >"$T/o" 2>&1 && [ "$(k l vow)" = "vow 0.2.0-dev-2" ]; then ok "$name"; else bad "$name"; tail -5 "$T/o"; fi
name="the file that release 2 dropped is gone and the new one is there"
if [ ! -e "$root/usr/share/doc/vow/examples/progressive.c" ] && [ -f "$root/usr/share/doc/vow/CHANGES" ]; then ok "$name"; else bad "$name"; fi
name="no stale file of vow remains: the files on disk are exactly the manifest"
(cd "$root" && find usr -type f | sed 's|^|/|' | sort | grep -E '/vow-run$|/vow\.h$|/libvow\.a$|/share/doc/vow/|/share/licenses/vow/' | grep -v USER-NOTE) >"$T/ondisk"
grep -v '/$' "$db/manifest" | grep -v '^/var/db/kiss/installed/vow/' | sort >"$T/inman"
if cmp -s "$T/ondisk" "$T/inman"; then ok "$name"; else bad "$name"; diff "$T/inman" "$T/ondisk" | head -5; fi
name="the version file, the source tarball and the recipe of release 2 replaced those of release 1"
if [ "$(cat "$db/version")" = "0.2.0-dev 2" ] && grep -q "second release" "$db/build"; then ok "$name"; else bad "$name"; fi
name="the owner is $ME for every path of release 2, the new file included"
owners_ok && ok "$name" || bad "$name"
name="the unowned files and the other package survive the upgrade"
snap >"$T/snap3"; if cmp -s "$T/snap0" "$T/snap3" && [ -f "$root/usr/share/doc/vow/USER-NOTE" ]; then ok "$name"; else bad "$name"; diff "$T/snap0" "$T/snap3" | head -5; fi
name="after the upgrade nothing is newer"
[ -z "$(k U -n 2>&1 | grep -c '=>' | grep -v '^0$')" ] && ok "$name" || bad "$name"
# nerd compares the version and the release as strings: a changed package with the same release is not seen
repo3=$T/repo3; mkdir "$repo3"; cp -R "$repo2/vow" "$repo3/vow"; printf 'x\n' >>"$repo3/vow/build"
KP=$repo3:$repo2:$repo
name="a changed package under the same release is not seen as newer (so the release must be bumped)"
if k U -n 2>&1 | grep -q '=>'; then bad "$name"; else ok "$name"; fi
KP=$repo2:$repo

# ---- a package that ships a file vow owns ----
name="a clashing package becomes an alternative: vow keeps its header, the other file is parked as a choice"
if build vowclash >/dev/null 2>&1 && k i vowclash >"$T/o" 2>&1; then
	if ! grep -q "not the header" "$root/usr/include/vow.h" && ls "$root/var/db/kiss/choices" 2>/dev/null | grep -q 'vowclash>'; then ok "$name"; else bad "$name"; fi
else
	# a refusal is also safe; say which it was
	if grep -q "not the header" "$root/usr/include/vow.h" 2>/dev/null; then bad "$name (the header was overwritten)"; else echo "pass  $name (refused: $(tail -1 "$T/o"))"; fi
fi
name="the file only the clashing package owns was installed next to vow's files"
[ -f "$root/usr/share/doc/vow/CLASH" ] && ok "$name" || bad "$name"
name="removing the clashing package leaves vow complete"
if k r vowclash >"$T/o" 2>&1 && [ ! -e "$root/usr/share/doc/vow/CLASH" ] && [ -f "$root/usr/include/vow.h" ] && ! grep -q "not the header" "$root/usr/include/vow.h" &&
    [ -z "$(ls "$root/var/db/kiss/choices" 2>/dev/null)" ]; then ok "$name"; else bad "$name"; tail -3 "$T/o"; fi

# ---- remove ----
name="removing vow takes its files and nothing else"
if k r vow >"$T/o" 2>&1; then
	left=$(vowfiles_now)
	snap >"$T/snap4"
	if [ -z "$left" ] && [ ! -e "$db" ] && [ "$(k l 2>&1)" = "base 1.0-1" ] && cmp -s "$T/snap0" "$T/snap4"; then ok "$name"; else bad "$name"; echo "$left" | head -3; diff "$T/snap0" "$T/snap4" | head -5; fi
else bad "$name"; tail -3 "$T/o"; fi
name="the directories that existed before are all still there, and vow left no empty directory of its own"
dirs >"$T/dirs4"
if [ -z "$(comm -23 "$T/dirs0" "$T/dirs4")" ]; then
	extra=$(comm -13 "$T/dirs0" "$T/dirs4"); [ -z "$extra" ] && ok "$name" || { bad "$name"; echo "$extra" | head -5; }
else bad "$name (a directory is gone)"; comm -23 "$T/dirs0" "$T/dirs4" | head -3; fi
name="the unowned note and the neighbour package are still there"
[ -f "$root/usr/share/doc/vow/USER-NOTE" ] && [ -f "$root/usr/lib/unowned.a" ] && [ -f "$root/etc/other.conf" ] && ok "$name" || bad "$name"
name="installing again after the removal works"
KP=$repo
if k i vow >"$T/o" 2>&1 && [ "$(k l vow)" = "vow 0.2.0-dev-1" ] && [ "$(vowfiles_now)" = "$(expect_files)" ]; then ok "$name"; else bad "$name"; tail -3 "$T/o"; fi

# ---- the original kiss as the reference: the same tarball, installed by both, under two umasks ----
# what is compared: for every path of the root, the type, the mode, the owner and the content; and the manifest
# and the version of the database entry. the claim is that nerd does what kiss does, nothing more
tree() { (cd "$1" && find . | sort | while read -r f; do
	if [ -L "$f" ]; then t="l $(readlink "$f")"; elif [ -d "$f" ]; then t=d; else t="f $(sha256sum "$f" | cut -d' ' -f1)"; fi
	printf '%s %s %s %s\n' "$f" "$(stat -c '%a %u:%g' "$f")" "$t" ""
done); }
if command -v kiss >/dev/null; then
	for um in 022 077; do
		rn=$T/ref-nerd-$um; rk=$T/ref-kiss-$um
		mkdir -p "$rn/var/db/kiss" "$rk/var/db/kiss"
		root_save=$root
		root=$rn; ( umask $um; k i vow >"$T/o" 2>&1 ); okn=$?
		root=$rk; ( umask $um; kk i vow >"$T/o2" 2>&1 ); okk=$?
		root=$root_save
		name="umask $um: nerd and the original kiss install the same tarball to the same tree (modes, owners, content, manifest)"
		if [ $okn = 0 ] && [ $okk = 0 ] && cmp -s "$T/o" "$T/o" && [ "$(tree "$rn" | grep -v '/var/db/kiss/installed/vow/vow-0.2.0-dev.tar.gz')" = "$(tree "$rk" | grep -v '/var/db/kiss/installed/vow/vow-0.2.0-dev.tar.gz')" ]; then
			ok "$name"
		else bad "$name (nerd rc $okn, kiss rc $okk)"; diff "$T/o" "$T/o2" | head -3; tree "$rn" >"$T/tn"; tree "$rk" >"$T/tk"; diff "$T/tn" "$T/tk" | head -6; fi
		echo "info  umask $um, both tools: binary $(stat -c %a "$rn/usr/bin/vow-run"), file $(stat -c %a "$rn/usr/share/doc/vow/README.md"), directory $(stat -c %a "$rn/usr/share/doc/vow"), owner $(stat -c %u:%g "$rn/usr/bin/vow-run")"
	done
	name="the owner is $ME for every path installed by nerd under both umasks"
	bad_o=0; for um in 022 077; do for f in usr/bin/vow-run usr/lib/libvow.a usr/include/vow.h usr/share/doc/vow; do
		[ "$(stat -c %u:%g "$T/ref-nerd-$um/$f")" = "$ME" ] || bad_o=1; done; done
	[ $bad_o = 0 ] && ok "$name" || bad "$name"
else
	echo "SKIP  the original kiss is not installed: no reference to compare with"
fi

# ---- a package with a post-install hook (nerd runs it in a chroot, which needs root) ----
if [ $PRIV = 1 ]; then
	name="a post-install hook runs in a chroot of the root, as uid 0, with / as its directory"
	if k b hookpkg >/dev/null 2>&1 && k i hookpkg >"$T/o" 2>&1 && [ "$(cat "$root/hook-ran" 2>/dev/null)" = "$(printf 'uid=0\ncwd=/')" ]; then ok "$name"; else bad "$name"; tail -3 "$T/o"; cat "$root/hook-ran" 2>&1 | head -3; fi
	name="the hook file is kept in the package database and the hook package is removable"
	if [ -f "$root/var/db/kiss/installed/hookpkg/post-install" ] && k r hookpkg >/dev/null 2>&1 && [ ! -e "$root/usr/share/doc/hookpkg" ]; then ok "$name"; else bad "$name"; fi
else
	echo "SKIP  the hook test needs root (nerd runs hooks in a chroot)"
fi

# ---- the audit ----
name="no privilege tool was asked for"
[ ! -e "$T/su/attempts" ] && ok "$name" || { bad "$name"; cat "$T/su/attempts"; }
name="the package database of the real system is unchanged"
[ "$(real_fp)" = "$FP0" ] && ok "$name" || bad "$name"
name="the checkout is unchanged"
[ "$(git status --porcelain | sha256sum | cut -d' ' -f1)" = "$GIT0" ] && ok "$name" || bad "$name"
if command -v strace >/dev/null; then
	name="every write nerd made (strace, $n calls) is under the scratch directory"
	cat >"$T/audit.py" <<'PY'
import re, sys, glob, os
T, logdir, start, cache = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
allowed = (T + "/", cache + "/", "/dev/null", "/dev/tty", "/dev/stdout", "/dev/stderr")
writeflags = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC")
chowns = ("chown", "fchown", "fchownat", "lchown")
outside = []; ninja = []; total = 0; nchown = 0; nother = 0; nchroot = 0
def strings(args): return [x for x in re.findall(r'"((?:[^"\\]|\\.)*)"', args)]
for log in sorted(glob.glob(logdir + "/*")):
    is_nerd = os.path.basename(log).startswith("nerd-")
    cwd = {}; proot = {}; pend = {}
    def real(pid, p, base=None):
        # a path as the process sees it -> a path on the host: the root of the process (after chroot) and its directory
        r = proot.get(pid, "")
        if p.startswith("/"): return os.path.normpath(r + p) if r else os.path.normpath(p)
        return os.path.normpath(os.path.join(base if base else cwd.get(pid, start), p))
    for line in open(log, errors="replace"):
        m = re.match(r"(\d+)\s+(.*)", line)
        if not m: continue
        pid, rest = int(m.group(1)), m.group(2).rstrip()
        r = re.match(r"<\.\.\. (\w+) resumed>(.*)\)\s+=\s+(-?\d+)", rest)
        if r:
            call, tail, ret = r.group(1), r.group(2), int(r.group(3))
            args = pend.pop(pid, "") + tail
        elif "<unfinished ...>" in rest:
            r = re.match(r"(\w+)\((.*?)\s*<unfinished \.\.\.>", rest)
            if r: pend[pid] = r.group(2)
            continue
        else:
            r = re.match(r"(\w+)\((.*)\)\s+=\s+(-?\d+)", rest)
            if not r: continue
            call, args, ret = r.group(1), r.group(2), int(r.group(3))
        if call in chowns:
            if is_nerd: nchown += 1
            else: nother += 1
        if call in ("clone", "clone3", "fork", "vfork") and ret > 0:
            cwd[ret] = cwd.get(pid, start)
            if pid in proot: proot[ret] = proot[pid]
            continue
        if call == "chroot" and ret == 0:
            ss = strings(args)
            if ss: proot[pid] = real(pid, ss[0]); nchroot += 1
            continue
        if call == "chdir" and ret == 0:
            ss = strings(args)
            if ss: cwd[pid] = real(pid, ss[0])
            continue
        if call == "fchdir" and ret == 0:
            fd = re.match(r"\d+<([^>]*)>", args)
            if fd: cwd[pid] = fd.group(1)
            continue
        if ret < 0: continue
        if call in ("open", "openat") and not any(f in args for f in writeflags): continue
        if call in ("clone", "clone3", "fork", "vfork", "chdir", "fchdir", "chroot"): continue
        if call in ("ftruncate", "fchmod", "fchown"):
            fd = re.match(r"\d+<([^>]*)>", args)
            paths = [fd.group(1)] if fd else []
        else:
            ss = strings(args)
            if call in ("symlink", "symlinkat"): ss = ss[-1:]    # the first string is the target text, not a path that is written
            dirfd = re.match(r"(?:AT_FDCWD|\d+<([^>]*)>)", args)
            base = dirfd.group(1) if dirfd and dirfd.group(1) else None
            paths = [real(pid, x, base) for x in ss]
        for p in paths:
            total += 1
            if os.path.basename(p) in ("build.ninja", ".ninja_log", ".ninja_deps", "graph.ninja") or "/.make-shin." in p: ninja.append(p)
            if not (p.startswith(allowed) or p in allowed): outside.append((call, p))
print("writes checked: %d, relative paths not resolved: 0, outside: %d, chown calls: %d, chroots followed: %d, chown calls of the other tool (kiss): %d" % (total, len(outside), nchown, nchroot, nother))
for c, p in outside[:20]: print("  outside:", c, p)
print("make temp files (build.ninja, .ninja_*, .make-shin.*): %d writes, all under the scratch directory: %s%s" % (len(ninja), all(x.startswith((T + "/", cache + "/")) for x in ninja), (", e.g. " + ninja[0].replace(T, "$T")) if ninja else ""))
PY
	python3 "$T/audit.py" "$T" "$T/strace" "$PWD" "$cachedir" >"$T/audit.txt" 2>"$T/audit.err" || { bad "the audit script failed"; sed 's/^/    /' "$T/audit.err"; }
	head -1 "$T/audit.txt" | sed 's/^/    /'
	grep "^make temp files" "$T/audit.txt" | sed 's/^/    /'
	name="nerd made no call of the chown family (so what it creates belongs to the user that runs it)"
	nch=$(sed -n 's/.*chown calls: \([0-9]*\).*/\1/p' "$T/audit.txt")
	[ "${nch:-1}" = 0 ] && ok "$name" || bad "$name ($nch calls)"
	unres=$(sed -n 's/.*not resolved: \([0-9]*\),.*/\1/p' "$T/audit.txt")
	name="every relative path in a write call is resolved from the working directory of its process"
	[ "${unres:-1}" = 0 ] && ok "$name" || bad "$name ($unres left)"
	checked=$(sed -n 's/^writes checked: \([0-9]*\),.*/\1/p' "$T/audit.txt")
	if [ "${checked:-0}" -lt 100 ]; then bad "$name (too few writes seen: ${checked:-0}; the audit saw nothing)"
	elif grep -q "^  outside:" "$T/audit.txt"; then bad "$name"; sed 's/^/    /' "$T/audit.txt"
	else ok "$name"; fi
	# control: the audit must flag a write outside the scratch directory, or its silence means nothing
	mkdir "$T/fake"
	printf '%s\n' '100 openat(AT_FDCWD</tmp>, "/etc/vow-audit-control", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3</etc/vow-audit-control>' \
	    '100 unlink("/usr/bin/vow-audit-control") = 0' '100 openat(AT_FDCWD</tmp>, "/etc/passwd", O_RDONLY) = 4</etc/passwd>' >"$T/fake/nerd-control"
	name="control: the audit flags a write outside the scratch directory (and ignores a read)"
	python3 "$T/audit.py" "$T" "$T/fake" "$PWD" "$cachedir" >"$T/audit2.txt"
	if grep -q "outside: 2" "$T/audit2.txt" && grep -q "outside: openat /etc/vow-audit-control" "$T/audit2.txt" && ! grep -q "outside: openat /etc/passwd" "$T/audit2.txt"; then ok "$name"; else bad "$name"; cat "$T/audit2.txt" | sed 's/^/    /'; fi
else
	echo "SKIP  no strace for the audit of the writes"
fi
exit $fail
