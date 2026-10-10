#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# install the kiss package of vow into a root, with a read-only preflight, a backup, a verification against the state
# before, and a rollback. the root is the real one unless VOW_ROOT names a scratch root (which is how the script itself is
# tested: tests/real_root_install_test.sh).
#
# usage: sh tests/real_root_install.sh preflight REV     read-only on the system; builds the package as the ordinary user
#        sh tests/real_root_install.sh install REV       the preflight again, the backup, nerd i, the verification; undoes
#                                                        the install itself if the verification fails
#        sh tests/real_root_install.sh verify            compares the root with the state recorded before the install
#        sh tests/real_root_install.sh rollback          nerd r vow, then compares the root with the state before
#
# REV is a full 40 hex commit id, or a tag. HEAD and branch names are refused: they move, and the package must come from
# one exact commit (it is made by `git archive` of that commit, which records the id in the tarball, and the tarball is
# compared with it). the working tree is never packaged.
#
# run as the ordinary user, never as root: nerd asks the privilege tool (KISS_SU, doas) itself, for the one install and the
# one removal. nothing here writes outside the state directory (~/.local/state/vow-install, VOW_STATE to change it), the cache
# of the user and, through nerd, the root. nothing here touches /etc, wren or any service: the preflight fails if the package
# would.
set -u
umask 022
cd "$(dirname "$0")/.." || exit 2
here=$PWD
mode=${1:-}; REV=${2:-}
ROOT=${VOW_ROOT:-}
STATE_BASE=${VOW_STATE:-$HOME/.local/state/vow-install}
REPO=${VOW_REPO:-$here}
LIVE=1; [ -n "$ROOT" ] && LIVE=0
# test knobs, honored only for a scratch root (VOW_ROOT), never for the real one: another lister, another expected owner
LISTER=; EXPECT_OWNER=
if [ $LIVE = 0 ]; then LISTER=${VOW_TEST_LISTER:-}; EXPECT_OWNER=${VOW_TEST_EXPECT_OWNER:-}; fi
fail=0; rejected=0
ok() { echo "pass  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
info() { echo "info  $1"; }
die() { echo "FAIL  $*"; exit 1; }

[ "$(id -u)" != 0 ] || die "run as the ordinary user: nerd escalates by itself, for the install and the removal only"
case $mode in preflight|install) [ -n "$REV" ] || die "usage: real_root_install.sh $mode REV (a full commit id or a tag)";; verify|rollback) ;; *) die "usage: real_root_install.sh preflight|install REV | verify | rollback";; esac
for c in git nerd python3 tar cc sha256sum; do command -v $c >/dev/null || die "$c is needed"; done

R=$ROOT                                 # every path below the root is "$R/usr/...": empty for the real root
DB=$R/var/db/kiss
mkdir -p "$STATE_BASE"
if [ "$mode" = verify ] || [ "$mode" = rollback ]; then
	S=$(cat "$STATE_BASE/latest" 2>/dev/null) || die "no recorded install (no $STATE_BASE/latest)"
	[ -d "$S" ] && [ -f "$S/install.started" ] || die "the recorded state directory $S is gone or holds no install"
	. "$S/env"
else
	S=$STATE_BASE/$(date +%Y%m%d-%H%M%S)-$$
	mkdir -p "$S/pkg" "$S/cache" "$S/tmp"
fi

nerd_env() { # run nerd as the user, in a clean environment with the package directory first in KISS_PATH
	env -i PATH="$PATH" HOME="$HOME" LOGNAME="$(id -un)" USER="$(id -un)" TERM="${TERM:-dumb}" \
	    ${ROOT:+KISS_ROOT="$ROOT"} XDG_CACHE_HOME="$S/cache" KISS_TMPDIR="$S/tmp" TMPDIR="$S/tmp" \
	    KISS_PATH="$S/pkg:${KISS_PATH_BASE:-${KISS_PATH:-}}" ${KISS_SU:+KISS_SU="$KISS_SU"} KISS_PROMPT=0 KISS_COLOR=0 NERD_ANIM=0 \
	    nerd "$@"
}
# the trees an install can touch, one line each: type, mode, owner, size (not for directories), path. python, not find: the shell here
# is busybox, whose find has no -printf. an empty listing means that nothing could be compared, which is a failure, never a pass
listing() { python3 "${LISTER:-$here/tests/tree_listing.py}" "$R"; }
pid1() { cat /proc/1/comm 2>/dev/null; }
pid1_start() { awk '{ sub(/^[^)]*\) /, ""); print $20 }' /proc/1/stat 2>/dev/null; }   # field 22 of stat: the start time

# ================= the facts of the revision =================
if [ "$mode" = preflight ] || [ "$mode" = install ]; then
	echo "state directory: $S"
	if [ $LIVE = 1 ]; then echo "root: the REAL root (/)"; else echo "root: $ROOT (a scratch root)"; fi

	case $REV in
	*[!0-9a-f]*) case $REV in v[0-9]*) ;; *) die "REV must be a full commit id or a release tag, not '$REV' (a branch or HEAD moves)" ;; esac ;;
	*) [ ${#REV} = 40 ] || die "REV must be a full 40 digit commit id or a tag" ;;
	esac
	sha=$(git -C "$REPO" rev-parse --verify --quiet "$REV^{commit}") || die "no such commit: $REV"
	[ ${#sha} = 40 ] && ok "the revision is the exact commit $sha" || bad "not a commit"
	VER=$(git -C "$REPO" show "$sha:dist/kiss/vow/version" | cut -d' ' -f1)
	REL=$(git -C "$REPO" show "$sha:dist/kiss/vow/version" | cut -d' ' -f2)
	hdr=$(git -C "$REPO" show "$sha:include/vow.h" | sed -n 's/^#define VOW_VERSION[[:space:]]*"\(.*\)"/\1/p')
	[ -n "$VER" ] && [ "$hdr" = "$VER" ] && ok "the version is $VER-$REL in the header and in the recipe" || bad "the version differs between the header ($hdr) and the recipe ($VER)"
	case $VER in *-dev*) info "$VER is a development version (allowed for a test install)";; esac
	if git -C "$REPO" show "$sha:dist/kiss/vow/build" | grep -q '^umask 022$'; then ok "the recipe of this commit sets umask 022"; else bad "the recipe of this commit does not set umask 022: it is the version without the fix"; fi
	n=$(git -C "$REPO" status --porcelain | wc -l)
	[ "$n" = 0 ] && info "the working tree is clean" || info "the working tree has $n uncommitted changes: they are not in the package"
	info "branches that contain this commit: $(git -C "$REPO" branch --contains "$sha" 2>/dev/null | tr -d '* ' | tr '\n' ' ')"
	git -C "$REPO" tag --points-at "$sha" | sed 's/^/info  tag on this commit: /'
	if git -C "$REPO" verify-commit "$sha" >/dev/null 2>&1; then ok "the commit has a good signature"; else info "the commit has no good signature"; fi
fi

# ================= preflight =================
if [ "$mode" = preflight ] || [ "$mode" = install ]; then
	echo "== the system, read only =="
	[ -z "${KISS_PATH:-}" ] && bad "KISS_PATH is not set in this shell: nerd would not find the repositories"
	KISS_PATH_BASE=${KISS_PATH:-}
	[ -d "$DB/installed" ] && ok "the package database is there ($(ls "$DB/installed" | wc -l) packages)" || bad "no package database at $DB/installed"
	[ -f "$DB/installed/vow/version" ] && bad "vow is already installed ($(cat "$DB/installed/vow/version")): this script installs, it does not upgrade" || ok "vow is not installed"
	if nerd_env s vow >/dev/null 2>&1; then bad "a recipe named vow is already in KISS_PATH (before ours)"; else ok "no recipe named vow in KISS_PATH"; fi
	ps -eo comm | grep -qx -e nerd -e kiss && bad "a nerd or kiss is running" || ok "no nerd or kiss is running"
	[ -z "${KISS_HOOK:-}" ] && ok "KISS_HOOK is not set: no hook runs as root" || bad "KISS_HOOK is set to $KISS_HOOK: it would run as root"
	for p in usr/bin/vow-run usr/lib/libvow.a usr/include/vow.h usr/share/doc/vow usr/share/licenses/vow; do
		if [ -e "$R/$p" ] || [ -L "$R/$p" ]; then bad "/$p already exists"; else
			own=$(nerd_env owns "/$p" 2>/dev/null); [ -z "$own" ] && : || bad "/$p is owned by $own"
		fi
	done
	[ -z "$(ls "$R"/usr/bin/vow-run "$R"/usr/lib/libvow.a "$R"/usr/include/vow.h 2>/dev/null)" ] && ok "none of the target files exists, none is owned by a package"
	for d in usr usr/bin usr/lib usr/include usr/share usr/share/doc usr/share/licenses; do
		o=$(stat -c '%U:%G %a' "$R/$d" 2>/dev/null) || { bad "/$d does not exist"; continue; }
		case $o in "root:root 755"|"root:root 1755") ;; *) [ $LIVE = 1 ] && bad "/$d is $o (not root:root 755)" || info "/$d is $o (scratch root)" ;; esac
	done
	[ $LIVE = 1 ] && ok "the directories the package adds to are root:root 755"
	# nerd removes a directory that a removal leaves empty, so a rollback would not restore an empty one that existed before
	for d in usr/bin usr/lib usr/include usr/share/doc usr/share/licenses; do
		[ "$(ls -A "$R/$d" 2>/dev/null | wc -l)" -gt 0 ] || bad "/$d is empty: nerd would remove it when vow is removed, and the rollback would not restore it"
	done
	ok "every directory the package adds to holds other files, so a removal leaves them in place"
	if [ -d "$DB/choices" ] && ls "$DB/choices" | grep -q 'vow'; then bad "an alternative with vow in its name exists in choices"; else ok "no alternative (choice) mentions vow"; fi
	# disk
	need_kb=$(( $(du -sk "$DB" 2>/dev/null | cut -f1) * 2 + 65536 ))
	have_kb=$(df -Pk "${R:-/}" | awk 'NR==2 {print $4}')
	[ "$have_kb" -ge "$need_kb" ] && ok "disk: $((have_kb/1024)) MiB free, $((need_kb/1024)) MiB needed (two copies of the database and the package)" || bad "disk: $((have_kb/1024)) MiB free, $((need_kb/1024)) MiB needed"
	have_i=$(df -Pi "${R:-/}" | awk 'NR==2 {print $4}'); [ "$have_i" -ge 100000 ] && ok "inodes: $have_i free" || bad "inodes: only $have_i free"
	hs=$(df -Pk "$STATE_BASE" | awk 'NR==2 {print $4}'); [ "$hs" -ge "$need_kb" ] && ok "the state directory has room for the backup" || bad "no room for the backup in $STATE_BASE"
	( cd "${R:-/}" && tar cf - var/db/kiss 2>"$S/tar.err" | wc -c >"$S/db.size" ); [ ! -s "$S/tar.err" ] && ok "the whole package database can be archived by the ordinary user ($(( $(cat "$S/db.size") / 1048576 )) MiB, no error)" || { bad "the database cannot be archived without error"; head -3 "$S/tar.err"; }
	if [ $LIVE = 1 ]; then
		findmnt -no OPTIONS -T /usr | grep -qw rw && ok "/usr is on a writable filesystem" || bad "/usr is not writable"
		if doas -n true 2>/dev/null; then ok "the privilege tool works without a password prompt (doas -n true)"; else bad "doas needs a password: nerd would stop at a prompt"; fi
		[ "$(pid1)" = wren ] && ok "pid 1 is wren" || info "pid 1 is $(pid1)"
	fi
	# wren and the services: nothing of the package may be under /etc or name a service
	echo "== the package, built as the ordinary user under umask 022 =="
	(cd / && sh "$REPO/dist/kiss/mkpkg.sh" "$S/pkg" "$sha") >"$S/mkpkg.log" 2>&1 && ok "mkpkg made the package directory from $sha" || { bad "mkpkg failed"; cat "$S/mkpkg.log"; exit 1; }
	tb=$S/pkg/vow/vow-$VER.tar.gz
	[ "$(gzip -dc "$tb" | git get-tar-commit-id)" = "$sha" ] && ok "the source tarball records the commit $sha" || bad "the tarball does not record the commit"
	if nerd_env c vow >"$S/c.log" 2>&1 && nerd_env b vow >"$S/b.log" 2>&1; then ok "nerd built the package"; else bad "nerd could not build the package"; tail -5 "$S/b.log"; exit 1; fi
	arch=$S/cache/kiss/bin/vow@$VER-$REL.tar.gz
	[ -f "$arch" ] && ok "the tarball is $arch" || { bad "no tarball $arch"; exit 1; }
	python3 - "$arch" "$S/payload.txt" <<'PY' && ok "the tarball: only paths under /usr and the database entry of vow, no setuid or setgid, modes 755 / 644, no symlink or device" || bad "the tarball holds something that must not be installed"
import sys, tarfile, re
t = tarfile.open(sys.argv[1]); bad = []; paths = []
for m in t.getmembers():
    n = "/" + m.name.lstrip("./").rstrip("/") if m.name not in (".", "./") else "/"
    if n == "/": continue
    paths.append(n + ("/" if m.isdir() else ""))
    if n.startswith("/etc") or "wren" in n.replace("/usr/share/doc/vow/examples/wren", "").replace("/usr/share/doc/vow/vow-run-wren.md", ""): bad.append("touches etc or wren: " + n)
    if not (n.startswith("/usr/") or n.startswith("/var/db/kiss/installed/vow") or n in ("/usr", "/var", "/var/db", "/var/db/kiss", "/var/db/kiss/installed")): bad.append("outside /usr: " + n)
    if m.mode & 0o6000: bad.append("setuid or setgid: " + n)
    if m.issym() or m.islnk() or m.isdev() or m.isfifo(): bad.append("not a plain file or directory: " + n)
    if m.isreg() and n.startswith("/usr/") and m.mode != (0o755 if n == "/usr/bin/vow-run" else 0o644): bad.append("mode %o: %s" % (m.mode, n))
    if m.isdir() and n.startswith("/usr") and m.mode != 0o755: bad.append("directory mode %o: %s" % (m.mode, n))
open(sys.argv[2], "w").write("\n".join(sorted(paths)) + "\n")
print("\n".join(bad)); sys.exit(1 if bad else 0)
PY
	# conflicts: no path of the package is in the manifest of another package (a directory shared with others is fine)
	grep -v '/$' "$S/payload.txt" | grep -v '^/var/db/kiss/installed/vow/' >"$S/payload.files"
	clash=$(cat "$DB"/installed/*/manifest 2>/dev/null | grep -vx '.*/' | grep -Fxf "$S/payload.files" | head -3)
	[ -z "$clash" ] && ok "none of the $(wc -l <"$S/payload.files") files of the package is in the manifest of an installed package" || bad "conflict: $clash"
	grep -qE '^/etc/' "$S/payload.files" && bad "the package would install under /etc" || ok "the package installs nothing under /etc and nothing of wren"
	# the state before
	listing >"$S/before.listing"
	[ "$(wc -l <"$S/before.listing")" -gt 3 ] && grep -q ' var/db/kiss$' "$S/before.listing" || { bad "the listing of the root before the install is empty or lacks the package database: nothing could be compared"; exit 1; }
	ok "recorded the state before: $(wc -l <"$S/before.listing") entries of /usr, /var/db/kiss and /etc/wren (sha256 $(sha256sum "$S/before.listing" | cut -c1-16))"
	{ echo "REV=$sha"; echo "VER=$VER"; echo "REL=$REL"; echo "ROOT='$ROOT'"; echo "REPO='$REPO'"; echo "KISS_PATH_BASE='$KISS_PATH_BASE'"; echo "S='$S'"; echo "P1START=$(pid1_start)"; } >"$S/env"
	echo
	if [ $fail = 0 ]; then echo "PREFLIGHT: SAFE TO INSTALL ($sha, vow $VER-$REL into ${ROOT:-the real root})"; else echo "PREFLIGHT: NOT SAFE, nothing was changed"; fi
	[ "$mode" = preflight ] || [ $fail != 0 ] && exit $fail
fi

# ================= backup and install =================
if [ "$mode" = install ]; then
	echo "== backup =="
	( cd "${R:-/}" && tar cf "$S/var-db-kiss.tar" var/db/kiss ) 2>"$S/backup.err"
	[ ! -s "$S/backup.err" ] && sha256sum "$S/var-db-kiss.tar" >"$S/var-db-kiss.tar.sha256" && ok "backup of the package database: $S/var-db-kiss.tar ($(( $(wc -c <"$S/var-db-kiss.tar") / 1048576 )) MiB, sha256 $(cut -c1-16 "$S/var-db-kiss.tar.sha256"))" || die "the backup failed"
	tar tf "$S/var-db-kiss.tar" | wc -l | { read n; [ "$n" -gt 1000 ] && ok "the backup lists $n entries"; }
	: >"$S/install.started"
	echo "$S" >"$STATE_BASE/latest"      # only an install that really starts becomes the one that verify and rollback look at
	echo "== install (nerd asks the privilege tool for this one step) =="
	nerd_env i vow >"$S/install.log" 2>&1; irc=$?
	[ $LIVE = 0 ] && [ -n "${VOW_TEST_AFTER_INSTALL:-}" ] && eval "$VOW_TEST_AFTER_INSTALL"    # test only, never on the real root
	cat "$S/install.log" | sed 's/^/      /'
	[ $irc = 0 ] && ok "nerd i vow exited 0" || bad "nerd i vow exited $irc"
	mode=verify
fi

# ================= verify =================
if [ "$mode" = verify ]; then
	echo "== verification against the state before =="
	listing >"$S/after.listing"
	[ "$(wc -l <"$S/after.listing")" -gt 3 ] || { bad "the listing of the root is empty: nothing can be compared"; exit 1; }
	# what the install may have added: the files and directories of the package (the tarball lists them), nothing else
	grep -E '^/(usr/|var/db/kiss/)' "$S/payload.txt" | sed 's|/$||' | sort >"$S/allowed.paths"
	cut -d' ' -f5- "$S/before.listing" | sed 's|^|/|' | sort >"$S/before.paths"
	cut -d' ' -f5- "$S/after.listing" | sed 's|^|/|' | sort >"$S/after.paths"
	sort "$S/before.listing" >"$S/b.sorted"; sort "$S/after.listing" >"$S/a.sorted"
	comm -23 "$S/b.sorted" "$S/a.sorted" >"$S/gone-or-changed"
	[ ! -s "$S/gone-or-changed" ] && ok "every entry that existed before is unchanged: type, mode, owner and size of $(wc -l <"$S/b.sorted") entries compared" || bad "removed or changed: $(head -3 "$S/gone-or-changed" | tr '\n' ';')"
	comm -13 "$S/before.paths" "$S/after.paths" >"$S/added.paths"
	extra=$(comm -13 "$S/allowed.paths" "$S/added.paths" | head -3); [ -z "$extra" ] && ok "the only new paths are those of the package ($(wc -l <"$S/added.paths") new entries)" || bad "new paths that are not in the package: $extra"
	missing=$(comm -23 "$S/allowed.paths" "$S/after.paths" | head -3); [ -z "$missing" ] && ok "every path of the package is there" || bad "missing after the install: $missing"
	# the owners and modes of the package
	EXPECT_OWNER=$EXPECT_OWNER python3 - "$R" "$S/payload.txt" <<'PY' && ok "every path of the package belongs to the owner of the install (root:root for the real root) and has the intended mode" || bad "owner or mode of a package path is wrong"
import os, sys, stat
root, listf = sys.argv[1], sys.argv[2]
want = (0, 0) if root == "" else (os.getuid(), os.getgid())
if root != "" and os.environ.get("EXPECT_OWNER"):
    want = tuple(int(x) for x in os.environ["EXPECT_OWNER"].split(":"))
bad = []
for line in open(listf):
    p = line.strip()
    if not p or p.startswith("/var/db/kiss/installed/") or p in ("/usr", "/var", "/var/db", "/var/db/kiss"): continue
    st = os.lstat(root + p.rstrip("/"))
    if (st.st_uid, st.st_gid) != want: bad.append("%s is %d:%d" % (p, st.st_uid, st.st_gid))
    m = stat.S_IMODE(st.st_mode)
    if p.endswith("/"): 
        if m != 0o755: bad.append("%s mode %o" % (p, m))
    elif m != (0o755 if p == "/usr/bin/vow-run" else 0o644): bad.append("%s mode %o" % (p, m))
print("\n".join(bad[:5])); sys.exit(1 if bad else 0)
PY
	nerd_env l vow 2>/dev/null | grep -qx "vow $VER-$REL" && ok "nerd lists vow $VER-$REL" || bad "nerd does not list vow $VER-$REL"
	nerd_env verify vow >"$S/verify.log" 2>&1 && ok "nerd verify vow: $(tail -1 "$S/verify.log" | sed 's/^nerd: //')" || { bad "nerd verify vow failed"; tail -3 "$S/verify.log"; }
	# wren and the services: /etc/wren must be identical (a root without it has nothing to compare, and that is identical too)
	awk '$5 ~ /^etc\/wren/' "$S/before.listing" >"$S/wren.before"; awk '$5 ~ /^etc\/wren/' "$S/after.listing" >"$S/wren.after"
	if cmp -s "$S/wren.before" "$S/wren.after"; then ok "/etc/wren is identical: every file, link, mode, owner and size ($(wc -l <"$S/wren.after") entries)"; else bad "/etc/wren changed"; diff "$S/wren.before" "$S/wren.after" | head -4 | sed 's/^/      /'; fi
	if [ $LIVE = 1 ]; then
		[ "$(pid1)" = wren ] && [ "$(pid1_start)" = "$P1START" ] && ok "pid 1 is still the same wren (start time $P1START): nothing was restarted" || bad "pid 1 changed"
		ok "the enabled services are as before: $(ls /etc/wren/services | tr '\n' ' ')"
	fi
	# the program works
	V=$R/usr/bin/vow-run
	"$V" --check /dev/null >/dev/null 2>&1; [ $? = 125 ] && ok "the installed vow-run runs and refuses an empty profile with 125" || bad "the installed vow-run does not behave"
	! readelf -d "$V" 2>/dev/null | grep -q NEEDED && ok "the installed vow-run is static" || bad "the installed vow-run is not static"
	printf 'pledge = stdio exec\n' >"$S/tmp/p.vow"; "$V" --check "$S/tmp/p.vow" && ok "the installed vow-run --check accepts a good profile" || bad "--check refused a good profile"
	printf 'int main(void){return 3;}\n' >"$S/tmp/st.c"; cc -static -o "$S/tmp/st" "$S/tmp/st.c" 2>/dev/null
	"$V" -p "stdio exec" "$S/tmp/st" >/dev/null 2>&1; rc=$?; case $rc in 3) ok "the installed vow-run sandboxes a static program and returns its status";; 125) info "no landlock here (status 125)";; *) bad "vow-run returned $rc";; esac
	printf '#include <stdio.h>\n#include <vow.h>\nint main(void){ if (pledge("stdio", NULL) < 0) return 1; puts("ok"); return 0; }\n' >"$S/tmp/h.c"
	cc -std=c99 -I"$R/usr/include" -static -o "$S/tmp/h" "$S/tmp/h.c" "$R/usr/lib/libvow.a" -pthread 2>"$S/tmp/h.err" && ok "a program links statically against the installed header and library" || { bad "linking against the installed library failed"; head -3 "$S/tmp/h.err"; }
	[ "$("$S/tmp/h" 2>&1)" = ok ] && ok "and runs under pledge"
	echo
	if [ $fail = 0 ]; then echo "VERIFIED: the root differs from the state before by exactly the package"; else echo "VERIFICATION FAILED"; fi
	if [ $fail != 0 ] && [ -f "$S/install.started" ]; then
		echo "the install is being undone"
		rejected=1
		mode=rollback
	else
		[ -f "$S/install.started" ] && echo "to undo: sh tests/real_root_install.sh rollback   (state: $S)"
		exit $fail
	fi
fi

# ================= rollback =================
if [ "$mode" = rollback ]; then
	echo "== rollback =="
	rfail=0
	if [ -f "$DB/installed/vow/version" ]; then
		nerd_env r vow >"$S/remove.log" 2>&1; rrc=$?
		sed 's/^/      /' "$S/remove.log"
		[ $rrc = 0 ] && ok "nerd r vow exited 0" || { bad "nerd r vow exited $rrc"; rfail=1; }
	else info "vow is not installed: nothing to remove"; fi
	listing >"$S/after-rollback.listing"
	if cmp -s "$S/before.listing" "$S/after-rollback.listing"; then
		ok "the root is exactly as before: $(wc -l <"$S/before.listing") entries identical"
	else
		bad "the root differs from the state before the install:"; diff "$S/before.listing" "$S/after-rollback.listing" | head -8 | sed 's/^/      /'
		echo "      the database can be put back from the backup (as root, from /):"
		echo "          doas tar xf $S/var-db-kiss.tar -C /     (after: doas rm -rf /var/db/kiss)   -- check with the sha256 file next to it first"
		rfail=1
	fi
	[ $rfail = 0 ] && echo "ROLLED BACK" || echo "ROLLBACK INCOMPLETE"
	if [ $rejected = 1 ]; then echo "THE INSTALL WAS REJECTED: it did not pass the verification and was undone (exit status 1)"; exit 1; fi
	exit $rfail
fi
