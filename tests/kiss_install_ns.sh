#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# the privileged install test: tests/kiss_install.sh as root of a disposable user and mount namespace.
#
# usage: sh tests/kiss_install_ns.sh [revision]
#
# root here is a namespace root, not the root of the host: uid 0 inside is the uid of the user that runs this
# (a single id is mapped: there is no subuid range, so the builder uid 1000 of the archives is unmapped and any
# attempt to chown to it fails with EINVAL, which is visible). inside, the home tree and the real package
# database are bind-mounted read-only, and the run is refused if that did not work. nothing is escalated on the
# host: no sudo, doas or su. if user namespaces are not available the test is skipped, it does not try anything
# else. the scratch directory is made outside the checkout and the home tree.
set -u
cd "$(dirname "$0")/.." || exit 2
here=$PWD
rev=${1:-HEAD}
command -v unshare >/dev/null || { echo "SKIP  needs unshare"; exit 0; }
if ! unshare -Urm true 2>/dev/null; then
	echo "SKIP  no user namespaces here; not trying anything else"
	exit 0
fi
base=$(mktemp -d "${TMPDIR:-/tmp}/vow-kiss-ns.XXXXXX") || exit 2
case $base in /tmp/*|/var/tmp/*) ;; *) case $base in "$HOME"/*|"$here"/*) echo "FAIL  the scratch directory is inside the home tree"; exit 1;; esac ;; esac
# the scratch directory goes on every exit, also when a phase fails (KEEP=1 keeps it)
cleanup() { case $base in /tmp/vow-kiss-ns.*|/var/tmp/vow-kiss-ns.*) if [ -n "${KEEP:-}" ]; then echo "info  kept $base"; else rm -rf "$base"; fi ;; esac; }
trap cleanup EXIT
fp() { find /var/db/kiss -type f 2>/dev/null | sort | xargs sha256sum 2>/dev/null | sha256sum | cut -d' ' -f1; }
before=$(fp)

# phase 1, as the ordinary user: build every package, so that the archives record the builder uid, as they do
# when a package is built as a user and installed by root
echo "info  phase 1: the packages are built by $(id -un) (uid $(id -u)) and installed in an unprivileged root"
p1=$(KEEP=1 KI_BASE="$base" sh tests/kiss_install.sh "$rev" 2>&1); r1=$?
printf '%s\n' "$p1" | grep -E "^FAIL|^SKIP" | sed 's/^/  phase 1: /'
echo "info  phase 1: $(printf '%s\n' "$p1" | grep -c '^pass') checks passed, $(printf '%s\n' "$p1" | grep -c '^FAIL') failed"
dir=$(printf '%s\n' "$p1" | sed -n 's/^info  kept //p' | head -1)
[ $r1 = 0 ] && [ -d "$dir/cache" ] || { echo "FAIL  phase 1 did not leave a usable cache"; exit 1; }
tb=$(sha256sum "$dir"/cache/kiss/bin/vow@*.tar.gz | sha256sum | cut -d' ' -f1)

# phase 2, as root of a disposable namespace, from that cache
echo "info  phase 2: installation as root of a namespace"
unshare -Urm sh -c '
	set -u
	here=$1; base=$2; rev=$3; cache=$4
	# the host stays read-only: the home tree (the checkout and the real cache are in it), the real package database
	for d in /home /var/db/kiss "$here"; do
		mount --bind "$d" "$d" && mount -o remount,ro,bind "$d" || { echo "FAIL  cannot make $d read-only"; exit 1; }
	done
	for d in "$HOME" /var/db/kiss "$here"; do
		if touch "$d/.vow-ns-probe" 2>/dev/null; then echo "FAIL  $d is writable in the namespace; refusing to run"; exit 1; fi
	done
	echo "info  /home, /var/db/kiss and the checkout are read-only in the namespace"
	cd "$here" && KI_BASE="$base" KI_CACHE="$cache" sh tests/kiss_install.sh "$rev"
' sh "$here" "$base" "$rev" "$dir/cache"
rc=$?

after=$(fp)
tb2=$(sha256sum "$dir"/cache/kiss/bin/vow@*.tar.gz | sha256sum | cut -d' ' -f1)
if [ "$tb" = "$tb2" ]; then echo "pass  the vow packages built by the ordinary user were installed as they were (not rebuilt by root)"; else echo "FAIL  a vow package was rebuilt in the namespace"; rc=1; fi
if [ "$before" = "$after" ]; then echo "pass  the package database of the real system is unchanged (seen from outside)"; else echo "FAIL  the package database of the real system changed"; rc=1; fi
exit $rc
