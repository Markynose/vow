#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# the example of examples/wren, run by wren in its dev mode (the supervisor without pid 1) from a scratch build.
#
# usage: sh tests/wren_example.sh          (WREN_SRC=path to the source of wren, default ~/src/wren; needs build/vow-run)
#
# wren is only read: its Makefile and src/ are copied into the scratch directory and built there, and the test
# checks afterwards that no file of the wren tree was created or changed. the files of the example are installed
# into the scratch directory with nothing changed but their paths. everything that is killed is killed by the exact
# pid that this test started or that wren logged: on a machine where pid 1 is a wren, never kill by name.
# skipped when there is no wren source, no landlock, or wren does not build. this is not a test of wren as pid 1,
# of a boot, or of any service that wren ships.
set -u
cd "$(dirname "$0")/.." || exit 2
here=$PWD
WREN_SRC=${WREN_SRC:-$HOME/src/wren}
VR=$here/build/vow-run
[ -f "$WREN_SRC/src/wren.c" ] || { echo "SKIP  no source of wren at $WREN_SRC (set WREN_SRC)"; exit 0; }
[ -x "$VR" ] || { echo "SKIP  build/vow-run is missing (make tools)"; exit 0; }
fail=0
ok() { echo "pass  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
mkdir -p build/tmp
T=$(mktemp -d "$PWD/build/tmp/wx.XXXXXX") || exit 2
wp=; dpids=
cleanup() {
	[ -n "$wp" ] && kill -KILL "$wp" 2>/dev/null
	for p in $dpids; do kill -KILL "$p" 2>/dev/null; done
	case $T in "$here"/build/tmp/wx.*) rm -rf "$T" ;; esac
}
trap cleanup EXIT
: >"$T/stamp"

# a landlock that works is needed for everything below
if ! "$VR" -p "stdio exec" /bin/true >"$T/o" 2>&1 && grep -q "not implemented\\|not supported" "$T/o"; then
	echo "SKIP  no landlock signal scope here"; exit 0
fi

# ---- the shipped files, as they are ----
name="the shipped profile passes vow-run --check unchanged"
"$VR" --check examples/wren/vow/exampled.vow && ok "$name" || bad "$name"
name="the shipped run script is valid shell and ends in exec vow-run ... 2>&1"
if sh -n examples/wren/sv/exampled/run && tail -n 1 examples/wren/sv/exampled/run | grep -q '^exec /usr/bin/vow-run --profile /etc/wren/vow/exampled.vow -- /usr/bin/exampled .* 2>&1$'; then ok "$name"; else bad "$name"; fi

# ---- a scratch wren, built from a copy ----
mkdir "$T/wsrc" && cp -R "$WREN_SRC/Makefile" "$WREN_SRC/src" "$T/wsrc/"
if ! (cd "$T/wsrc" && make wren) >"$T/wbuild.log" 2>&1 || [ ! -x "$T/wsrc/wren" ]; then
	echo "SKIP  wren does not build from $WREN_SRC:"; tail -3 "$T/wbuild.log" | sed 's/^/        /'; exit 0
fi

# ---- the example installed into the scratch directory: only the paths change ----
I=$T/inst
mkdir -p "$I/bin" "$I/etc/wren/vow" "$I/etc/exampled" "$I/svc/exampled" "$I/svc/broken"
cc -std=c99 -Wall -Wextra -Werror -static -o "$I/bin/exampled" examples/wren/exampled.c || { bad "exampled builds"; exit 1; }
printf 'the motd of the example\n' >"$I/etc/exampled/motd"
sed -e "s|/usr/bin/vow-run|$VR|" -e "s|/etc/wren/vow/exampled.vow|$I/etc/wren/vow/exampled.vow|" \
    -e "s|/usr/bin/exampled|$I/bin/exampled|" -e "s|/etc/exampled/motd|$I/etc/exampled/motd|" \
    examples/wren/sv/exampled/run >"$I/svc/exampled/run"
sed -e "s|/etc/exampled|$I/etc/exampled|" examples/wren/vow/exampled.vow >"$I/etc/wren/vow/exampled.vow"
sed -e "s|exampled.vow|missing.vow|" "$I/svc/exampled/run" >"$I/svc/broken/run"
chmod +x "$I/svc/exampled/run" "$I/svc/broken/run"
name="only the paths differ between the shipped files and the ones that ran"
back=$(sed -e "s|$VR|/usr/bin/vow-run|" -e "s|$I/etc/wren/vow/exampled.vow|/etc/wren/vow/exampled.vow|" -e "s|$I/bin/exampled|/usr/bin/exampled|" -e "s|$I/etc/exampled/motd|/etc/exampled/motd|" "$I/svc/exampled/run")
backp=$(sed -e "s|$I/etc/exampled|/etc/exampled|" "$I/etc/wren/vow/exampled.vow")
if [ "$back" = "$(cat examples/wren/sv/exampled/run)" ] && [ "$backp" = "$(cat examples/wren/vow/exampled.vow)" ]; then ok "$name"; else bad "$name"; fi

waitfor() { # pattern [tries]: wait (0.2 s steps) until the pattern appears in the log of wren
	i=0; while [ $i -lt ${2:-50} ]; do grep -q -- "$1" "$T/wren.log" 2>/dev/null && return 0; sleep 0.2; i=$((i+1)); done; return 1
}
field() { awk '{ sub(/^[^)]*\) /, ""); print $'"$2"' }' "/proc/$1/stat" 2>/dev/null; }   # fields after the command name: 3 ppid, 4 pgrp, 5 session

"$T/wsrc/wren" -s "$I/svc" >"$T/wren.log" 2>&1 &
wp=$!

# ---- start ----
name="wren starts the service and the daemon reports itself"
if waitfor "exampled: up, pid" 60; then ok "$name"; else bad "$name"; sed 's/^/    /' "$T/wren.log" | head -8; fi
dp=$(sed -n 's/^exampled: up, pid \([0-9]*\)$/\1/p' "$T/wren.log" | head -n 1); dpids="$dp"
sp=$(sed -n 's/^wren: started exampled (pid \([0-9]*\))$/\1/p' "$T/wren.log" | head -n 1)
name="the pid that wren supervises is the daemon itself (vow-run replaced itself)"
[ -n "$dp" ] && [ "$dp" = "$sp" ] && ok "$name" || bad "$name (wren $sp, daemon $dp)"
name="the daemon is sandboxed: no_new_privs and a seccomp filter"
if grep -q '^NoNewPrivs:[[:space:]]*1' "/proc/$dp/status" 2>/dev/null && grep -q '^Seccomp:[[:space:]]*2' "/proc/$dp/status"; then ok "$name"; else bad "$name"; fi
name="it is the leader of the session and of the process group that wren made for it"
[ "$(field "$dp" 3)" = "$dp" ] && [ "$(field "$dp" 4)" = "$dp" ] && ok "$name" || bad "$name ($(field "$dp" 3) $(field "$dp" 4))"
name="it reads the file the profile unveils"
grep -q "exampled: motd: the motd of the example" "$T/wren.log" && ok "$name" || bad "$name"
name="and cannot read a file the profile does not unveil"
grep -q "exampled: /etc/passwd is outside the profile: Permission denied" "$T/wren.log" && ok "$name" || bad "$name"

# ---- a broken profile: vow-run says so, wren restarts with its usual backoff ----
name="a profile that does not exist: vow-run exits 125 with its message and wren restarts with backoff"
if waitfor "wren: broken exited with status 125, restart in 1s" 40 && waitfor "wren: broken exited with status 125, restart in 2s" 40 && grep -q "vow-run: .*missing.vow" "$T/wren.log"; then ok "$name"; else bad "$name"; grep broken "$T/wren.log" | head -4 | sed 's/^/    /'; fi

# ---- a crash of the daemon: it comes back sandboxed ----
kill -KILL "$dp"
name="killed with signal 9, the daemon is restarted by wren after 1s"
if waitfor "wren: exampled killed by signal 9, restart in 1s" 40 && waitfor "wren: started exampled" 40; then ok "$name"; else bad "$name"; fi
n=0; dp2=; while [ $n -lt 50 ]; do dp2=$(sed -n 's/^exampled: up, pid \([0-9]*\)$/\1/p' "$T/wren.log" | tail -n 1); [ -n "$dp2" ] && [ "$dp2" != "$dp" ] && break; sleep 0.2; n=$((n+1)); done
dpids="$dp2"
name="the new daemon is another process and is sandboxed too"
if [ -n "$dp2" ] && [ "$dp2" != "$dp" ] && grep -q '^NoNewPrivs:[[:space:]]*1' "/proc/$dp2/status" 2>/dev/null && grep -q '^Seccomp:[[:space:]]*2' "/proc/$dp2/status"; then ok "$name"; else bad "$name"; fi

# ---- shutdown ----
kill -TERM "$wp"
i=0; while [ $i -lt 100 ] && kill -0 "$wp" 2>/dev/null; do sleep 0.2; i=$((i+1)); done
name="wren shuts down on SIGTERM"
kill -0 "$wp" 2>/dev/null && bad "$name (still running)" || ok "$name"
wp=
name="the daemon got the SIGTERM of wren, handled it and exited 0"
if grep -q "exampled: got TERM, leaving" "$T/wren.log" && grep -q "wren: exampled exited with status 0" "$T/wren.log"; then ok "$name"; else bad "$name"; fi
name="nothing of the service is left running"
if [ -n "$dp2" ] && kill -0 "$dp2" 2>/dev/null; then bad "$name"; else ok "$name"; fi
dpids=

# ---- wren was only read ----
name="no file of the wren tree was created or changed by this test"
touched=$(find "$WREN_SRC" -path "$WREN_SRC/.git" -prune -o -newer "$T/stamp" -print 2>/dev/null | head -3)
[ -z "$touched" ] && ok "$name" || { bad "$name"; echo "$touched" | sed 's/^/    /'; }
exit $fail
