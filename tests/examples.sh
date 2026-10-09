#!/bin/sh
# run the example programs and check what they print. needs build/ examples built (make examples).
# netclient needs python3 for a throwaway server; without it that part is skipped.
set -u
cd "$(dirname "$0")/.." || exit 2
fail=0
mkdir -p build/tmp
T=$(mktemp -d "$PWD/build/tmp/ex.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT

ok() { echo "pass  $1"; }
bad() { echo "FAIL  $1"; fail=1; }

printf 'hello\n' >"$T/in"
mkdir "$T/out"

[ "$(build/cli "$T/in" "$T/in")" = "$(printf 'hello\nhello')" ] && ok "cli prints the files it was given" || bad "cli prints the files it was given"
build/cli "$T/nope" >/dev/null 2>&1 && bad "cli fails on a missing file" || ok "cli fails on a missing file"

build/fileproc "$T/in" "$T/out" up
[ "$(cat "$T/out/up" 2>/dev/null)" = "HELLO" ] && ok "fileproc writes the upper cased copy" || bad "fileproc writes the upper cased copy"
build/fileproc "$T/in" "$T/missing" up >/dev/null 2>&1 && bad "fileproc fails on a missing directory" || ok "fileproc fails on a missing directory"

out=$(build/progressive "$T/in" 2>/dev/null); rc=$?
[ "$rc" = 159 ] && ok "progressive is killed by SIGSYS" || bad "progressive is killed by SIGSYS (status $rc)"
case $out in
*"config says: hello"*"rpath given up"*) ok "progressive prints before the violation";;
*) bad "progressive prints before the violation";;
esac
case $out in *"not reached"*) bad "progressive stops at the violation";; *) ok "progressive stops at the violation";; esac

if command -v python3 >/dev/null; then
	python3 - <<'P' &
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 17777))
s.listen(1)
c, _ = s.accept()
d = c.recv(100)
c.sendall(b"echo: " + d)
c.close()
P
	sleep 1
	[ "$(build/netclient 127.0.0.1 17777 hello 2>&1)" = "echo: hello" ] && ok "netclient talks to a server" || bad "netclient talks to a server"
	wait
else
	echo "SKIP  netclient (no python3)"
fi
build/netclient not-an-address 1 x >/dev/null 2>&1 && bad "netclient refuses a name" || ok "netclient refuses a name"
exit $fail
