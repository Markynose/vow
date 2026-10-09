#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# tests for tools/vow-run: needs build/vow-run, build/hlp_static, build/hlp_dyn (make test builds them).
# a signal death shows as 128 + n in $? of the shell, the same number vow-run -v exits with.
set -u
cd "$(dirname "$0")/.." || exit 2
B=$PWD/build
R=$B/vow-run
H=$B/hlp_static
fail=0
mkdir -p build/tmp
T=$(mktemp -d "$PWD/build/tmp/vr.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT

# landlock is needed for everything below. only a missing kernel feature skips; a vow-run that is broken must fail the tests
if ! "$R" -p "stdio exec" "$H" ok >"$T/out" 2>"$T/err"; then
	if grep -q "not implemented\|not supported" "$T/err"; then
		echo "SKIP  no landlock signal scope here (abi 6 or later needed)"
		exit 0
	fi
fi

# t name expected-status command...   (stderr goes to $T/err)
t() {
	name=$1; want=$2; shift 2
	"$@" >"$T/out" 2>"$T/err"
	got=$?
	if [ "$got" = "$want" ]; then echo "pass  $name"; else echo "FAIL  $name (status $got, wanted $want)"; fail=1; fi
}
# e name pattern: the last stderr must contain the pattern
e() {
	if grep -q -- "$2" "$T/err"; then echo "pass  $1"; else echo "FAIL  $1 (stderr: $(cat "$T/err"))"; fail=1; fi
}

t "runs a static program" 0 "$R" -p "stdio exec" "$H" ok
t "the status of the program is the status of vow-run" 10 "$R" -p "stdio inet exec" "$H" socket
t "a pledge violation kills the program with SIGSYS" 159 "$R" -p "stdio exec" "$H" socket
t "promises without exec are refused" 125 "$R" -p "stdio" "$H" ok
e "  and say why" "need exec"
t "missing promises option" 125 "$R" "$H" ok
t "no program" 125 "$R" -p "stdio exec"
t "a bad promise" 125 "$R" -p "stdio exec bogus" "$H" ok
t "an unknown promise" 125 "$R" -p "stdio exec dns" "$H" ok
t "a program that does not exist" 127 "$R" -p "stdio exec" "$T/nope"
t "a bare name that is not in PATH" 127 "$R" -p "stdio exec" no-such-program-here
t "a file that is not executable" 126 "$R" -p "stdio exec" "$T/err"
t "a directory" 126 "$R" -p "stdio exec" "$T"
printf '#!/bin/sh\nexit 0\n' >"$T/script"; chmod 755 "$T/script"
t "a script is refused" 126 "$R" -p "stdio exec" "$T/script"
e "  and the message says elf" "not an elf"
t "a dynamic program runs, its interpreter is unveiled for it" 0 "$R" -p "stdio exec" "$B/hlp_dyn" ok
t "a dynamic program is sandboxed" 0 "$R" -p "stdio rpath exec" -u /proc/self/status:r "$B/hlp_dyn" status
t "a program with its own copy of the loader" 0 "$R" -p "stdio exec" "$B/hlp_dynld" ok
t "PATH search" 0 env PATH="$B" "$R" -p "stdio exec" hlp_static ok
t "a relative name with a slash" 0 sh -c "cd '$B' && ./vow-run -p 'stdio exec' ./hlp_static ok"

mkdir "$T/a" "$T/b"; echo x >"$T/a/f"; echo y >"$T/b/f"
t "a -u directory is readable" 10 "$R" -p "stdio rpath exec" -u "$T/a:r" "$H" open "$T/a/f"
t "a path that was not unveiled is denied" 0 "$R" -p "stdio rpath exec" -u "$T/a:r" "$H" open "$T/b/f"
t "a -u path with a colon in it" 10 sh -c "mkdir -p '$T/c:d' && echo z >'$T/c:d/f' && '$R' -p 'stdio rpath exec' -u '$T/c:d:r' '$H' open '$T/c:d/f'"
t "-u without permissions" 125 "$R" -p "stdio exec" -u "$T/a" "$H" ok
t "-u with a missing path is fatal" 125 "$R" -p "stdio exec" -u "$T/missing:r" "$H" ok
t "-u with bad permissions is fatal" 125 "$R" -p "stdio exec" -u "$T/a:q" "$H" ok

t "the program is sandboxed (no_new_privs, a filter)" 0 "$R" -p "stdio rpath exec" -u /proc/self/status:r "$H" status
t "the environment is kept" 0 env VOWTEST=1 "$R" -p "stdio exec" "$H" envset
t "-i clears the environment" 1 env VOWTEST=1 "$R" -i -p "stdio exec" "$H" envset

# descriptors above 2 are closed, 1 stays
exec 7>"$T/fd7"
t "a descriptor above 2 is not inherited" 29 "$R" -p "stdio exec" "$H" writefd 7
exec 7>&-
t "standard output is" 0 "$R" -p "stdio exec" "$H" writefd 1

# shared libraries are not found for the program: -u lists them, rpath lets the loader open them
t "a library that was not unveiled is not found" 127 "$R" -p "stdio rpath exec" "$B/hlp_so"
e "  the loader says so" "Error loading shared library"
t "a library with -u and rpath" 0 "$R" -p "stdio rpath exec" -u "$B/libx.so:r" "$B/hlp_so"
t "a library with -u but without rpath is a violation" 159 "$R" -p "stdio exec" -u "$B/libx.so:r" "$B/hlp_so"

# the interpreter is named by the program file, so it is checked before it is unveiled
t "an interpreter that is a data file" 126 "$R" -p "stdio exec" "$B/hlp_bad1" ok
e "  is not executable" "not an executable file"
t "an interpreter that is a script" 126 "$R" -p "stdio exec" "$B/hlp_bad5" ok
e "  is not an elf" "not an elf"
t "an interpreter with a relative path" 126 "$R" -p "stdio exec" "$B/hlp_bad2" ok
e "  is not absolute" "not an absolute path"
t "an interpreter that does not exist" 126 "$R" -p "stdio exec" "$B/hlp_bad3" ok
e "  and the message says why" "No such file"
t "an interpreter that has an interpreter itself" 126 "$R" -p "stdio exec" "$B/hlp_bad4" ok
e "  and the message says so" "interpreter itself"

# -v
t "-v: the status of the program" 10 "$R" -v -p "stdio inet exec" "$H" socket
t "-v: a violation exits with 128 + 31" 159 "$R" -v -p "stdio exec" "$H" socket
e "  and names the syscall" "socket (41)"
e "  and the promise that would allow it" "allowed by: inet"
t "-v: a violation with no promise to allow it" 159 "$R" -v -p "stdio exec" "$H" mount
e "  and it says so" "no promise allows it"
t "-v: a violation in a second thread" 159 "$R" -v -p "stdio exec" "$H" tmount
e "  names the thread that did it" "mount (165)"
if grep -q "nanosleep" "$T/err"; then echo "FAIL  and not the thread that was only waiting"; fail=1; else echo "pass  and not the thread that was only waiting"; fi
t "-v: a violation in a dynamic program" 159 "$R" -v -p "stdio exec" "$B/hlp_dyn" socket
e "  is named too" "socket (41)"
t "-v: a program that runs" 0 "$R" -v -p "stdio rpath exec" -u /proc/self/status:r "$H" status


# ---- profiles ----
# pf writes a profile (printf escapes work in the argument), rp runs the helper under it
pf() { printf "$1" >"$T/p.vow"; }
rp() { want=$1; name=$2; shift 2; t "$name" "$want" "$R" --profile "$T/p.vow" -- "$@"; }
bad() {
	pf "$1"; rp 125 "profile refused: $2" "$H" ok; e "  with the line" "$3"
	t "check refuses it too: $2" 125 "$R" --check "$T/p.vow"; e "  with the same message" "$3"
}

mkdir "$T/sp ace" "$T/h#sh"; echo q >"$T/sp ace/f"; echo q >"$T/h#sh/f"
pf "# a comment\n\n   # an indented one\npledge = stdio rpath exec\nunveil = $T/a:r\n\nunveil = $T/sp ace:r\nunveil = $T/h#sh:r\n"
rp 10 "a profile with comments, blank lines, a path with a space" "$H" open "$T/sp ace/f"
rp 10 "a # inside a value is part of the value" "$H" open "$T/h#sh/f"
rp 10 "the profile unveils like -u" "$H" open "$T/a/f"
rp 0 "and nothing else is reachable" "$H" open "$T/b/f"
pf "pledge=stdio exec\n"
rp 0 "no spaces around = and no unveil lines" "$H" ok
pf "pledge = stdio exec"
rp 0 "no newline at the end" "$H" ok
pf "pledge = stdio exec\n"
rp 159 "the pledge of the profile is enforced" "$H" socket
pf "pledge = stdio inet exec\n"
rp 10 "and a wider one allows it" "$H" socket
t "a profile with -v" 159 "$R" -v --profile "$T/p.vow" -- "$H" mount
pf "pledge = stdio exec\n"
t "--profile=file" 0 "$R" --profile="$T/p.vow" -- "$H" ok
t "a relative profile path" 0 sh -c "cd '$T' && '$R' --profile p.vow -- '$H' ok"
t "-i and --profile together" 1 env VOWTEST=1 "$R" -i --profile "$T/p.vow" -- "$H" envset

t "--profile with -p" 125 "$R" --profile "$T/p.vow" -p "stdio exec" -- "$H" ok
e "  says why" "cannot be combined"
t "--profile with -u" 125 "$R" --profile "$T/p.vow" -u "$T/a:r" -- "$H" ok
t "-p after --profile" 125 "$R" -p "stdio exec" --profile "$T/p.vow" -- "$H" ok
t "--profile twice" 125 "$R" --profile "$T/p.vow" --profile "$T/p.vow" -- "$H" ok
t "--profile without a file" 125 "$R" --profile
t "--profile and no program" 125 "$R" --profile "$T/p.vow"
t "a profile that does not exist" 125 "$R" --profile "$T/nope.vow" -- "$H" ok
t "a profile that is a directory" 125 "$R" --profile "$T" -- "$H" ok
mkfifo "$T/fifo"
t "a profile that is a fifo does not hang" 125 "$R" --profile "$T/fifo" -- "$H" ok
e "  not a regular file" "not a regular file"

bad "unveil = $T/a:r\n" "no pledge" "no pledge line"
bad "" "an empty file" "no pledge line"
bad "# only a comment\n" "only a comment" "no pledge line"
bad "pledge = stdio exec\npledge = stdio exec\n" "a second pledge" ":2: a second pledge"
bad "pledge = stdio\n" "no exec" "need exec"
bad "pledge = stdio exec dns\n" "a promise that is not implemented" "dns is not a promise"
bad "pledge = stdio exec bogus\n" "an unknown promise" "bogus is not a promise"
bad "pledge = stdio exec exec\n" "a promise twice" "exec twice"
bad "pledge = stdio  exec\n" "two spaces between promises" "empty word"
bad "pledge = \n" "an empty pledge" "no value"
bad "pledge =\n" "an empty pledge without a space" "no value"
bad "pledge stdio exec\n" "no =" "expected directive"
bad "pledge = stdio exec\nfoo = bar\n" "an unknown directive" ":2: unknown directive foo"
bad "pledge = stdio exec\nPledge = stdio exec\n" "a directive in the wrong case" "unknown directive Pledge"
bad "pledge = stdio exec\n= x\n" "no directive" "unknown directive"
bad "pledge = stdio exec\nunveil = /tmp\n" "unveil without permissions" "expected path:permissions"
bad "pledge = stdio exec\nunveil = :r\n" "unveil with an empty path" "empty path"
bad "pledge = stdio exec\nunveil = /tmp:\n" "unveil with empty permissions" "empty permissions"
bad "pledge = stdio exec\nunveil = tmp:r\n" "a relative path" "must be absolute"
bad "pledge = stdio exec\nunveil = ./tmp:r\n" "a path starting with ." "must be absolute"
bad "pledge = stdio exec\nunveil = /tmp/../etc:r\n" "a .. component" "not allowed in the path"
bad "pledge = stdio exec\nunveil = /tmp/./x:r\n" "a . component" "not allowed in the path"
bad "pledge = stdio exec\nunveil = /tmp//x:r\n" "an empty component" "empty path component"
bad "pledge = stdio exec\nunveil = /tmp/:r\n" "a trailing slash" "no trailing slash"
bad "pledge = stdio exec\nunveil = /tmp:q\n" "a bad permission" "not a permission"
bad "pledge = stdio exec\nunveil = /tmp:rwr\n" "a permission twice" "permission r twice"
bad "pledge = stdio exec\nunveil = /tmp:x\n" "x without r" "x needs r"
bad "pledge = stdio exec\nunveil = /tmp:R\n" "an upper case permission" "not a permission"
bad "pledge = stdio exec\nunveil = /tmp:r\nunveil = /tmp:rw\n" "the same path twice" "again"
bad "pledge = stdio exec\nunveil = /tmp:r\t\n" "a tab after the value is not a space" "control character"
bad "pledge = stdio exec\nunveil =\t/tmp:r\n" "a tab" "control character"
bad "pledge = stdio exec\r\n" "a carriage return" "control character"
bad "pledge = stdio exec\nunveil = /tmp/\001x:r\n" "a control character in a path" "control character"
printf 'pledge = stdio exec\nunveil = /tmp:r\0\n' >"$T/p.vow"
rp 125 "a NUL byte in the file" "$H" ok
e "  says so" "NUL byte"
{ printf 'pledge = stdio exec\nunveil = /'; head -c 5000 /dev/zero | tr '\0' a; printf ':r\n'; } >"$T/p.vow"
rp 125 "a line longer than 4096" "$H" ok
e "  says so" "longer than"
{ printf 'pledge = stdio exec\n'; head -c 70000 /dev/zero | tr '\0' '#'; printf '\n'; } >"$T/p.vow"
rp 125 "a file larger than 64 KiB" "$H" ok
e "  says so" "larger than"
{ printf 'pledge = stdio exec\n'; i=0; while [ $i -lt 65 ]; do printf 'unveil = /tmp/r%s:r\n' $i; i=$((i+1)); done; } >"$T/p.vow"
rp 125 "more than 64 unveil lines" "$H" ok
e "  says so" "more than 64"

# ---- --check: the parser and nothing else ----
pf "# valid\npledge = stdio rpath exec\nunveil = $T/a:r\n"
t "check: a valid profile" 0 "$R" --check "$T/p.vow"
if [ -s "$T/out" ] || [ -s "$T/err" ]; then echo "FAIL  check: says nothing when the profile is valid"; fail=1; else echo "pass  check: says nothing when the profile is valid"; fi
pf "pledge = stdio exec\nunveil = /nowhere/at/all/$$:rw\nunveil = /also/missing:rwc\n"
t "check: paths that do not exist are not looked at" 0 "$R" --check "$T/p.vow"
rp 125 "  while the same profile fails when it is used" "$H" ok
e "  at the unveil" "cannot unveil"
mkdir "$T/n2"; echo x >"$T/n2/f"
pf "pledge = stdio rpath exec\nunveil = $T/n2:rw\nunveil = $T/n2/f:r\n"
t "check: a pair of rules the library refuses is not seen" 0 "$R" --check "$T/p.vow"
rp 125 "  and is refused when the profile is used" "$H" ok
e "  by the narrowing check" "asks for less"
t "check: a missing profile" 125 "$R" --check "$T/nope.vow"
t "check: a directory" 125 "$R" --check "$T"
t "check: a fifo" 125 "$R" --check "$T/fifo"
t "check: no file" 125 "$R" --check
t "check: with a program" 125 "$R" --check "$T/p.vow" -- "$H" ok
e "  says what it takes" "one profile and nothing else"
t "check: with -p" 125 "$R" --check "$T/p.vow" -p "stdio exec"
t "check: with -u" 125 "$R" --check "$T/p.vow" -u "$T/a:r"
t "check: with -i" 125 "$R" --check "$T/p.vow" -i
t "check: with -v" 125 "$R" --check "$T/p.vow" -v
t "check: with --profile" 125 "$R" --check "$T/p.vow" --profile "$T/p.vow"
t "check: twice" 125 "$R" --check "$T/p.vow" --check "$T/p.vow"
t "check: --check=file" 0 "$R" --check="$T/p.vow"
if command -v strace >/dev/null; then
	pf "pledge = stdio exec\nunveil = $T/a:r\nunveil = $T/lnk:r\n"
	strace -f -e trace=landlock_create_ruleset,landlock_add_rule,landlock_restrict_self,seccomp,prctl,execve,fork,vfork,clone,close_range -o "$T/strace.out" "$R" --check "$T/p.vow" >/dev/null 2>&1
	if grep -q "landlock\|seccomp\|prctl\|close_range\|clone\|fork" "$T/strace.out"; then echo "FAIL  check: installs no restriction and starts nothing"; fail=1; else echo "pass  check: installs no restriction and starts nothing"; fi
	strace -f -e trace=%file,%stat,%desc -o "$T/strace.out" "$R" --check "$T/p.vow" >/dev/null 2>&1
	if grep -q "$T/a\|$T/lnk" "$T/strace.out"; then echo "FAIL  check: touches no path of the profile"; fail=1; else echo "pass  check: touches no path of the profile"; fi
else
	echo "SKIP  no strace for the checks that --check installs and touches nothing"
fi

# the whole profile is checked before anything is unveiled: a missing path on line 2 and a syntax error on line 3
pf "pledge = stdio exec\nunveil = $T/does-not-exist:r\nfoo = bar\n"
rp 125 "an error late in the profile is found before the sandbox is built" "$H" ok
e "  the syntax error is the one reported" ":3: unknown directive"
pf "pledge = stdio exec\nunveil = $T/does-not-exist:r\n"
rp 125 "a path that does not exist" "$H" ok
e "  is reported with its line" ":2: cannot unveil"

# ---- the narrowing rule is the library's, with the real inodes ----
mkdir "$T/n1"; echo x >"$T/n1/f"
pf "pledge = stdio rpath exec\nunveil = $T/n1:rw\nunveil = $T/n1/f:r\n"
rp 125 "a file rule with fewer permissions than its directory" "$H" ok
e "  is reported with the line of the second rule" ":3: cannot unveil"
e "  and says what is wrong" "asks for less"
pf "pledge = stdio rpath exec\nunveil = $T/n1/f:r\nunveil = $T/n1:rw\n"
rp 125 "the same two rules in the other order" "$H" ok
e "  is reported with the line of the second rule" ":3: cannot unveil"
pf "pledge = stdio rpath exec\nunveil = $T/n1:r\nunveil = $T/n1/f:rw\n"
rp 0 "a file rule with more permissions than its directory is fine" "$H" ok
if "$R" -p "stdio rpath exec" -u "$T/n1:rs" "$H" ok >/dev/null 2>&1; then
	pf "pledge = stdio rpath exec\nunveil = $T/n1:rs\nunveil = $T/n1/f:r\n"
	rp 0 "s on a directory does not matter to a regular file below it" "$H" ok
else
	echo "SKIP  s needs landlock abi 9"
fi

# ---- the path is taken as written: nothing is resolved by the parser ----
ln -s "$T/a" "$T/lnk"; ln -s "$T/nowhere" "$T/dangling"
pf "pledge = stdio rpath exec\nunveil = $T/lnk:r\n"
rp 10 "a symlink in a profile is followed by unveil, the rule is on the target" "$H" open "$T/a/f"
rp 0 "and other paths stay denied" "$H" open "$T/b/f"
pf "pledge = stdio rpath exec\nunveil = $T/dangling:r\n"
rp 125 "a dangling symlink" "$H" ok
e "  is reported as written" "cannot unveil $T/dangling"
pf "pledge = stdio rpath exec\nunveil = $T/lnk/../b:r\n"
rp 125 "a .. after a symlink is refused by its spelling, not resolved" "$H" ok
e "  without touching the file system" "not allowed in the path"
if command -v strace >/dev/null; then
	pf "pledge = stdio rpath exec\nunveil = $T/a:r\nunveil = $T/lnk:r\nbogus = 1\n"
	strace -f -e trace=%file,%stat,%desc -o "$T/strace.out" "$R" --profile "$T/p.vow" -- "$H" ok >/dev/null 2>&1
	if grep -q "$T/a\|$T/lnk" "$T/strace.out"; then echo "FAIL  the parser touched a path of the profile"; fail=1; else echo "pass  the parser touches no path of the profile"; fi
else
	echo "SKIP  no strace for the check that the parser touches no path"
fi

# ---- a profile that changes, or lies about its size, while it is read ----
big=$(head -c 100000 /dev/zero | tr '\0' a)
t "a regular file that reports no size but has 100 KB" 125 "$R" --profile /proc/self/cmdline -- "$H" ok "$big"
e "  is cut at the limit" "larger than"
t "the same with a small one (it holds NUL bytes)" 125 "$R" --profile /proc/self/cmdline -- "$H" ok
e "  and is refused" "NUL byte"
pf "pledge = stdio rpath exec\nunveil = $T/a:r\n"; cp "$T/p.vow" "$T/pa.keep"
pf "pledge = stdio rpath exec\nunveil = $T/b:r\n"; cp "$T/p.vow" "$T/pb.keep"
( n=0; while [ $n -lt 400 ]; do
	cp "$T/pa.keep" "$T/p.vow"; : >"$T/p.vow"; cp "$T/pb.keep" "$T/p.vow"
	printf 'pledge = stdio rpath exec\nunveil = %s/a:' "$T" >"$T/p.vow"; head -c 3000 /dev/zero | tr '\0' x >>"$T/p.vow"
	cp "$T/pa.keep" "$T/p.vow"; n=$((n+1)); done ) &
writer=$!
badr=0; i=0; ra=0; rb=0
while [ $i -lt 250 ]; do
	"$R" --profile "$T/p.vow" -- "$H" open "$T/a/f" >/dev/null 2>&1; c=$?
	case $c in 10) ra=$((ra+1));; 0|125) rb=$((rb+1));; *) badr=$((badr+1));; esac
	i=$((i+1))
done
wait $writer
if [ $badr = 0 ]; then echo "pass  a profile rewritten while it is read: only a run or a clean error ($ra read a, $rb other)"; else echo "FAIL  a profile rewritten while it is read ($badr odd statuses)"; fail=1; fi

# the program file replaced while vow-run starts: it runs sandboxed or it does not run, never unsandboxed
cp "$H" "$T/prog"
( n=0; while [ $n -lt 300 ]; do cp "$H" "$T/prog.new" && mv -f "$T/prog.new" "$T/prog"; n=$((n+1)); done ) &
swapper=$!
bad=0; i=0
while [ $i -lt 150 ]; do
	"$R" -p "stdio rpath exec" -u /proc/self/status:r "$T/prog" status >/dev/null 2>&1
	case $? in 0|125|126|127) ;; *) bad=$((bad+1));; esac
	i=$((i+1))
done
wait $swapper
if [ $bad = 0 ]; then echo "pass  a replaced program file never runs unsandboxed"; else echo "FAIL  a replaced program file ($bad bad runs)"; fail=1; fi

# the same for the interpreter of a dynamic program: replaced while vow-run starts, the unveil rule is on the old file
cp -L "$B/ldcopy.so" "$T/ld.keep"
( n=0; while [ $n -lt 300 ]; do cp "$T/ld.keep" "$B/ldcopy.new" && mv -f "$B/ldcopy.new" "$B/ldcopy.so"; n=$((n+1)); done ) &
swapper=$!
bad=0; i=0
while [ $i -lt 150 ]; do
	"$R" -p "stdio rpath exec" -u /proc/self/status:r "$B/hlp_dynld" status >/dev/null 2>&1
	case $? in 0|125|126|127) ;; *) bad=$((bad+1));; esac
	i=$((i+1))
done
wait $swapper
cp "$T/ld.keep" "$B/ldcopy.so"
if [ $bad = 0 ]; then echo "pass  a replaced interpreter never runs unsandboxed"; else echo "FAIL  a replaced interpreter ($bad bad runs)"; fail=1; fi
exit $fail
