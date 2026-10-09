#!/bin/sh
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
