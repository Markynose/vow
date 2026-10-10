#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# every check that a release needs, in order, with one result at the end. see RELEASE.md.
#
# usage: sh tests/release_gate.sh                  on the release commit (HEAD, clean tree): the strict gate
#        sh tests/release_gate.sh --worktree       on a tree that is not committed yet (a throwaway commit of it is
#                                                  used where a commit is needed; the strict commit and tag facts are only reported)
#        --no-mutants                              leave out the mutants (about half an hour): not a release gate any more
#
# the output of each step is kept in the log directory that is printed first. needs git, python3, nerd (for the install
# tests; a missing nerd is a failure here, not a skip: a release is not made without them), strace, cc, make.
set -u
cd "$(dirname "$0")/.." || exit 2
rev=HEAD; strict=--release; mutants=1
for a in "$@"; do
	case $a in
	--worktree) rev=WORKTREE; strict= ;;
	--no-mutants) mutants=0 ;;
	*) echo "usage: release_gate.sh [--worktree] [--no-mutants]"; exit 2 ;;
	esac
done
base=${KI_BASE:-$PWD/build/tmp}
log=$PWD/release-gate-log
mkdir -p "$log"
rm -f "$log"/*.txt
echo "log directory: $log"
fail=0; n=0
step() { # name, command...
	name=$1; shift; n=$((n+1)); f=$log/$(printf '%02d' $n)-$(echo "$name" | tr -c 'a-zA-Z0-9\n' '-' | cut -c1-40).txt
	t0=$(date +%s)
	if "$@" >"$f" 2>&1; then r=PASS; else r=FAIL; fail=1; fi
	printf '%-5s %-62s %4ss  %s\n' "$r" "$name" "$(( $(date +%s) - t0 ))" "$(basename "$f")"
}
have() { command -v "$1" >/dev/null; }

for c in git python3 nerd strace cc make; do have $c || { echo "FAIL  $c is needed"; exit 1; }; done

# 1. the commit and the metadata
step "the release facts: commit, version, tag, archive, static binary" sh tests/release_check.sh $strict $rev
# 2. the whole regression on a clean build
step "clean build, all tests, header check, static check" sh -c 'make clean >/dev/null 2>&1; mkdir -p build/tmp; make all tools check-header test static-check'
# 3. the fuzzers, six seeds each
step "library fuzz, seeds 1 to 6 (20000 tables, 600 through the kernel)" sh -c 'for s in 1 2 3 4 5 6; do VOW_FUZZ_SEED=$s VOW_FUZZ_N=20000 VOW_FUZZ_KN=600 TMPDIR=$PWD/build/tmp ./build/fuzz_test || exit 1; done'
step "profile fuzz, seeds 1 to 6 (2000 profiles each)" sh -c 'for s in 1 2 3 4 5 6; do python3 tests/profile_fuzz.py $s 2000 || exit 1; done'
# 4. the kiss package with nerd, unprivileged and as root of a namespace
step "kiss package with nerd, isolated root" sh tests/kiss_install.sh $rev
step "kiss package with nerd, root of a disposable namespace" sh tests/kiss_install_ns.sh $rev
# 5. the example of a wren service
step "wren example under a scratch wren" sh tests/wren_example.sh
# 6. the mutants
mutants_ok() {
	python3 tests/mutate.py >"$log/mutants-raw.txt" 2>&1
	total=$(python3 -c '
import ast
t = ast.parse(open("tests/mutate.py").read())
print([len(n.value.elts) for n in t.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "M"][0])')
	caught=$(grep -c ": CAUGHT by" "$log/mutants-raw.txt")
	broken=$(grep -cE "NOT CAUGHT|BUILD FAILED|PATTERN MISSING" "$log/mutants-raw.txt")
	echo "caught $caught of $total, not caught or broken: $broken"
	[ "$caught" = "$total" ] && [ "$broken" = 0 ]
}
if [ $mutants = 1 ]; then
	step "every mutant is caught" mutants_ok
fi
# 7. the build left behind by the mutant script is gone: rebuild and look at the result once more
rebuild_ok() {
	make clean >/dev/null 2>&1; mkdir -p build/tmp
	make all tools static-check && sh tests/release_check.sh $strict $rev
}
step "rebuild after the mutants, static check, release facts again" rebuild_ok

echo
if [ $fail = 0 ]; then echo "GATE PASSED ($n steps)"; else echo "GATE FAILED: see $log"; fi
[ $mutants = 0 ] && echo "note: the mutants were not run; this is not a release gate"
[ -n "$strict" ] && echo "note: tag and archive facts above are for $(git rev-parse HEAD)"
exit $fail
