#!/bin/sh
# run the whole suite on the running kernel and print one line per binary plus the landlock abi.
# copy the repo (or only build/ and tests/) into each kernel under test and run this there.
# usage: sh tests/kernel_matrix.sh
set -u
cd "$(dirname "$0")/.." || exit 2
mkdir -p build/tmp
export TMPDIR="$PWD/build/tmp"
echo "kernel: $(uname -r)"
for t in unveil_test filter_test seccomp_test fuzz_test; do
	[ -x build/$t ] || { echo "$t: missing, run make test first"; continue; }
	build/$t </dev/null >build/$t.log 2>&1
	echo "$t: $(grep -E '[0-9]+ passed' build/$t.log | tail -1)"
	grep -E '^FAIL' build/$t.log | sed 's/^/  /'
done
