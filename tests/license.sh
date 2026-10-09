#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# the license coverage of the tree: every file has the license its place asks for, the two texts are the official
# ones, the library never takes GPL code, and no binary is tracked. see LICENSE and LICENSING.md.
set -u
cd "$(dirname "$0")/.." || exit 2
fail=0
ok() { echo "pass  $1"; }
bad() { echo "FAIL  $1"; fail=1; }

# the texts: unchanged copies of gnu.org gpl-3.0.txt and lgpl-3.0.txt, and the 0BSD text of the SPDX list with
# the copyright line filled in
for pair in "GPL-3.0-only 3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986" \
    "LGPL-3.0-only e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118" \
    "0BSD 90703490ba12b83e024fe79c018f2d4aed0520ed85b3b8ac16f27b3189ea20da"; do
	id=${pair% *}; sum=${pair#* }
	if [ "$(sha256sum "LICENSES/$id.txt" 2>/dev/null | cut -d' ' -f1)" = "$sum" ]; then ok "LICENSES/$id.txt is the expected text"; else bad "LICENSES/$id.txt is not the expected text"; fi
done
# the notice of musl, as it is in the release 1.2.6 (the license of the third party code that is linked into the binaries)
if [ "$(sha256sum third-party/musl/COPYRIGHT 2>/dev/null | cut -d' ' -f1)" = "b870108ec5e7790e9f9919064f1b9421d62d5f9b0e6c230c6adf7ea2da62e97b" ]; then ok "third-party/musl/COPYRIGHT is the notice of musl 1.2.6, unchanged"; else bad "third-party/musl/COPYRIGHT is not the notice of musl 1.2.6"; fi

# the files: tracked ones and new ones that are not ignored
files=$( (git ls-files; git ls-files --others --exclude-standard) 2>/dev/null | sort -u)
if [ -z "$files" ]; then echo "SKIP  not a git checkout"; exit $fail; fi
n=0; missing=0; wrong=0; elf=0; ids=
for f in $files; do
	[ -f "$f" ] || continue
	n=$((n+1))
	if [ "$(head -c 4 "$f")" = "$(printf '\177ELF')" ]; then elf=$((elf+1)); echo "    binary tracked: $f"; fi
	case $f in
	LICENSE|LICENSES/*|third-party/*|.gitignore|dist/kiss/vow/version|dist/kiss/vow/sources) continue ;;
	esac
	case $f in
	tools/vow-run/*|tests/vow_run.sh|tests/profile_fuzz.py) want=GPL-3.0-only ;;
	examples/*) want=0BSD ;;
	*) want=LGPL-3.0-only ;;
	esac
	got=$(head -n 3 "$f" | sed -n 's/.*SPDX-License-Identifier: \([A-Za-z0-9.+-]*\).*/\1/p' | head -n 1)
	if [ -z "$got" ]; then missing=$((missing+1)); echo "    no SPDX line: $f"
	elif [ "$got" != "$want" ]; then wrong=$((wrong+1)); echo "    $f is $got, its place asks for $want"; fi
	case " $ids " in *" $got "*) ;; *) ids="$ids $got" ;; esac
done
[ $missing = 0 ] && ok "every file says which license it has ($n files)" || bad "files without an SPDX line: $missing"
[ $wrong = 0 ] && ok "every file has the license of its place" || bad "files with the wrong license: $wrong"
[ $elf = 0 ] && ok "no binary is tracked" || bad "binaries tracked: $elf"

# every license that is used has its text
for id in $ids; do
	if [ -s "LICENSES/$id.txt" ]; then ok "LICENSES/$id.txt exists for the files that use it"; else bad "LICENSES/$id.txt is missing"; fi
done

# the library side takes nothing from the GPL side
if grep -rn "tools/\|profile\.h\|sysnames\.h" include src examples >/dev/null 2>&1; then bad "include, src or examples refer to tools/"; else ok "include, src and examples do not refer to tools/"; fi
if grep -rln "GPL-3.0-only" include src examples 2>/dev/null | xargs -r grep -L "LGPL-3.0-only" 2>/dev/null | grep -q .; then bad "GPL-only file on the library side"; else ok "no GPL-only file on the library side"; fi

# the documents that explain it exist and name both licenses
if grep -q "LGPL-3.0-only" LICENSE && grep -q "GPL-3.0-only" LICENSE && grep -q "0BSD" LICENSE && grep -q "third-party/musl" LICENSE && [ -f LICENSING.md ]; then
	ok "LICENSE and LICENSING.md exist and name the licenses and the third party notice"
else bad "LICENSE or LICENSING.md missing or incomplete"; fi
exit $fail
