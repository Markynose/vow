#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# usage: sh tests/snapshot.sh DIR
# makes a throwaway git repository in DIR that holds the files of the working tree (tracked files and new ones
# that are not ignored) as a single commit, and prints the commit id. the tests that need a commit (the package,
# the release check) use it to test a tree that is not committed yet; DIR is deleted by the caller.
set -eu
cd "$(dirname "$0")/.."
dir=${1:?usage: snapshot.sh DIR}
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
mkdir -p "$dir"
(git ls-files; git ls-files --others --exclude-standard) | sort -u | while read -r f; do
	[ -f "$f" ] || continue
	mkdir -p "$dir/$(dirname "$f")"
	cp -p "$f" "$dir/$f"
done
git -C "$dir" init -q
git -C "$dir" add -A
git -C "$dir" -c user.name=snapshot -c user.email=snapshot@invalid -c commit.gpgsign=false commit -q -m snapshot
git -C "$dir" rev-parse HEAD
