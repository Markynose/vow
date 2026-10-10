#!/bin/sh
# SPDX-License-Identifier: LGPL-3.0-only
# the documents against the tree: every `make target`, and every path under tests/, tools/, dist/, examples/, src/, include/,
# third-party/ or LICENSES/ that a markdown file puts in backticks, must exist. it catches the drift that reading misses:
# a renamed script, a target that was dropped, a file that moved. it does not check that the sentences are true.
# things that are named on purpose and are not in this tree are listed below (a kernel header, files of wren).
set -u
cd "$(dirname "$0")/.." || exit 2
python3 - <<'PY'
import re, subprocess, sys
files = subprocess.run("(git ls-files; git ls-files --others --exclude-standard) | sort -u", shell=True, capture_output=True, text=True).stdout.split()
tracked = set(files)
docs = [f for f in files if f.endswith(".md") or f == "LICENSE"]
targets = set(re.findall(r"^([A-Za-z][A-Za-z0-9_.-]*):", open("Makefile").read(), re.M))
external = ("include/uapi/",)                      # a path in the linux source tree
external_in = {"tools/vow-run/WREN.md": ("src/sv.c", "src/wren.c", "src/ctl.c")}     # files of wren, named where wren is discussed
bad = []
for d in docs:
    for m in re.finditer(r"`([^`\n]+)`", open(d).read()):
        s = m.group(1).strip()
        mm = re.match(r"^make\s+([a-z][a-z0-9/.-]*)", s)
        if mm and mm.group(1) not in targets and not mm.group(1).startswith("build/"):
            bad.append("%s: `%s`: no such make target" % (d, s))
        p = re.match(r"^(?:sh |python3 )?((?:tests|tools|dist|examples|src|include|third-party|LICENSES)/[A-Za-z0-9_./+-]+)", s)
        if not p: continue
        path = p.group(1).rstrip(".,;:")
        if "*" in path or path.endswith("/"): continue
        if path.startswith(external) or path in external_in.get(d, ()): continue
        if path not in tracked and not any(t.startswith(path + "/") for t in tracked):
            bad.append("%s: `%s`: no such file" % (d, path))
n = len(docs)
for b in sorted(set(bad)): print("    " + b)
print(("FAIL  " if bad else "pass  ") + ("%d reference(s) in the documents point at nothing" % len(set(bad)) if bad else "every make target and every path named in the %d documents exists" % n))
sys.exit(1 if bad else 0)
PY
