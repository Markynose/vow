#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""
usage: python3 tests/tree_listing.py ROOT

prints one line per file, symlink and directory under ROOT/usr, ROOT/var/db/kiss and ROOT/etc/wren (ROOT empty or / for the real
root), without crossing a mount point:   type mode uid:gid size path     (path relative to ROOT; directories show - for the size,
because the size of a directory changes with its entries and says nothing). it is the state that tests/real_root_install.sh
compares before and after an install. it does not use find or stat: the shell of the system is busybox, whose find has no -printf,
and an empty listing there made every comparison pass without comparing anything; so the callers also refuse an empty listing.
"""
import os, stat, sys

TREES = ("usr", "var/db/kiss", "etc/wren")


def walk(root, rel, dev, out):
    path = os.path.join(root, rel)
    try:
        st = os.lstat(path)
    except OSError:
        return
    if st.st_dev != dev and rel not in TREES:
        return                                  # another mount point
    kind = "d" if stat.S_ISDIR(st.st_mode) else "l" if stat.S_ISLNK(st.st_mode) else "f" if stat.S_ISREG(st.st_mode) else "o"
    size = "-" if kind == "d" else str(st.st_size)
    out.append("%s %o %d:%d %s %s" % (kind, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, size, rel.replace("\n", "\\n")))
    if kind == "d":
        try:
            with os.scandir(path) as it:
                names = sorted(e.name for e in it)
        except OSError:
            return
        for n in names:
            walk(root, os.path.join(rel, n), st.st_dev, out)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else "/"
    out = []
    for t in TREES:
        try:
            dev = os.lstat(os.path.join(root, t)).st_dev
        except OSError:
            continue
        walk(root, t, dev, out)
    sys.stdout.write("\n".join(out) + ("\n" if out else ""))


main()
