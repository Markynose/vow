#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""
mutation check: apply one small wrong change to a source file, build the tests, run them, and expect
at least one test to fail. the file is restored afterwards (also on errors).

    python3 tests/mutate.py            all mutants
    python3 tests/mutate.py 2 5        only these numbers

a mutant that does not compile is reported as BUILD FAILED and is not a result. NOT CAUGHT is a hole
in the tests (or an equivalent mutant: a change that does not change behavior, listed in a comment).

nothing of a mutant survives the run: the source is put back after every mutant, and when the script ends
(also on an error or a signal) build/ is removed, so no mutant executable can be mistaken for a good one.
rebuild with make afterwards. if the script is killed without a chance to clean up (SIGKILL), .mutate/ keeps
the original of the file that was changed; the next start restores it, and `python3 tests/mutate.py --restore`
does only that. `make test` refuses to run while .mutate/ exists.
"""
import os, subprocess, sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

M = [
 ("unveil commit without the thread check", "unveil.c",
  "\terr = vow_threads_single();\n\tif (err <= 0) {\n\t\tif (err == 0)\n\t\t\terrno = EBUSY;\n\t\treturn -1;\n\t}\n\tmemset(&attr, 0, sizeof attr);",
  "\tmemset(&attr, 0, sizeof attr);"),
 ("scope without the thread check", "scope.c", "\tif (check) {", "\tif (0) {"),
 ("filter lets landlock tsync through", "filter.c",
  "static const struct vow_cond c_llrestrict[] = { EQ32(1, 0) };",
  "static const uint32_t llf[] = { 0, 8 };\nstatic const struct vow_cond c_llrestrict[] = { IN32(1, llf) };"),
 ("no check after the domain (unveil)", "unveil.c",
  "\tif (vow_threads_single() != 1) {\n\t\terrno = EBUSY;\n\t\treturn -1;\n\t}\n\treturn 0;\nfail:", "\treturn 0;\nfail:"),
 ("no check after the domain (scope)", "scope.c",
  "\tif (check && vow_threads_single() != 1) {", "\tif (0 && check && vow_threads_single() != 1) {"),
 ("thread list not reopened in the child", "unveil.c", "\ttlock = 0;\n\ttask_stale = 1;", "\ttlock = 0;"),
 ("a thread list that cannot be read counts as one thread", "unveil.c", "\telse if (c < 0)\n\t\tc = 0;", "\telse if (c < 0)\n\t\tc = 1;"),
 ("no retry for a joined thread", "unveil.c", "for (i = 0; i < 2000; i++) {\n\t\tc = threads_count_locked();", "for (i = 0; i < 1; i++) {\n\t\tc = threads_count_locked();"),
 ("old abi silently accepted", "scope.c", "\tif (a < VOW_SCOPE_ABI) {\n\t\terrno = ENOSYS;\n\t\treturn -1;\n\t}", "\tif (a < VOW_SCOPE_ABI)\n\t\treturn 0;"),
 ("scope error ignored", "pledge.c", "\t\tif (vow_scope_enter() < 0)\n\t\t\treturn -1;", "\t\tif (vow_scope_enter() < 0)\n\t\t\t(void)0;"),
 ("stdio without tkill", "filter.c", "ALLOW(kill), ALLOW(tgkill), ALLOW(tkill),", "ALLOW(kill), ALLOW(tgkill),"),
 ("scope entered again on every pledge", "pledge.c", "\t\tscoped = 1;", "\t\tscoped = 0;"),
 ("no atfork handlers", "fork.c", "if (!__sync_lock_test_and_set(&done, 1)) {", "if (0 && !__sync_lock_test_and_set(&done, 1)) {"),
 ("scope domain handles a filesystem right", "scope.c", "\tattr.scoped = VOW_LL_SCOPE_SIGNAL;", "\tattr.scoped = VOW_LL_SCOPE_SIGNAL;\n\tattr.handled_access_fs = VOW_LL_FS_EXECUTE;"),
 ("inet domains add AF_UNIX", "filter.c", "static const uint32_t inet_domains[] = { 2 /* AF_INET */, 10 /* AF_INET6 */ };", "static const uint32_t inet_domains[] = { 1, 2, 10 };"),
 ("setsockopt allows SO_ATTACH_FILTER", "filter.c", "static const uint32_t so_sock[] = { 2, 5,", "static const uint32_t so_sock[] = { 26, 2, 5,"),
 ("exec without execveat", "filter.c", "\tALLOW(execve), ALLOW(execveat),\n};", "\tALLOW(execve),\n};"),
 ("socket type flag mask too small", "filter.c", "~(uint32_t)(0x800 | 0x80000)", "~(uint32_t)(0x800)"),
 ("stream sockets allow sctp", "filter.c", "static const uint32_t inet_proto_stream[] = { 0, 6 };", "static const uint32_t inet_proto_stream[] = { 0, 6, 132 };"),
 ("seccomp flags allow SPEC_ALLOW", "filter.c", "static const uint32_t seccomp_flags[] = { 0, VOW_SECCOMP_FILTER_FLAG_TSYNC };", "static const uint32_t seccomp_flags[] = { 0, VOW_SECCOMP_FILTER_FLAG_TSYNC, 4 };"),
 ("O_TRUNC ignored", "filter.c", "\tif (f & VOW_O_TRUNC)\n\t\tneed |= NEED_W;", "\tif (0)\n\t\tneed |= NEED_W;"),
 ("access mode 3 as read only", "filter.c", "\tdefault:\t/* O_RDWR, and 3, which the kernel checks as read and write */\n\t\tneed |= NEED_R | NEED_W;", "\tcase VOW_O_RDWR:\n\t\tneed |= NEED_R | NEED_W;\n\t\tbreak;\n\tdefault:\n\t\tneed |= NEED_R;"),
 ("renameat2 without the whiteout check", "filter.c", "NOFLAG(4, VOW_RENAME_WHITEOUT)", "NOFLAG(4, 0)"),
 ("linkat without the empty-path check", "filter.c", "NOFLAG(4, VOW_AT_EMPTY_PATH)", "NOFLAG(4, 0)"),
 ("fallocate dropped from wpath", "filter.c", "ALLOW(truncate), ALLOW(ftruncate), ALLOW(fallocate),", "ALLOW(truncate), ALLOW(ftruncate),"),
 ("socketpair domain read as 64 bits", "filter.c", "static const struct vow_cond c_socketpair[] = { EQ32(0, 1) };", "static const struct vow_cond c_socketpair[] = { EQ64(0, 1) };"),
 ("sendto address read as 32 bits", "filter.c", "c_sendto[] = { EQ64(4, 0) }", "c_sendto[] = { EQ32(4, 0) }"),
 ("generator: maskeq masks with the value", "filter.c", "\temit(b, VOW_BPF_ALU | VOW_BPF_AND | VOW_BPF_K, 0, 0, c->m);", "\temit(b, VOW_BPF_ALU | VOW_BPF_AND | VOW_BPF_K, 0, 0, lo);"),
 ("generator: onlybits does not invert", "filter.c", "0, 0, ~lo);", "0, 0, lo);"),
 ("generator: notallbits jumps the wrong way", "filter.c", "fix_add(b, f, nf, at, 1);\n\t\tbreak;\n\tcase VC_ONLYBITS", "fix_add(b, f, nf, at, 0);\n\t\tbreak;\n\tcase VC_ONLYBITS"),
 ("generator: high word of a 64 bit compare not loaded", "filter.c", "LD(b, VOW_SD_ARG(c->arg) + 4);", "LD(b, VOW_SD_ARG(c->arg));"),
 # equivalent mutant, expected NOT CAUGHT: dropping the x32 check changes nothing, because an x32 number
 # matches no rule and is denied anyway (the check is kept as a second line of defence)
 ("unveil: no check that the string names the pinned inode", "unveil.c", "if (stat(canon, &cst) < 0 || cst.st_dev != st.st_dev || cst.st_ino != st.st_ino) {", "if (stat(canon, &cst) < 0) {"),
 ("vow-run: no seal", "../tools/vow-run/vow-run.c", "\tif (unveil(NULL, NULL) < 0)\n\t\tdie(EXIT_SETUP, \"unveil: %s\", strerror(errno));\n", ""),
 ("vow-run: descriptors not closed", "../tools/vow-run/vow-run.c", "\tclose_fds();\n", "\t(void)close_fds;\n"),
 ("vow-run: exec not required in the promises", "../tools/vow-run/vow-run.c", "if ((promise_set(promises) & P_EXEC) == 0)", "if (0)"),
 ("vow-run: a failed -u rule ignored", "../tools/vow-run/vow-run.c", "if (unveil(rules[i].path, rules[i].perms) < 0)", "if (0)"),
 ("vow-run: a failed pledge ignored", "../tools/vow-run/vow-run.c", "if (pledge(promises, NULL) < 0)", "if (pledge(promises, NULL) < 0 && 0)"),
 ("vow-run: the interpreter of a dynamic program is never read", "../tools/vow-run/vow-run.c", "if (ph.p_type != PT_INTERP)\n\t\t\tcontinue;", "if (1)\n\t\t\tcontinue;"),
 ("vow-run: program not executable under the rule", "../tools/vow-run/vow-run.c", "unveil(prog, \"rx\")", "unveil(prog, \"r\")"),
 ("vow-run: -i ignored", "../tools/vow-run/vow-run.c", "envp = clear ? empty : environ;", "envp = ((void)empty, (void)clear, environ);"),
 ("vow-run: -v loses the signal in the status", "../tools/vow-run/vow-run.c", "return 128 + WTERMSIG(st);", "return WTERMSIG(st);"),
 ("vow-run: -v reports threads that did nothing", "../tools/vow-run/vow-run.c", "if (act == VOW_SECCOMP_RET_ALLOW || act == ~0u)", "if ((act == VOW_SECCOMP_RET_ALLOW || act == ~0u) && 0)"),
 ("vow-run: -v never reports", "../tools/vow-run/vow-run.c", "report(w, progname, prog, n, promises))", "0 && report(w, progname, prog, n, promises))"),
 ("vow-run: the list of promises that allow it is empty", "../tools/vow-run/vow-run.c", "if (m && bpf_run(one, m, &d) == VOW_SECCOMP_RET_ALLOW) {", "if (m && bpf_run(one, m, &d) == VOW_SECCOMP_RET_ALLOW && 0) {"),
 ("vow-run: the interpreter is not unveiled", "../tools/vow-run/vow-run.c", "if (interp != NULL && unveil(interp, \"rx\") < 0)", "if (0 && interp != NULL && unveil(interp, \"rx\") < 0)"),
 ("vow-run: a relative interpreter accepted", "../tools/vow-run/vow-run.c", "if (name[0] != '/')", "if (0 && name[0] != '/')"),
 ("vow-run: an interpreter that is not an executable file accepted", "../tools/vow-run/vow-run.c", "if (stat(real, &st) < 0 || !S_ISREG(st.st_mode) || access(real, X_OK) != 0)", "if ((stat(real, &st) < 0 || !S_ISREG(st.st_mode) || access(real, X_OK) != 0) && 0)"),
 ("vow-run: an interpreter with an interpreter accepted", "../tools/vow-run/vow-run.c", "if (again != NULL)\n\t\tdie(EXIT_NOEXEC, \"%s: the interpreter %s has", "if (again != NULL && 0)\n\t\tdie(EXIT_NOEXEC, \"%s: the interpreter %s has"),
 ('profile: a second pledge accepted', '../tools/vow-run/profile.c', 'if (p->promises != NULL)\n\t\treturn fail(c, "a second pledge line");', 'if (0 && p->promises != NULL)\n\t\treturn fail(c, "a second pledge line");'),
 ('profile: an unknown directive accepted', '../tools/vow-run/profile.c', 'if (strcmp(name, "pledge") != 0 && strcmp(name, "unveil") != 0)', 'if (0)'),
 ('profile: x without r accepted', '../tools/vow-run/profile.c', 'if ((seen & 4u) && !(seen & 1u))', 'if (0 && (seen & 4u) && !(seen & 1u))'),
 ('profile: a relative path accepted', '../tools/vow-run/profile.c', "if (value[0] != '/')", "if (0 && value[0] != '/')"),
 ('profile: .. in a path accepted', '../tools/vow-run/profile.c', "if ((cl == 1 && q[0] == '.') || (cl == 2 && q[0] == '.' && q[1] == '.'))", 'if (0)'),
 ('profile: the same path twice accepted', '../tools/vow-run/profile.c', 'if (strcmp(p->rules[i].path, path) == 0)\n\t\t\treturn fail(c, "unveil: %s again', 'if (0 && strcmp(p->rules[i].path, path) == 0)\n\t\t\treturn fail(c, "unveil: %s again'),
 ('profile: control characters accepted', '../tools/vow-run/profile.c', 'if (has_control(line))', 'if (has_control(line) && 0)'),
 ('profile: a fifo accepted', '../tools/vow-run/profile.c', 'if (!S_ISREG(st.st_mode))', 'if (0 && !S_ISREG(st.st_mode))'),
 ('profile: no limit on the line length', '../tools/vow-run/profile.c', 'if (len > MAX_LINE)', 'if (len > MAX_LINE * 100)'),
 ('profile: NUL bytes accepted', '../tools/vow-run/profile.c', "if (memchr(buf, '\\0', len) != NULL)", "if (0 && memchr(buf, '\\0', len) != NULL)"),
 ('profile: a promise twice accepted', '../tools/vow-run/profile.c', 'if (seen & bit)\n\t\t\treturn fail(c, "pledge: %.*s twice"', 'if (0 && (seen & bit))\n\t\t\treturn fail(c, "pledge: %.*s twice"'),
 ('vow-run: --profile mixed with -p accepted', '../tools/vow-run/vow-run.c', 'if (from_flags)\n\t\t\tdie(EXIT_SETUP, "--profile cannot be combined', 'if (0 && from_flags)\n\t\t\tdie(EXIT_SETUP, "--profile cannot be combined'),
 ('vow-run: the rules of the profile dropped', '../tools/vow-run/vow-run.c', 'nrules = prof.nrules;', 'nrules = 0;'),
 ('unveil: the narrowing check ignores the type of the object', 'unveil.c', 'if (S_ISREG(mode))\n\t\treturn P_R | P_W | P_X | P_C;', 'if (0)\n\t\treturn P_R | P_W | P_X | P_C;'),
 ('unveil: the narrowing check looks only at the rule above', 'unveil.c', '(perms & ~tab[i].perms & reach(tab[i].mode))', '0'),
 ('unveil: no narrowing check', 'unveil.c', 'if (conflicts(e, canon, perms, st.st_mode)) {', 'if (0 && conflicts(e, canon, perms, st.st_mode)) {'),
 ('unveil: a socket node is treated like a directory', 'unveil.c', 'if (S_ISSOCK(mode))\n\t\treturn P_S | P_C;', 'if (0)\n\t\treturn P_S | P_C;'),
 ('unveil: c above a regular file is ignored', 'unveil.c', 'return P_R | P_W | P_X | P_C;\n\tif (S_ISSOCK', 'return P_R | P_W | P_X;\n\tif (S_ISSOCK'),
 ('unveil: the type of an earlier rule is forgotten', 'unveil.c', '\ttab[n].mode = st.st_mode;\n', ''),
 ('vow-run --check: parse errors ignored', '../tools/vow-run/vow-run.c', 'if (profile_load(check_file, &prof, perr, sizeof perr) < 0)', 'if (0 && profile_load(check_file, &prof, perr, sizeof perr) < 0)'),
 ('vow-run --check: a program after it accepted', '../tools/vow-run/vow-run.c', 'clear || verbose || optind < argc)', 'clear || verbose)'),
 ('vow-run --check: -p and -u accepted next to it', '../tools/vow-run/vow-run.c', 'if (from_flags || profile_file != NULL || clear || verbose || optind < argc)', 'if (profile_file != NULL || clear || verbose || optind < argc)'),
 ('vow-run --check: does not stop after the check', '../tools/vow-run/vow-run.c', 'return 0; /* --check ends here */', '/* --check ends here */'),
 ('vow-run --check: twice accepted', '../tools/vow-run/vow-run.c', 'if (check_file != NULL)\n\t\t\t\tdie(EXIT_SETUP, "--check twice");', 'if (0)\n\t\t\t\tdie(EXIT_SETUP, "--check twice");'),
 ('package: the header is not installed', '../dist/kiss/vow/build', 'install -Dm644 include/vow.h   "$1/usr/include/vow.h"\n', ''),
 ('package: no architecture guard', '../dist/kiss/vow/build', '*) echo "vow: x86-64 only, not building for $(${CC:-cc} -dumpmachine)" >&2; exit 1 ;;', '*) ;;'),
 ('package: the document of the tool is not installed', '../dist/kiss/vow/build', 'install -Dm644 tools/vow-run/DESIGN.md  "$doc/vow-run.md"\n', ''),
 ('package: mkpkg does not compare the version with the header', '../dist/kiss/mkpkg.sh', '[ "$hdr" = "$ver" ] || die', 'true || die'),
 ('package: mkpkg does not check the sources file', '../dist/kiss/mkpkg.sh', '[ "$src" = "vow-$ver.tar.gz" ] || die', 'true || die'),
 ('package: the tarball takes the tests along', '../dist/kiss/mkpkg.sh', 'examples third-party |', 'examples third-party tests |'),
 ('package: mkpkg ignores the revision it is given', '../dist/kiss/mkpkg.sh', '"$rev^{commit}"', '"HEAD^{commit}"'),
 ('package: mkpkg does not mention uncommitted changes', '../dist/kiss/mkpkg.sh', 'if [ -n "$(git -C "$root" status --porcelain 2>/dev/null)" ]; then', 'if false; then'),
 ('package: mkpkg only works from the checkout', '../dist/kiss/mkpkg.sh', 'root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null)', 'root=$(git rev-parse --show-toplevel 2>/dev/null)'),
 ('package: the license texts are not installed', '../dist/kiss/vow/build', 'install -Dm644 LICENSES/GPL-3.0-only.txt    "$lic/GPL-3.0-only.txt"\n', ''),
 ('package: a libc other than musl goes unmentioned', '../dist/kiss/vow/build', '*) echo "vow: warning: $(${CC:-cc} -dumpmachine) is not musl; only x86-64 musl is supported and tested" >&2 ;;', '*) ;;'),
 ('license: a library file without its SPDX line', 'pledge.c', '/* SPDX-License-Identifier: LGPL-3.0-only */\n', ''),
 ('license: a library file under the GPL', 'lock.h', '/* SPDX-License-Identifier: LGPL-3.0-only */', '/* SPDX-License-Identifier: GPL-3.0-only */'),
 ('license: a launcher file under the LGPL', '../tools/vow-run/profile.c', '/* SPDX-License-Identifier: GPL-3.0-only */', '/* SPDX-License-Identifier: LGPL-3.0-only */'),
 ('license: the library refers to the launcher', 'fork.c', '/* SPDX-License-Identifier: LGPL-3.0-only */\n', '/* SPDX-License-Identifier: LGPL-3.0-only */\n/* see tools/vow-run/profile.h */\n'),
 ('license: a license text that is not the official one', '../LICENSES/LGPL-3.0-only.txt', 'GNU LESSER GENERAL PUBLIC LICENSE', 'GNU LESSER GENERAL PUBLIC LICENCE'),
 ('license: an example under the LGPL', '../examples/cli.c', '/* SPDX-License-Identifier: 0BSD */', '/* SPDX-License-Identifier: LGPL-3.0-only */'),
 ('license: the musl notice altered', '../third-party/musl/COPYRIGHT', 'Rich Felker', 'Rich Felkr'),
 ('license: the 0BSD text altered', '../LICENSES/0BSD.txt', 'with or without fee', 'with fee'),
 ('package: the musl notice is not installed', '../dist/kiss/vow/build', 'install -Dm644 third-party/musl/COPYRIGHT   "$lic/musl-COPYRIGHT"\n', ''),
 ('package: the 0BSD text is not installed', '../dist/kiss/vow/build', 'install -Dm644 LICENSES/0BSD.txt            "$lic/0BSD.txt"\n', ''),
 ('package: the examples are not installed', '../dist/kiss/vow/build', 'install -Dm644 "$f" "$doc/examples/${f##*/}"', ':'),
 ('package: the tarball leaves out the third party notice', '../dist/kiss/mkpkg.sh', 'examples third-party |', 'examples |'),
]

def sh(cmd, t):
    try:
        r = subprocess.run(cmd, shell=True, cwd=root, capture_output=True, text=True, timeout=t, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        return 124, "timeout"

import atexit, shutil, signal

STATE = os.path.join(root, ".mutate")


def restore_stale():
    stamp = os.path.join(STATE, "stamp")
    if not os.path.exists(stamp):
        shutil.rmtree(STATE, ignore_errors=True)	# interrupted before the source was touched
        return False
    target = open(stamp).read().strip()
    shutil.copyfile(os.path.join(STATE, "orig"), target)
    shutil.rmtree(STATE)
    print("restored %s from an interrupted run" % target, flush=True)
    return True


def finish():
    restore_stale()
    sh("make clean >/dev/null 2>&1", 60)


def on_signal(signum, frame):
    raise SystemExit(128 + signum)


if "--restore" in sys.argv:
    restore_stale()
    sys.exit(0)
restore_stale()
only = sys.argv[1:]
for sg in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(sg, on_signal)
atexit.register(finish)
os.makedirs(os.path.join(root, "build", "tmp"), exist_ok=True)
for i, (label, f, old, new) in enumerate(M):
    if only and str(i) not in only:
        continue
    p = os.path.normpath(os.path.join(root, "src", f))
    orig = open(p).read()
    if old not in orig:
        print("[%d] %s: PATTERN MISSING" % (i, label), flush=True)
        continue
    os.makedirs(STATE, exist_ok=True)
    open(os.path.join(STATE, "orig"), "w").write(orig)
    open(os.path.join(STATE, "stamp"), "w").write(p + "\n")
    open(p, "w").write(orig.replace(old, new, 1))
    try:
        if label.startswith("license:"):
            rc, out = sh("sh tests/license.sh 2>&1 | grep -E '^FAIL'", 120)
            fails = [l.strip() for l in out.splitlines() if l.startswith("FAIL")]
            if fails:
                print("[%d] %s: CAUGHT by license.sh (%d failures; first: %s)" % (i, label, len(fails), fails[0][6:70]), flush=True)
            else:
                print("[%d] %s: NOT CAUGHT" % (i, label), flush=True)
            continue
        if f.startswith("../dist/"):
            rc, out = sh("sh tests/package.sh 2>&1 | grep -E '^FAIL'", 600)
            fails = [l.strip() for l in out.splitlines() if l.startswith("FAIL")]
            if fails:
                print("[%d] %s: CAUGHT by package.sh (%d failures; first: %s)" % (i, label, len(fails), fails[0][6:70]), flush=True)
            else:
                print("[%d] %s: NOT CAUGHT" % (i, label), flush=True)
            continue
        if f.startswith("../tools/"):
            rc, out = sh("make build/vow-run build/hlp_static build/hlp_dyn 2>&1 | grep -E 'error|job failed'", 300)
            if out.strip():
                print("[%d] %s: BUILD FAILED: %s" % (i, label, out.strip()[:120]), flush=True)
                continue
            rc, out = sh("sh tests/vow_run.sh 2>&1 | grep -E '^FAIL'", 600)
            fails = [l.strip() for l in out.splitlines() if l.startswith("FAIL")]
            if fails:
                print("[%d] %s: CAUGHT by vow_run.sh (%d failures; first: %s)" % (i, label, len(fails), fails[0][6:70]), flush=True)
            else:
                print("[%d] %s: NOT CAUGHT" % (i, label), flush=True)
            continue
        rc, out = sh("make build/filter_test build/fuzz_test build/seccomp_test build/unveil_test 2>&1 | grep -E 'error|job failed'", 300)
        if out.strip():
            print("[%d] %s: BUILD FAILED: %s" % (i, label, out.strip()[:120]), flush=True)
            continue
        fails = []
        for t in ("filter_test", "fuzz_test", "unveil_test", "seccomp_test"):
            rc, out = sh("TMPDIR=%s/build/tmp ./build/%s 2>&1 | grep -E '^FAIL'" % (root, t), 400)
            fails = [l.strip() for l in out.splitlines() if l.startswith("FAIL")]
            sh("pkill -9 -x %s" % t, 5)
            if fails:
                print("[%d] %s: CAUGHT by %s (%d failures; first: %s)" % (i, label, t, len(fails), fails[0][6:70]), flush=True)
                break
        else:
            print("[%d] %s: NOT CAUGHT" % (i, label), flush=True)
    finally:
        open(p, "w").write(orig)
        shutil.rmtree(STATE, ignore_errors=True)
print("done", flush=True)
