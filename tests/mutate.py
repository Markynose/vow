#!/usr/bin/env python3
"""
mutation check: apply one small wrong change to a source file, build the tests, run them, and expect
at least one test to fail. the file is restored afterwards (also on errors).

    python3 tests/mutate.py            all mutants
    python3 tests/mutate.py 2 5        only these numbers

a mutant that does not compile is reported as BUILD FAILED and is not a result. NOT CAUGHT is a hole
in the tests (or an equivalent mutant: a change that does not change behavior, listed in a comment).
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
 ("vow-run: dynamic programs accepted", "../tools/vow-run/vow-run.c", "if (ph.p_type == PT_INTERP)", "if (0)"),
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
]

def sh(cmd, t):
    try:
        r = subprocess.run(cmd, shell=True, cwd=root, capture_output=True, text=True, timeout=t, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired as e:
        return 124, "timeout"

only = sys.argv[1:]
os.makedirs(os.path.join(root, "build", "tmp"), exist_ok=True)
for i, (label, f, old, new) in enumerate(M):
    if only and str(i) not in only:
        continue
    p = os.path.normpath(os.path.join(root, "src", f))
    orig = open(p).read()
    if old not in orig:
        print("[%d] %s: PATTERN MISSING" % (i, label), flush=True)
        continue
    open(p, "w").write(orig.replace(old, new, 1))
    try:
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
print("done", flush=True)
