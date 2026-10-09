<!-- SPDX-License-Identifier: GPL-3.0-only -->
# vow-run design

status: approved and implemented for static and dynamic executables (sections 11 and 12) for profiles (section 13) and for `--check` (section 14). the findings were measured on linux 7.2.9, musl, x86-64 (landlock abi 10), with the scratch programs described in each section; nothing here was run on another kernel or on glibc.

vow-run applies unveil and pledge to a process and then executes a program in it, so a program whose source is not changed can be sandboxed. it lives in `tools/vow-run/`, is c99, builds static on musl, and links `libvow.a`. libvow does not know about it and its public api (`pledge`, `unveil`) does not change.

## 1. command line

```
vow-run -p promises [-u path:perms]... [-i] [-v] [--] program [args...]
vow-run --profile file.vow [-i] [-v] [--] program [args...]
vow-run --check file.vow
```

- `-p promises`: required. the pledge string, passed to `pledge(promises, NULL)` as it is. it must contain `exec` (section 2).
- `-u path:perms`: repeatable. one `unveil(path, perms)`. the split is at the last colon, so a path may contain colons; permissions are the letters of `unveil` (`r w x c s`). rules from a file are the `--profile` option below.
- `--profile file.vow`: take the promises and the unveil rules from a profile (section 13) instead of `-p` and `-u`. it cannot be combined with them (125); `-i` and `-v` can.
- `--check file.vow`: only validate a profile (section 14); takes nothing else.
- `-i`: start the program with an empty environment. without it the environment is passed unchanged.
- `-v`: report which syscall killed the program (section 8). off by default.
- `--` ends the options. there is no option after the program name.
- the program is found like `execvp` does: a name with a slash is used as it is, a bare name is searched in `PATH` of vow-run.

exit status, following `env` and `timeout`:

| status | meaning |
|---|---|
| the exit status of the program | it ran and exited |
| 128 + n | the program was killed by signal n; the message says more for `SIGSYS` |
| 125 | vow-run failed before it could start the program (bad option, unveil or pledge error) |
| 126 | the program was found but cannot be executed (not a regular file, not executable, refused by the sandbox) |
| 127 | the program was not found |

messages are one line on stderr in the form `vow-run: what: reason`, lowercase, the reason from `strerror`. a pledge violation prints `vow-run: <program>: killed by SIGSYS (a pledge was violated)` and, with `-v`, the syscall and the promise that would have allowed it.

without `-v` vow-run replaces itself with the program (no fork, no wait): the exit status and the process id are the program own, and nothing stays outside the sandbox. that means it cannot print the `SIGSYS` message either: the parent of vow-run sees the status. the 128 + n rule and the `SIGSYS` message only exist with `-v`, where vow-run stays as the parent; without it nothing is left to print them, and the shell that started vow-run reports the kill itself. this is decision D1 (section 10).

## 2. applying the restrictions before exec

order, all in one thread (the library needs exactly one, DESIGN.md section 2.6):

1. parse the options. no files are touched.
2. resolve the program to a canonical path (`PATH` search, then `realpath`). a failure here is 127 or 126.
3. open it and read the elf header; check that it is a regular, executable elf for x86-64 (section 3). if it names an interpreter (`PT_INTERP`), check the interpreter too (section 12).
4. close every descriptor above 2 (`close_range`, fall back to a loop): descriptors cross `exec` and keep their power (DESIGN.md section 6), so nothing is inherited by accident. descriptors 0, 1, 2 stay.
5. `unveil(program, "rx")`, `unveil(interpreter, "rx")` for a dynamic program, then every `-u` rule in the order given. a rule that fails is fatal (125): a sandbox with a missing rule is not the sandbox that was asked for.
6. `unveil(NULL, NULL)` to commit and seal.
7. `pledge(promises, NULL)`. any error is fatal.
8. `execve(resolved path, argv, envp)` with `argv[0]` as given by the user.

`exec` must be in the promises because the `execve` of step 8 runs under the filter. this has a consequence that is stated, not hidden: the program can itself execute other files that are unveiled with `x`. vow-run refuses a promise string without `exec` (125, "promises need exec to start the program") instead of adding it, so the sandbox is never wider than the user wrote. decision D2 in section 10.

races: the rule for the program is on its inode and the exec uses the canonical path. if the path is replaced between the resolution and the exec the new file is another inode and the exec fails with `EACCES`; it does not run unsandboxed and it does not run with the old rule. unveil already fails with `ESTALE` for a swapped symlink (DESIGN.md section 6).

## 3. static and dynamic executables

measured with `lau`, a scratch program (unveil list, seal, pledge, execve) and the helpers of the test suite:

| program | unveil | pledge | result |
|---|---|---|---|
| static | program `rx` | `stdio exec` | runs |
| dynamic musl, no other library | program `rx` | `stdio exec` | `execve` fails with `EACCES` (the kernel checks the interpreter) |
| dynamic musl, no other library | program `rx`, `/lib/ld-musl-x86_64.so.1` `rx` | `stdio exec` | runs (musl libc and loader are one file) |
| dynamic, one extra shared library, library not unveiled | program, loader | `stdio rpath exec` | loader error, "libx.so: no such file", status 127 (to the loader a denied file is a missing one) |
| same, library `r`, no `rpath` | program, loader, library `r` | `stdio exec` | killed by `SIGSYS`: the loader `open`s the library |
| same, with `rpath` | program, loader, library `r` | `stdio rpath exec` | runs |
| same, library `x` | | | `unveil` refuses a bare `x` (`ENOTSUP`, known) |

what follows for vow-run:

- static is the baseline: the program `rx` is all that is needed, and vow-run adds it by itself.
- dynamic needs, besides the program: the interpreter named in `PT_INTERP` with `rx`, every library the loader will open with `r`, and `rpath` in the promises (the loader opens the libraries and reads `/proc/self/exe`). vow-run can find the interpreter itself by reading `PT_INTERP`; it cannot know the libraries without running the loader. `ldd` runs the loader outside the sandbox, which executes the program code path of the loader on an untrusted file; that is not acceptable as a default. options for the next step: (a) the user lists libraries with `-u`; (b) vow-run reads `DT_NEEDED` and searches the loader path itself (needs the search rules of each libc: musl `/etc/ld-musl-*.path`, glibc `ld.so.cache`, `RPATH`, `RUNPATH`, `LD_LIBRARY_PATH`); (c) a learning mode that runs the program once under `-v`. b is the work of re-implementing a loader search and will be wrong for some libc; start with a.
- `LD_PRELOAD`, `LD_LIBRARY_PATH` and similar in the environment are inherited by default. they run inside the sandbox, so they cannot widen it, but they change which files the loader wants. `-i` is the way to remove them. glibc also reads `/etc/ld.so.preload`.
- scripts (`#!`): the kernel opens the interpreter; it needs `rx` as well and its own libraries. refused in this version (not an elf).
- glibc (deferred, from the trial in DESIGN.md section 14): programs read `/proc/self/exe` at start so `rpath` is needed even for static ones, name lookup loads nss modules with `dlopen`, and `pthread_cancel` loads `libgcc_s.so.1`. none of that was tested with vow-run.

## 4. environment, descriptors, path resolution

- environment: unchanged, or empty with `-i`. no filtering of `LD_*` in this version because filtering by name is a policy that will be wrong for some libc; it is documented instead.
- descriptors: all above 2 are closed before the sandbox (step 4). there is no option to keep one in this version; passing a socket or a log descriptor is a later, explicit `-k fd`.
- current directory: unchanged and not granted. a relative path in `-u` is resolved against it before the sandbox, and the canonical path is what is unveiled.
- path resolution happens once, outside the sandbox, as in section 2; after the sandbox the program cannot see the directories above its unveiled paths.
- signals: vow-run in the no-supervisor mode becomes the program. in `-v` mode the parent is outside the landlock domain, and a scoped child cannot signal it (kernel generated `SIGCHLD` still arrives).

## 5. can the restriction be applied after exec, without trusting the program?

short answer: not with the means vow uses, and not in a way worth building.

- landlock and seccomp restrict the calling thread only. there is no call that restricts another process. a filter or domain installed before `exec` stays for the whole life of the program, and one installed by the program itself needs the program to cooperate (it calls `pledge`).
- "pre-exec" restriction is therefore the only kind that does not trust the program, and what it can express is: the program runs with the promises it was started with from its first instruction. it cannot start wide and narrow itself.
- in principle a tracer can stop the new image at the exec event, before its first instruction, and make the tracee run `seccomp` and `landlock_restrict_self` by rewriting registers and the instruction it is about to execute. this was not tried. it needs machine code injected into the target, depends on the architecture and the loader, needs a tracer with the right to trace, and leaves the tracer as a trusted, privileged part of the sandbox. rejected for this project; it is not simpler or more auditable than the pre-exec model.

## 6. `execpromises`

the library today accepts `execpromises` only when equal to `promises` (`ENOTSUP` otherwise), because filters and domains cannot be swapped at `execve`. what vow-run could add, and what each costs:

1. inherit everything (today): `-p` is both. no new mechanism.
2. a launcher stub (a small program that applies the narrower set and then executes the target): it does not help. the stub is already inside the filter of the caller, so it can only narrow that filter, never widen it, and a filter cannot be swapped when the stub calls `execve`. for the stub to be useful the caller would have to run it before getting its wider promises, which is exactly option 1 with the narrower set. nothing is gained over inheriting.
3. an interposer that intercepts the program own `execve` (a ptrace tracer or a seccomp user notification supervisor) and swaps in a launcher: it has to be a trusted process that stays alive, it has the time-of-check problems of user notifications (the paths the program passes can change while the supervisor looks at them), and ptrace changes the semantics of the program.

conclusion for this version: no `execpromises` in vow-run; the question "can a program under `promises` start a child under a narrower set" has the answer "not without an interposer", and an interposer is a new trusted component with its own attack surface. options 2 and 3 are not implemented. a program that wants its child to be narrower calls `pledge` in the child after `fork`, before `exec`, as the library already allows (promises only narrow).

security notes for any future mechanism: the child must never run with a wider set than the parent had; descriptors must be closed or accounted for before the narrowing; and the check of the policy and the exec must refer to the same file (inode), not the same string.

## 7. test strategy

- a test program per case, run by a shell script (`tests/vow_run.sh`) in `make test`, like `tests/examples.sh`: exit status propagation (0, a code, 125, 126, 127, killed by a signal), `PATH` search, a relative path, a path with colons, no `exec` in the promises refused, a failing rule is fatal, descriptors above 2 are closed in the program, environment kept and cleared with `-i`, a static program runs under the minimum unveil, a dynamic program is refused in this version, a script is refused.
- denial tests: the program tries a file outside its unveil (expects `EACCES` from the helper), a syscall outside its promise (expects `SIGSYS`), a second exec of a file that is not unveiled `x`.
- race test: replace the program file between resolution and exec (a hook-free version: swap the path in a loop from another process); the run either works or fails with `EACCES`, never runs unsandboxed. checked by asking the program for `NoNewPrivs` and `Seccomp: 2` in `/proc/self/status` (the helper `status` mode does this already).
- mutants for `vow-run`: the apply order (pledge before unveil), the missing seal, the missing close, the missing `exec` check, each must be caught.
- static musl on x86-64 only. glibc is unsupported and not planned for v0.2; nothing is claimed for it (section 3 lists what a glibc program would be expected to need, from reading, not from a run).
- needs: landlock abi 6 or later like the library tests; the script skips with status 77 otherwise.

## 8. violation reporting

problem: a parent that only calls `waitpid` learns that the program was killed by `SIGSYS` (status 31) and nothing else; the syscall number is not in the wait status.

measured, with scratch tracers (`trace`, `trace2`), on 7.2.9, `ptrace_scope` 1 (a parent may trace its children), `dmesg_restrict` 1:

| method | result |
|---|---|
| `waitpid` / `waitid` | only "killed by signal 31". no syscall number. |
| ptrace, wait for a `SIGSYS` signal stop | no stop is reported: the kernel kills the process for a seccomp `KILL_PROCESS` without a signal-delivery-stop for the tracer. |
| ptrace with `PTRACE_O_TRACEEXIT`, read the registers at the exit event | works. status `0x1f` (`SIGSYS`) and `orig_rax` is the syscall number: `open` (2) for a single thread. |
| the same with threads (`PTRACE_O_TRACECLONE`) | every thread reports the exit event with status `0x1f`, because the whole group is killed. the culprit thread has the violating syscall in `orig_rax`; the others show the call they were blocked in (a `nanosleep` in the test). so the status cannot tell which thread did it; the registers have to be checked against the policy. |
| kernel audit (`type=1326`) or `dmesg` | not readable here (`dmesg_restrict` 1, no audit tools, no capability). depends on the machine. cannot be a feature of a user tool. not measured further. |
| core dump | holds `si_syscall`, but depends on `core_pattern`, `RLIMIT_CORE` and a tool to read it; the tests turn cores off. rejected. |
| `SECCOMP_RET_TRAP` (a catchable `SIGSYS`) | would give `si_syscall` to a handler in the process. that changes the filter from "kill" to "handler", and a handler is code inside the process under attack. rejected as a default (roadmap v0.2 item 5 allowed it only as an explicit debug mode; this finding makes it unnecessary). |
| `SECCOMP_RET_USER_NOTIF` | needs a supervisor that decides each call; far larger and the target pauses on every denied call. rejected. |

recommended design for `-v`: vow-run forks; the child does `PTRACE_TRACEME`, stops itself, applies the sandbox and execs; the parent (outside the sandbox) sets `PTRACE_O_TRACEEXIT | PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL`, resumes it and passes every signal through unchanged. at each exit event with status `0x1f` it reads the registers and asks the policy (the same rule tables the filter is built from, evaluated by vow-run, not the kernel) which events would have been denied; those are the culprit threads. it prints the syscall name (from the table of names the tests already generate), the first arguments if they decide the answer (the open flags), and the promise that would have allowed it, or "no promise allows it". `PTRACE_O_EXITKILL` also kills the program if vow-run is killed.

does it weaken the sandbox? the tracer is the parent, outside the domain, and the traced program cannot ptrace it (no implemented promise allows `ptrace`, and with `ptrace_scope` 1 a process may only trace its own descendants). the program sees `TracerPid` and cannot be attached by a debugger at the same time. what it costs, and is why `-v` is opt-in and the default is the replace-itself mode:
- the program is traced for its whole life, `SIGSTOP`, `SIGTRAP` and job control behave differently, and `strace -p` or a debugger cannot attach.
- ptrace may be refused: `ptrace_scope` 2 or 3, containers whose seccomp profile blocks `ptrace`, `CAP_SYS_PTRACE` rules. then `-v` fails with 125 and says so; it does not silently run without a report.
- threads are followed (`PTRACE_O_TRACECLONE`). no implemented promise allows `fork` or `vfork`, so a new process cannot appear; a future `proc` promise needs `TRACEFORK` and `TRACEVFORK` here.
- stop signals (`SIGSTOP`, `SIGTSTP`) are passed through to the program as they come, so job control is only roughly right in `-v` mode.
- it was measured with one kind of violation (`open` under `stdio`) and one thread layout; wider coverage is a test task for the implementation.

## 9. what this version does not do

`wren` integration, new promises, kernel work, `execpromises`, scripts, finding the shared libraries of a program by itself (`-u` lists them), keeping descriptors, environment filtering, other architectures, glibc.

## 10. decisions to confirm before the code

- D1: without `-v`, vow-run replaces itself with the program (no supervisor, exit status and pid are the program own). the 128 + n and the `SIGSYS` message exist only with `-v`. alternative: always fork and supervise, which keeps a process outside the sandbox and changes pids and signals.
- D2: `-p` must contain `exec`; vow-run refuses otherwise, it does not add it. alternative: add it and print a note.
- D3: `-v` uses ptrace as in section 8. alternative: no reporting in this version, only the plain `128 + 31`.
- D4: static first, then dynamic by step (a) of section 3: the interpreter found from `PT_INTERP`, libraries listed by the user with `-u`. both are implemented; scripts are still refused.
- D5: the descriptors above 2 are closed with no way to keep one for now.

## 11. implementation notes (static executables)

- `tools/vow-run/vow-run.c`, one file, about 460 lines. licensed GPL-3.0-only (`LICENSE`, `LICENSING.md`): it contains libvow (LGPL-3.0-only) through the internal header and `libvow.a`, which the LGPL allows to be combined under the GPL; libvow contains nothing of it. `make tools` or `make build/vow-run`; `make test` builds it and runs `tests/vow_run.sh`. static, no `NEEDED`.
- it links `libvow.a` for `pledge` and `unveil`, and for `-v` it includes `src/filter.h` and calls `vow_build`, so the report asks the same rule tables the kernel filter was built from. so vow-run depends on the library internals; the library does not know vow-run exists, and its public api is unchanged.
- the names in the report come from `sysnames.h`, the x86-64 system call names generated by `gen-sysnames.sh` from the linux headers and checked in (the names the filter itself knows are only the ones it allows, and a violation is by definition a call it does not allow).
- as designed: the program is canonicalized once; elf without `PT_INTERP`; descriptors above 2 closed with `close_range` (a loop if that fails); `unveil` of the program `rx`, the `-u` rules, the seal, the pledge, then `execve` of the canonical path with `argv[0]` as given. without `-v` there is no fork. with `-v` the child does `PTRACE_TRACEME` and stops itself, the parent sets `TRACEEXIT | TRACECLONE | TRACEEXEC | EXITKILL`, passes signals through and, at each exit event of a thread killed by `SIGSYS`, runs the registers through the filter built for the user promises; a thread the filter would not kill is not reported. exit status 128 + n for a signal.
- tests: `tests/vow_run.sh`, 59 checks, among them exit statuses, refusals (no `exec`, scripts, five bad interpreters, bad `-u`), unveil enforcement, the environment, descriptors, `-v` reports (a socket call with and without `inet`, a call no promise allows, a violation in a second thread that must not blame the waiting thread), and a run against a program file that is replaced while vow-run starts (never runs unsandboxed). it skips only when the kernel reports that landlock is not available. sixteen mutants of vow-run are in `tests/mutate.py` (32 to 47); all are caught.
- not tested: `-v` on a kernel with `ptrace_scope` 2 or inside a container that blocks `ptrace` (the failure path exists and says "cannot trace"); a violation by a system call with arguments that decide the verdict (the open flags); glibc.
- the helper modes added to `tests/helper.c` for this: `mount`, `tmount`, `envset`.

## 12. dynamic executables: requirements and how each was checked

the new thing a dynamic program brings is a path that is chosen by the program file and not by the user: the kernel opens the interpreter that the file names, so vow-run has to unveil it `rx`, outside the sandbox, from what the file says. what was required, and what was done:

| requirement | what vow-run does | checked by |
|---|---|---|
| the program must not make vow-run grant a read of any file it likes | the interpreter must be an absolute path to a regular, executable x86-64 elf that has no interpreter itself (a loader). a data file, a script, a shell, a dynamic program, a relative path or a missing file are refused with 126 before anything is unveiled | `tests/vow_run.sh` with five fixture programs (`hlp_bad1` to `hlp_bad5`); mutants 45 to 47 |
| the interpreter is unveiled, nothing else is guessed | `unveil(interpreter, "rx")` after the program; the libraries are not unveiled | a dynamic program runs with only that; mutant 44 |
| the program or the interpreter replaced while vow-run starts | the rules are on the inodes and the exec uses the canonical paths, so a replaced file is another inode and the `execve` fails with `EACCES` (126), or `unveil` fails with `ESTALE` (125) | two race tests (program, interpreter): the status is only ever 0, 125 or 126, and the program reports `NoNewPrivs` and a filter when it runs. in one measured run 119 of 200 starts were refused and 79 ran, so the race is exercised. 2 other starts in that run ended with another status that was not captured and did not come back in 750 later runs; most likely the 125 above, but not shown |
| libraries are not found unless listed | a library that is not in `-u` is invisible to the loader: it exits with its own message ("Error loading shared library") and status 127, which is the same number vow-run uses for "not found"; the message tells them apart | test with `hlp_so`; with `-u lib:r` and `rpath` it runs; with `-u` but without `rpath` it is killed by `SIGSYS` (the loader opens the library) |
| the loader configuration | the files a loader reads at start (musl: `/etc/ld-musl-*.path`; glibc: `ld.so.cache`, `ld.so.preload`) are not unveiled, so they are not seen; the musl test programs run without them | only the musl programs above; glibc not run |
| the environment | `LD_PRELOAD` and `LD_LIBRARY_PATH` are inherited unless `-i`; they run inside the sandbox and cannot widen it, but a preloaded library has to be listed with `-u` or the loader fails | not tested |
| `PROT_EXEC` mappings of libraries | allowed (not w^x, as everywhere in vow) | the dynamic programs map their libraries |
| setuid and capabilities | `no_new_privs` is set before the exec, so a setuid dynamic program runs without its privileges | the status test shows `NoNewPrivs`; a setuid program was not run |

what the program can still do with the interpreter rule: it can read and execute that one file, which is a loader the user chose to run by running the program. a program file cannot name anything else (the checks above), but it can name any loader on the machine that the user can read, for example a static executable with no interpreter. that is the remaining exposure of this design; closing it would need the user to name the interpreter (an option for it, not built).

not tested: an elf with more than one `PT_INTERP`, an interpreter name without its terminating zero or with a huge size (the code refuses them, with no crafted file to prove it); the `-v` report for a violation in the loader before `main`; glibc programs; `LD_*` handling.

## 13. profiles

`vow-run --profile editor.vow -- ./program` reads the promises and the rules from a small file, so a sandbox can be kept, reviewed and reused. the parser is `tools/vow-run/profile.c`; libvow does not know profiles exist and reads no files.

```
# a comment, on a line of its own
pledge = stdio rpath wpath cpath exec
unveil = /home/mark/docs:rwc
unveil = /path with spaces/notes:r
```

rules of the format, all enforced by the parser:

- a profile has exactly one `pledge` line and any number of `unveil` lines, up to 64. nothing else: no includes, variables, inheritance or sections; any other directive is an error. directive names are lower case.
- a line is `name = value`. spaces around the `=` and at both ends of the line are ignored; the value runs to the end of the line, so a path may contain spaces and `#` and `=`. a tab or any other control character (CR included, so CRLF files are refused) anywhere in a line that is not a comment is an error, and so is a byte 0 anywhere in the file. a comment is a line whose first non-space character is `#`; there are no comments after a value. blank lines are skipped. a path cannot start or end with a space.
- limits: a line of 4096 bytes at most, a file of 64 KiB at most, a regular file only (a fifo, a device or a directory is refused without being read; the open is non-blocking so that a fifo cannot hold vow-run).
- `pledge`: words separated by exactly one space. every word must be a promise that exists in this version (`stdio rpath wpath cpath inet exec`), none twice, and `exec` must be among them (section 2). a promise that is only planned (`dns`, `proc`) is an error here, not a later failure of `pledge()`.
- `unveil`: `path:permissions`, split at the last colon, so a path may contain colons. the path is absolute, in textual canonical form (no `//`, no `.` or `..` component, no trailing slash except `/` itself). permissions are a non-empty set of `r w x c s`, each at most once, and `x` needs `r` (as in the library). the same spelling twice is an error. the parser never looks at the file system and never resolves a symlink: the path is handed to `unveil` exactly as written, and `unveil` follows symlinks and pins the inode they lead to (a rule on a link is a rule on its target; checked by a test, and by `strace` showing that an invalid profile makes no call on its paths). a `..` after a symlink is refused for its spelling, not resolved. two spellings of one inode are not seen by the parser: the later line replaces the earlier, as repeated `unveil` calls do.
- rules below one another: the parser does not judge them. whether a rule below another asks for less than it gets depends on what the paths are (a socket, a file, a directory), which only the file system knows, and the library check is type-aware (DESIGN.md section 2.6, measured against the kernel). a profile with such a pair stops at the `unveil` call with `file:line: cannot unveil path: Operation not supported (it asks for less than a rule above or below it gives)`, before the sandbox is committed and before the program starts. an earlier version of the parser compared letters alone and would have refused pairs the kernel handles correctly.
- errors are one line, `vow-run: file:line: what`, status 125. a path that does not exist, or a pair of rules the narrowing check refuses, is not a profile error but an `unveil` failure, reported with the same line: `file:line: cannot unveil path: reason`.

validation order: the whole profile is read and checked before vow-run resolves the program, closes descriptors or calls `unveil`, so a mistake on line 30 is found before line 2 has been tried, and a profile is never half applied. checking the real file system (does the path exist, is it a directory) is left to the `unveil` calls, which also run before anything is committed and before the program starts; a failure there changes nothing but vow-run itself.

what the profile cannot say: the program (the command line names it), the environment (`-i`), the interpreter and the libraries of a dynamic program beyond what `unveil` lines list (the interpreter is still added by vow-run, section 12), anything about descriptors. `--profile` with `-p` or `-u` is an error rather than a merge, because a merge needs rules for which one wins; this can be lifted later.

tests: about 125 checks in `tests/vow_run.sh` (valid forms, every error above, the cross-checks with `-p`/`-u`, order of validation, hostile files: NUL, control characters, long lines, a 70 KB file, 65 rules, a fifo, a directory, symlinks, rules that conflict, and files that change or lie about their size while they are read), `tests/profile_fuzz.py` (random and mangled profiles against an independent python implementation of this section; six seeds of 2000 profiles agreed, and `make test` runs a short one), and the mutants listed for `profile.c`, `vow-run.c` and the narrowing check in `tests/mutate.py`, all caught. one deliberate overlap: the check for `exec` exists in the parser and in `main`; removing either alone is invisible from outside, so it is not a mutant.

while the profile is read: the file is opened once, its type checked, and read once into memory up to 64 KiB; everything after works on that copy and the rules that are applied are copies too, so a file that is truncated, rewritten or swapped later changes nothing and a torn read is just a different byte string. what was tested: a regular file that reports size 0 and holds 100 KB (`/proc/self/cmdline`) is cut at the limit; the same file with NUL bytes is refused; a writer that rewrites the profile in place (truncate then write, with empty, half-written and alternative contents) while 250 runs read it produced only runs and clean errors, never a crash, a hang or a signal. what is not claimed: that a run during a rewrite sees one of the complete versions. it can see a prefix. a prefix of a profile has fewer lines, so fewer promises or rules, except in one contrived case (a path containing `:` followed by letters, cut inside the path); the profile is trusted configuration, and whoever can write it already controls the policy, so protect it like the program itself.

not tested: profiles with non-UTF-8 paths beyond the fuzz bytes; paths longer than `PATH_MAX`; glibc.

## 14. `--check`: validating a profile without using it

`vow-run --check file.vow` runs the profile parser (section 13) and nothing else. it exists so that a package, an installer or an administrator can reject a bad profile before a service restarts on it forever (the restart loop with backoff of `WREN.md`).

- status 0 and no output when the profile is valid. status 125 and the one-line message `vow-run: file:line: what`, exactly as in `--profile` mode, when it is not. 125 is the status of every setup failure of vow-run, so there is a single number to look for. `--check` takes one profile and no other option or program (`-p`, `-u`, `-i`, `-v`, `--profile`, a second `--check`, a program): any of them is a usage error, 125.
- it does not look up or run a program, does not close descriptors, does not call `unveil`, `pledge`, `landlock_*` or `seccomp`, does not fork, and does not open or stat any path that the profile names. a test runs it under `strace` and fails on any of those. so it works where the kernel has no landlock (a build machine) and on paths that exist only on the target.
- what a pass means: the file is a regular file of at most 64 KiB; every line has the form of section 13; there is exactly one `pledge`, with known promises, none twice, and `exec`; every `unveil` has an absolute canonical path, valid permissions and no duplicate; at most 64 rules.
- **what a pass does not mean.** it does not mean the profile will be enforced as written, or that the service will start under it. not checked, because they depend on the machine: that a path exists or is the kind of object the permissions assume; the narrowing check between rules (`unveil` decides that with the real inodes, DESIGN.md section 2.6); that the kernel has landlock or a new enough abi; that the program works under the promises (it may be killed for a call no promise allows). two tests show it: a profile with paths that do not exist and a profile with a pair of rules that the library refuses both pass `--check` and both fail when used. validation at install time lowers the risk of a restart loop, it does not remove it.
- tests: every invalid profile of the `--profile` tests is also run through `--check` and must give the same message; the valid and the argument cases; the `strace` checks; `tests/profile_fuzz.py` runs `--check` on every random profile and requires status 0 exactly when the independent oracle says valid, whatever the file system looks like. mutants 67 to 71 in `tests/mutate.py`, all caught.
