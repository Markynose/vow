<!-- SPDX-License-Identifier: GPL-3.0-only -->
# vow-run under wren

status: approved design and findings; nothing in wren is changed or will be. `vow-run --check` and the kiss package (`dist/kiss/vow`) now exist in this repository. wren (`~/src/wren`) was read, never built or modified there: it has uncommitted work, so a copy of `src/`, `etc/` and the `Makefile` was built in a scratch directory and run in its dev mode (`./wren -s servicedir`, which is the supervisor half without pid 1) against real `vow-run` services. kernel 7.2.9, musl, landlock abi 10.

## conclusion

wren needs no change. a service is a directory with an executable `run` file, and `run` is a shell script that ends in `exec`. so a sandboxed service is a run script that ends in `exec vow-run --profile ... -- daemon`. vow-run replaces itself with the daemon (no fork unless `-v`), so the pid wren supervises is the daemon, in the process group wren made for it. restarts, backoff, stopping on purpose and shutdown all work unchanged. wren does not link libvow, does not parse profiles, and does not know vow-run exists.

the real limit is not wren, it is what the promises can express today (section 7).

## 1. how wren starts a service (read from `src/sv.c`)

- `start()` forks. the child calls `setsid()` (own session and process group, so `kill(-pid, ...)` reaches the whole service), restores the signal mask, `chdir`s to the service directory, reopens stdin on `/dev/null`, and `execl("./run", "run", NULL)`. stdout and stderr stay on the console. the environment is whatever wren got from the kernel. no user switching, no fds closed.
- if `run` cannot be executed, the child prints `cannot run <path>` and exits 127.
- when the service exits, wren reaps it, kills the rest of the process group with SIGKILL, and restarts it after 1s, 2s, 4s ... up to 30s (a run of 30s or more resets the wait to 1s). the log line is `wren: <name> exited with status N, restart in Ns` or `killed by signal N, restart in Ns`.
- stopping on purpose (a `down` file plus `wrenctl rescan`, or a removed directory) sends SIGTERM and SIGCONT to the group and SIGKILL after 5s, with no backoff. shutdown does the same to every group (5s grace), then sweeps everything else.
- a service has no exit status policy: every exit, whatever the status, is a restart.

## 2. the integration

```sh
#!/bin/sh
# /etc/wren/sv/exampled/run
exec /usr/bin/vow-run --profile /etc/wren/vow/exampled.vow -- /usr/bin/exampled -f 2>&1
```

```
# /etc/wren/vow/exampled.vow
pledge = stdio rpath wpath cpath inet exec
unveil = /etc/exampled:r
unveil = /var/lib/exampled:rwc
```

rules for the run script:

- end with `exec`, as wren already requires, so the supervised pid is vow-run and then the daemon. a run script that forks vow-run into the background would leave wren watching a shell.
- absolute paths for vow-run, the profile and the daemon. the cwd of a service is its service directory and wren does not set `PATH`.
- `2>&1` after the command redirects the shell before the `exec`, so the error messages of vow-run go where the output of the daemon goes (the console, or a pipe to a logger if the script has one).
- the profile and the executable are unveiled by vow-run; the service directory (the cwd) is not, so the daemon must use absolute paths.
- do not use `-v` under wren: with `-v` the supervised pid is vow-run, the parent of a traced daemon, and the SIGTERM of wren to the group would kill the tracer before it can report. use `-v` by hand to find out what a service needs (section 5).

## 3. what was run (scratch wren, dev mode, static and dynamic test daemons)

| case | result |
|---|---|
| static daemon, profile `pledge = stdio exec` | started, pid equals the daemon pid, session and process group equal the pid, `NoNewPrivs: 1`, `Seccomp: 2` |
| dynamic daemon (musl, loader found from the elf) | the same; the loader is unveiled by vow-run, no profile line needed |
| wren shutdown (`SIGTERM` to wren) | `powering off`, the group got TERM, both daemons logged their handler and exited 0, wren logged `exited with status 0`, nothing left behind |
| a daemon that ignores TERM | wren waited exactly 5.0s and then SIGKILLed it; the sandbox did not get in the way, no leftovers |
| `kill -9` of a daemon | `killed by signal 9, restart in 1s`, started again as a new pid with the sandbox again |
| `down` file and rescan, then the file removed and rescan | TERM, daemon handled it and exited 0, `exited with status 0` without a backoff; started again at once when the file was removed |
| a daemon that makes a call no promise allows (`fork` under `stdio exec`) | `killed by signal 31, restart in 1s`, then 2s, 4s, 8s: a pledge violation is a crash to wren |
| profile file missing | vow-run prints `vow-run: <file>: No such file or directory`, status 125, restart loop 1, 2, 4, 8s |
| profile with an error | `vow-run: <file>:2: unknown directive bogus`, status 125, same loop |
| daemon missing | `vow-run: <path>: No such file or directory`, status 127, same loop |
| daemon not executable | `vow-run: <path>: Permission denied`, status 126, same loop |
| rules from the profile | a file under an unveiled directory opened (status 0), another file denied (the daemon saw EACCES and exited 4), repeated by the backoff |

why signals work: the signal scope of landlock stops a process from signalling targets outside its own domain, and wren is outside every domain, so its TERM, CONT and KILL to the group always arrive. what a sandboxed daemon cannot do is signal wren or any other process outside its domain (the scope is required for `stdio`, DESIGN.md section 2.7).

not run: wren as real pid 1 (no qemu or `fakeroot` here), a real boot, any real kiss service, a kernel without landlock, `/proc` missing.

## 4. profile placement

- `/etc/wren/vow/<service>.vow`, next to `/etc/wren/sv/<service>/run` and `/etc/wren/services/`. one profile per service; a profile can be shared by pointing two run scripts at it.
- owned by root, mode 0644, in a directory only root can write. the profile is trusted configuration: whoever can write it controls the policy (DESIGN.md of vow-run section 13 on a profile that changes while it is read).
- profile paths are absolute and written in the run script, not found by search.
- nobody owns `/etc/wren/vow/` yet: the package of vow (`dist/kiss/vow`) deliberately does not create anything under `/etc/wren`, and the package of wren does not know about vow. the administrator creates the directory (`install -d -m755 /etc/wren/vow`) when the first profile goes in.

## 5. failure handling

| what happened | what wren shows | what to do |
|---|---|---|
| vow-run refused the profile or the daemon (125, 126, 127) | `exited with status 125`, `126` or `127`, restart in Ns, and the `vow-run:` line on the console | read the line; the status alone is ambiguous only for 127 (wren itself uses it for "cannot run ./run") |
| the daemon was killed by a pledge violation | `killed by signal 31`, restart in Ns | run it by hand with `vow-run -v --profile ... -- daemon` to see `pledge violation: <syscall> (<nr>), allowed by: <promise>` |
| the daemon failed to open something unveiled wrongly | the own error of the daemon (EACCES), usually an exit status | the same `-v` run does not help here (no kill); `strace -f -e trace=file` on the run shows the denied path |
| landlock is missing in the kernel | vow-run: `pledge: Function not implemented` or similar, status 125, restart loop | see below |
| `/proc` not mounted when the service starts | the unveil commit is refused with `EBUSY` (vow-run cannot prove it has one thread without `/proc/self/task`); restart loop | the boot script mounts `/proc` before wren starts services (kiss `rc.boot` does) |

fail closed is the only behavior built in: if the sandbox cannot be applied, the daemon does not run, and wren keeps retrying with backoff up to 30s. vow-run never falls back to running unsandboxed. an administrator who wants a fallback has to write it in the run script on purpose (test first, then `exec` one or the other), and that choice belongs in the open, not in the tool.

**decision (approved):** wren keeps its restart behavior and gets no knowledge of vow-run. a persistent vow-run failure (status 125, 126 or 127) is a restart every 30 seconds once the backoff has grown to its maximum (1, 2, 4, 8, 16, then 30s), with the `vow-run:` message on the console each time, until the profile, the program or the kernel is fixed. wren has no way to stop retrying on a status and no `finish` script, and adding either is a wren change that runs against its list of things left out on purpose. a service with a broken profile is therefore a loud console, not a hidden failure. the checks of section 6 keep it from happening on a running machine, they do not stop it.

## 6. checks that belong at install time, not in wren

- `vow-run --check file.vow` parses a profile and nothing else and exits 0, or 125 with the usual `file:line: message` (implemented, `DESIGN.md` of vow-run section 14). a package can run it on the profiles it installs. a pass is not a guarantee that the profile is enforceable or that the service starts: it does not see the file system, the narrowing check between rules, the kernel or the program.
- a vm scenario for wren that boots a service under vow-run and greps the console. it would live in `test/scenarios` of wren (a wren change, to be agreed) and needs qemu and a kernel with landlock; the host kernel is used by the vm, so on this machine the scenario would test this kernel.

## 7. what can be sandboxed today

the promises are `stdio rpath wpath cpath inet exec`. there is no promise for creating a process, unix sockets, name lookup, terminal control, or changing uid. so a daemon that

- stays a single process (no `fork`, `vfork`, or `clone` without being a thread),
- uses files, tcp or udp sockets and threads,
- does not use `AF_UNIX` (including `/dev/log`), `AF_NETLINK`, raw sockets, name lookups by hostname, `ioctl` on terminals, or `setuid`,

fits. none of the services in wren dist/kiss do, judged from their promise needs and not run: sshd forks per connection and needs ptys; dhcpcd forks privilege separation helpers and uses raw and netlink sockets; syslogd listens on `/dev/log` (unix socket); mdev writes device nodes; getty drives a terminal and execs login. sandboxing them waits for the promises the roadmap lists as investigations (`proc`, `unix`, `dns`, `fattr`, a terminal one, an id one). until then the integration is ready and tested, and the useful services are the ones people write or package as single-process network and file daemons.

consequences that apply to every profile:

- every profile needs `exec` (vow-run itself uses it), so the daemon can exec any file the profile unveils with `x`. keep `x` out of the profile.
- `no_new_privs` is set, so a daemon cannot gain privileges through setuid binaries, and a daemon that drops from root with `setuid` is not possible yet. wren has no user switching either, so services run as root; the sandbox is what limits them.
- processes in one landlock domain can signal each other, and the children of the daemon share its domain (DESIGN.md section 2.7).

## 8. what is genuinely needed beyond a run script

nothing in wren. possible, small, separate pieces, none started:

1. a package recipe for vow-run (done: `dist/kiss/vow`, which installs the binary, the library, the header and the documents, and creates no `/etc/wren` directory; wren and vow stay independent packages).
2. `vow-run --check` (done, section 6).
3. a profile and run script example under `dist/kiss/` in this repository, built around a test daemon, so the wiring is shown without pretending that sshd works.
4. a wren vm scenario (a change in wren, to be agreed).

## 9. decisions

- pure run-script integration, no change in wren: approved.
- the 30 second restart loop for a persistent vow-run failure: accepted and documented (section 5). no vow-specific exit handling in wren.
- `--check` before anything else: done. the kiss package: done, see `dist/kiss/README.md` for what it assumes.
