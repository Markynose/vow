<!-- SPDX-License-Identifier: 0BSD -->
# a service of wren under vow-run

a complete, minimal example. wren needs no change: its services are directories with a `run` script, and the script ends in `exec vow-run`.

| file | install as |
|---|---|
| `exampled.c` | build static, install as `/usr/bin/exampled` |
| `sv/exampled/run` | `/etc/wren/sv/exampled/run`, mode 755 |
| `vow/exampled.vow` | `/etc/wren/vow/exampled.vow`, owned by root, not writable by others |

and create `/etc/exampled/motd` with one line of text. to turn the service on, `ln -s /etc/wren/sv/exampled /etc/wren/services/exampled` and `wrenctl rescan`.

what it shows: the process wren supervises is the daemon itself (vow-run replaces itself), in the process group wren made for it; it can read `/etc/exampled/motd` (unveiled) and cannot read `/etc/passwd` (not unveiled); it is killed by `SIGSYS` if it makes a call that `pledge = stdio rpath exec` does not allow; wren's `SIGTERM` reaches it and it exits cleanly; a wrong profile or path makes vow-run exit with 125, 126 or 127 and wren restarts the service with its usual backoff (1, 2, 4 ... 30 seconds), printing the message of vow-run each time. see `tools/vow-run/WREN.md` for the design and what was and was not tested.

`tests/wren_example.sh` (`make wren-test`) runs exactly these files under a scratch build of wren in its dev mode (the supervisor without pid 1); nothing is installed and wren is only read. it was not run with wren as pid 1, on a real boot, or on a kernel without landlock. note that none of the services that ship with wren on kiss linux (sshd, dhcpcd, syslogd, mdev, getty) can be sandboxed with the promises of v0.2.
