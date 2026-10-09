# v0.1 release checklist

nothing here is done by the build; each line is checked by hand and the result written next to it.

## code freeze
- [ ] no new promises, no new public api (include/vow.h has pledge and unveil only)
- [ ] make all check-header test static-check passes (output to a file, not piped)
- [ ] python3 tests/mutate.py: every mutant CAUGHT (the x32 one is an equivalent mutant, listed in the file)
- [ ] fuzz: VOW_FUZZ_SEED over at least six seeds, VOW_FUZZ_N=20000 VOW_FUZZ_KN=600, no disagreement
- [ ] header compiles as c89 and from c++ (make check-header)

## kernels
- [ ] sh tests/kernel_matrix.sh on real kernels: abi 3 (6.2), abi 4 (6.7), abi 5 (6.10), abi 6 (6.12), abi 7 (6.15), abi 8, abi 9 and later; fill the table below
- [ ] one run inside a container (docker or podman default profile), one in a systemd service with SystemCallFilter
- [ ] the stdio rule table checked against the syscalls added since 5.x (kernel syscall table diff)

| kernel | abi | unveil | filter | seccomp | fuzz | notes |
|---|---|---|---|---|---|---|
| 7.2.9 (dev machine) | 11 | 60 pass | 12 pass | 213 pass | pass | musl, kiss |

abi 3 to 5 and 6 to 8 are simulated only so far (vow_test_abi_cap), no real kernel was available.

## documents
- [ ] DESIGN.md and ROADMAP.md agree with the source (section numbers, test counts, decisions)
- [ ] README.md written (not yet) and examples/ (cli, fileproc, netclient, progressive; not yet)
- [ ] every limitation in DESIGN.md section 6 and 14 is in the user documentation

## known limits that ship with v0.1 (do not hide)
- threads before the first vow call: unveil commit and pledge stdio refuse with EBUSY
- processes in the same landlock domain can signal each other; raw fork children share the domain and locks
- wpath and cpath without unveil are broad; descriptors opened before the sandbox keep their power
- sendmsg destinations and inet addresses and ports are not filtered; the landlock layer limit is 16
- uprobe and uretprobe are exempt from seccomp; PROT_EXEC is not w^x
- kernel facts verified on 7.2.9 only; glibc is not supported in v0.1

## tag
- [ ] version macros in include/vow.h
