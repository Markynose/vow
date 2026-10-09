# v0.1 release checklist

each line is checked by hand and the result written next to it. not done items are listed as not done on purpose; v0.1 ships with them open.

## code freeze
- [x] no new promises, no new public api (include/vow.h has pledge and unveil only)
- [x] make all check-header test static-check passes: 61 unveil, 12 filter, 3 fuzz, 215 seccomp tests, examples script
- [x] python3 tests/mutate.py: all 32 mutants CAUGHT (the x32 check is an equivalent mutant, see the file)
- [x] fuzz: seeds 1 to 6 with VOW_FUZZ_N=20000 VOW_FUZZ_KN=600, no disagreement
- [x] header compiles as c89 to c2x and from c++ (make check-header)

## kernels and environments (not done)
- [ ] real kernels per landlock abi: not done. only 7.2.9 (abi 10) was run. abi 3 to 9 are simulated with vow_test_abi_cap. tests/kernel_matrix.sh exists for whoever runs it.
- [ ] a container with a default seccomp profile: not done
- [ ] a systemd service with SystemCallFilter: not done
- [ ] the stdio rule table against syscalls added since linux 5.x: not done
- [x] user namespace as root (unshare -Ur): suites passed; low ulimit -n: only the many-descriptor tests fail, with EMFILE

| kernel | abi | unveil | filter | seccomp | fuzz | notes |
|---|---|---|---|---|---|---|
| 7.2.9 (dev machine) | 10 | 61 pass | 12 pass | 215 pass | pass | musl, kiss |

## documents
- [x] DESIGN.md and ROADMAP.md updated with the final counts and the open items
- [x] README.md and examples/ (cli, fileproc, netclient, progressive), run by tests/examples.sh
- [x] CLAUDE.md in ~/mds/vow is current
- [x] limits are in README.md and DESIGN.md sections 6 and 14

## known limits that ship with v0.1 (do not hide)
- threads before the first vow call: unveil commit and pledge stdio refuse with EBUSY
- processes in the same landlock domain can signal each other; raw fork children share the domain and locks
- wpath and cpath without unveil are broad; descriptors opened before the sandbox keep their power
- sendmsg destinations and inet addresses and ports are not filtered; the landlock layer limit is 16
- uprobe and uretprobe are exempt from seccomp; PROT_EXEC is not w^x
- kernel behavior verified on 7.2.9 only; glibc is not supported in v0.1
- failure-state table rows without a test are from reading the code

## tag
- [x] version macros in include/vow.h set to 0.1.0
- [x] commit signed, one short subject; tag v0.1.0 signed
