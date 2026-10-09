CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2
WARN     = -std=c99 -Wall -Wextra -Wpedantic -Werror
DEFS     = -D_GNU_SOURCE
INC      = -Iinclude
B        = build
OBJ      = $(B)/unveil.o $(B)/pledge.o $(B)/filter.o $(B)/fork.o $(B)/scope.o
TESTS    = $(B)/unveil_test $(B)/filter_test $(B)/fuzz_test $(B)/seccomp_test
HELPERS  = $(B)/hlp_static $(B)/hlp_dyn $(B)/hlp_dynld $(B)/hlp_so $(B)/libx.so $(B)/hlp_bad1 $(B)/hlp_bad2 $(B)/hlp_bad3 $(B)/hlp_bad4 $(B)/hlp_bad5
TOOLS    = $(B)/vow-run
EXAMPLES = $(B)/cli $(B)/fileproc $(B)/netclient $(B)/progressive

all: $(B)/libvow.a

$(B)/%.o: src/%.c include/vow.h src/sys.h src/lock.h src/filter.h
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(WARN) $(DEFS) $(INC) -c -o $@ $<

$(B)/libvow.a: $(OBJ)
	$(AR) rcs $@ $(OBJ)

# tests compile the library sources with test hooks and link statically
$(B)/unveil_test: tests/unveil_test.c tests/t.h src/unveil.c src/sys.h src/lock.h include/vow.h
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -Wno-format-truncation -DVOW_TEST $(INC) -Isrc -static -o $@ \
	    tests/unveil_test.c src/unveil.c src/pledge.c src/filter.c src/fork.c src/scope.c -pthread

$(B)/filter_test: tests/filter_test.c tests/t.h tests/bpfi.h tests/oracle.h tests/nr_list.h src/filter.c src/filter.h src/sys.h src/lock.h
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -DVOW_TEST $(INC) -Isrc -static -o $@ \
	    tests/filter_test.c src/filter.c

$(B)/fuzz_test: tests/fuzz_test.c tests/t.h tests/bpfi.h tests/oracle.h tests/nr_list.h src/filter.c src/filter.h src/sys.h src/pledge.c src/unveil.c src/fork.c src/scope.c
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -DVOW_TEST $(INC) -Isrc -static -o $@ \
	    tests/fuzz_test.c src/filter.c src/pledge.c src/unveil.c src/fork.c src/scope.c -pthread

$(B)/seccomp_test: tests/seccomp_test.c tests/t.h tests/bpfi.h tests/oracle.h src/filter.c src/pledge.c src/unveil.c src/fork.c src/scope.c src/filter.h src/sys.h src/lock.h
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -Wno-format-truncation -DVOW_TEST $(INC) -Isrc -static -o $@ \
	    tests/seccomp_test.c src/filter.c src/pledge.c src/unveil.c src/fork.c src/scope.c -pthread

# programs the exec tests run: one static, one dynamic (the only dynamic thing in the tree)
$(B)/hlp_static: tests/helper.c
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -static -o $@ tests/helper.c

$(B)/hlp_dyn: tests/helper.c
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -o $@ tests/helper.c

# dynamic fixtures for the vow-run tests: a copy of the loader that a program names as its interpreter, a
# program with a library besides libc, and programs whose interpreter must be refused
$(B)/ldcopy.so: $(B)/hlp_dyn
	cp -L "$$(readelf -l $(B)/hlp_dyn | sed -n 's/.*interpreter: \(.*\)\]/\1/p')" $@

$(B)/hlp_dynld: tests/helper.c $(B)/ldcopy.so
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -o $@ tests/helper.c -Wl,--dynamic-linker=$(CURDIR)/$(B)/ldcopy.so

$(B)/libx.so: tests/libx.c
	$(CC) $(CFLAGS) $(WARN) -shared -fPIC -o $@ tests/libx.c

$(B)/hlp_so: tests/hlp_so.c $(B)/libx.so
	$(CC) $(CFLAGS) $(WARN) -o $@ tests/hlp_so.c -L$(B) -lx -Wl,-rpath,'$$ORIGIN'

$(B)/hlp_bad1: tests/helper.c
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -o $@ tests/helper.c -Wl,--dynamic-linker=/etc/passwd

$(B)/hlp_bad2: tests/helper.c
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -o $@ tests/helper.c -Wl,--dynamic-linker=ld.so

$(B)/hlp_bad3: tests/helper.c
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -o $@ tests/helper.c -Wl,--dynamic-linker=/nonexistent/ld.so

$(B)/interp.sh:
	@mkdir -p $(B)
	printf '#!/bin/sh\nexit 0\n' > $@ && chmod 755 $@

$(B)/hlp_bad5: tests/helper.c $(B)/interp.sh
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -o $@ tests/helper.c -Wl,--dynamic-linker=$(CURDIR)/$(B)/interp.sh

$(B)/hlp_bad4: tests/helper.c $(B)/hlp_dyn
	$(CC) $(CFLAGS) $(WARN) $(DEFS) -o $@ tests/helper.c -Wl,--dynamic-linker=$(CURDIR)/$(B)/hlp_dyn

test: $(TESTS) $(HELPERS) $(EXAMPLES) $(TOOLS)
	@if [ -e .mutate ]; then echo 'a mutation run was interrupted: run python3 tests/mutate.py --restore, then make clean'; exit 1; fi
	@mkdir -p $(B)/tmp
	@for t in $(TESTS); do TMPDIR=$(CURDIR)/$(B)/tmp ./$$t || exit 1; done
	@sh tests/examples.sh
	@sh tests/vow_run.sh
	@if command -v python3 >/dev/null; then python3 tests/profile_fuzz.py 1 500; else echo 'SKIP  profile fuzz (no python3)'; fi

$(B)/vow-run: tools/vow-run/vow-run.c $(B)/libvow.a src/filter.h src/sys.h tools/vow-run/sysnames.h tools/vow-run/profile.h tools/vow-run/profile.c
	$(CC) $(CFLAGS) $(WARN) $(DEFS) $(INC) -Isrc -Itools/vow-run -static -o $@ tools/vow-run/vow-run.c tools/vow-run/profile.c $(B)/libvow.a -pthread

tools: $(TOOLS)

$(B)/%: examples/%.c $(B)/libvow.a
	$(CC) $(CFLAGS) $(WARN) $(DEFS) $(INC) -static -o $@ $< $(B)/libvow.a -pthread

examples: $(EXAMPLES)

check-header:
	@for s in c89 c99 c11 c17 c2x; do \
	    echo "header $$s"; \
	    $(CC) -std=$$s -pedantic -Wall -Wextra -Werror -Iinclude -fsyntax-only tests/hdr.c || exit 1; \
	done
	@if command -v g++ >/dev/null; then echo "header c++"; \
	    g++ -x c++ -std=c++11 -pedantic -Wall -Wextra -Werror -Iinclude -fsyntax-only tests/hdr.c || exit 1; fi

static-check: $(TESTS) $(TOOLS)
	@for t in $(TESTS) $(TOOLS); do \
	    if readelf -d $$t 2>/dev/null | grep -q NEEDED; then echo "$$t is dynamic"; exit 1; fi; \
	    echo "$$t: static"; \
	done

clean:
	rm -rf $(B)

.PHONY: all tools examples test check-header static-check clean
