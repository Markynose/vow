CC      ?= cc
AR      ?= ar
CFLAGS  ?= -O2
WARN     = -std=c99 -Wall -Wextra -Wpedantic -Werror
DEFS     = -D_GNU_SOURCE
INC      = -Iinclude
B        = build
OBJ      = $(B)/unveil.o $(B)/pledge.o $(B)/filter.o $(B)/fork.o $(B)/scope.o
TESTS    = $(B)/unveil_test $(B)/filter_test $(B)/fuzz_test $(B)/seccomp_test
HELPERS  = $(B)/hlp_static $(B)/hlp_dyn

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

test: $(TESTS) $(HELPERS)
	@mkdir -p $(B)/tmp
	@for t in $(TESTS); do TMPDIR=$(CURDIR)/$(B)/tmp ./$$t || exit 1; done

EXAMPLES = $(B)/cli $(B)/fileproc $(B)/netclient $(B)/progressive

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

static-check: $(TESTS)
	@for t in $(TESTS); do \
	    if readelf -d $$t 2>/dev/null | grep -q NEEDED; then echo "$$t is dynamic"; exit 1; fi; \
	    echo "$$t: static"; \
	done

clean:
	rm -rf $(B)

.PHONY: all examples test check-header static-check clean
