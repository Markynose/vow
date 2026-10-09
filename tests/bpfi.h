/* SPDX-License-Identifier: LGPL-3.0-only */
#ifndef BPFI_H
#define BPFI_H

/*
 * a userspace interpreter for the classic bpf subset the generator may use,
 * plus the structural checks the kernel makes at load time. any opcode
 * outside the subset is a test failure, so the generator cannot start
 * emitting something this file does not understand.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sys.h"

struct sdata {
	uint32_t nr;
	uint32_t arch;
	uint64_t ip;
	uint64_t args[6];
};

static uint32_t
bpf_load(const struct sdata *d, uint32_t off)
{
	uint32_t v;

	if (off % 4 != 0 || off + 4 > sizeof *d) {
		fprintf(stderr, "bpf: bad load offset %u\n", off);
		abort();
	}
	memcpy(&v, (const unsigned char *)d + off, 4);
	return v;
}

/* returns 0 if the program passes the load-time checks of the kernel */
static int
bpf_validate(const struct vow_insn *p, size_t n)
{
	size_t i;

	if (n == 0 || n > 4096)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned c = p[i].code;

		if (c == (VOW_BPF_LD | VOW_BPF_W | VOW_BPF_ABS)) {
			if (p[i].k % 4 || p[i].k + 4 > sizeof(struct sdata))
				return 0;
		} else if (c == (VOW_BPF_ALU | VOW_BPF_AND | VOW_BPF_K)) {
			;
		} else if (c == (VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K) ||
		    c == (VOW_BPF_JMP | VOW_BPF_JSET | VOW_BPF_K)) {
			if (i + 1 + p[i].jt >= n || i + 1 + p[i].jf >= n)
				return 0;
		} else if (c == (VOW_BPF_RET | VOW_BPF_K)) {
			;
		} else {
			fprintf(stderr, "bpf: opcode 0x%x outside the generator subset\n", c);
			return 0;
		}
	}
	/* the last instruction must be a return, and since jumps only go forward every path ends */
	return p[n - 1].code == (VOW_BPF_RET | VOW_BPF_K);
}

static uint32_t
bpf_run(const struct vow_insn *p, size_t n, const struct sdata *d)
{
	uint32_t a = 0;
	size_t pc = 0;

	while (pc < n) {
		const struct vow_insn *i = &p[pc];

		switch (i->code) {
		case VOW_BPF_LD | VOW_BPF_W | VOW_BPF_ABS:
			a = bpf_load(d, i->k);
			break;
		case VOW_BPF_ALU | VOW_BPF_AND | VOW_BPF_K:
			a &= i->k;
			break;
		case VOW_BPF_JMP | VOW_BPF_JEQ | VOW_BPF_K:
			pc += a == i->k ? i->jt : i->jf;
			break;
		case VOW_BPF_JMP | VOW_BPF_JSET | VOW_BPF_K:
			pc += (a & i->k) ? i->jt : i->jf;
			break;
		case VOW_BPF_RET | VOW_BPF_K:
			return i->k;
		default:
			fprintf(stderr, "bpf: bad opcode 0x%x at %zu\n", i->code, pc);
			abort();
		}
		pc++;
	}
	fprintf(stderr, "bpf: ran off the end\n");
	abort();
}

#endif
