#ifndef VOW_FILTER_H
#define VOW_FILTER_H

#include <stddef.h>
#include <stdint.h>

#include "sys.h"

/* promise bits. only stdio is implemented in milestone 2 */
#define P_STDIO 0x01u
#define P_RPATH 0x02u
#define P_WPATH 0x04u
#define P_CPATH 0x08u
#define P_INET  0x10u
#define P_EXEC  0x20u

/*
 * how one syscall argument is judged. the kind says how the *kernel* reads
 * the register, so the generator and the test oracle agree with it:
 *   VK_LO32   the kernel truncates to 32 bits (int, unsigned int, pid_t, and
 *             clone flags): junk in the high half must not change the verdict
 *   VK_FULL64 the kernel uses all 64 bits (pointers, unsigned long): the
 *             high half is part of the value
 * mask operations always test the low 32 bits, whatever the kind.
 */
enum vow_kind { VK_LO32, VK_FULL64 };

enum vow_cop {
	VC_EQ,		/* arg == v */
	VC_IN,		/* arg is one of set[0..nset-1] (LO32 only) */
	VC_ALLBITS,	/* (arg & v) == v */
	VC_NOTALLBITS,	/* (arg & v) != v */
	VC_ONLYBITS,	/* (arg & ~v) == 0 */
	VC_MASKEQ	/* (arg & m) == v, low 32 bits */
};

struct vow_cond {
	uint8_t op, arg, kind, nset;
	uint64_t v;
	const uint32_t *set;
	uint32_t m;
};

/*
 * a rule matches syscall nr when all conds hold and then allows it, or when
 * err != 0 and then returns that errno without checking conds. several rules
 * may share an nr; they are alternatives, first match wins.
 */
struct vow_rule {
	uint32_t nr;
	uint32_t err;
	uint8_t ncond;
	const struct vow_cond *cond;
};

struct vow_table {
	const struct vow_rule *r;
	size_t n;
};

#define VOW_MAX_TABLES 12

struct vow_ctx {
	uint32_t deny;	/* action for everything not allowed; VOW_SECCOMP_RET_KILL_PROCESS in production */
};

/*
 * rules that depend on the promise set (the open(2) flag classes) are built
 * into storage the caller provides
 */
#define VOW_POLICY_RULES 48
#define VOW_POLICY_CONDS 48
struct vow_policy {
	struct vow_rule rule[VOW_POLICY_RULES];
	struct vow_cond cond[VOW_POLICY_CONDS];
	size_t nrule, ncond;
};

/*
 * the rule tables a promise set selects. always includes the core table.
 * pol is scratch space that the returned tables may point into
 */
size_t vow_tables(unsigned promises, struct vow_policy *pol, struct vow_table out[VOW_MAX_TABLES]);

/* the generator on any tables (the fuzz test uses it); returns the program length, or 0 with errno set (E2BIG: does not fit) */
size_t vow_build_tables(const struct vow_table *t, size_t nt, const struct vow_ctx *ctx, struct vow_insn *out, size_t max);

/* the same for the tables a promise set selects */
size_t vow_build(unsigned promises, const struct vow_ctx *ctx, struct vow_insn *out, size_t max);

/* running landlock abi (-1 with errno if there is none) and whether this process has exactly one thread */
int vow_landlock_abi(void);
int vow_threads_single(void);		/* 1: exactly one thread listed; 0: more, or no proof; -1: out of descriptors or memory (errno) */
void vow_threads_prepare(void);		/* open the thread list now, while /proc is still reachable */
void vow_threads_forked(void);		/* in the child of a fork: the inherited list is the parent's, reopen it later */
/* enter a landlock domain that scopes signals, only with one thread; 0 or -1 with errno */
int vow_scope_enter(void);
/* the same for the child right after a fork, which has one thread by construction and may be under a
   filter that does not allow reading the thread list: the caller vouches for it */
int vow_scope_enter_child(void);

/* sets no_new_privs and loads the program on every thread; 0 or -1 with errno */
int vow_install(const struct vow_insn *prog, size_t n);

/*
 * 1 if a pledge is active that no longer allows reading paths (unveil must refuse), 0 if not,
 * -1 if this very thread is inside pledge() already (a signal handler calling back in)
 */
int vow_pledge_blocks_unveil(void);

/* locks for fork handling; lock returns what to pass to unlock (0 if this thread held it already) */
int vow_pledge_lock(void);
void vow_pledge_unlock(int took);
int vow_unveil_lock(void);
void vow_unveil_unlock(int took);
void vow_atfork_register(void);

#ifdef VOW_TEST
extern long vow_test_seccomp_nr;	/* nonzero: use this number instead of seccomp(2) */
extern struct vow_table vow_test_extra;	/* rules appended to every set, for tests of inheritance */
extern const char *vow_test_proc_task;	/* if set, the directory the thread list is read from */
extern void (*vow_test_after_restrict)(void);	/* called right after a landlock domain was entered */
extern void (*vow_test_after_open)(void);	/* called right after unveil opened a path */
extern void (*vow_test_window)(void);	/* called inside the locked region, to widen race windows */
unsigned vow_test_promises(void);
int vow_test_scope_state(void);	/* 1 once pledge() has entered the landlock signal scope */
#endif

#endif
