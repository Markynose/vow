/*
 * vow-run: apply unveil and pledge, then execute a program (tools/vow-run/DESIGN.md).
 *
 *   vow-run -p promises [-u path:perms]... [-i] [-v] [--] program [args...]
 *   vow-run --profile file.vow [-i] [-v] [--] program [args...]
 *
 * static and dynamic executables (the interpreter is unveiled for you, shared libraries are not: -u). without -v the process becomes the program; with -v it
 * stays outside the sandbox as the parent and says which syscall killed the program.
 */
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <vow.h>
/* the policy tables are the library internals: the report asks them what the filter would do */
#include "filter.h"
#include "profile.h"

#define EXIT_SETUP 125
#define EXIT_NOEXEC 126
#define EXIT_NOTFOUND 127
#define AUDIT_ARCH_X86_64 0xc000003eu

extern char **environ;

static void
die(int code, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "vow-run: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(code);
}

static void
usage(void)
{
	fprintf(stderr, "usage: vow-run -p promises [-u path:perms]... [-i] [-v] [--] program [args...]\n"
	    "       vow-run --profile file.vow [-i] [-v] [--] program [args...]\n");
	exit(EXIT_SETUP);
}

/* ---- the program ---- */

/* the canonical path of the program, searched in PATH like execvp when the name has no slash */
static char *
find_prog(const char *name)
{
	char *path, *dup, *dir, *save = NULL, cand[PATH_MAX + 1], *real;
	struct stat st;
	int seen = 0;

	if (strchr(name, '/')) {
		if (stat(name, &st) < 0)
			die(errno == ENOENT ? EXIT_NOTFOUND : EXIT_NOEXEC, "%s: %s", name, strerror(errno));
		seen = 1;
		snprintf(cand, sizeof cand, "%s", name);
		goto check;
	}
	path = getenv("PATH");
	dup = strdup(path && *path ? path : "/usr/bin:/bin");
	if (dup == NULL)
		die(EXIT_SETUP, "out of memory");
	for (dir = strtok_r(dup, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
		snprintf(cand, sizeof cand, "%s/%s", *dir ? dir : ".", name);
		if (stat(cand, &st) == 0) {
			seen = 1;
			if (S_ISREG(st.st_mode) && access(cand, X_OK) == 0)
				goto check;
		}
	}
	die(seen ? EXIT_NOEXEC : EXIT_NOTFOUND, seen ? "%s: found, but not an executable file" : "%s: not found", name);
check:
	if (!S_ISREG(st.st_mode))
		die(EXIT_NOEXEC, "%s: not a regular file", cand);
	if (access(cand, X_OK) != 0)
		die(EXIT_NOEXEC, "%s: %s", cand, strerror(errno));
	real = realpath(cand, NULL);
	if (real == NULL)
		die(EXIT_NOEXEC, "%s: %s", cand, strerror(errno));
	return real;
}

/*
 * an x86-64 elf. if it names an interpreter (a dynamic program) the path is returned in *interp, else NULL.
 * the interpreter itself must be an elf without an interpreter, see check_interp.
 */
static void
check_elf(const char *path, char **interp)
{
	Elf64_Ehdr eh;
	Elf64_Phdr ph;
	int fd, i;

	*interp = NULL;
	if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0)
		die(EXIT_NOEXEC, "%s: %s", path, strerror(errno));
	if (pread(fd, &eh, sizeof eh, 0) != (ssize_t)sizeof eh || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
		die(EXIT_NOEXEC, "%s: not an elf executable (scripts are not supported yet)", path);
	if (eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_ident[EI_DATA] != ELFDATA2LSB ||
	    eh.e_machine != EM_X86_64 || (eh.e_type != ET_EXEC && eh.e_type != ET_DYN))
		die(EXIT_NOEXEC, "%s: not an x86-64 executable", path);
	if (eh.e_phentsize != sizeof ph || eh.e_phnum == 0 || eh.e_phnum > 256)
		die(EXIT_NOEXEC, "%s: odd program header table", path);
	for (i = 0; i < eh.e_phnum; i++) {
		if (pread(fd, &ph, sizeof ph, (off_t)(eh.e_phoff + (uint64_t)i * sizeof ph)) != (ssize_t)sizeof ph)
			die(EXIT_NOEXEC, "%s: cannot read the program headers", path);
		if (ph.p_type != PT_INTERP)
			continue;
		if (*interp != NULL)
			die(EXIT_NOEXEC, "%s: more than one interpreter", path);
		if (ph.p_filesz < 2 || ph.p_filesz > PATH_MAX)
			die(EXIT_NOEXEC, "%s: odd interpreter name", path);
		*interp = malloc(ph.p_filesz);
		if (*interp == NULL)
			die(EXIT_SETUP, "out of memory");
		if (pread(fd, *interp, ph.p_filesz, (off_t)ph.p_offset) != (ssize_t)ph.p_filesz ||
		    (*interp)[ph.p_filesz - 1] != '\0' || strlen(*interp) != ph.p_filesz - 1)
			die(EXIT_NOEXEC, "%s: odd interpreter name", path);
	}
	close(fd);
}

/*
 * the kernel opens the interpreter that the program file names, so the program picks a path that gets
 * unveiled rx. it has to be an absolute path to an executable regular elf that has no interpreter of its
 * own (a loader), so a shell, an interpreter of scripts or a data file cannot be named, and the program
 * cannot make vow-run grant a read of an arbitrary file. returns the canonical path.
 */
static char *
check_interp(const char *prog, const char *name)
{
	struct stat st;
	char *real, *again;

	if (name[0] != '/')
		die(EXIT_NOEXEC, "%s: the interpreter %s is not an absolute path", prog, name);
	if ((real = realpath(name, NULL)) == NULL)
		die(EXIT_NOEXEC, "%s: the interpreter %s: %s", prog, name, strerror(errno));
	if (stat(real, &st) < 0 || !S_ISREG(st.st_mode) || access(real, X_OK) != 0)
		die(EXIT_NOEXEC, "%s: the interpreter %s is not an executable file", prog, name);
	check_elf(real, &again);
	if (again != NULL)
		die(EXIT_NOEXEC, "%s: the interpreter %s has an interpreter itself", prog, name);
	return real;
}

/* descriptors cross exec and keep their power: nothing above 2 is inherited */
static void
close_fds(void)
{
	struct rlimit rl;
	long i, max = 1024;

	if (syscall(436 /* close_range */, 3u, ~0u, 0u) == 0)
		return;
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < 65536)
		max = (long)rl.rlim_cur;
	else if (rl.rlim_cur == RLIM_INFINITY)
		max = 65536;
	for (i = 3; i < max; i++)
		close((int)i);
}

/* ---- the sandbox ---- */

const struct promise_bit promise_bits[] = {
	{ "stdio", P_STDIO }, { "rpath", P_RPATH }, { "wpath", P_WPATH },
	{ "cpath", P_CPATH }, { "inet", P_INET }, { "exec", P_EXEC },
};
const size_t npromise_bits = sizeof promise_bits / sizeof *promise_bits;

/* the bits of the promises named in the string; unknown words are the business of pledge() */
static unsigned
promise_set(const char *s)
{
	char *dup = strdup(s), *tok, *save = NULL;
	unsigned bits = 0;
	size_t i;

	if (dup == NULL)
		die(EXIT_SETUP, "out of memory");
	for (tok = strtok_r(dup, " ", &save); tok; tok = strtok_r(NULL, " ", &save))
		for (i = 0; i < sizeof promise_bits / sizeof *promise_bits; i++)
			if (strcmp(tok, promise_bits[i].name) == 0)
				bits |= promise_bits[i].bit;
	free(dup);
	return bits;
}

static const char *profile_file;

static void
sandbox(const char *prog, const char *interp, const struct rule *rules, int nrules, const char *promises)
{
	int i;

	if (unveil(prog, "rx") < 0)
		die(EXIT_SETUP, "unveil %s: %s", prog, strerror(errno));
	if (interp != NULL && unveil(interp, "rx") < 0)
		die(EXIT_SETUP, "unveil %s: %s", interp, strerror(errno));
	for (i = 0; i < nrules; i++)
		if (unveil(rules[i].path, rules[i].perms) < 0) {
			/* ENOTSUP here is the narrowing check of the library: a rule below another with fewer permissions */
			int e = errno;
			const char *why = e == ENOTSUP ? " (it asks for less than a rule above or below it gives)" : "";

			if (rules[i].line > 0)
				die(EXIT_SETUP, "%s:%d: cannot unveil %s: %s%s", profile_file, rules[i].line, rules[i].path, strerror(e), why);
			die(EXIT_SETUP, "unveil %s: %s%s", rules[i].path, strerror(e), why);
		}
	if (unveil(NULL, NULL) < 0)
		die(EXIT_SETUP, "unveil: %s", strerror(errno));
	if (pledge(promises, NULL) < 0)
		die(EXIT_SETUP, "pledge: %s", strerror(errno));
}

static void
run(const char *prog, char **argv, char **envp)
{
	execve(prog, argv, envp);
	die(errno == ENOENT ? EXIT_NOTFOUND : EXIT_NOEXEC, "%s: %s", argv[0], strerror(errno));
}

/* ---- the report (-v) ---- */

struct sdata {
	uint32_t nr;
	uint32_t arch;
	uint64_t ip;
	uint64_t args[6];
};

/* the classic bpf subset the generator emits; returns the action, or ~0 for anything else */
static uint32_t
bpf_run(const struct vow_insn *p, size_t n, const struct sdata *d)
{
	uint32_t a = 0, v;
	size_t pc = 0;

	while (pc < n) {
		const struct vow_insn *i = &p[pc];

		switch (i->code) {
		case VOW_BPF_LD | VOW_BPF_W | VOW_BPF_ABS:
			if (i->k % 4 || i->k + 4 > sizeof *d)
				return ~0u;
			memcpy(&v, (const unsigned char *)d + i->k, 4);
			a = v;
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
			return ~0u;
		}
		pc++;
	}
	return ~0u;
}

static const struct { long nr; const char *name; } sysnames[] = {
#include "sysnames.h"
};

static const char *
sysname(long nr)
{
	size_t i;

	for (i = 0; i < sizeof sysnames / sizeof *sysnames; i++)
		if (sysnames[i].nr == nr)
			return sysnames[i].name;
	return "unknown";
}

/* the thread at its exit event: if the policy would have killed it for the call it was making, say so */
static int
report(pid_t tid, const char *progname, const struct vow_insn *prog, size_t n, unsigned promises)
{
	struct user_regs_struct r;
	struct sdata d;
	struct vow_ctx ctx;
	struct vow_insn one[VOW_MAX_INSNS];
	char allowed[128] = "";
	uint32_t act;
	size_t i, m;

	if (ptrace(PTRACE_GETREGS, tid, 0, &r) < 0)
		return 0;
	memset(&d, 0, sizeof d);
	d.nr = (uint32_t)r.orig_rax;
	d.arch = AUDIT_ARCH_X86_64;
	d.ip = r.rip;
	d.args[0] = r.rdi; d.args[1] = r.rsi; d.args[2] = r.rdx;
	d.args[3] = r.r10; d.args[4] = r.r8; d.args[5] = r.r9;
	act = bpf_run(prog, n, &d);
	if (act == VOW_SECCOMP_RET_ALLOW || act == ~0u)
		return 0;
	/* which single promise would have allowed it */
	ctx.deny = VOW_SECCOMP_RET_KILL_PROCESS;
	for (i = 0; i < sizeof promise_bits / sizeof *promise_bits; i++) {
		m = vow_build(promise_bits[i].bit, &ctx, one, VOW_MAX_INSNS);
		if (m && bpf_run(one, m, &d) == VOW_SECCOMP_RET_ALLOW) {
			strncat(allowed, allowed[0] ? " " : "", sizeof allowed - strlen(allowed) - 1);
			strncat(allowed, promise_bits[i].name, sizeof allowed - strlen(allowed) - 1);
		}
	}
	(void)promises;
	fprintf(stderr, "vow-run: %s: pledge violation: %s (%u)%s%s\n", progname, sysname((long)d.nr), d.nr,
	    allowed[0] ? ", allowed by: " : ", no promise allows it", allowed);
	return 1;
}

/* the parent of the traced program: waits for it, reports a pledge violation, returns its exit status */
static int
supervise(pid_t child, const char *progname, unsigned promises)
{
	struct vow_insn prog[VOW_MAX_INSNS];
	struct vow_ctx ctx;
	size_t n;
	int st, started = 0, reported = 0;
	long opts = PTRACE_O_TRACEEXIT | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;

	ctx.deny = VOW_SECCOMP_RET_KILL_PROCESS;
	n = vow_build(promises, &ctx, prog, VOW_MAX_INSNS);
	if (n == 0)
		die(EXIT_SETUP, "cannot build the policy for the report");
	for (;;) {
		pid_t w = waitpid(-1, &st, __WALL);
		int sig;
		unsigned long msg;

		if (w < 0) {
			if (errno == EINTR)
				continue;
			die(EXIT_SETUP, "waitpid: %s", strerror(errno));
		}
		if (WIFEXITED(st) || WIFSIGNALED(st)) {
			if (w != child)
				continue;
			if (WIFEXITED(st))
				return WEXITSTATUS(st);
			if (WTERMSIG(st) == SIGSYS && !reported)
				fprintf(stderr, "vow-run: %s: killed by SIGSYS (the syscall is not known)\n", progname);
			return 128 + WTERMSIG(st);
		}
		if (!WIFSTOPPED(st))
			continue;
		sig = WSTOPSIG(st);
		if ((st >> 16) == PTRACE_EVENT_EXIT) {
			if (ptrace(PTRACE_GETEVENTMSG, w, 0, &msg) == 0 && (msg & 0x7f) == SIGSYS &&
			    report(w, progname, prog, n, promises))
				reported = 1;
			ptrace(PTRACE_CONT, w, 0, 0);
			continue;
		}
		if ((st >> 16) != 0) {
			ptrace(PTRACE_CONT, w, 0, 0);
			continue;
		}
		if (sig == SIGSTOP && (w != child || !started)) {
			if (w == child) {
				if (ptrace(PTRACE_SETOPTIONS, w, 0, opts) < 0)
					die(EXIT_SETUP, "-v: cannot trace the program: %s", strerror(errno));
				started = 1;
			}
			ptrace(PTRACE_CONT, w, 0, 0);
			continue;
		}
		ptrace(PTRACE_CONT, w, 0, (void *)(long)sig);
	}
}

/* ---- main ---- */

int
main(int argc, char **argv)
{
	struct rule rules[NRULES];
	struct profile prof;
	char perr[512];
	int nrules = 0, clear = 0, verbose = 0, c, from_flags = 0;
	const char *promises = NULL;
	static const struct option longopts[] = { { "profile", required_argument, NULL, 'P' }, { NULL, 0, NULL, 0 } };
	char *prog, *colon, *name, *interp = NULL;
	char *empty[] = { NULL };
	char **envp;

	while ((c = getopt_long(argc, argv, "+p:u:iv", longopts, NULL)) != -1) {
		switch (c) {
		case 'P':
			if (profile_file != NULL)
				die(EXIT_SETUP, "--profile twice");
			profile_file = optarg;
			break;
		case 'p':
			promises = optarg;
			from_flags = 1;
			break;
		case 'u':
			from_flags = 1;
			if (nrules == NRULES)
				die(EXIT_SETUP, "too many -u rules");
			colon = strrchr(optarg, ':');
			if (colon == NULL || colon == optarg || colon[1] == '\0')
				die(EXIT_SETUP, "-u %s: expected path:perms", optarg);
			rules[nrules].path = strndup(optarg, (size_t)(colon - optarg));
			rules[nrules].perms = strdup(colon + 1);
			if (rules[nrules].path == NULL || rules[nrules].perms == NULL)
				die(EXIT_SETUP, "out of memory");
			nrules++;
			break;
		case 'i':
			clear = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
		}
	}
	if (profile_file != NULL) {
		if (from_flags)
			die(EXIT_SETUP, "--profile cannot be combined with -p or -u");
		if (optind >= argc)
			usage();
		/* all of it is checked here; nothing has touched the file system for the sandbox yet */
		if (profile_load(profile_file, &prof, perr, sizeof perr) < 0)
			die(EXIT_SETUP, "%s", perr);
		promises = prof.promises;
		memcpy(rules, prof.rules, sizeof(struct rule) * (size_t)prof.nrules);
		nrules = prof.nrules;
	}
	if (promises == NULL || optind >= argc)
		usage();
	if ((promise_set(promises) & P_EXEC) == 0)
		die(EXIT_SETUP, "the promises need exec to start the program");
	argv += optind;
	envp = clear ? empty : environ;

	prog = find_prog(argv[0]);
	check_elf(prog, &name);
	if (name != NULL)
		interp = check_interp(prog, name);
	close_fds();

	if (!verbose) {
		sandbox(prog, interp, rules, nrules, promises);
		run(prog, argv, envp);
	}
	{
		pid_t p = fork();

		if (p < 0)
			die(EXIT_SETUP, "fork: %s", strerror(errno));
		if (p == 0) {
			if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
				die(EXIT_SETUP, "-v: cannot be traced: %s", strerror(errno));
			raise(SIGSTOP);
			sandbox(prog, interp, rules, nrules, promises);
			run(prog, argv, envp);
		}
		return supervise(p, argv[0], promise_set(promises));
	}
}
