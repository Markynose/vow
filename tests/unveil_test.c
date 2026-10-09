#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <utime.h>

#include <stddef.h>

#include "vow.h"
#include "sys.h"
#include "t.h"

extern int vow_test_abi_cap;
extern int vow_test_alloc_fail;
extern const char *vow_test_proc_task;
extern void (*vow_test_after_open)(void);
extern void (*vow_test_after_restrict)(void);

static char root[PATH_MAX], self[PATH_MAX];
static char B[PATH_MAX], A[PATH_MAX], D[PATH_MAX];

static const char *
pj(const char *a, const char *b)
{
	static char buf[4][PATH_MAX];
	static int i;
	char *s = buf[i++ & 3];

	snprintf(s, PATH_MAX, "%s/%s", a, b);
	return s;
}

static int
real_abi(void)
{
	return (int)syscall(VOW_SYS_landlock_create_ruleset, NULL, 0, VOW_LL_CREATE_VERSION);
}

static void
wr(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	CHECK(fd >= 0);
	CHECK(write(fd, s, strlen(s)) == (ssize_t)strlen(s));
	close(fd);
}

/* 0 if the open worked, else errno */
static int
try_open(const char *path, int flags)
{
	int fd = open(path, flags, 0600);

	if (fd < 0)
		return errno;
	close(fd);
	return 0;
}

#define ERR(expr, e) do { errno = 0; CHECK((expr) == -1 && errno == (e)); } while (0)
#define OK(expr) CHECK((expr) == 0)

/* fresh tree for one test: allow/{f,sub/g,escape,inside}, allow2/, deny/h */
static void
tree(const char *name)
{
	if (real_abi() < VOW_MIN_ABI)
		SKIP("landlock abi < 3 or unavailable");
	snprintf(B, sizeof B, "%s/%s", root, name);
	snprintf(A, sizeof A, "%s/allow", B);
	snprintf(D, sizeof D, "%s/deny", B);
	CHECK(mkdir(B, 0755) == 0);
	CHECK(mkdir(A, 0755) == 0);
	CHECK(mkdir(pj(A, "sub"), 0755) == 0);
	CHECK(mkdir(pj(B, "allow2"), 0755) == 0);
	CHECK(mkdir(D, 0755) == 0);
	wr(pj(A, "f"), "hello\n");
	wr(pj(A, "sub/g"), "gee\n");
	wr(pj(D, "h"), "secret\n");
	CHECK(symlink("../deny/h", pj(A, "escape")) == 0);
	CHECK(symlink("f", pj(A, "inside")) == 0);
}

static void
t_args(void)
{
	tree("args");
	ERR(unveil(A, NULL), EINVAL);
	ERR(unveil(NULL, "r"), EINVAL);
	ERR(unveil(A, "rz"), EINVAL);
	ERR(unveil(A, "R"), EINVAL);
	ERR(unveil(A, "r w"), EINVAL);
	ERR(unveil("", "r"), ENOENT);
	ERR(unveil(pj(A, "nope"), "r"), ENOENT);
	/* failures change nothing: a good call still works and is enforced */
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

static void
t_read_only(void)
{
	tree("ro");
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
	CHECK(try_open(pj(A, "sub/g"), O_RDONLY) == 0);
	CHECK(try_open(A, O_RDONLY | O_DIRECTORY) == 0);
	CHECK(try_open(pj(A, "f"), O_WRONLY) == EACCES);
	CHECK(try_open(pj(A, "f"), O_RDWR) == EACCES);
	CHECK(try_open(pj(A, "new"), O_WRONLY | O_CREAT) == EACCES);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
	CHECK(try_open(D, O_RDONLY | O_DIRECTORY) == EACCES);
	ERR(truncate(pj(A, "f"), 0), EACCES);
	ERR(unlink(pj(A, "f")), EACCES);
	ERR(mkdir(pj(A, "nd"), 0755), EACCES);
	ERR(rename(pj(A, "f"), pj(A, "f2")), EACCES);
	ERR(symlink("f", pj(A, "sl")), EACCES);
}

static void
t_rw(void)
{
	int fd;

	tree("rw");
	OK(unveil(A, "rw"));
	OK(unveil(NULL, NULL));
	fd = open(pj(A, "f"), O_WRONLY | O_TRUNC);
	CHECK(fd >= 0);
	CHECK(write(fd, "x", 1) == 1);
	close(fd);
	OK(truncate(pj(A, "f"), 0));
	CHECK(try_open(pj(A, "f"), O_RDWR) == 0);
	CHECK(try_open(pj(A, "new"), O_WRONLY | O_CREAT) == EACCES);
	ERR(mkdir(pj(A, "nd"), 0755), EACCES);
	ERR(unlink(pj(A, "f")), EACCES);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
	CHECK(try_open(pj(D, "h"), O_WRONLY) == EACCES);
}

static void
t_rwc(void)
{
	tree("rwc");
	OK(unveil(A, "rwc"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "new"), O_WRONLY | O_CREAT) == 0);
	OK(mkdir(pj(A, "nd"), 0755));
	OK(rename(pj(A, "new"), pj(A, "new2")));
	OK(rename(pj(A, "new2"), pj(A, "sub/new3")));
	OK(symlink("f", pj(A, "sl")));
	OK(link(pj(A, "f"), pj(A, "hl")));
	OK(mkfifo(pj(A, "ff"), 0600));
	OK(unlink(pj(A, "sl")));
	OK(unlink(pj(A, "hl")));
	OK(rmdir(pj(A, "nd")));
	/* nothing crosses into the part of the tree without rules */
	CHECK(rename(pj(A, "f"), pj(D, "f")) == -1 && (errno == EACCES || errno == EXDEV));
	CHECK(link(pj(D, "h"), pj(A, "hl2")) == -1 && (errno == EACCES || errno == EXDEV));
	CHECK(rename(pj(D, "h"), pj(A, "h2")) == -1 && (errno == EACCES || errno == EXDEV));
	CHECK(symlink("x", pj(D, "sl")) == -1 && errno == EACCES);
	ERR(unlink(pj(D, "h")), EACCES);
	ERR(mkdir(pj(D, "nd"), 0755), EACCES);
}

static void
t_exec_self_x(void)
{
	pid_t p;
	int st;


	tree("xok");
	OK(unveil(self, "rx"));
	OK(unveil(NULL, NULL));
	p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		execl(self, self, "--child", (char *)NULL);
		_exit(99);
	}
	CHECK(waitpid(p, &st, 0) == p);
	CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static void
t_exec_denied(void)
{
	tree("xno");
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	ERR(execl(self, self, "--child", (char *)NULL), EACCES);
}

static void
t_exec_needs_read(void)
{
	tree("xread");
	/* landlock cannot execute what it cannot read, so a bare x is refused */
	ERR(unveil(A, "x"), ENOTSUP);
	ERR(unveil(A, "wx"), ENOTSUP);
	ERR(unveil(A, "cx"), ENOTSUP);
	OK(unveil(A, "rx"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
	CHECK(try_open(pj(A, "f"), O_WRONLY) == EACCES);
}

static void
t_file_rules(void)
{
	tree("file");
	/* c cannot work on a non-directory, so it is refused rather than ignored */
	ERR(unveil(pj(A, "f"), "rc"), ENOTSUP);
	OK(unveil(pj(A, "f"), "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
	CHECK(try_open(pj(A, "f"), O_WRONLY) == EACCES);
	CHECK(try_open(pj(A, "sub/g"), O_RDONLY) == EACCES);
	CHECK(try_open(A, O_RDONLY | O_DIRECTORY) == EACCES);
}

static void
t_file_write_only(void)
{
	tree("filew");
	OK(unveil(pj(A, "f"), "w"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_WRONLY) == 0);
	CHECK(try_open(pj(A, "f"), O_WRONLY | O_TRUNC) == 0);
	CHECK(try_open(pj(A, "f"), O_RDONLY) == EACCES);
}

static void
t_sealed(void)
{
	tree("sealed");
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	ERR(unveil(A, "r"), EPERM);
	ERR(unveil(pj(A, "sub"), "r"), EPERM);
	ERR(unveil(NULL, NULL), EPERM);
}

static void
t_seal_only(void)
{
	tree("sealonly");
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(D, "h"), O_RDONLY) == 0);
	CHECK(try_open(pj(D, "h"), O_WRONLY) == 0);
	ERR(unveil(A, "r"), EPERM);
	ERR(unveil(NULL, NULL), EPERM);
}

static void
t_replace_narrow(void)
{
	tree("repl1");
	OK(unveil(A, "rw"));
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
	CHECK(try_open(pj(A, "f"), O_WRONLY) == EACCES);
}

static void
t_replace_widen(void)
{
	tree("repl2");
	OK(unveil(A, "r"));
	OK(unveil(A, "rw"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_WRONLY) == 0);
}

static void
t_conflict_child_narrower(void)
{
	tree("conf1");
	OK(unveil(A, "rw"));
	ERR(unveil(pj(A, "sub"), "r"), ENOTSUP);
	ERR(unveil(pj(A, "sub"), ""), ENOTSUP);
	OK(unveil(pj(A, "sub"), "rw"));
	/* the refused calls did not disturb the earlier rule */
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "sub/g"), O_WRONLY) == 0);
	CHECK(try_open(pj(A, "f"), O_WRONLY) == 0);
}

static void
t_conflict_parent_wider(void)
{
	tree("conf2");
	OK(unveil(pj(A, "sub"), "r"));
	ERR(unveil(A, "rw"), ENOTSUP);
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "sub/g"), O_WRONLY) == EACCES);
}

static void
t_conflict_replace_checks(void)
{
	tree("conf3");
	OK(unveil(A, "r"));
	OK(unveil(pj(A, "sub"), "rw"));
	/* widening the parent over a narrower child, and narrowing a child under a parent */
	ERR(unveil(A, "rwx"), ENOTSUP);
	ERR(unveil(pj(A, "sub"), "x"), ENOTSUP);
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "sub/g"), O_WRONLY) == 0);
	CHECK(try_open(pj(A, "f"), O_WRONLY) == EACCES);
}

static void
t_child_wider_ok(void)
{
	tree("conf4");
	OK(unveil(A, "r"));
	OK(unveil(pj(A, "sub"), "rw"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "sub/g"), O_WRONLY) == 0);
	CHECK(try_open(pj(A, "f"), O_WRONLY) == EACCES);
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
}

static void
t_prefix_not_ancestor(void)
{
	tree("conf5");
	/* allow and allow2 share a string prefix but are siblings */
	OK(unveil(A, "rw"));
	OK(unveil(pj(B, "allow2"), "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_WRONLY) == 0);
	CHECK(try_open(pj(B, "allow2"), O_RDONLY | O_DIRECTORY) == 0);
}

static void
t_escape(void)
{
	tree("escape");
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "escape"), O_RDONLY) == EACCES);
	CHECK(try_open(pj(A, "inside"), O_RDONLY) == 0);
	CHECK(try_open(pj(A, "../deny/h"), O_RDONLY) == EACCES);
	CHECK(try_open(pj(A, "sub/../../deny/h"), O_RDONLY) == EACCES);
	CHECK(try_open(pj(A, "sub/../f"), O_RDONLY) == 0);
}

static void
t_open_fd_survives(void)
{
	char c;
	int fd, wfd;

	tree("fdkeep");
	fd = open(pj(D, "h"), O_RDONLY);
	wfd = open(pj(D, "h"), O_WRONLY);
	CHECK(fd >= 0 && wfd >= 0);
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	/* documented gap: descriptors opened earlier keep their access */
	CHECK(read(fd, &c, 1) == 1);
	CHECK(write(wfd, "z", 1) == 1);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

static void
t_dirfd_escape(void)
{
	int dfd;

	tree("dirfd");
	dfd = open(A, O_PATH | O_DIRECTORY);
	CHECK(dfd >= 0);
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(openat(dfd, "f", O_RDONLY) >= 0);
	errno = 0;
	CHECK(openat(dfd, "../deny/h", O_RDONLY) == -1 && errno == EACCES);
}

/* documented gaps: landlock does not cover these. if one starts failing, the docs must change */
static void
t_metadata_gap(void)
{
	struct stat st;
	struct utimbuf ut;

	tree("meta");
	OK(stat(pj(D, "h"), &st));
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	OK(stat(pj(D, "h"), &st));
	OK(lstat(pj(D, "h"), &st));
	OK(access(pj(D, "h"), R_OK));
	OK(chmod(pj(D, "h"), st.st_mode & 07777));
	ut.actime = ut.modtime = 1;
	OK(utime(pj(D, "h"), &ut));
	OK(chdir(D));
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

static void
t_proc_reopen(void)
{
	char p[64];
	int fd;

	tree("reopen");
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	fd = open(pj(A, "f"), O_RDONLY);
	CHECK(fd >= 0);
	snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
	if (try_open(p, O_RDONLY) != 0)
		SKIP("/proc/self/fd not usable");
	CHECK(try_open(p, O_WRONLY) == EACCES);
}

static void
t_nnp(void)
{
	tree("nnp");
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(prctl(39 /* PR_GET_NO_NEW_PRIVS */, 0, 0, 0, 0) == 1);
}

static void
t_abi_gate(void)
{
	tree("abi");
	vow_test_abi_cap = 2;
	ERR(unveil(A, "r"), ENOSYS);
	vow_test_abi_cap = -1;
	ERR(unveil(A, "r"), ENOSYS);
	ERR(unveil(A, "z"), EINVAL);
	/* a lock with no rules needs no kernel support */
	OK(unveil(NULL, NULL));
	ERR(unveil(A, "r"), EPERM);
}

static void
t_commit_failure_state(void)
{
	tree("cfail");
	OK(unveil(A, "r"));
	vow_test_abi_cap = 2;
	ERR(unveil(NULL, NULL), ENOSYS);
	/* a failed commit enforces nothing and does not seal */
	CHECK(try_open(pj(D, "h"), O_RDONLY) == 0);
	vow_test_abi_cap = 0;
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

/* an add that fails leaves the rules added before it, and the commit enforces them */
static void
t_failed_add_keeps_earlier_rules(void)
{
	tree("fadd");
	OK(unveil(A, "r"));
	ERR(unveil(pj(A, "nope"), "r"), ENOENT);
	ERR(unveil(pj(A, "f"), "q"), EINVAL);
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

static int rd_p[2], rs_p[2];

static void *
worker(void *arg)
{
	char c = 'r';
	int e;

	(void)arg;
	CHECK(write(rd_p[1], &c, 1) == 1);
	CHECK(read(rs_p[0], &c, 1) == 1);
	e = try_open(pj(D, "h"), O_RDONLY);
	c = e == EACCES ? 'D' : e == 0 ? 'O' : 'E';
	CHECK(write(rd_p[1], &c, 1) == 1);
	return NULL;
}

static void
start_worker(pthread_t *t)
{
	char c;

	CHECK(pipe(rd_p) == 0 && pipe(rs_p) == 0);
	CHECK(pthread_create(t, NULL, worker, NULL) == 0);
	CHECK(read(rd_p[0], &c, 1) == 1);
}

static char
release_worker(pthread_t t)
{
	char c = 'g';

	CHECK(write(rs_p[1], &c, 1) == 1);
	CHECK(read(rd_p[0], &c, 1) == 1);
	pthread_join(t, NULL);
	return c;
}



static void
t_old_abi_single_thread(void)
{
	tree("abi7");
	vow_test_abi_cap = 7;
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
}

static void *
late_worker(void *arg)
{
	*(int *)arg = try_open(pj(D, "h"), O_RDONLY);
	return NULL;
}

static void
t_thread_after_commit(void)
{
	pthread_t t;
	int e = -1;

	tree("late");
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(pthread_create(&t, NULL, late_worker, &e) == 0);
	pthread_join(t, NULL);
	CHECK(e == EACCES);
}

static void
t_many_entries(void)
{
	char d[PATH_MAX + 64];
	int i;

	tree("many");
	for (i = 0; i < 300; i++) {
		snprintf(d, sizeof d, "%s/sub/d%d", A, i);
		CHECK(mkdir(d, 0755) == 0);
		OK(unveil(d, "r"));
	}
	OK(unveil(NULL, NULL));
	for (i = 0; i < 300; i += 37) {
		snprintf(d, sizeof d, "%s/sub/d%d", A, i);
		CHECK(try_open(d, O_RDONLY | O_DIRECTORY) == 0);
	}
	CHECK(try_open(pj(A, "f"), O_RDONLY) == EACCES);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

static void
t_alloc_failure(void)
{
	char d[PATH_MAX + 64];
	int i;

	tree("alloc");
	for (i = 0; i < 17; i++) {
		snprintf(d, sizeof d, "%s/sub/d%d", A, i);
		CHECK(mkdir(d, 0755) == 0);
	}
	vow_test_alloc_fail = 1;
	snprintf(d, sizeof d, "%s/sub/d0", A);
	ERR(unveil(d, "r"), ENOMEM);
	for (i = 0; i < 16; i++) {
		snprintf(d, sizeof d, "%s/sub/d%d", A, i);
		OK(unveil(d, "r"));
	}
	/* the 17th entry needs the table to grow */
	vow_test_alloc_fail = 1;
	snprintf(d, sizeof d, "%s/sub/d16", A);
	ERR(unveil(d, "r"), ENOMEM);
	OK(unveil(NULL, NULL));
	snprintf(d, sizeof d, "%s/sub/d15", A);
	CHECK(try_open(d, O_RDONLY | O_DIRECTORY) == 0);
	snprintf(d, sizeof d, "%s/sub/d16", A);
	CHECK(try_open(d, O_RDONLY | O_DIRECTORY) == EACCES);
}

static void
t_emfile(void)
{
	struct rlimit rl, old;
	char d[PATH_MAX + 64];
	int i, got = 0;

	tree("emfile");
	for (i = 0; i < 40; i++) {
		snprintf(d, sizeof d, "%s/sub/d%d", A, i);
		CHECK(mkdir(d, 0755) == 0);
	}
	CHECK(getrlimit(RLIMIT_NOFILE, &old) == 0);
	rl = old;
	rl.rlim_cur = 12;
	CHECK(setrlimit(RLIMIT_NOFILE, &rl) == 0);
	for (i = 0; i < 40; i++) {
		snprintf(d, sizeof d, "%s/sub/d%d", A, i);
		if (unveil(d, "r") < 0)
			break;
		got++;
	}
	CHECK(i < 40 && errno == EMFILE && got > 0);
	CHECK(setrlimit(RLIMIT_NOFILE, &old) == 0);
	OK(unveil(NULL, NULL));
	snprintf(d, sizeof d, "%s/sub/d0", A);
	CHECK(try_open(d, O_RDONLY | O_DIRECTORY) == 0);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

static void
t_relative_and_symlink(void)
{
	tree("rel");
	CHECK(symlink(A, pj(B, "lnk")) == 0);
	OK(chdir(A));
	OK(unveil(".", "r"));
	OK(unveil(pj(B, "lnk"), "r"));	/* same inode as ".": replaces, no new entry */
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}


/* ---- pathname unix sockets (s permission, landlock abi 9) ---- */

static int
sockaddr_path(struct sockaddr_un *a, const char *path)
{
	memset(a, 0, sizeof *a);
	a->sun_family = AF_UNIX;
	if (strlen(path) >= sizeof a->sun_path)
		return -1;
	strcpy(a->sun_path, path);
	return (int)sizeof *a;
}

/* server created before the sandbox, outside any domain */
static int
srv(const char *path, int type)
{
	struct sockaddr_un a;
	int fd = socket(AF_UNIX, type, 0);

	CHECK(fd >= 0 && sockaddr_path(&a, path) > 0);
	CHECK(bind(fd, (struct sockaddr *)&a, sizeof a) == 0);
	if (type == SOCK_STREAM)
		CHECK(listen(fd, 8) == 0);
	return fd;
}

static int
try_connect(const char *path)
{
	struct sockaddr_un a;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0), e = 0;

	CHECK(fd >= 0 && sockaddr_path(&a, path) > 0);
	if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0)
		e = errno;
	close(fd);
	return e;
}

static int
try_sendto(const char *path)
{
	struct sockaddr_un a;
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0), e = 0;

	CHECK(fd >= 0 && sockaddr_path(&a, path) > 0);
	if (sendto(fd, "x", 1, 0, (struct sockaddr *)&a, sizeof a) < 0)
		e = errno;
	close(fd);
	return e;
}

static void
need_unix_abi(void)
{
	if (real_abi() < VOW_UNIX_ABI)
		SKIP("kernel landlock abi < 9");
}

static void
t_unix_allow(void)
{
	tree("unixok");
	need_unix_abi();
	srv(pj(A, "s.sock"), SOCK_STREAM);
	srv(pj(D, "s.sock"), SOCK_STREAM);
	OK(unveil(A, "s"));
	OK(unveil(NULL, NULL));
	CHECK(try_connect(pj(A, "s.sock")) == 0);
	CHECK(try_connect(pj(D, "s.sock")) == EACCES);
	/* s grants nothing else */
	CHECK(try_open(pj(A, "f"), O_RDONLY) == EACCES);
}

static void
t_unix_default_deny(void)
{
	tree("unixno");
	need_unix_abi();
	srv(pj(A, "s.sock"), SOCK_STREAM);
	OK(unveil(A, "rwc"));
	OK(unveil(NULL, NULL));
	CHECK(try_connect(pj(A, "s.sock")) == EACCES);
}

static void
t_unix_file_rule(void)
{
	tree("unixfile");
	need_unix_abi();
	srv(pj(A, "s.sock"), SOCK_STREAM);
	srv(pj(A, "t.sock"), SOCK_STREAM);
	OK(unveil(pj(A, "s.sock"), "s"));
	OK(unveil(NULL, NULL));
	CHECK(try_connect(pj(A, "s.sock")) == 0);
	CHECK(try_connect(pj(A, "t.sock")) == EACCES);
}

static void
t_unix_dgram(void)
{
	tree("unixdg");
	need_unix_abi();
	srv(pj(A, "d.sock"), SOCK_DGRAM);
	srv(pj(D, "d.sock"), SOCK_DGRAM);
	OK(unveil(A, "s"));
	OK(unveil(NULL, NULL));
	CHECK(try_sendto(pj(A, "d.sock")) == 0);
	CHECK(try_sendto(pj(D, "d.sock")) == EACCES);
}

/* documented limits: connections made before the sandbox keep working */
static void
t_unix_existing_connection(void)
{
	struct sockaddr_un a;
	char c;
	int s, cl, ac;

	tree("unixold");
	need_unix_abi();
	s = srv(pj(D, "s.sock"), SOCK_STREAM);
	cl = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(cl >= 0 && sockaddr_path(&a, pj(D, "s.sock")) > 0);
	CHECK(connect(cl, (struct sockaddr *)&a, sizeof a) == 0);
	ac = accept(s, NULL, NULL);
	CHECK(ac >= 0);
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(write(cl, "x", 1) == 1);
	CHECK(read(ac, &c, 1) == 1 && c == 'x');
	/* a new connection to the same server is refused */
	CHECK(try_connect(pj(D, "s.sock")) == EACCES);
	/* the already listening server also still accepts nothing new from outside the rule, but
	   a socketpair has no path and is never restricted */
	{
		int sv[2];

		OK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
	}
}

/* servers created inside the domain stay reachable without s (kernel semantics) */
static void
t_unix_same_domain(void)
{
	tree("unixsame");
	need_unix_abi();
	srv(pj(A, "old.sock"), SOCK_STREAM);
	OK(unveil(A, "rwc"));
	OK(unveil(NULL, NULL));
	srv(pj(A, "new.sock"), SOCK_STREAM);
	CHECK(try_connect(pj(A, "new.sock")) == 0);
	CHECK(try_connect(pj(A, "old.sock")) == EACCES);
}

/* documented gap: abstract sockets are a separate namespace and are not covered */
static void
t_unix_abstract_gap(void)
{
	struct sockaddr_un a;
	int s, c;

	tree("unixabs");
	need_unix_abi();
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&a, 0, sizeof a);
	a.sun_family = AF_UNIX;
	memcpy(a.sun_path + 1, "vowtest-abstract", 16);
	CHECK(bind(s, (struct sockaddr *)&a, offsetof(struct sockaddr_un, sun_path) + 17) == 0);
	CHECK(listen(s, 4) == 0);
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	c = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(connect(c, (struct sockaddr *)&a, offsetof(struct sockaddr_un, sun_path) + 17) == 0);
}

static void
t_unix_old_abi_refused(void)
{
	tree("unixabi");
	vow_test_abi_cap = 8;
	ERR(unveil(A, "s"), ENOTSUP);
	ERR(unveil(A, "rs"), ENOTSUP);
	/* the refusal changed nothing, and ordinary rules still work on this abi */
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

static void
t_unix_conflict(void)
{
	tree("unixconf");
	vow_test_abi_cap = 0;
	need_unix_abi();
	OK(unveil(A, "rs"));
	ERR(unveil(pj(A, "sub"), "r"), ENOTSUP);
	OK(unveil(pj(A, "sub"), "rs"));
}

/* evidence for refusing a bare x: with read_file handled, exec needs it (static binary, no interpreter) */
static void
exec_with(uint64_t allowed)
{
	struct vow_ruleset_attr attr;
	struct vow_path_beneath pb;
	int rs, fd;

	memset(&attr, 0, sizeof attr);
	attr.handled_access_fs = VOW_LL_FS_HANDLED;
	rs = (int)syscall(VOW_SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
	CHECK(rs >= 0);
	fd = open(self, O_PATH | O_CLOEXEC);
	CHECK(fd >= 0);
	memset(&pb, 0, sizeof pb);
	pb.allowed_access = allowed;
	pb.parent_fd = fd;
	CHECK(syscall(VOW_SYS_landlock_add_rule, rs, VOW_LL_RULE_PATH_BENEATH, &pb, 0) == 0);
	CHECK(prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	CHECK(syscall(VOW_SYS_landlock_restrict_self, rs, 0) == 0);
}

static void
t_kernel_exec_needs_read(void)
{
	pid_t p;
	int st;

	tree("xkernel");
	exec_with(VOW_LL_FS_EXECUTE);
	ERR(execl(self, self, "--child", (char *)NULL), EACCES);
	(void)p;
	(void)st;
}

static void
t_kernel_exec_read_works(void)
{
	pid_t p;
	int st;


	tree("xkernel2");
	exec_with(VOW_LL_FS_EXECUTE | VOW_LL_FS_READ_FILE);
	p = fork();
	CHECK(p >= 0);
	if (p == 0) {
		execl(self, self, "--child", (char *)NULL);
		_exit(99);
	}
	CHECK(waitpid(p, &st, 0) == p && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}


extern void (*vow_test_window)(void);

static void
spin_window(void)
{
	volatile int i;

	for (i = 0; i < 20000; i++)
		;
}

#define UTHREADS 6
#define UPER 15

static char udirs[UTHREADS * UPER][PATH_MAX + 64];
static volatile int ugo;
static volatile int ubad;

static void *
unveil_racer(void *arg)
{
	long t = (long)arg;
	int i;

	while (!ugo)
		;
	for (i = 0; i < UPER; i++)
		if (unveil(udirs[t * UPER + i], "r") != 0)
			ubad = 1;
	return NULL;
}

/* concurrent unveil calls must not lose or corrupt rules */
static void
t_unveil_race(void)
{
	pthread_t t[UTHREADS];
	long i;

	tree("urace");
	for (i = 0; i < UTHREADS * UPER; i++) {
		snprintf(udirs[i], sizeof udirs[i], "%s/sub/d%ld", A, i);
		CHECK(mkdir(udirs[i], 0755) == 0);
	}
	vow_test_window = spin_window;
	for (i = 0; i < UTHREADS; i++)
		CHECK(pthread_create(&t[i], NULL, unveil_racer, (void *)i) == 0);
	ugo = 1;
	for (i = 0; i < UTHREADS; i++)
		pthread_join(t[i], NULL);
	CHECK(!ubad);
	vow_test_window = NULL;
	OK(unveil(NULL, NULL));
	for (i = 0; i < UTHREADS * UPER; i++)
		CHECK(try_open(udirs[i], O_RDONLY | O_DIRECTORY) == 0);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}




/* the commit never goes process-wide: with another thread it is refused, on any abi, and changes nothing */
static void
t_commit_refused_with_threads(void)
{
	pthread_t t;

	tree("ebusy");
	start_worker(&t);
	OK(unveil(A, "r"));
	ERR(unveil(NULL, NULL), EBUSY);
	/* nothing was enforced anywhere: not on the caller, not on the other thread */
	CHECK(try_open(pj(D, "h"), O_RDONLY) == 0);
	CHECK(release_worker(t) == 'O');
	/* and the unveil is not sealed: with the thread gone the same commit works */
	{
		int i, r = -1;

		for (i = 0; i < 100 && r != 0; i++)
			r = unveil(NULL, NULL);
		CHECK(r == 0);
	}
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

/* the other thread has a domain of its own that is stricter: it keeps it, and so does the caller's view */
static volatile int ov_stage, ov_res = -9;

static void *
ov_thread(void *arg)
{
	struct vow_ruleset_attr attr;
	int rs;

	(void)arg;
	memset(&attr, 0, sizeof attr);
	attr.handled_access_fs = VOW_LL_FS_READ_FILE;	/* handled, nothing granted: no file can be read */
	rs = (int)syscall(VOW_SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
	if (rs < 0 || prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
	    syscall(VOW_SYS_landlock_restrict_self, rs, 0) != 0) {
		ov_stage = -1;
		return NULL;
	}
	ov_stage = 1;
	while (ov_stage != 2)
		;
	ov_res = try_open(pj(A, "f"), O_RDONLY);
	return NULL;
}

static void
t_commit_refused_keeps_sibling_domain(void)
{
	pthread_t t;

	tree("ovref");
	ov_stage = 0;
	CHECK(pthread_create(&t, NULL, ov_thread, NULL) == 0);
	while (ov_stage == 0)
		;
	CHECK(ov_stage == 1);
	OK(unveil(A, "r"));
	ERR(unveil(NULL, NULL), EBUSY);	/* would have replaced the domain of the sibling */
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0 && try_open(pj(D, "h"), O_RDONLY) == 0);
	ov_stage = 2;
	pthread_join(t, NULL);
	CHECK(ov_res == EACCES);	/* the sibling is as restricted as it was */
}

/*
 * a finding about the kernel, not about vow, kept as a test so the reason for the rule above stays
 * checked: landlock_restrict_self with TSYNC replaces the domain of every sibling thread by the one of
 * the caller, so a thread with a stricter domain of its own loses it. needs abi 8.
 */
static void
t_kernel_tsync_replaces_sibling_domain(void)
{
	struct vow_ruleset_attr attr;
	pthread_t t;
	int rs;

	tree("ovraw");
	if (real_abi() < VOW_TSYNC_ABI)
		SKIP("kernel landlock abi < 8");
	ov_stage = 0;
	ov_res = -9;
	CHECK(pthread_create(&t, NULL, ov_thread, NULL) == 0);
	while (ov_stage == 0)
		;
	CHECK(ov_stage == 1);
	/* the caller restricts itself and everyone else the way unveil would have, with TSYNC */
	memset(&attr, 0, sizeof attr);
	attr.handled_access_fs = VOW_LL_FS_HANDLED;
	rs = (int)syscall(VOW_SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
	CHECK(rs >= 0);
	{
		struct vow_path_beneath pb;
		int fd = open(A, O_PATH | O_DIRECTORY);

		memset(&pb, 0, sizeof pb);
		pb.allowed_access = VOW_LL_FS_READ_FILE | VOW_LL_FS_READ_DIR;
		pb.parent_fd = fd;
		CHECK(syscall(VOW_SYS_landlock_add_rule, rs, VOW_LL_RULE_PATH_BENEATH, &pb, 0) == 0);
	}
	CHECK(prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	CHECK(syscall(VOW_SYS_landlock_restrict_self, rs, VOW_LL_RESTRICT_TSYNC) == 0);
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
	ov_stage = 2;
	pthread_join(t, NULL);
	CHECK(ov_res == 0);	/* it could read nothing, by its own domain; now it reads what the caller reads */
}

/* an outside restriction on the one thread that exists is kept: the commit stacks a layer on it */
static void
t_commit_stacks_on_existing_domain(void)
{
	struct vow_ruleset_attr attr;
	struct vow_path_beneath pb;
	int rs, fd;

	tree("stack");
	/* outside restriction: files may be read only under deny/ */
	memset(&attr, 0, sizeof attr);
	attr.handled_access_fs = VOW_LL_FS_READ_FILE | VOW_LL_FS_READ_DIR;
	rs = (int)syscall(VOW_SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
	CHECK(rs >= 0);
	fd = open(D, O_PATH | O_DIRECTORY);
	memset(&pb, 0, sizeof pb);
	pb.allowed_access = VOW_LL_FS_READ_FILE | VOW_LL_FS_READ_DIR;
	pb.parent_fd = fd;
	CHECK(syscall(VOW_SYS_landlock_add_rule, rs, VOW_LL_RULE_PATH_BENEATH, &pb, 0) == 0);
	/* the thread list must stay readable, or vow cannot show that there is one thread (next test) */
	{
		int pfd = open("/proc", O_PATH | O_DIRECTORY);

		pb.parent_fd = pfd;
		CHECK(pfd >= 0 && syscall(VOW_SYS_landlock_add_rule, rs, VOW_LL_RULE_PATH_BENEATH, &pb, 0) == 0);
	}
	CHECK(prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	CHECK(syscall(VOW_SYS_landlock_restrict_self, rs, 0) == 0);
	CHECK(try_open(pj(A, "f"), O_RDONLY) == EACCES);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == 0);
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	/* unveil allows A and the outside domain allows D: what is left is the intersection, nothing */
	CHECK(try_open(pj(A, "f"), O_RDONLY) == EACCES);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

/* the list of threads is opened at the first call, while /proc can still be reached: later it is still read */
static void
t_commit_uses_early_thread_list(void)
{
	struct vow_ruleset_attr attr;
	int rs;

	tree("early");
	OK(unveil(A, "r"));	/* first call: the thread list is opened here */
	memset(&attr, 0, sizeof attr);
	attr.handled_access_fs = VOW_LL_FS_READ_FILE | VOW_LL_FS_READ_DIR;
	rs = (int)syscall(VOW_SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
	CHECK(rs >= 0 && prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	CHECK(syscall(VOW_SYS_landlock_restrict_self, rs, 0) == 0);	/* an outside domain that grants nothing, /proc included */
	errno = 0;
	CHECK(open("/proc/self/task", O_RDONLY | O_DIRECTORY) == -1 && errno == EACCES);
	OK(unveil(NULL, NULL));	/* still works: the list is read through the descriptor that was already open */
}

/* the price of asking the kernel: a process that an outside domain keeps away from /proc cannot commit */
static void
t_commit_refused_when_proc_is_hidden(void)
{
	struct vow_ruleset_attr attr;
	struct vow_path_beneath pb;
	int rs, fd;

	tree("hidden");
	memset(&attr, 0, sizeof attr);
	attr.handled_access_fs = VOW_LL_FS_READ_FILE | VOW_LL_FS_READ_DIR;
	rs = (int)syscall(VOW_SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
	CHECK(rs >= 0);
	fd = open(D, O_PATH | O_DIRECTORY);
	memset(&pb, 0, sizeof pb);
	pb.allowed_access = VOW_LL_FS_READ_FILE | VOW_LL_FS_READ_DIR;
	pb.parent_fd = fd;
	CHECK(syscall(VOW_SYS_landlock_add_rule, rs, VOW_LL_RULE_PATH_BENEATH, &pb, 0) == 0);
	CHECK(prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
	CHECK(syscall(VOW_SYS_landlock_restrict_self, rs, 0) == 0);
	OK(unveil(D, "r"));
	ERR(unveil(NULL, NULL), EBUSY);
}

/* what cannot be read is not guessed: no thread list, no commit */
static void
t_commit_refused_without_proc(void)
{
	tree("noproc");
	vow_test_proc_task = "/no/such/dir";	/* before the first call: that is when the list is opened */
	OK(unveil(A, "r"));
	ERR(unveil(NULL, NULL), EBUSY);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == 0);
	vow_test_proc_task = NULL;
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

/* a thread appears right after the domain was entered: the domain is in force on the caller, and the
   caller is told it did not reach the new thread */
static pthread_t late_thread_t;
static volatile int late_thread_go;

static void *
late_thread_fn(void *arg)
{
	(void)arg;
	while (!late_thread_go)
		;
	return NULL;
}

static void
spawn_in_window(void)
{
	pthread_create(&late_thread_t, NULL, late_thread_fn, NULL);
}

static void
t_commit_reports_late_thread(void)
{
	tree("late2");
	OK(unveil(A, "r"));
	vow_test_after_restrict = spawn_in_window;
	ERR(unveil(NULL, NULL), EBUSY);
	vow_test_after_restrict = NULL;
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);	/* in force on the caller */
	ERR(unveil(A, "r"), EPERM);				/* and sealed */
	late_thread_go = 1;
	pthread_join(late_thread_t, NULL);
}

/* ------------------------------------------------------------------ */
/* hostile paths, mounts and races                                     */
/* ------------------------------------------------------------------ */

static char lk[PATH_MAX + 64], lk_x[PATH_MAX + 64], lk_y[PATH_MAX + 64];

static void
point_lk_at(const char *target)
{
	char tmp[PATH_MAX + 80];

	snprintf(tmp, sizeof tmp, "%s.tmp%d", lk, (int)getpid());
	unlink(tmp);
	if (symlink(target, tmp) != 0 || rename(tmp, lk) != 0)
		_exit(2);
}

static void
flip_to_y(void)
{
	point_lk_at(lk_y);
}

/*
 * the path is resolved twice: once to pin the inode (the descriptor), once to get a string for the
 * narrowing check. if a symlink is changed in between, the two disagree and the call fails with
 * ESTALE, and nothing is recorded: the rule is never for an inode the string did not name.
 */
static void
t_race_symlink_swap_after_open(void)
{
	tree("race1");
	snprintf(lk, sizeof lk, "%s/lnk", B);
	snprintf(lk_x, sizeof lk_x, "%s", A);
	snprintf(lk_y, sizeof lk_y, "%s/allow2", B);
	point_lk_at(lk_x);
	vow_test_after_open = flip_to_y;
	ERR(unveil(lk, "r"), ESTALE);
	vow_test_after_open = NULL;
	/* nothing was recorded: the commit seals and enforces nothing */
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0 && try_open(pj(D, "h"), O_RDONLY) == 0);
}

static volatile int flip_stop;

static void *
flipper(void *arg)
{
	int i = 0;

	(void)arg;
	while (!flip_stop) {
		point_lk_at((i++ & 1) ? lk_y : lk_x);
		sched_yield();
	}
	return NULL;
}

/* the same with a thread that keeps swapping the link: every answer is either a rule for one of the two or an error */
static void
t_race_symlink_swap_stress(void)
{
	pthread_t t;
	int i, ok = 0, stale = 0;

	tree("race2");
	snprintf(lk, sizeof lk, "%s/lnk", B);
	snprintf(lk_x, sizeof lk_x, "%s", A);
	snprintf(lk_y, sizeof lk_y, "%s/allow2", B);
	point_lk_at(lk_x);
	CHECK(pthread_create(&t, NULL, flipper, NULL) == 0);
	for (i = 0; i < 2000; i++) {
		errno = 0;
		if (unveil(lk, "r") == 0)
			ok++;
		else {
			CHECK(errno == ESTALE);
			stale++;
		}
	}
	flip_stop = 1;
	CHECK(pthread_join(t, NULL) == 0);
	printf("    %d unveils of a swapped link: %d recorded, %d refused as stale\n", ok, ok, stale);
	CHECK(ok > 0);
	OK(unveil(NULL, NULL));
	/* only the two directories the link pointed at can have been granted, and at least one was */
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0 || try_open(pj(B, "allow2"), O_RDONLY | O_DIRECTORY) == 0);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
	CHECK(try_open(pj(A, "sub/g"), O_RDONLY) == 0 || try_open(pj(A, "sub/g"), O_RDONLY) == EACCES);
}

static void
t_hostile_paths(void)
{
	char name[PATH_MAX + 64], longp[6000];
	int fd;

	tree("hostile");
	/* loops, trailing slash on a file, names too long, the middle of the path missing */
	CHECK(symlink("loop2", pj(A, "loop1")) == 0 && symlink("loop1", pj(A, "loop2")) == 0);
	ERR(unveil(pj(A, "loop1"), "r"), ELOOP);
	snprintf(name, sizeof name, "%s/", pj(A, "f"));
	ERR(unveil(name, "r"), ENOTDIR);
	memset(longp, 'a', sizeof longp - 1);
	longp[0] = '/';
	longp[sizeof longp - 1] = 0;
	ERR(unveil(longp, "r"), ENAMETOOLONG);
	ERR(unveil(pj(A, "nope/deeper"), "r"), ENOENT);
	ERR(unveil("", "r"), ENOENT);
	/* a directory the caller cannot enter */
	if (geteuid() != 0) {
		CHECK(mkdir(pj(A, "closed"), 0) == 0);
		ERR(unveil(pj(A, "closed/x"), "r"), EACCES);
		CHECK(chmod(pj(A, "closed"), 0755) == 0);	/* so the cleanup can remove it */
	}
	/* names with blanks and a newline are just names */
	snprintf(name, sizeof name, "%s/we ird\\nname", A);
	CHECK(mkdir(name, 0755) == 0);
	snprintf(longp, sizeof longp, "%s/f", name);
	wr(longp, "w\\n");
	OK(unveil(name, "r"));
	/* the current directory through /proc, and a device file */
	CHECK(chdir(pj(A, "sub")) == 0);
	OK(unveil("/proc/self/cwd", "r"));
	OK(unveil("/dev/null", "rw"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(longp, O_RDONLY) == 0);
	CHECK(try_open(pj(A, "sub/g"), O_RDONLY) == 0);
	CHECK(try_open(pj(A, "f"), O_RDONLY) == EACCES);
	CHECK(try_open("/dev/null", O_WRONLY) == 0);
	CHECK(try_open("/dev/zero", O_RDONLY) == EACCES);
	(void)fd;
}

/* a rule on a file is a rule on the inode: every name of it is covered (landlock keys rules on inodes) */
static void
t_hardlink_file_rule(void)
{
	tree("hardl");
	CHECK(link(pj(A, "f"), pj(D, "hl")) == 0);
	OK(unveil(pj(A, "f"), "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
	CHECK(try_open(pj(D, "hl"), O_RDONLY) == 0);	/* the other name of the same file: covered */
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);
}

/* the rule on a directory is on the directory: a hard link to a file in it from elsewhere is not covered */
static void
t_hardlink_dir_rule(void)
{
	tree("hardd");
	CHECK(link(pj(A, "f"), pj(D, "hl")) == 0);
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "f"), O_RDONLY) == 0);
	CHECK(try_open(pj(D, "hl"), O_RDONLY) == EACCES);	/* the same file, reached by a name outside */
}

/* ---- mounts, in a user and mount namespace of our own ---- */

static int
enter_userns(void)
{
	uid_t u = getuid();
	gid_t g = getgid();
	char buf[64];
	int fd;

	if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0)
		return -1;
	fd = open("/proc/self/setgroups", O_WRONLY);
	if (fd >= 0) {
		(void)!write(fd, "deny", 4);
		close(fd);
	}
	fd = open("/proc/self/uid_map", O_WRONLY);
	if (fd < 0)
		return -1;
	snprintf(buf, sizeof buf, "0 %u 1", (unsigned)u);
	if (write(fd, buf, strlen(buf)) < 0) {
		close(fd);
		return -1;
	}
	close(fd);
	fd = open("/proc/self/gid_map", O_WRONLY);
	if (fd < 0)
		return -1;
	snprintf(buf, sizeof buf, "0 %u 1", (unsigned)g);
	if (write(fd, buf, strlen(buf)) < 0) {
		close(fd);
		return -1;
	}
	close(fd);
	(void)mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
	return 0;
}

/* a bind mount made before the commit puts a denied directory under an allowed path: reachable through it */
static void
t_mount_bind_reexposes(void)
{
	tree("mnt1");
	if (enter_userns() != 0)
		SKIP("no user namespaces");
	CHECK(mkdir(pj(A, "mnt"), 0755) == 0);
	if (mount(D, pj(A, "mnt"), NULL, MS_BIND, NULL) != 0)
		SKIP("cannot mount in a user namespace here");
	OK(unveil(A, "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "mnt/h"), O_RDONLY) == 0);		/* through the allowed path: reachable */
	CHECK(try_open(pj(D, "h"), O_RDONLY) == EACCES);	/* by its own name: still denied */
}

/* a rule on a mount point pins what is mounted there, the root of the other tree */
static void
t_mount_rule_on_mountpoint(void)
{
	tree("mnt2");
	if (enter_userns() != 0)
		SKIP("no user namespaces");
	CHECK(mkdir(pj(A, "mnt"), 0755) == 0);
	if (mount(D, pj(A, "mnt"), NULL, MS_BIND, NULL) != 0)
		SKIP("cannot mount in a user namespace here");
	OK(unveil(pj(A, "mnt"), "r"));
	OK(unveil(NULL, NULL));
	CHECK(try_open(pj(A, "mnt/h"), O_RDONLY) == 0);
	CHECK(try_open(pj(D, "h"), O_RDONLY) == 0);		/* the rule is on the inode: the other name of the tree is covered */
	CHECK(try_open(pj(A, "f"), O_RDONLY) == EACCES);	/* but the directory above the mount point is not */
}

/* after the commit the process cannot change the mount layout, even as root of its namespace */
static void
t_mount_refused_after_commit(void)
{
	tree("mnt3");
	if (enter_userns() != 0)
		SKIP("no user namespaces");
	CHECK(mkdir(pj(A, "mnt"), 0755) == 0);
	OK(unveil(A, "rw"));
	OK(unveil(NULL, NULL));
	errno = 0;
	CHECK(mount(D, pj(A, "mnt"), NULL, MS_BIND, NULL) == -1 && errno == EPERM);
	errno = 0;
	CHECK(umount2(pj(A, "mnt"), 0) == -1);
	/* chroot is not a landlock right: it is allowed, and only moves the root to a place already granted (DESIGN.md section 6) */
	CHECK(chroot(A) == 0);
	CHECK(syscall(155 /* pivot_root */, A, A) == -1);
}

static const struct test tests[] = {
	{ "args", t_args, 0 },
	{ "read only", t_read_only, 0 },
	{ "read write", t_rw, 0 },
	{ "read write create", t_rwc, 0 },
	{ "exec allowed", t_exec_self_x, 0 },
	{ "exec denied", t_exec_denied, 0 },
	{ "exec needs read", t_exec_needs_read, 0 },
	{ "file rules", t_file_rules, 0 },
	{ "file write only", t_file_write_only, 0 },
	{ "sealed", t_sealed, 0 },
	{ "seal only", t_seal_only, 0 },
	{ "replace narrower", t_replace_narrow, 0 },
	{ "replace wider", t_replace_widen, 0 },
	{ "conflict child narrower", t_conflict_child_narrower, 0 },
	{ "conflict parent wider", t_conflict_parent_wider, 0 },
	{ "conflict on replace", t_conflict_replace_checks, 0 },
	{ "child wider is fine", t_child_wider_ok, 0 },
	{ "string prefix is not ancestor", t_prefix_not_ancestor, 0 },
	{ "path escapes", t_escape, 0 },
	{ "open fd survives (gap)", t_open_fd_survives, 0 },
	{ "dirfd escape", t_dirfd_escape, 0 },
	{ "metadata not restricted (gap)", t_metadata_gap, 0 },
	{ "proc fd reopen", t_proc_reopen, 0 },
	{ "no_new_privs set", t_nnp, 0 },
	{ "abi gate", t_abi_gate, 0 },
	{ "failed commit state", t_commit_failure_state, 0 },
	{ "a failed add keeps earlier rules", t_failed_add_keeps_earlier_rules, 0 },
	{ "old abi single thread", t_old_abi_single_thread, 0 },
	{ "commit refused with other threads", t_commit_refused_with_threads, 0 },
	{ "commit refused keeps a stricter sibling", t_commit_refused_keeps_sibling_domain, 0 },
	{ "kernel: tsync replaces the domain of a sibling thread", t_kernel_tsync_replaces_sibling_domain, 0 },
	{ "commit stacks on an existing domain", t_commit_stacks_on_existing_domain, 0 },
	{ "commit refused without a thread list", t_commit_refused_without_proc, 0 },
	{ "commit refused when an outside domain hides /proc", t_commit_refused_when_proc_is_hidden, 0 },
	{ "commit uses the thread list opened early", t_commit_uses_early_thread_list, 0 },
	{ "commit reports a thread made during it", t_commit_reports_late_thread, 0 },
	{ "thread after commit", t_thread_after_commit, 0 },
	{ "many entries", t_many_entries, 0 },
	{ "allocation failure", t_alloc_failure, 0 },
	{ "emfile", t_emfile, 0 },
	{ "relative and symlink args", t_relative_and_symlink, 0 },
	{ "unix s allows only the rule", t_unix_allow, 0 },
	{ "unix denied without s", t_unix_default_deny, 0 },
	{ "unix s on a socket file", t_unix_file_rule, 0 },
	{ "unix datagram sendto", t_unix_dgram, 0 },
	{ "unix existing connection (limit)", t_unix_existing_connection, 0 },
	{ "unix same-domain server (limit)", t_unix_same_domain, 0 },
	{ "unix abstract socket (gap)", t_unix_abstract_gap, 0 },
	{ "unix s refused on old abi", t_unix_old_abi_refused, 0 },
	{ "unix s conflict check", t_unix_conflict, 0 },
	{ "concurrent unveil calls", t_unveil_race, 0 },
	{ "race: a link swapped after the open", t_race_symlink_swap_after_open, 0 },
	{ "race: a link swapped all the time", t_race_symlink_swap_stress, 0 },
	{ "hostile paths", t_hostile_paths, 0 },
	{ "a rule on a file covers its other names", t_hardlink_file_rule, 0 },
	{ "a rule on a directory does not cover a link from outside", t_hardlink_dir_rule, 0 },
	{ "mount: a bind mount re-exposes under an allowed path", t_mount_bind_reexposes, 0 },
	{ "mount: a rule on a mount point", t_mount_rule_on_mountpoint, 0 },
	{ "mount: refused after the commit", t_mount_refused_after_commit, 0 },
	{ "kernel: exec needs read_file", t_kernel_exec_needs_read, 0 },
	{ "kernel: exec with read works", t_kernel_exec_read_works, 0 },
};

int
main(int argc, char **argv)
{
	const char *tmp = getenv("TMPDIR");
	char tpl[PATH_MAX], cmd[PATH_MAX + 16];
	int rc;

	if (argc > 1 && strcmp(argv[1], "--child") == 0)
		return 0;
	if (realpath(argv[0], self) == NULL) {
		perror("realpath");
		return 1;
	}
	snprintf(tpl, sizeof tpl, "%s/vowt.XXXXXX", tmp ? tmp : "/tmp");
	if (mkdtemp(tpl) == NULL || realpath(tpl, root) == NULL) {
		perror("mkdtemp");
		return 1;
	}
	printf("kernel landlock abi: %d\n", real_abi());
	rc = t_main(tests, (int)(sizeof tests / sizeof *tests), 61);
	snprintf(cmd, sizeof cmd, "rm -rf '%s'", root);
	if (system(cmd) != 0)
		rc = 1;
	return rc;
}
