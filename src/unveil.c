#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vow.h"
#include "sys.h"
#include "filter.h"
#include "lock.h"

#define P_R 1
#define P_W 2
#define P_X 4
#define P_C 8
#define P_S 16

struct entry {
	int fd;			/* O_PATH, pins the inode until commit */
	unsigned perms;
	dev_t dev;
	ino_t ino;
	char *path;		/* canonical, only for the narrowing check */
};

static vow_lock_t ulock;
static __thread int in_u;	/* this thread is inside unveil() */
static struct entry *tab;	/* tab, n, cap and sealed are guarded by ulock */
static size_t n, cap;
static int sealed;

#ifdef VOW_TEST
int vow_test_abi_cap;		/* >0: pretend the kernel abi is at most this; <0: no landlock */
int vow_test_alloc_fail;	/* n>0: the nth table allocation from now fails */
const char *vow_test_proc_task;	/* if set, the directory that lists the threads */
void (*vow_test_after_restrict)(void);	/* called right after the domain is entered */
void (*vow_test_after_open)(void);	/* called right after a path was opened, before it is resolved again */
#endif

static void *
xrealloc(void *p, size_t sz)
{
#ifdef VOW_TEST
	if (vow_test_alloc_fail > 0 && --vow_test_alloc_fail == 0)
		return NULL;
#endif
	return realloc(p, sz);
}

/* running landlock abi, or -1 with errno (ENOSYS: no landlock, EOPNOTSUPP: disabled) */
static int
abi(void)
{
	static int cached, cached_errno;
	long v;
	int a;

	if (cached == 0) {
		v = syscall(VOW_SYS_landlock_create_ruleset, NULL, 0, VOW_LL_CREATE_VERSION);
		/* the errno goes first: pledge() may call in at the same time as unveil() */
		if (v < 1) {
			cached_errno = errno ? errno : ENOSYS;
			__sync_synchronize();
			cached = -1;
		} else
			cached = (int)v;
	}
	a = cached;
#ifdef VOW_TEST
	if (vow_test_abi_cap < 0) {
		a = -1;
		cached_errno = ENOSYS;
	} else if (vow_test_abi_cap > 0 && a > vow_test_abi_cap)
		a = vow_test_abi_cap;
#endif
	if (a < 0) {
		errno = cached_errno;
		return -1;
	}
	return a;
}

/* unveil needs at least abi 3, otherwise rename and truncate would stay unrestricted */
static int
need_abi(void)
{
	int a = abi();

	if (a >= 0 && a < VOW_MIN_ABI) {
		errno = ENOSYS;
		return -1;
	}
	return a;
}

static int
parse(const char *s, unsigned *out)
{
	unsigned p = 0;

	for (; *s; s++) {
		switch (*s) {
		case 'r': p |= P_R; break;
		case 'w': p |= P_W; break;
		case 'x': p |= P_X; break;
		case 'c': p |= P_C; break;
		case 's': p |= P_S; break;
		default: errno = EINVAL; return -1;
		}
	}
	/*
	 * the kernel opens an executable for reading, so landlock needs
	 * read_file next to execute. a bare x cannot be enforced as asked
	 * and granting read behind the caller back would widen it: refuse.
	 */
	if ((p & P_X) && !(p & P_R)) {
		errno = ENOTSUP;
		return -1;
	}
	*out = p;
	return 0;
}

static uint64_t
rights(unsigned p, int isdir)
{
	uint64_t r = 0;

	if (p & P_R)
		r |= VOW_LL_FS_READ_FILE | (isdir ? VOW_LL_FS_READ_DIR : 0);
	if (p & P_W)
		r |= VOW_LL_FS_WRITE_FILE | VOW_LL_FS_TRUNCATE;
	if (p & P_X)
		r |= VOW_LL_FS_EXECUTE;
	/* connect or sendto to a pathname unix socket; only handled from abi 9 */
	if (p & P_S)
		r |= VOW_LL_FS_RESOLVE_UNIX;
	/* c is directory only. char and block device creation are never granted */
	if ((p & P_C) && isdir)
		r |= VOW_LL_FS_MAKE_REG | VOW_LL_FS_MAKE_DIR | VOW_LL_FS_MAKE_SYM |
		    VOW_LL_FS_MAKE_SOCK | VOW_LL_FS_MAKE_FIFO | VOW_LL_FS_REMOVE_FILE |
		    VOW_LL_FS_REMOVE_DIR | VOW_LL_FS_REFER;
	return r;
}

static int
is_ancestor(const char *a, const char *b)
{
	size_t l = strlen(a);

	if (strcmp(a, "/") == 0)
		return strcmp(b, "/") != 0;
	return strncmp(a, b, l) == 0 && b[l] == '/';
}

/*
 * landlock only adds rights down a tree, it cannot take them away, so a
 * child rule with fewer permissions than an ancestor cannot be enforced.
 * refuse instead of leaving the extra access in place. string based and
 * therefore best effort (bind mounts, hardlinks), not a security boundary.
 */
static int
conflicts(const struct entry *self, const char *path, unsigned perms)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (&tab[i] == self)
			continue;
		if (is_ancestor(tab[i].path, path) && (tab[i].perms & ~perms))
			return 1;
		if (is_ancestor(path, tab[i].path) && (perms & ~tab[i].perms))
			return 1;
	}
	return 0;
}

static void
drop_all(void)
{
	size_t i;

	for (i = 0; i < n; i++) {
		close(tab[i].fd);
		free(tab[i].path);
	}
	free(tab);
	tab = NULL;
	n = cap = 0;
}

static int
add(const char *path, unsigned perms, int a)
{
	struct stat st, cst;
	struct entry *e = NULL;
	char *canon;
	size_t i;
	int fd, isdir, err;

	if ((perms & P_S) && a < VOW_UNIX_ABI) {
		/* an old kernel would leave pathname unix sockets open: do not pretend */
		errno = ENOTSUP;
		return -1;
	}
	if (n == cap) {
		size_t nc = cap ? cap * 2 : 16;
		struct entry *t = xrealloc(tab, nc * sizeof *tab);

		if (t == NULL) {
			errno = ENOMEM;
			return -1;
		}
		tab = t;
		cap = nc;
	}
	fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0)
		return -1;
#ifdef VOW_TEST
	if (vow_test_after_open)
		vow_test_after_open();
#endif
	if (fstat(fd, &st) < 0)
		goto fail;
	isdir = S_ISDIR(st.st_mode);
	if ((perms & P_C) && !isdir) {
		/* landlock cannot create-by-name; the parent directory needs the c */
		errno = ENOTSUP;
		goto fail;
	}
	canon = realpath(path, NULL);
	if (canon == NULL)
		goto fail;
	/* the string is only used for the conflict check; make sure it names the pinned inode */
	if (stat(canon, &cst) < 0 || cst.st_dev != st.st_dev || cst.st_ino != st.st_ino) {
		free(canon);
		errno = ESTALE;
		goto fail;
	}
	for (i = 0; i < n; i++)
		if (tab[i].dev == st.st_dev && tab[i].ino == st.st_ino)
			e = &tab[i];
	if (conflicts(e, canon, perms)) {
		free(canon);
		errno = ENOTSUP;
		goto fail;
	}
	if (e != NULL) {
		/* same inode again: replace, as openbsd does */
		e->perms = perms;
		free(canon);
		close(fd);
		return 0;
	}
#ifdef VOW_TEST
	if (vow_test_window)
		vow_test_window();
#endif
	tab[n].fd = fd;
	tab[n].perms = perms;
	tab[n].dev = st.st_dev;
	tab[n].ino = st.st_ino;
	tab[n].path = canon;
	n++;
	return 0;
fail:
	err = errno;
	close(fd);
	errno = err;
	return -1;
}

/* landlock_restrict_self binds one thread before abi 8, so prove there is only one */
/*
 * the list of threads of this process, as the kernel gives it. the directory is opened at the first
 * call into the library and kept, because once a landlock domain is entered /proc may no longer be
 * reachable by path, while reading a directory that is already open is not checked again. a handle
 * that could not be opened is tried again when it is needed (and fails if /proc is out of reach by
 * then: no list, no proof, no commit). the child of a fork opens its own: the inherited one lists
 * the threads of the parent.
 */
static vow_lock_t tlock;
static DIR *task_dir;
static int task_err;	/* why the last open failed */
static int task_stale;	/* inherited by fork: it lists the threads of the parent */

static void
threads_open_locked(void)
{
	const char *path = "/proc/self/task";

	if (task_stale) {
		if (task_dir != NULL)
			closedir(task_dir);
		task_dir = NULL;
		task_stale = 0;
	}
	if (task_dir != NULL)
		return;
#ifdef VOW_TEST
	if (vow_test_proc_task)
		path = vow_test_proc_task;
#endif
	task_dir = opendir(path);
	task_err = task_dir ? 0 : errno;
}

void
vow_threads_prepare(void)
{
	vow_lock(&tlock);
	threads_open_locked();
	vow_unlock(&tlock);
}

void
vow_threads_forked(void)
{
	/*
	 * no system call here: the child may be under a filter that allows none. the list is reopened
	 * the next time it is needed, and the lock may have been held by a thread that is not here
	 */
	tlock = 0;
	task_stale = 1;
}

/* number of threads, or -1 if the list cannot be read */
static int
threads_count_locked(void)
{
	struct dirent *de;
	int count = 0;

	threads_open_locked();
	if (task_dir == NULL)
		return -1;
	rewinddir(task_dir);
	errno = 0;
	while ((de = readdir(task_dir)) != NULL)
		if (de->d_name[0] != '.')
			count++;
	if (errno != 0)
		return -1;
	return count;
}

/*
 * 1 only if the kernel lists exactly one thread. a thread that has just been joined may still be
 * listed for a moment (measured up to a few hundred microseconds when idle), so a longer list is read
 * again up to 2000 times, which costs about ten milliseconds when there really is another thread.
 * 0: more than one, or anything that cannot be read (no /proc, a /proc that is not this process): not provably one. -1 with
 * errno: the list could not be opened for lack of descriptors or memory, which is not an answer.
 */
int
vow_threads_single(void)
{
	int i, c = -1;

	vow_lock(&tlock);
	for (i = 0; i < 2000; i++) {
		c = threads_count_locked();
		if (c <= 1)
			break;
	}
	if (c < 0 && (task_err == EMFILE || task_err == ENFILE || task_err == ENOMEM))
		errno = task_err;
	else if (c < 0)
		c = 0;
	vow_unlock(&tlock);
	return c < 0 ? -1 : c == 1;
}

int
vow_landlock_abi(void)
{
	return abi();
}


static int
commit(void)
{
	struct vow_ruleset_attr attr;
	struct vow_path_beneath pb;
	size_t i;
	int a, rs, err;

	if (sealed) {
		errno = EPERM;
		return -1;
	}
	if (n == 0) {
		/* no path was ever unveiled: nothing to enforce, only lock */
		sealed = 1;
		return 0;
	}
	a = need_abi();
	if (a < 0)
		return -1;
	/*
	 * never for several threads, on any abi: landlock_restrict_self with TSYNC replaces the
	 * domains of the other threads with this one (DESIGN.md 6), which can take restrictions away,
	 * and without it only the calling thread is restricted. the kernel is asked, not the library
	 */
	err = vow_threads_single();
	if (err <= 0) {
		if (err == 0)
			errno = EBUSY;
		return -1;
	}
	memset(&attr, 0, sizeof attr);
	attr.handled_access_fs = VOW_LL_FS_HANDLED;
	if (a >= VOW_UNIX_ABI)
		attr.handled_access_fs |= VOW_LL_FS_RESOLVE_UNIX;
	rs = (int)syscall(VOW_SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
	if (rs < 0)
		return -1;
	for (i = 0; i < n; i++) {
		struct stat st;

		if (fstat(tab[i].fd, &st) < 0)
			goto fail;
		memset(&pb, 0, sizeof pb);
		pb.allowed_access = rights(tab[i].perms, S_ISDIR(st.st_mode));
		pb.parent_fd = tab[i].fd;
		/* an empty right set (for example "" or "c") is a rule that grants nothing: skip */
		if (pb.allowed_access == 0)
			continue;
		if (syscall(VOW_SYS_landlock_add_rule, rs, VOW_LL_RULE_PATH_BENEATH, &pb, 0) < 0)
			goto fail;
	}
	if (prctl(VOW_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		goto fail;
	if (syscall(VOW_SYS_landlock_restrict_self, rs, 0) < 0)
		goto fail;
	close(rs);
	drop_all();
	sealed = 1;
#ifdef VOW_TEST
	if (vow_test_after_restrict)
		vow_test_after_restrict();
#endif
	/* a thread made meanwhile (only this thread's own signal handler could) was made before the domain */
	if (vow_threads_single() != 1) {
		errno = EBUSY;
		return -1;
	}
	return 0;
fail:
	err = errno;
	close(rs);
	errno = err;
	return -1;
}

static int
unveil_locked(const char *path, const char *permissions)
{
	unsigned perms;
	int a;

	/* a pledge that took away rpath also locks unveil, as on openbsd */
	{
		int b = vow_pledge_blocks_unveil();

		if (b) {
			errno = b > 0 ? EPERM : EDEADLK;
			return -1;
		}
	}
	if (path == NULL && permissions == NULL)
		return commit();
	if (path == NULL || permissions == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (parse(permissions, &perms) < 0)
		return -1;
	if (sealed) {
		errno = EPERM;
		return -1;
	}
	a = need_abi();
	if (a < 0)
		return -1;
	return add(path, perms, a);
}

int
unveil(const char *path, const char *permissions)
{
	int r;

	vow_atfork_register();
	if (in_u) {
		errno = EDEADLK;
		return -1;
	}
	vow_lock(&ulock);
	in_u = 1;
	r = unveil_locked(path, permissions);
	in_u = 0;
	vow_unlock(&ulock);
	return r;
}

int
vow_unveil_lock(void)
{
	if (in_u)
		return 0;
	vow_lock(&ulock);
	return 1;
}

void
vow_unveil_unlock(int took)
{
	if (took)
		vow_unlock(&ulock);
}
