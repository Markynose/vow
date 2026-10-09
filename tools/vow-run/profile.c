#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "profile.h"

#define MAX_FILE 65536
#define MAX_LINE 4096

struct ctx {
	const char *file;
	char *err;
	size_t errsz;
	int line;
};

static int
fail(const struct ctx *c, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (c->line > 0)
		n = snprintf(c->err, c->errsz, "%s:%d: ", c->file, c->line);
	else
		n = snprintf(c->err, c->errsz, "%s: ", c->file);
	if (n > 0 && (size_t)n < c->errsz) {
		va_start(ap, fmt);
		vsnprintf(c->err + n, c->errsz - (size_t)n, fmt, ap);
		va_end(ap);
	}
	return -1;
}

static int
has_control(const char *s)
{
	for (; *s; s++)
		if ((unsigned char)*s < 0x20 || (unsigned char)*s == 0x7f)
			return 1;
	return 0;
}

static int
parse_pledge(struct ctx *c, struct profile *p, const char *value)
{
	unsigned seen = 0, bit, exec = 0;
	size_t i, len;
	const char *w = value;

	if (p->promises != NULL)
		return fail(c, "a second pledge line");
	for (;;) {
		len = strcspn(w, " ");
		if (len == 0)
			return fail(c, "pledge: an empty word (one space between promises)");
		for (i = 0; i < npromise_bits; i++)
			if (strlen(promise_bits[i].name) == len && strncmp(promise_bits[i].name, w, len) == 0)
				break;
		if (i == npromise_bits)
			return fail(c, "pledge: %.*s is not a promise vow-run knows", (int)len, w);
		bit = promise_bits[i].bit;
		if (seen & bit)
			return fail(c, "pledge: %.*s twice", (int)len, w);
		seen |= bit;
		if (w[len] == '\0')
			break;
		w += len + 1;
	}
	for (i = 0; i < npromise_bits; i++)
		if (strcmp(promise_bits[i].name, "exec") == 0)
			exec = promise_bits[i].bit;
	if (!(seen & exec))
		return fail(c, "pledge: the promises need exec to start the program");
	if ((p->promises = strdup(value)) == NULL)
		return fail(c, "out of memory");
	return 0;
}

static int
parse_unveil(struct ctx *c, struct profile *p, const char *value)
{
	const char *colon = strrchr(value, ':'), *s, *q, *r;
	size_t plen, cl, i;
	char *path, *perms;
	unsigned seen = 0;

	if (p->nrules == NRULES)
		return fail(c, "unveil: more than %d rules", NRULES);
	if (colon == NULL)
		return fail(c, "unveil: expected path:permissions");
	plen = (size_t)(colon - value);
	if (plen == 0)
		return fail(c, "unveil: an empty path");
	if (value[0] != '/')
		return fail(c, "unveil: the path must be absolute");
	if (plen > 1 && value[plen - 1] == '/')
		return fail(c, "unveil: no trailing slash");
	if ((path = strndup(value, plen)) == NULL)
		return fail(c, "out of memory");
	/* a path is its components; none is empty, ., or .. (the canonical form, so equal paths compare equal) */
	for (q = path + 1; plen > 1;) {
		r = strchr(q, '/');
		cl = r ? (size_t)(r - q) : strlen(q);
		if (cl == 0)
			return fail(c, "unveil: an empty path component (//)");
		if ((cl == 1 && q[0] == '.') || (cl == 2 && q[0] == '.' && q[1] == '.'))
			return fail(c, "unveil: . and .. are not allowed in the path");
		if (r == NULL)
			break;
		q = r + 1;
	}
	s = colon + 1;
	if (*s == '\0')
		return fail(c, "unveil: empty permissions");
	for (; *s; s++) {
		const char *k = strchr("rwxcs", *s);

		if (k == NULL)
			return fail(c, "unveil: %c is not a permission (r w x c s)", *s);
		if (seen & (1u << (k - "rwxcs")))
			return fail(c, "unveil: permission %c twice", *s);
		seen |= 1u << (k - "rwxcs");
	}
	if ((seen & 4u) && !(seen & 1u))
		return fail(c, "unveil: x needs r");
	if ((perms = strdup(colon + 1)) == NULL)
		return fail(c, "out of memory");
	/*
	 * the same spelling twice is an error here. whether a rule below another asks for less than it gets
	 * depends on what the two paths are (a socket, a file, a directory), which only the file system
	 * knows, so that check is left to unveil(), which has the real inodes.
	 */
	for (i = 0; i < (size_t)p->nrules; i++)
		if (strcmp(p->rules[i].path, path) == 0)
			return fail(c, "unveil: %s again (first on line %d)", path, p->rules[i].line);
	p->rules[p->nrules].path = path;
	p->rules[p->nrules].perms = perms;
	p->rules[p->nrules].line = c->line;
	p->nrules++;
	return 0;
}

static int
parse_line(struct ctx *c, struct profile *p, char *line, size_t len)
{
	char *eq, *name, *value, *end;

	if (len > MAX_LINE)
		return fail(c, "the line is longer than %d bytes", MAX_LINE);
	while (*line == ' ')
		line++;
	end = line + strlen(line);
	while (end > line && end[-1] == ' ')
		end--;
	*end = '\0';
	if (*line == '\0' || *line == '#')
		return 0;
	if (has_control(line))
		return fail(c, "a control character in the line");
	if ((eq = strchr(line, '=')) == NULL)
		return fail(c, "expected directive = value");
	name = line;
	value = eq + 1;
	end = eq;
	while (end > name && end[-1] == ' ')
		end--;
	*end = '\0';
	while (*value == ' ')
		value++;
	if (strcmp(name, "pledge") != 0 && strcmp(name, "unveil") != 0)
		return fail(c, "unknown directive %s", *name ? name : "(none)");
	if (*value == '\0')
		return fail(c, "%s: no value", name);
	return name[0] == 'p' ? parse_pledge(c, p, value) : parse_unveil(c, p, value);
}

int
profile_load(const char *file, struct profile *p, char *err, size_t errsz)
{
	struct ctx c = { file, err, errsz, 0 };
	struct stat st;
	char *buf, *cur, *nl;
	size_t len = 0;
	ssize_t r;
	int fd;

	memset(p, 0, sizeof *p);
	/* O_NONBLOCK so that a fifo does not hold vow-run before the file type is known */
	if ((fd = open(file, O_RDONLY | O_CLOEXEC | O_NONBLOCK)) < 0)
		return fail(&c, "%s", strerror(errno));
	if (fstat(fd, &st) < 0)
		return close(fd), fail(&c, "%s", strerror(errno));
	if (!S_ISREG(st.st_mode))
		return close(fd), fail(&c, "not a regular file");
	if (st.st_size > MAX_FILE)
		return close(fd), fail(&c, "larger than %d bytes", MAX_FILE);
	if ((buf = malloc(MAX_FILE + 2)) == NULL)
		return close(fd), fail(&c, "out of memory");
	while ((r = read(fd, buf + len, MAX_FILE + 1 - len)) > 0) {
		len += (size_t)r;
		if (len > MAX_FILE)
			return close(fd), fail(&c, "larger than %d bytes", MAX_FILE);
	}
	close(fd);
	if (r < 0)
		return fail(&c, "%s", strerror(errno));
	buf[len] = '\0';
	if (memchr(buf, '\0', len) != NULL)
		return fail(&c, "a NUL byte in the file");
	for (cur = buf; *cur;) {
		c.line++;
		nl = strchr(cur, '\n');
		if (nl)
			*nl = '\0';
		if (parse_line(&c, p, cur, strlen(cur)) < 0)
			return -1;
		if (!nl)
			break;
		cur = nl + 1;
	}
	c.line = 0;
	if (p->promises == NULL)
		return fail(&c, "no pledge line");
	return 0;
}
