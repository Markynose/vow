#ifndef VOW_RUN_PROFILE_H
#define VOW_RUN_PROFILE_H

/*
 * the .vow profile format, strict and small:
 *
 *   # a comment line, blank lines are skipped
 *   pledge = stdio rpath wpath cpath exec
 *   unveil = /home/mark/docs:rwc
 *   unveil = /path with spaces:r
 *
 * exactly one pledge line, any number (up to NRULES) of unveil lines, nothing else. see DESIGN.md section 13.
 */

#include <stddef.h>

#define NRULES 64

struct rule {
	char *path;
	char *perms;
	int line;		/* the line of the profile, 0 for a rule from -u */
};

struct promise_bit {
	const char *name;
	unsigned bit;
};

/* the implemented promises, defined by vow-run.c */
extern const struct promise_bit promise_bits[];
extern const size_t npromise_bits;

struct profile {
	char *promises;
	struct rule rules[NRULES];
	int nrules;
};

/* returns 0, or -1 with a message "file:line: what" in err. nothing is touched on the file system but the profile itself */
int profile_load(const char *file, struct profile *p, char *err, size_t errsz);

#endif
