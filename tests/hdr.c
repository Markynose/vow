/* SPDX-License-Identifier: LGPL-3.0-only */
#include <vow.h>

int
main(void)
{
	int (*p)(const char *, const char *) = pledge;
	int (*u)(const char *, const char *) = unveil;

	return p == 0 || u == 0 || VOW_VERSION_MAJOR < 0;
}
