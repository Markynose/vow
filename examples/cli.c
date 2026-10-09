/* SPDX-License-Identifier: 0BSD */
/* cli: a cat that can only read the files named on its command line.
 *   ./cli file...
 * every path is unveiled read only, the list is sealed, and only stdio and rpath stay. */
#include <err.h>
#include <stdio.h>
#include <vow.h>

int
main(int argc, char **argv)
{
	FILE *f;
	char buf[4096];
	size_t n;
	int i;

	for (i = 1; i < argc; i++)
		if (unveil(argv[i], "r") < 0)
			err(1, "unveil %s", argv[i]);
	if (unveil(NULL, NULL) < 0)
		err(1, "unveil");
	if (pledge("stdio rpath", NULL) < 0)
		err(1, "pledge");
	for (i = 1; i < argc; i++) {
		if ((f = fopen(argv[i], "r")) == NULL)
			err(1, "%s", argv[i]);
		while ((n = fread(buf, 1, sizeof buf, f)) > 0)
			fwrite(buf, 1, n, stdout);
		fclose(f);
	}
	return 0;
}
