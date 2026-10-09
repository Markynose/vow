/* fileproc: copy one file to a new file in a directory, upper casing it.
 *   ./fileproc in outdir name
 * reads in, writes outdir/name, nothing else on the file system is reachable. */
#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <vow.h>

int
main(int argc, char **argv)
{
	char path[4096];
	FILE *in, *out;
	int c;

	if (argc != 4)
		errx(2, "usage: fileproc in outdir name");
	if (unveil(argv[1], "r") < 0 || unveil(argv[2], "rwc") < 0)
		err(1, "unveil");
	if (unveil(NULL, NULL) < 0)
		err(1, "unveil");
	if (pledge("stdio rpath wpath cpath", NULL) < 0)
		err(1, "pledge");
	snprintf(path, sizeof path, "%s/%s", argv[2], argv[3]);
	if ((in = fopen(argv[1], "r")) == NULL)
		err(1, "%s", argv[1]);
	if ((out = fopen(path, "w")) == NULL)
		err(1, "%s", path);
	while ((c = getc(in)) != EOF)
		putc(toupper(c), out);
	if (fclose(out) != 0)
		err(1, "%s", path);
	return 0;
}
