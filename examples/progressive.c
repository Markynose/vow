/* progressive: read a config file, then give up the right to read files.
 *   ./progressive config
 * promises only shrink: first stdio rpath to load the config, then stdio alone. the last step opens
 * a file on purpose; the process is killed there, which is what a violation looks like. */
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <vow.h>

int
main(int argc, char **argv)
{
	char line[256];
	FILE *f;

	if (argc != 2)
		errx(2, "usage: progressive config");
	if (unveil(argv[1], "r") < 0 || unveil(NULL, NULL) < 0)
		err(1, "unveil");
	if (pledge("stdio rpath", NULL) < 0)
		err(1, "pledge");
	if ((f = fopen(argv[1], "r")) == NULL)
		err(1, "%s", argv[1]);
	if (fgets(line, sizeof line, f) != NULL)
		printf("config says: %s", line);
	fclose(f);
	if (pledge("stdio", NULL) < 0)
		err(1, "pledge");
	puts("rpath given up, trying to open the config again");
	fflush(stdout);
	open(argv[1], O_RDONLY);
	puts("not reached");
	return 0;
}
