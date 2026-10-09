/* SPDX-License-Identifier: 0BSD */
/* netclient: send one line to an ip address and port, print the answer.
 *   ./netclient 127.0.0.1 7777 hello
 * no file system is needed, so there is no unveil; no name lookup either (it would need files),
 * only numeric addresses. inet allows the sockets, stdio the reading and writing. */
#include <arpa/inet.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vow.h>

int
main(int argc, char **argv)
{
	struct sockaddr_in sa;
	char buf[512];
	ssize_t n;
	int s;

	if (argc != 4)
		errx(2, "usage: netclient ipv4 port text");
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons((unsigned short)atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &sa.sin_addr) != 1)
		errx(2, "not an ipv4 address: %s", argv[1]);
	if (pledge("stdio inet", NULL) < 0)
		err(1, "pledge");
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		err(1, "socket");
	if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0)
		err(1, "connect");
	if (write(s, argv[3], strlen(argv[3])) < 0 || write(s, "\n", 1) < 0)
		err(1, "write");
	while ((n = read(s, buf, sizeof buf)) > 0)
		write(1, buf, (size_t)n);
	return 0;
}
