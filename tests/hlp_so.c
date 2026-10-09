/* needs libx.so: exit 0 when the library loaded and answers */
int xval(void);

int
main(void)
{
	return xval() == 42 ? 0 : 1;
}
