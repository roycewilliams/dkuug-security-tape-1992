#include <stdio.h>

main()
{
    setcheckpasswd("-c", "checkpasswd.cf", 0);

    for (;;) {
	char *p, *getpass();
	char buf[128];
	p=gets(buf);
	if (p == NULL || !*p) break;
	printf("checkpasswd returns %d\n", checkpasswd(0, p));
    }
    exit(0);
}
