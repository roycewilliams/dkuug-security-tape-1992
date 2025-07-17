 /*
  * try - program to try out host access-control tables, including the
  * optional shell commands.
  * 
  * usage: try process_name host_name
  * 
  * where process_name is a daemon process name (argv[0] value), and host_name
  * is a host name or address.
  * 
  * Prints YES if access is granted, NO if denied.
  */

#include <stdio.h>
#include <syslog.h>

main(argc, argv)
int     argc;
char  **argv;
{
#ifdef HOSTS_ACCESS

#ifdef LOG_MAIL
    openlog(argv[0], LOG_PID, FACILITY);
#else
    openlog(argv[0], LOG_PID);
#endif

    if (argc != 3) {
	fprintf(stderr, "usage: %s process_name host_name\n", argv[0]);
	return (1);
    } else {
	printf(hosts_access(argv[1], argv[2]) ? "YES\n" : "NO\n");
	return (0);
    }
#else
    fprintf(stderr, "host access control is not enabled.\n");
    return (1);
#endif
}
