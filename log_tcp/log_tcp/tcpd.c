 /*
  * General front end for stream and datagram IP services. This program logs
  * the remote host name and then invokes the real daemon. For example,
  * install as /usr/etc/{tftpd,fingerd,telnetd,ftpd,rlogind,rshd,rexecd},
  * after saving the real daemons in the directory "/usr/etc/...". This
  * arrangement requires that the network daemons are started by inetd or
  * something similar. Connections and diagnostics are logged through
  * syslog(3).
  * 
  * Compile with -DHOSTS_ACCESS in order to enable access control. See the
  * hosts_access(5) manual page for details.
  * 
  * Compile with -DPARANOID if service should be refused to hosts that pretend
  * to have someone elses host name. This gives some protection against rsh
  * and rlogin attacks that involve compromised domain name servers.
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) tcpd.c 1.2 91/10/02 23:01:44";
#endif

/* System libraries. */

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <syslog.h>

#ifndef MAXPATHNAMELEN
#define MAXPATHNAMELEN	BUFSIZ
#endif

/* Local stuff. */

#include "log_tcp.h"

/* The following specifies where the vendor-provided daemons should go. */

#define REAL_DAEMON_DIR	"/usr/etc/..."

main(argc, argv)
int     argc;
char  **argv;
{
    struct from_host from;
    int     from_stat;
    char    path[MAXPATHNAMELEN];

    /*
     * Open a channel to the syslog daemon. Older versions of openlog()
     * require only two arguments.
     */

#ifdef LOG_MAIL
    (void) openlog(argv[0], LOG_PID, FACILITY);
#else
    (void) openlog(argv[0], LOG_PID);
#endif

    /*
     * Find out and verify the remote host name. Sites concerned with
     * security may choose to refuse connections from hosts that pretend to
     * have someone elses host name.
     */

    from_stat = fromhost(&from);
#ifdef PARANOID
    if (from_stat == -1)
	refuse(&from);
#endif

    /*
     * Check whether this host can access the service in argv[0]. The
     * access-control code invokes optional shell commands as specified in
     * the access-control tables.
     */

#ifdef HOSTS_ACCESS
    if (!hosts_access(argv[0], from.source))
	refuse(&from);
#endif

    /* Report remote host name and invoke the real daemon program. */

    syslog(LOG_INFO, "connect from %s", from.source);
    sprintf(path, "%s/%s", REAL_DAEMON_DIR, argv[0]);
    (void) execv(path, argv);
    syslog(LOG_ERR, "%s: %m", path);
    return (1);
}
