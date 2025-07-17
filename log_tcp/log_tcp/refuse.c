#if defined(PARANOID) || defined(HOSTS_ACCESS)

 /*
  * refuse - do the necessary cleanup if we refuse service to some host. This
  * code is never invoked when access control and protection against bad host
  * names are disabled.
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) refuse.c 1.1 91/10/02 23:01:53";
#endif

/* System libraries. */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <syslog.h>

extern void exit();

/* Local stuff. */

#include "log_tcp.h"

/* refuse - refuse request from bad host */

void    refuse(f)
struct from_host *f;
{
    char    buf[BUFSIZ];
    struct sockaddr sa;
    int     size = sizeof(sa);

    syslog(LOG_WARNING, "refused connect from %s", f->source);

    /*
     * In the case of non-connection-oriented services we must discard the
     * packet sent by the client. Otherwise, a fresh daemon will be started
     * each time the present one exits. Some systems insist on a non-zero
     * source address argument in the recvfrom() call below.
     */

    if (f->sock_type == FROM_UNCONNECTED)
	(void) recvfrom(0, buf, sizeof(buf), 0, &sa, &size);

    /* Terminate with zero exit status to keep the inetd happy. */

    exit(0);
}

#endif
