 /*
  * fromhost() returns the type of connection (datagram, stream) and the name
  * of the host at the other end of standard input (the host address if host
  * name lookup fails, "stdin" if it is connected to a terminal, or "unknown"
  * in all other cases). The return status is (-1) if the remote host
  * pretends to have someone elses host name, otherwise a zero status is
  * returned.
  * 
  * Diagnostics are reported through syslog(3).
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) fromhost.c 1.4 91/10/02 23:01:46";
#endif

/* System libraries. */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>

extern char *inet_ntoa();
extern char *strncpy();
extern char *strcpy();

/* Local stuff. */

#include "log_tcp.h"

/* Forward declarations. */

static int matchname();

/* The following are to be used in assignment context, not in comparisons. */

#define	GOOD	1
#define	BAD	0

 /*
  * The apollo sr10.3 getpeername(2) does not return an error in case of a
  * datagram-oriented socket. Instead, it claims that all UDP or RPC requests
  * come from address 0.0.0.0. The following code works around the problem.
  */

#ifdef GETPEERNAME_BUG

static int fix_getpeername(sock, sa, len)
int     sock;
struct sockaddr *sa;
int    *len;
{
    int     ret;
    struct sockaddr_in *sin = (struct sockaddr_in *) sa;

    if ((ret = getpeername(sock, sa, len)) >= 0
	&& sa->sa_family == AF_INET
	&& strcmp(inet_ntoa(sin->sin_addr), "0.0.0.0") == 0) {
	errno = ENOTCONN;
	return (-1);
    } else {
	return (ret);
    }
}

#define	getpeername	fix_getpeername
#endif

/* fromhost - find out what is at the other end of standard input */

int     fromhost(f)
struct from_host *f;
{
    struct sockaddr sa;
    struct sockaddr_in *sin = (struct sockaddr_in *) (&sa);
    struct hostent *hp;
    int     length = sizeof(sa);
    char    buf[BUFSIZ];

    /*
     * Look up the remote host address. Hal R. Brand <BRAND@addvax.llnl.gov>
     * suggested how to get the remote host info in case of UDP connections:
     * peek at the first message without actually looking at its contents.
     */

#define	punt(name) { f->sock_type = 0; strcpy(f->source, name); return(0); }

    if (getpeername(0, &sa, &length) >= 0) {	/* assume TCP request */
	f->sock_type = FROM_CONNECTED;
    } else {
	switch (errno) {
	case ENOTSOCK:				/* stdin is not a socket */
	    punt(isatty(0) ? "stdin" : "unknown");
	case ENOTCONN:				/* assume UDP request */
	    if (recvfrom(0, buf, sizeof(buf), MSG_PEEK, &sa, &length) < 0) {
		syslog(LOG_ERR, "recvfrom: %m");
		punt("unknown");
	    }
	    f->sock_type = FROM_UNCONNECTED;
	    break;
	default:				/* other, punt */
	    syslog(LOG_ERR, "getpeername: %m");
	    punt("unknown");
	}
    }

    /*
     * Now that we have the remote host address, look up the remote host
     * name. Use the address if name lookup fails. At present, we can only
     * handle names or addresses that belong to the AF_INET addres family.
     */

    if (sa.sa_family != AF_INET) {
	syslog(LOG_ERR, "unexpected address family %ld", (long) sa.sa_family);
	strcpy(f->source, "unknown");
	return (0);
    }
    if ((hp = gethostbyaddr((char *) &sin->sin_addr.s_addr,
			    sizeof(sin->sin_addr.s_addr),
			    AF_INET)) == 0) {
	strcpy(f->source, inet_ntoa(sin->sin_addr));	/* use address */
	return (0);
    }

    /*
     * Save the host name, even if we may decide to not use it, because the
     * next gethostbyxxx() call will clobber it.
     */

    strncpy(f->source, hp->h_name, sizeof(f->source) - 1);
    f->source[sizeof(f->source) - 1] = 0;

    /*
     * Verify that the host name does not belong to someone else. If host
     * name verification fails, ignore the host name and use the address
     * instead.
     */

    if (matchname(f->source, sin)) {
	return (0);
    } else {
	strcpy(f->source, inet_ntoa(sin->sin_addr));
	return (-1);				/* verification failed */
    }
}

/* matchname - determine if host name matches IP address */

static int matchname(remotehost, sin)
char   *remotehost;
struct sockaddr_in *sin;
{
    struct hostent *hp;
    int     i;

    if ((hp = gethostbyname(remotehost)) == 0) {

	/*
	 * Unable to verify that the host name matches the address. This may
	 * be a transient problem or a botched name server setup. We decide
	 * to play safe.
	 */

	syslog(LOG_ERR, "gethostbyname(%s): lookup failure", remotehost);
	return (BAD);

    } else {

	/* Look up the host address in the address list we just got. */

	for (i = 0; hp->h_addr_list[i]; i++) {
	    if (memcmp(hp->h_addr_list[i],
		       (caddr_t) & sin->sin_addr,
		       sizeof(sin->sin_addr)) == 0)
		return (GOOD);
	}

	/*
	 * The host name does not map to the original host address. Perhaps
	 * someone has compromised a name server. More likely someone botched
	 * it, but that could be dangerous, too.
	 */

	syslog(LOG_ERR, "host name/address mismatch: %s != %s",
	       inet_ntoa(sin->sin_addr), hp->h_name);
	return (BAD);
    }
}

#ifdef TEST

/* Code for stand-alone testing. */

main(argc, argv)
int     argc;
char  **argv;
{
    struct from_host from;

#ifdef LOG_MAIL
    (void) openlog(argv[0], LOG_PID, FACILITY);
#else
    (void) openlog(argv[0], LOG_PID);
#endif
    (void) fromhost(&from);
    printf("%s\n", from.source);
    return (0);
}

#endif
