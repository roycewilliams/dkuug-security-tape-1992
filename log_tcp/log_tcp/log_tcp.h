/* @(#) log_tcp.h 1.1 91/10/02 23:01:55 */

 /*
  * Structure filled in by the fromhost() routine. Prerequisites:
  * <sys/types.h> and <sys/param.h>.
  */

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	1024
#endif

struct from_host {
    int     sock_type;			/* socket type, see below */
    char    source[MAXHOSTNAMELEN + 1];	/* host name or address */
};

/* Socket types: 0 means unknown. */

#define	FROM_CONNECTED		1	/* connection-oriented */
#define	FROM_UNCONNECTED	2	/* non connection-oriented */

/* Global functions. */

extern int fromhost();			/* get/validate remote host info */
extern int hosts_access();		/* access control */
extern void refuse();			/* refuse request */
extern void shell_cmd();		/* execute shell command */
