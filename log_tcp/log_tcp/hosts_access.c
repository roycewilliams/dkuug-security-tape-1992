#ifdef HOSTS_ACCESS

 /*
  * This module implements a simple but effective form of access control
  * based on host (or domain) names, netgroup, internet addresses (or network
  * numbers) and daemon process names, with wild card support. Upon the first
  * match with an entry in the access-control tables, an optional shell
  * command is executed.
  * 
  * Diagnostics are reported through syslog(3).
  * 
  * Compile with -DHOSTS_ACCESS in order to enable access control. See the
  * hosts_access(5) manual page for details.
  * 
  * Compile with -DNETGROUP if your library provides support for netgroups.
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) hosts_access.c 1.6 91/10/02 23:01:49";
#endif

 /* System libraries. */

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <syslog.h>
#include <ctype.h>

extern char *fgets();
extern char *strchr();
extern char *strtok();
extern void exit();

/* Local stuff. */

#include "log_tcp.h"

/* Path names of the access control files. */

#define HOSTS_ALLOW	"/etc/hosts.allow"
#define HOSTS_DENY	"/etc/hosts.deny"

/* Delimiters for lists of daemons or clients. */

static char sep[] = ", \t";

/* Constants to be used in assignments only, not in comparisons... */

#define	YES		1
#define	NO		0

/* Forward declarations. */

static int table_match();
static int list_match();

/* hosts_access - host access control facility */

int hosts_access(daemon, client)
char   *daemon;
char   *client;
{

    /*
     * If the (daemon, client) pair is matched by an entry in the file
     * /etc/hosts.allow, access is granted. Otherwise, if the (daemon,
     * client) pair is matched by an entry in the file /etc/hosts.deny,
     * access is denied. Otherwise, access is granted. A non-existent
     * access-control file is treated as an empty file.
     */

    if (table_match(HOSTS_ALLOW, daemon, client))
	return (YES);
    if (table_match(HOSTS_DENY, daemon, client)) 
	return (NO);
    return (YES);
}

/* table_match - match table entries with (daemon, client) pair */

static int table_match(table, daemon, client)
char   *table;
char   *daemon;
char   *client;
{
    FILE   *fp;
    char    sv_list[BUFSIZ];		/* becomes list of daemons */
    char   *cl_list;			/* becomes list of clients */
    char   *sh_cmd;			/* becomes optional shell command */
    int     match = NO;
    int     end;

    /*
     * Process the table one line at a time. Lines that begin with a '#'
     * character are ignored. Non-comment lines are broken at the ':'
     * character (we complain if there is none). The first field is matched
     * against the daemon process name (argv[0]), the second field against
     * the host name. A non-existing table is treated as if it were an empty
     * table. The optional shell command (third field) is executed when the
     * first match is found.
     */

    if (fp = fopen(table, "r")) {
	while (match == 0 && fgets(sv_list, sizeof(sv_list), fp)) {
	    if (sv_list[end = strlen(sv_list) - 1] != '\n') {
		syslog(LOG_ERR, "%s: line exceeds STDIO buffer size", table);
		continue;
	    } else {
		sv_list[end] = '\0';		/* strip trailing newline */
	    }
	    if (sv_list[0] == '#') {		/* skip comments */
		continue;
	    } else if ((cl_list = strchr(sv_list, ':')) == 0) {
		syslog(LOG_ERR, "%s: malformed entry: \"%s\"", table, sv_list);
		continue;
	    } else {
		*cl_list++ = '\0';		/* split 1st and 2nd fields */
		if ((sh_cmd = strchr(cl_list, ':')) != 0)
		    *sh_cmd++ = '\0';		/* split 2nd and 3rd fields */
		match = (list_match(sv_list, daemon)
			 && list_match(cl_list, client));
	    }
	}
	(void) fclose(fp);
    }
    if (match && sh_cmd)
	shell_cmd(sh_cmd, daemon, client);
    return (match);
}

/* list_match - match a string against a list of tokens */

static int list_match(list, string)
char   *list;
char   *string;
{
    char   *tok;
    int     tok_len;
    int     str_len;

    /*
     * Process tokens one at a time. If a token has the magic value "ALL" the
     * match always succeeds. If the token is a domain name, return YES if it
     * matches the last fields of the string. If the token has the magic
     * value "LOCAL", return YES if the string does not contain a "."
     * character. If the token is a network number, return YES if it matches
     * the head of the string. If the token looks like a netgroup name,
     * return YES if the string is a (host) member of the netgroup.
     * Otherwise, return YES if the token fully matches the string. Note: we
     * assume that a daemon process name never begins or ends with a "." or
     * "@" character.
     */

    for (tok = strtok(list, sep); tok; tok = strtok((char *) 0, sep)) {
	if (tok[0] == '.') {			/* domain: match last fields */
	    if ((str_len = strlen(string)) > (tok_len = strlen(tok))
		&& strcasecmp(tok, string + str_len - tok_len) == 0)
		return (YES);
#ifdef	NETGROUP
	} else if (tok[0] == '@') {		/* netgroup: look it up */
	    if (innetgr(tok + 1, string, (char *) 0, (char *) 0))
		return (YES);
#endif
	} else if (strcasecmp(tok, "ALL") == 0) {	/* all: match any */
	    return (YES);
	} else if (strcasecmp(tok, "LOCAL") == 0) {	/* local: no dots */
	    if (strchr(string, '.') == 0)
		return (YES);
	} else if (!strcasecmp(tok, string)) {	/* match host name or address */
	    return (YES);
	} else if (tok[(tok_len = strlen(tok)) - 1] == '.'	/* net number */
		   && strncmp(tok, string, tok_len) == 0) {
	    return (YES);
	}
    }
    return (NO);
}

#endif
