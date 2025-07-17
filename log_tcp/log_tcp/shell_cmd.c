#ifdef HOSTS_ACCESS

 /*
  * shell_cmd() takes a shell command, performs %h (host name or address), %d
  * (daemon name) and %p (daemon process id) substitutions and passes the
  * result to /bin/sh, with standard input, standard output and standard
  * error connected to /dev/null. This code is never called when host access
  * control is disabled.
  * 
  * Diagnostics are reported through syslog(3).
  * 
  * Author: Wietse Venema, Eindhoven University of Technology, The Netherlands.
  */

#ifndef lint
static char sccsid[] = "@(#) shell_cmd.c 1.1 91/10/02 23:01:51";
#endif

/* System libraries. */

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <syslog.h>

extern char *strcpy();
extern void closelog();
extern void exit();

/* Local stuff. */

#include "log_tcp.h"

/* Forward declarations. */

static void do_percent();
static void do_child();

/* shell_cmd - expand %<char> sequences and execute shell command */

void    shell_cmd(string, daemon, client)
char   *string;
char   *daemon;
char   *client;
{
    char    cmd[BUFSIZ];
    int     child_pid;
    int     wait_pid;
    int     daemon_pid = getpid();

    /*
     * Most of the work is done within the child process, to minimize the
     * risk of damage to the parent.
     */

    switch (child_pid = fork()) {
    case -1:					/* error */
	syslog(LOG_ERR, "fork: %m");
	break;
    case 00:					/* child */
	do_percent(cmd, sizeof(cmd), string, daemon, client, daemon_pid);
	do_child(daemon, cmd);
	/* NOTREACHED */
    default:					/* parent */
	while ((wait_pid = wait((int *) 0)) != -1 && wait_pid != child_pid)
	     /* void */ ;
    }
}

/* do_percent - do %<char> expansion, abort if result buffer is too small */

static void do_percent(result, result_len, str, daemon, client, pid)
char   *result;
int     result_len;
char   *str;
char   *daemon;
char   *client;
int     pid;
{
    char   *end = result + result_len - 1;	/* end of result buffer */
    char   *expansion;
    int     expansion_len;
    char    pid_buf[10];

    /*
     * %h becomes the remote host name or address; %d the daemon process
     * name; %p the daemon process id; %% becomes a %, and %other is ignored.
     * We terminate with a diagnostic if we would overflow the result buffer.
     */

    while (*str) {
	if (*str == '%') {
	    str++;
	    expansion =
		*str == 'd' ? (str++, daemon) :
		*str == 'h' ? (str++, client) :
		*str == 'p' ? (str++, sprintf(pid_buf, "%d", pid), pid_buf) :
		*str == '%' ? (str++, "%") :
		*str == 0 ? "" : (str++, "");
	    expansion_len = strlen(expansion);
	    if (result + expansion_len >= end) {
		syslog(LOG_ERR, "shell command too long: %30s...", result);
		exit(0);
	    }
	    (void) strcpy(result, expansion);
	    result += expansion_len;
	} else {
	    *result++ = *str++;
	}
    }
    *result = 0;
}

/* do_child - exec command with { stdin, stdout, stderr } to /dev/null */

static void do_child(myname, command)
char   *myname;
char   *command;
{
    char   *error = 0;
    int     tmp_fd;

    /* Close a bunch of file descriptors. Ignore errors. */

    closelog();
    for (tmp_fd = 0; tmp_fd < 10; tmp_fd++)
	(void) close(tmp_fd);

    /* Set up new stdin, stdout, stderr, and exec the shell command. */

    if (open("/dev/null", 2) != 0) {
	error = "open /dev/null: %m";
    } else if (dup(0) != 1 || dup(0) != 2) {
	error = "dup: %m";
    } else {
	(void) execl("/bin/sh", "sh", "-c", command, (char *) 0);
	error = "execl /bin/sh: %m";
    }

    /* We can reach the following code only if there was an error. */

#ifdef LOG_MAIL
    (void) openlog(myname, LOG_PID, FACILITY);
#else
    (void) openlog(myname, LOG_PID);
#endif
    syslog(LOG_ERR, error);
    exit(0);
}

#endif
