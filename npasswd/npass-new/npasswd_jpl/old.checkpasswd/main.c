
/* --------------------------------------------------------------------  */
/*                                                                       */
/*                         Author: Clyde Hoover                          */
/*                          Computation Center                           */
/*                   The University of Texas at Austin                   */
/*                          Austin, Texas 78712                          */
/*                         clyde@emx.utexas.edu                          */
/*                   uunet!cs.utexas.edu!ut-emx!clyde                    */
/*                                                                       */
/*This code may be distributed freely, provided this notice is retained. */
/*                                                                       */
/* --------------------------------------------------------------------  */
/*
 *	checkpasswd - Main program for standalone version
 *		libmain.c is the driver for the library version
 *
 *	Compilation:	cc -o checkpasswd checkpasswd.c main.c pwck_dict.c
 *			pwck_passwd.c pwck_lexical.c pwck_local.c util.c 
 */

#ifndef lint
static char sccsid[] = "@(#)main.c	1.2 11/14/89 (cc.utexas.edu) /usr/src/ut/bin/passwd/checkpasswd/SCCS/s.main.c";
#endif

#include "checkpasswd.h"
#include "version.h"

char *replies[] = {
	"This password is ok for use",		/* PWCK_OK */
	"Empty password",			/* PWCK_NULL */
	"This password is too easy to guess",	/* PWCK_OBVIOUS */
	"This password is part of your 'finger' information", /* PWCK_FINGER */
	"This password was found in a dictionary",	/* PWCK_INDICT */
	"This password has an illegal character in it",	/* PWCK_ILLCHAR */
	"This password is too short",			/* PWCK_SHORT */
	0
};
#define	NREPLIES	7	/* Number of messages in replies */

char	elucidate[BUFSIZ];	/* Expanded error message */

int	silent = 0,		/* Silent mode switch */
	oneshot = 0,		/* Check only one password switch */
	errornum = 0;		/* Print error number with message */
int	standalone = 1;		/* Running as standalone application */

main(argc, argv)
int	argc;
char	**argv;
{
	int	uid = getuid(),		/* Invoker's uid */
		opt,			/* Argument parser */
		interactive = 0;	/* In interactive mode? */
	char	*configfile = CONFIG_FILE;	/* Configuration file */
	extern char	*optarg;	/* From getopt() */

	/* Process argument list */
	while ((opt = getopt(argc, argv, "c:eosu:V?")) != EOF) {
		switch (opt) {
		case 'c':	/* -c config-file */
			configfile = optarg;
			break;
		case 'e':	/* -e [print status number] */
			errornum++;
			break;
		case 'o':	/* -o [check one password & quit] */
			oneshot++;
			break;
		case 's':	/* -s [silent mode] */
			silent++;
			break;
		case 'u':	/* -u [user id] */
			if (uid == 0 && isdigit(*optarg))
				uid = atoi(optarg);
			break;
		case 'V':	/* -V [print version information] */
			printf("Version %s\nPatch level %s\n",
				version, patchlevel);
			break;
		case '?':
			printf("Usage: checkpasswd [-c config] [-e] [-o] [-s] [-V] [-u uid]\n");
			exit(0);
		}
	}
	(void) readconfig(configfile);
	interactive = isatty(fileno(stdin));
	for (;;) {
		int	rc;	/* Return code from checkpasswd() */
		char	ibuf[BUFSIZ];		/* Input buffer */
		char	*nl;	/* Newline postition */

		if (interactive) {
			printf("Password to check: ");
			fflush(stdout);
		}
		if (fgets(ibuf, sizeof(ibuf), stdin) == NULL)
			break;
		if (nl = index(ibuf, '\n'))
			*nl = 0;
		if (ibuf[0] == 0)
			continue;
		rc = checkpassword(ibuf, uid, elucidate);
		if (!silent) {
			if (errornum)
				printf("%d ", rc);
			if (rc <= NREPLIES) {
				if (elucidate[0])
					printf("%s.\n", elucidate);
				else if (replies[rc])
					printf("%s.\n", replies[rc]);
				else
					putchar('\n');
			}
			else
				printf("Error %d\n", rc);
		}
		if (oneshot)
			exit(rc);
	}
	exit(0);
}
/*	End main.c */
