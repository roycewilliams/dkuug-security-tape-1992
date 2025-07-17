
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
 *	checkpasswd - Library version main routine
 *
 *	Compilation:	ld -r -o checkpasswd.o checkpasswd.o libmain.o
 *		pwck_dict.o pwck_passwd.o pwck_lexical.o pwck_local.o util.o 
 */
#ifndef lint
static char sccsid[] = "@(#)libmain.c	1.2 11/14/89 (cc.utexas.edu)";
#endif

#include "checkpasswd.h"
#include <varargs.h>

static char *replies[] = {
	0,					/* PWCK_OK */
	"Empty password",			/* PWCK_NULL */
	"This password is too easy to guess",	/* PWCK_OBVIOUS */
	"This password is part of your 'finger' information", /* PWCK_FINGER */
	"This password was found in a dictionary",	/* PWCK_INDICT */
	"This password has an illegal character in it",	/* PWCK_ILLCHAR */
	"This password is too short",			/* PWCK_SHORT */
	0
};
#define	NREPLIES	7	/* Number of messages in replies */

static char	elucidate[BUFSIZ];	/* Expanded error message */
static char	*configfile = CONFIG_FILE;	/* Configuration file */
static char	configured = 0;		/* Has cf been read? */
static int	silent = 0;		/* Don't print messages */
		returncode = 0;		/* Return PWCK return code */
int	standalone = 0;			/* Not a standalone application */

/*
 *	setcheckpasswd - set parameters for checkpasswd
 *
 *	e.g setcheckpasswd("-c", <configfile>, "-e", "-s", 0);
 */
setcheckpasswd(va_alist)
va_dcl		/* List of options */
{
	va_list	optlist;
	char	*optx;

	va_start(optlist);
	while (optx = va_arg(optlist, char *)) {
		if (*optx == '-') {
			switch(*++optx) {
			case 's':	/* -s (silent) */
				silent = 1;
				break;
			case 'e':	/* -e (return error code) */
				returncode = 1;
				break;
			case 'c':	/* -c config-file */
				if (*++optx)
					configfile = optx;
				else {
					optx = va_arg(optlist, char *);
					if (optx)
						configfile = optx;
				}
				break;
			}
		}
	}
	va_end(optlist);
}

/*
 *	checkpasswd - check password candidate
 *
 *	Returns 1 if <pwd> is ok to use as a password
 *		0 if not & an appropriate error message is issued
 */
checkpasswd(uid, pwd)
int	uid;		/* User who wants this password */
char	*pwd;		/* Password they want */
{
	int	rc;	/* Return code */

#ifdef	DEBUG
	printf("checkpasswd %d %s\n", uid, pwd);
#endif
	if (!configured) {
		readconfig(configfile);
		configured++;
	}
	rc = checkpassword(pwd, uid, elucidate);
	if (rc == PWCK_OK)		/* Always silent on success */
		return(returncode ? rc : 1);
	if (silent)
		return(returncode ? rc : 0);
	if (rc <= NREPLIES) {
		if (elucidate[0])
			printf("%s.\n", elucidate);
		else if (replies[rc])
			printf("%s.\n", replies[rc]);
		else
			putchar('\n');
	}
	return(returncode ? rc : 0);
}
/*	End libmain.c */
