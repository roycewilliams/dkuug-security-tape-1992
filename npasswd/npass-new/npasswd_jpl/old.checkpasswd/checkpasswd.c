
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
 *	checkpasswd.c - Password check driver and data initialization
 */

#ifndef lint
static char sccsid[] = "@(#)checkpasswd.c	1.1 5/18/89 (cc.utexas.edu)";
#endif

#include "checkpasswd.h"

/*
 *	Table of password check parameters
 *	May be modified via the configuration file
 */
int	single_case =	0,		/* Single-case pwds ok */
	print_only =	0,		/* Printable ASCII chars only */
	run_length =	3,		/* How long chars runs can be */
	min_length =	5,		/* Minimum length */
	max_length =	8;		/* Maximum effective length */

/*
 *	Control characters best avoided - commonly-used terminal controls.
 *	Add characters here or replace entire contents via the
 *	configuration file.
 */
#define	ctrl(d)	('d' & 037)

char	illegalcc[sizeof_illegalcc] = {
	ctrl(c),	/* Interrupt character */
	ctrl(d),	/* UNIX end-of-file */
	ctrl(h),	/* Backspace */
/* 	ctrl(i), */
	ctrl(j),	/* Newline */
	ctrl(m),	/* Carriage return */
	ctrl(o),	/* Flush output */
	ctrl(r),	/* Retype pending input */
	ctrl(s),	/* Suspend output */
	ctrl(q),	/* Resume output */
	ctrl(y),	/* Suspend program deferred */
	ctrl(z),	/* Suspend program immediate */
	ctrl(\\),	/* Quit signal */
	ctrl([),	/* escape - may do strange things to ttys if echoed */
	ctrl(]),	/* UNIX telnet escape */
	'\0177',	/* rubout */
	0
};

/*
 *	The 'pwck_*' routines all use the PWCK_* return
 *	codes, which are then propigated up to the caller of checkpassword().
 *
 *	All pwck_* routines in the table below are called thusly:
 *		pwck_*(password, userid, mesg)
 *			password = plaintext password string to test.
 *			userid = the user id which wants to use <password>.
 *			mesg = buffer to place long explanation into
 *
 *	If more checks are desired, add the functions to the tables below.
 */
extern int
	pwck_lexical(),
	pwck_local(),
	pwck_passwd(),
	pwck_dictionary();

typedef	int	(*function)();

function checkprocs[] = {
	pwck_lexical,
	pwck_local,
	pwck_passwd,
	pwck_dictionary,
	0
};

/*
 *	checkpassword - Password candidate sanity checker.
 *
 *	Arguments;
 *		password = plain text password string to check.
 *		userid = the uid whom the password is for, -1 to disable.
 *
 *	Returns:
 *		PWCK_* values (see checkpasswd.h)
 */
checkpassword(password, userid, mesg)
char	*password;		/* Plaintext of password to check */
int	userid;			/* The user this is for */
char	*mesg;			/* Where to stash explanation message */
{
	int		rcode;		/* General purpose scratch */
	function	*checkfunc;	/* Check function pointer */

	if (password == 0 || *password == 0)
		return(PWCK_NULL);		/* Null password */

	mesg[0] = 0;
	for (checkfunc = checkprocs; *checkfunc; checkfunc++) {
		if ((rcode = (*checkfunc)(password, userid, mesg)) != PWCK_OK)
			return(rcode);
	}
	return(PWCK_OK);
}
/*	End checkpasswd.c */
