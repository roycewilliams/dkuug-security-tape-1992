
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
 *	pwck_local - Perform 'local' password checks.
 *
 *	Returns:
 *		PWCK_OBVIOUS if <password> == hostname
 *		PWCK_OK if otherwise
 */
#ifndef lint
static char sccsid[] = "@(#)pwck_local.c	1.1 5/18/89 (cc.utexas.edu)";
#endif

#include "checkpasswd.h"

pwck_local(password, userid, mesg)
char	*password;	/* Password to check */
int	userid;		/* NOTUSED */
char	*mesg;		/* Message buffer */
{
	char	myname[32];		/* Scratch */

	(void) gethostname(myname, sizeof(myname));
	try(password, myname, PWCK_OBVIOUS);
	/*
	 * Could try full canoncalized hostname here in case gethostname
	 * didn't get that for us.
	 *
	 * Then look in users' .rhosts and try those strings (maybe)
	 */
	return(PWCK_OK);
}
/*	End pwck_local.c */
