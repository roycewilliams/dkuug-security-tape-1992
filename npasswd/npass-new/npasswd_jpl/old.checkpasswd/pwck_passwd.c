
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
 *	pwck_password - Check password candidate against the users' password
 *		file information, or any other information that is publicly
 *		available about this user that a bandit could use as
 *		password guesses.
 *
 *	This code has an option for the User Information Data Base used
 *	at the UT Computation Center.  Here is the place to search 
 *	any local 'finger' database.
 */
#ifndef lint
static char sccsid[] = "@(#)pwck_passwd.c	1.2 6/5/89 (cc.utexas.edu)";
#endif

#include "checkpasswd.h"

#ifdef	UTEXAS_CC
/*
 *	For UTCC systems
 */
#include <local/userinfo.h>
#define	cname	pwp->ui_name
typedef	userptr	pwptr;
#define	setpwent	setuserent
#define	getpwuid	getuserbyuid

#else	/* UTEXAS_CC */

#include	<pwd.h>
#define	cname	pwp->pw_name
typedef	struct passwd *pwptr;

#endif	/* UTEXAS_CC */

pwck_passwd(password, userid, mesg)
char	*password;
int	userid;
char	*mesg;
{
	char	temp[BUFSIZ];	/* Scratch */
	pwptr	pwp;		/* Pointer to user information */

	mesg[0] = 0;
#ifdef	DEBUG
	printf("pwck_passwd: \"%s\"\n", password);
#endif
	if (userid < 0)			/* Can't do user checks */
		return(PWCK_FAIL);

	pwp = getpwuid(userid);
	if (pwp == (pwptr )0)
		return(PWCK_FAIL);

	strcpy(mesg, "Password is part of your passwd information");
	try(password, cname, PWCK_OBVIOUS);	/* Checks 'name' and 'Name' */

	(void) strcpy(temp, cname);
	(void) strcat(temp, cname);
	try(password, temp, PWCK_OBVIOUS);	/* Check 'namename' */

	(void) strcpy(temp, cname);
	_flipstring(temp);
	try(password, temp, PWCK_OBVIOUS);	/* 'eman' */

#ifdef	UTEXAS_CC
	/*
	 * Try the rest of the stuff in this userinfo record
	 */
	try(password, pwp->ui_rje_cc, PWCK_OBVIOUS);
	try(password, pwp->ui_bill_cc, PWCK_OBVIOUS);

	mesg[0] = 0;
	/* Try all 'finger' information */
	mtry(password, pwp->ui_personal_name, PWCK_FINGER);
	mtry(password, pwp->ui_nick_name, PWCK_FINGER);	
	mtry(password, pwp->ui_home_address, PWCK_FINGER);
	mtry(password, pwp->ui_work_address, PWCK_FINGER);
	mtry(password, pwp->ui_home_phone, PWCK_FINGER);
	mtry(password, pwp->ui_work_phone, PWCK_FINGER);
	mtry(password, pwp->ui_birthday, PWCK_FINGER);
	mtry(password, pwp->ui_project, PWCK_FINGER);
	mtry(password, pwp->ui_fellows, PWCK_FINGER);
#else
	/*
	 * Try every word in user's GECOS entry
	 */
	mesg[0] = 0;
	mtry(password, pwp->pw_gecos, PWCK_FINGER);
#endif
	return(PWCK_OK);
}
/*	End pwck_passwd.c */
