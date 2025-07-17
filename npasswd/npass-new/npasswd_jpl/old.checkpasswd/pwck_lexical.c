
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
 *	pwck_lexical - Perform lexical analysis of password candidate.
 *
 *	Things which are ok:
 *		Mixed case
 *		Digits
 *		Punctutation
 *		Control characters (except for those in the forbidden table)
 *
 *	Things which are NOT ok:
 *		Passwords less than 'min_length' characters
 *		Runs of more than <run_length> of the same character
 *			(e.g. 'zzz')
 *		Single-case strings (selectable via the config file)
 *
 *	Things NOT checked for:
 *		Cycles of character groups (e.g. 'aabbcc' or 'ababab')
 *		Sequential characters 'abcdef' or '123456'
 */

#ifndef lint
static char sccsid[] = "@(#)pwck_lexical.c	1.3 11/7/89 (cc.utexas.edu)";
#endif

#include "checkpasswd.h"

#define	P_U	0x1 	/* Upper case in password */
#define	P_L	0x2 	/* Lower case in password */
#define	P_C	0x4 	/* Control chars in password */
#define	P_D	0x8 	/* Digits in password */
#define	P_P	0x10 	/* Punctutation chars in password */

#define	hasone(P)	(what |= (P))
#define	hasany(P)	((what & (P)) == (P))

pwck_lexical(password, userid, mesg)
char	*password;		/* Password to check */
int	userid;			/* NOTUSED */
char	*mesg;		/* Message buffer */
{
	int	rc;		/* Duplicate character run count */
	char	*p = password;	/* Scratch */
	char	what = 0,	/* Lexical analysis result flags */
		last = 0;	/* Last character seen (for run checks) */

	mesg[0] = 0;
#ifdef	DEBUG
	printf("pwck_lexical: \"%s\"\n", password);
#endif
	rc = strlen(password);
	if (min_length && rc < min_length)
		return(PWCK_SHORT);
	/*
	 * Only the first <max_length> characters of a password are actually
	 * used due to the limitations of crypt(3).  If the given
	 * password is longer than this, issue warning message.
	 */
	if (max_length && rc > max_length) {
		printf("WARNING: Only the first %d characters of this password will be used \n",
			max_length);
	}

	for (p = password; *p; p++) {
		if (*p != last) {
			last = *p;
			rc = 1;
		}
		else {		/* Run of same characters */
			if (run_length && ++rc >= run_length) {
				(void) sprintf(mesg,
			"This password has %d or more repeated characters",
					run_length);
				return(PWCK_OBVIOUS);
			}
		}
		if (*p < ' ' || *p > '~') {	/* Non-printing character */
			char	*_ctran();

			if (print_only) {
				(void) strcpy(mesg,
			"This password has non-printing characters");
				return(PWCK_ILLCHAR);
			}
			if (index(illegalcc, *p)) {
				(void) sprintf(mesg,
				"Illegal character '%s' in this password",
					_ctran(*p));
				return(PWCK_ILLCHAR);
			}
			hasone(P_C);
		}
		else if (isupper(*p))	hasone(P_U);
		else if (islower(*p))	hasone(P_L);
		else if (ispunct(*p))	hasone(P_P);
		else if (isdigit(*p))	hasone(P_D);
	}
	if (hasany(P_U | P_L))	return(PWCK_OK);	/* UC+lc */
	if (hasany(P_D))	return(PWCK_OK);	/* Numbers */
	if (hasany(P_P))	return(PWCK_OK);	/* Punctutation chars */
	if (hasany(P_C))	return(PWCK_OK);	/* Control chars */
	/*
	 *	Check for mono-case passwords 
	 */
	if (!hasany(P_U) && single_case)	/* All lower case alpha */
		return(PWCK_OK);
	if (!hasany(P_L) && single_case)	/* All upper case alpha */
		return(PWCK_OK);

	if (!hasany(P_L))
		(void) strcpy(mesg,
			"Upper-case only passwords not allowed");
	if (!hasany(P_U))
		(void) strcpy(mesg,
			"Lower-case only passwords not allowed");
	return(PWCK_ILLCHAR);
}
/*	End pwck_lexical.c */
