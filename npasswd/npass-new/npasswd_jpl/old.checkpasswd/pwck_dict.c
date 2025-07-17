
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
 *	pwck_dictionary - Look in the forbidden password dictionaries.
 *	Returns:
 *		PWCK_INDICT if <password> was in any dictionary
 *		PWCK_OK if not
 */

#ifndef lint
static char sccsid[] = "@(#)pwck_dict.c	1.2 11/26/90 (cc.utexas.edu)";
#endif

#include "checkpasswd.h"

dictionary	*dictionaries = 0;	/* List of dictionaries */
static char	*egrep = "PATH=/bin:/usr/bin:/usr/ucb; egrep -s"; /* egrep */

pwck_dictionary(password, userid, mesgbuf)
char	*password;	/* Password to check */
int	userid;		/* NOTUSED */
char	*mesgbuf;	/* Message buffer */
{
	int	rcode;		/* Return code temp */
	char	*p;		/* Scratch */
	dictionary *d;		/* Current dictionary */

	/*
	 * If there are any non-alpha characters 
	 * don't bother with the dictionary checks.
	 */
	for (p = password; *p; p++) {
		if (!isalpha(*p))
			return(PWCK_OK);
	}
#ifdef	DEBUG
	printf("pwck_dictionary: \"%s\"\n", password);
#endif
	for (d = dictionaries; d; d = d->dict_next) {
#ifdef	DEBUG
		printf("\tdictionary '%s'\n", d->dict_path);
#endif
		if ((rcode = InDictionary(d->dict_path, password)) != PWCK_OK){
			(void) sprintf(mesgbuf,
				"Password found in dictionary '%s'",
				d->dict_path);
			return(rcode);
		}
	}
	return(PWCK_OK);
}

#ifdef  MDBM
/*
 *	Use the 'mdbm' package by Chris Torek and others
 */
#include "mdbm.h"
#define	DBM		struct mdbm
#define	DBM_FETCH	mdbm_fetch
#define	DBM_CLOSE	mdbm_close
#endif

/*
 *	Using the 4.3BSD 'ndbm' routines
 */
#ifdef  NDBM
#include <ndbm.h>
#define DBM_FETCH	dbm_fetch
#define DBM_CLOSE	dbm_close
#endif

/*
 *	InDictionary - look for <password> in <dictionary>
 *
 *	Look in a DBM version of the dictionary if present, 
 *	else use egrep to search the flat file.
 *
 *	Look for <password>, then if the first letter
 *	is capitalized, force to lower and look again.  I don't care
 *	if <password> is in the dictionary but has mixed case letters.
 *	BUT if the first letter has been capitalized, I care because
 *	that's not a sufficent permutation to be secure.
 *
 *	If more than the first letter is capitalized, then the dictionary
 *	lookup will fail.
 *
 *	Returns:
 *		PWCK_INDICT if <password> was found in <dictionary>
 *		PWCK_OK if not
 */
static
InDictionary(which_dictionary, password)
char	*which_dictionary,		/* Pathname of dictionary */
	*password;		/* Plaintext of password */
{
#if	defined(NDBM) || defined(MDBM)
	DBM	*dbp;		/* DBM database pointer */
	datum	k,		/* DBM lookup key */
		d;		/* DBM lookup datum */
#endif
	int	uc = isupper(password[0]);	/* Is first char UC? */
	char	pwtemp[BUFSIZ];			/* Scratch buffer */
#ifdef	MDBM
	if ((dbp = mdbm_open(which_dictionary, 0, 0,
	    (int *)0, (int *)0, (char *)0)) == (DBM *)0)
#endif
#ifdef	NDBM
	if ((dbp = dbm_open(which_dictionary, 0, 0)) == (DBM *)0)
#endif
	{
		char	command[BUFSIZ];	/* Command build buffer */
		int	rc;			/* Return code from sytem(3) */

		if ((rc = open(which_dictionary, 0)) < 0)
			return(PWCK_OK);
		(void) close(rc);
		/*
		 * If the first letter is capitalized, look for
		 * "[wW]ord" else look for "word"
		 */
		if (uc) 
			(void) sprintf(command,
				"%s '^[%c%c]%s$' %s > /dev/null",
				egrep, password[0], password[0] | 040,
				&password[1], which_dictionary);
		else
			(void) sprintf(command, "%s '^%s$' %s > /dev/null",
				egrep, password, which_dictionary);
		rc = system(command);
		if (rc == 0) 
			return(PWCK_INDICT);
		else
			return(PWCK_OK);
	} 
#if	defined(NDBM) || defined(MDBM)
#define	returnwith(code) { DBM_CLOSE(dbp); return(code); }
	/*
	 * Look in the DBM version of the dictionary.
	 */
	(void) strcpy(pwtemp, password);
	k.dptr = pwtemp;
	k.dsize = strlen(pwtemp);
	d = DBM_FETCH(dbp, k);
	if (d.dptr)
		returnwith(PWCK_INDICT);
	if (uc) {
		pwtemp[0] |= 040;
		d = DBM_FETCH(dbp, k);
		if (d.dptr)
			returnwith(PWCK_INDICT);
	}
	returnwith(PWCK_OK);
#endif	/* defined(NDBM) || defined(MDBM) */
}
/*	End pwck_dict.c */
