
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
 *	pw_userinfo.c - UTEXAS CC UNIX User Information Data Base
 *		backend for npasswd
 */
#ifndef lint
static char sccsid[] = "@(#)pw_userinfo.c	1.4 8/7/90 (cc.utexas.edu) /tmp_mnt/usr/share/src/private/ut/share/bin/passwd/SCCS/s.pw_userinfo.c";
#endif

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <strings.h>
#include <signal.h>
#include <pwd.h>
#include <local/userinfo.h>

static userdata	theUser,	/* User having password changed */
		Me;		/* User doing password change */

#define	P_USER	1
#define	P_PRIV	2
#define	P_SU	3

static short	priv = P_USER;	/* Privlege level of <Me> */

#define	QUOTEC	'"'		/* Character to start plaintext pwd */
#define	XPWLEN	3		/* Length of 'original CDC password' */

extern char	*getlogin(),
		*crypt(),
		*index(),
		*rindex();

/*
 *	pw_initialize - set up
 */
pw_initialize()
{
	char	*myname = getlogin();		/* Login name */
	struct passwd *pw;			/* If getlogin() fails... */
	userptr	u;			/* Temp */

	if (myname == NULL || *myname == '\0') {
		if ((pw = getpwuid(getuid())) == ((struct passwd *)NULL))
			quit(1, "Cannot get user name.\n");
		else
			myname = pw->pw_name;
	}
	bzero((char *)&theUser, sizeof(theUser));
	bzero((char *)&Me, sizeof(Me));
	if ((u = getuserbyname(myname)) == NULL)
		quit(1, "Cannot get user identification.\n");
	Me = *u;
	if (Me.ui_priv.p_acct_maint)	/* Account maintenance priv? */
		priv = P_PRIV;
	if (getuid() == 0)		/* SuperUser? */
		priv = P_SU;
}

/*
 *	pw_getuserbyname - Get userinfo data by name
 *
 *	Returns 1 if passwd info found for <name>
 *		0 otherwise
 */
pw_getuserbyname(name, passwdb)
char	*name,			/* Login name */
	*passwdb;		/* Where to stash password */
{
	userptr	u;			/* Temp */

	if ((u = getuserbyname(name)) == NULL)
		return(0);
	theUser = *u;
	(void) strcpy(passwdb, theUser.ui_password);
	return(1);
}

/*
 *	pw_permission - check if this user can change this password
 */
pw_permission()
{
	int	mypasswd		/* Wanting to change own password? */
		= (theUser.ui_uid == Me.ui_uid);

	/*
	 * Must be su to change root password.
	 */
	if (theUser.ui_uid == 0 && priv != P_SU) {
		fprintf(stderr, "Permission denied.\n");
		return(0);
	}

	/*
	 * Must be su or have 'account maintenace' capability to change
	 * someone else's password.
	 */
	if (!mypasswd && priv < P_PRIV) {
		fprintf(stderr, "Permission denied.\n");
		return(0);
	}

	/*
	 * If 'password change' capability denied, then user cannot
	 * change their own password.
	 */
	if (theUser.ui_priv.p_nopwchange && mypasswd) {
		fprintf(stderr, "Permission denied.\n");
		return(0);
	}
	/*
	 * We know at this point that the
	 * invoker does have permission to change the password.
	 */
	return(1);
}

/*
 *	pw_compare - compare old and new passwords
 *
 *	Returns 1 if check = new, 0 if not
 */
pw_compare(current, check)
char	*current,
	*check;
{
	if (!*current)
		return(1);
	return(strcmp(current, crypt(check, current)) == 0);
}

/*
 *	pw_check - sanity check password.  Performs some site-specific
 *		checks, then calls the checkpasswd() code.
 *
 *	Returns 1 if password is ok to use, 0 otherwise
 */
pw_check(new)
char	*new;		/* New password (plaintext) */
{
	/* Setting null password? */
	if (strcmp(new, "@") == 0) {
		if (theUser.ui_priv.p_null_pass == 0 || priv < P_PRIV) {
			fprintf(stderr, "Cannot set null password.\n");
			return(0);
		}
		else
			return(1);
	}

	/* A plain text password (enclosed in ""s)? */
	if (*new == QUOTEC) {
		char	*p = &new[1];

		while (*p) p++;
		if (p[-1] == QUOTEC) {
			if (priv == P_SU)	/* Reserved for superuser */
				return(1);
			else {
				fprintf(stderr,
					"Cannot set plaintext password.\n");
				return(0);
			}
		}
	}

	/* Special password (reserved for superuser) */
	if (strlen(new) == XPWLEN && priv == P_SU)
		return(1); 

	/* Dispatch to general password checker */
	return(checkpasswd(theUser.ui_uid, new));
}

/*
 *	pw_replace - Replace password in Userinfo database
 */
pw_replace(new, current)
char	*new,		/* New password (plaintext) */
	*current;	/* Current password (plaintext) [unused] */
{
	userptr	newu;			/* Temp */
	int	rc;			/* Temp */
	long	oldsigs,		/* Saved signal mask */
		blockedsigs = sigmask(SIGINT) |		/* Signals to block */
			      sigmask(SIGQUIT) |	/* while updating */
			      sigmask(SIGTSTP);		/* the database */
	extern int	errno;

	/*
	 * Password has already been validated by pw_check()
	 */
	if ((newu = getuserbyuid(theUser.ui_uid)) == NULL)
		quit(1, "pw_replace: Cannot refetch user information.\n");

	if (strcmp(new, "@") == 0) {
		printf("Password removed from %s\n", theUser.ui_name);
#ifndef	DEBUG
		syslog(LOG_INFO, "Password removed from %s\n", theUser.ui_name);
#endif
		newu->ui_password[0] = 0;
	}
	else {
		char	salt[2];

		randomstring(salt, sizeof(salt));
		(void) strcpy(newu->ui_password, crypt(new, salt));
		if (*new == QUOTEC && priv == P_SU) {
			char	*p = new;

			while (*p) p++;
			if (*--p == QUOTEC) {
				*p = 0;
				(void) strcpy(newu->ui_password, &new[1]);
				printf("Setting plain text password.\n");
			}
		}
	}
	ui_acct(newu)->a_pwchanged = time((time_t *)0);

#if	0
	if (UIRecordChanged(newu))
		quit(1, "Record synchronization error\n");
#endif
#ifdef	DEBUG
	printf("replace %s %s\n", theUser.ui_password, newu->ui_password);
#else
	errno = 0;
	oldsigs = sigblock(blockedsigs);
	if (lockuser(theUser.ui_uid) < 0) {
		if (errno == ETXTBSY)
			quit(1,
				"pw_replace: Data for %s locked out.\n",
				theUser.ui_name);
		else
			quit(1,
				"pw_replace: Data lock failure for user %s\n",
				theUser.ui_name);
	}
	rc = UIReplaceEntry(newu);
	(void) sigsetmask(oldsigs);
	unlockuser(theUser.ui_uid);
	if (rc < 0)
		quit(1, "Userinfo update failure %s\n", UIErrorMessage);
#endif
}

/*
 *	pw_cleanup - cleanup routine
 */
pw_cleanup()
{
	/* Do nothing */
}
/*	End pw_userinfo.c		*/
