
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
 *	pw_passwd - Routines for dealing with password files.
 *		Handles V7 / *.* BSD / Sys V format.
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>
#include <fcntl.h>

#ifndef lint
static char sccsid[] = "@(#)pw_passwd.c	1.9 1/24/91 (cc.utexas.edu)";
#endif

#define	SLOP	128	/*  Size difference tolerated old <> new passwd file */

#ifdef	SYSV
/*
 *	System V password aging stuff
 */
#define	SEC_PER_WEEK	((long )24 * 7 * 60 * 60)

extern long a64l();
extern char *l64a();

static time_t	pwage = 0,
		maxpwtime = 0,
		minpwtime = 0,
		now;
#endif

typedef struct passwd	passwd;
typedef	struct passwd	*passwdp;

static passwd	theUser,		/* The user to change */
		Me;			/* The user who invoked command */
static int	myuid,			/* Uid of program */
		mytempfile = 0;		/* Does PASSWD_TEMP belong to me? */

/*
 *	File names
 */
#ifndef	PASSWD_FILE
#define	PASSWD_FILE	"/etc/passwd"
#endif

#ifndef	PASSWD_SAVE
#define	PASSWD_SAVE	"/etc/opasswd"
#endif

#ifndef	PASSWD_TEMP
#define	PASSWD_TEMP	"/etc/ptmp"
#endif

#define	PASSWD_MODE	0644

#ifdef	DEBUG
static char	*passwdtemp = "./etc_ptmp",
		*passwdfile = "./etc_passwd",
		*savefile = "./etc_opasswd";
#else
static char	*passwdtemp = PASSWD_TEMP,
		*passwdfile = PASSWD_FILE,
		*savefile = PASSWD_SAVE;
#endif

extern int	errno;

char	*getlogin(),
	*crypt();

/*
 *	pw_initialize - set up
 */
pw_initialize()
{
	passwdp	me;	/* Temp */
	char	*myname = getlogin();	/* Name of invoker */

#ifdef	DEBUG
	setpwfile(passwdfile);
#endif
	myuid = getuid();
	if (myname && *myname) {
		if ((me = getpwnam(myname)) == NULL)
			quit(1, "Cannot get user identification from name.\n");
	} else {
		if ((me = getpwuid(myuid)) == NULL)
			quit(1, "Cannot get user identification from uid.\n");
	}

	_cppasswd(me, &Me);
	return(1);
}

/*
 *	pw_getuserbyname - get password 
 *
 *	Returns 1 if passwd info found for <name>
 *		0 otherwise
 */
pw_getuserbyname(name, passwdb)
char	*name,		/* User name */
	*passwdb;	/* Where to stuff password */
{
	passwdp	p;	/* Temp */

	if ((p = getpwnam(name)) == NULL)
		return(0);
	_cppasswd(p, &theUser);
	(void) strcpy(passwdb, p->pw_passwd);
	return(1);
}

/*
 *	pw_permission - check password change permission
 *
 *	Returns 1 if password can be changed
 *		0 if not
 */
pw_permission()
{
	if (strcmp(Me.pw_name, theUser.pw_name) && myuid)
		return(0);

	/*
	 * Other checks can be put here to determine if the invoker should
	 * be allowed to change this password.
	 */
#ifdef	SYSV
	if (theUser.pw_age) {
		pwage = a64l(theUser.pw_age);
		maxpwtime = pwage & 077;
		minpwtime = (pwage >> 6) & 077;
		pwage >>= 12;
		(void) time(&now);
		now /= SEC_PER_WEEK;
		if (pwage <= now) {
			if (myuid && (now < (pwage + minpwtime))) {
				fprintf(stderr, 
				     "Sorry: < %ld  weeks since last change\n",
				     minpwtime);
				return(0);
			}
			if ((minpwtime > maxpwtime) && myuid) {
				fprintf(stderr,
					"You may not change this password.\n");
				return(0);
			}
		}
	}
#endif
	return(1);
}

/*
 *	pw_compare - compare old and new passwords
 *
 *	Returns 1 if check = new, 0 if not
 */
pw_compare(current, check)
char	*current,		/* Current pw (encrypted) */
	*check;			/* check pw (plain) */
{
	if (!*current)
		return(0);
	return(!strcmp(current, crypt(check, current)));
}

/*
 *	pw_check - sanity check password.  Right now just calls
 *		the password check program
 *
 *	Returns 1 if password is ok to use, 0 otherwise
 */
pw_check(newpw)
char	*newpw;		/* New password (plain) */
{
	/* Put other administrative checks here */
	return(checkpasswd(theUser.pw_uid, newpw));
}

/*
 *	pw_replace - replace password in passwd file 
 */
pw_replace(newpwd, curpwd)
char	*newpwd,		/* New password (plain) */
	*curpwd;		/* Old password (plain) */
{
#ifdef	SYSV
	int	(*sigint)(),		/* Save SIGINT */
		(*sigquit)();		/* Save SIGQUIT */
#else
	long    oldsigs,		/* Signal mask save */
		blocksigs = sigmask(SIGINT) |	/* Signals to block */
			    sigmask(SIGQUIT) |	/* while updating */
			    sigmask(SIGTSTP);	/* password file */
#endif
	passwdp px;		/* Temp */
	char	salt[4];	/* Encryption salt */
	FILE	*tf;		/* File ptr to new passwd file */
	int	fd;		/* File desc. to new passwd file */
	struct stat	oldstat,	/* Stat of current passwd file */
			newstat;	/* Stat of new passwd file */

	/*
	 * Prepare password entry 'theUser' for replacement
	 */
	randomstring(salt, sizeof(salt));
	theUser.pw_passwd = crypt(newpwd, salt);
#ifdef	SYSV
	/*
	 * Update password age field
	 */
	if (theUser.pw_age) {
		if (maxpwtime == 0)
			*theUser.pw_age = '\0';
		else {
			now = time((time_t *)0) / SEC_PER_WEEK;
			pwage = maxpwtime
				+ (minpwtime << 6)
				+ (now << 12);
			theUser.pw_age = l64a(pwage);
		}
	}
#endif
	(void) umask(0);
	(void) stat(passwdfile, &oldstat);
	fd = open(passwdtemp, O_WRONLY|O_CREAT|O_EXCL, PASSWD_MODE);
	if (fd < 0) {
		if (errno == EEXIST)
			quit(0, "Password file busy - try again.\n");
		perror("Tempfile create");
		quit(1, "Cannot create temp file.\n");
	}
	mytempfile = 1;
	if ((tf = fdopen(fd, "w")) == NULL)
		quit(1, "Cannot fdopen temp file.");
#ifdef	SYSV
	sigint = signal(SIGINT, SIG_IGN);
	sigquit = signal(SIGQUIT, SIG_IGN);
#else
	oldsigs = sigblock(blocksigs);
#endif
	setpwent();
	while ((px = getpwent()) != NULL) {
		if (px->pw_name == 0 || px->pw_name[0] == 0) /* Sanity check */
			continue;
		if (strcmp(px->pw_name, theUser.pw_name) == 0)
			px = &theUser;
		(void) putpwent(px, tf);
	}
	endpwent();
	(void) fflush(tf);
	(void) fstat(fileno(tf), &newstat);
	(void) fclose(tf);
	/*
	 * Check if the new password file is complete.  Since the encrypted
	 * password is of a fixed length, the new file should be roughly
	 * the same size as the old one.
	 */
	if (newstat.st_size < (oldstat.st_size - SLOP))
		quit(1, "New password file appears to be incomplete - aborting.\n");

	if (rename(passwdfile, savefile) < 0) {
		perror("Password file save");
		unlink(passwdtemp);
		quit(1, "Can't save password file");
	}
	if (rename(passwdtemp, passwdfile) < 0) {
		perror("Password file replace");
		(void) unlink(passwdtemp);
		(void) link(savefile, passwdfile);
		quit(1, "Can't replace password file");
	}
#ifdef	BSD4_3
	updatedbm();
#endif
#ifdef	SYSV
	(void) signal(SIGINT, sigint);
	(void) signal(SIGQUIT, sigquit);
#else
	(void) sigsetmask(oldsigs);
#endif
}

/*
 *	pw_cleanup - clean up after myself
 */
pw_cleanup(code)
int	code;		/* 0 for normal, 1 for abort */ /*NOTUSED*/
{
	if (mytempfile)
		(void) unlink(passwdtemp);
}

/*
 *	_newstr - copy string into new storage
 */
static char *
_newstr(s)
char	*s;		/* String to copy */
{
	register char	*t;	/* Temp */
	char	*malloc();

	if (s == NULL)
		return(0);
	t = malloc(strlen(s) + 1);
	if (t == NULL)
		quit(1, "No memory.\n");
	(void) strcpy(t, s);
	return(t);
}

/*
 *	_cppasswd - copy a passwd structure
 */
static
_cppasswd(f,t)
passwdp	f,		/* From */
	t;		/* To */
{
	*t = *f;
	t->pw_name = _newstr(f->pw_name);
#ifdef	SYSV
	t->pw_age = _newstr(f->pw_age);
#endif
	t->pw_passwd = _newstr(f->pw_passwd);
	t->pw_comment = _newstr(f->pw_comment);
	t->pw_gecos = _newstr(f->pw_gecos);
	t->pw_dir = _newstr(f->pw_dir);
	t->pw_shell = _newstr(f->pw_shell);
}

#ifdef	BSD4_3
/*
 *	Update the hashed password data base
 */
#include <ndbm.h>

#define	SCOPY(S) xp = (S); while (*cp++ = *xp++)
#define	BCOPY(B) bcopy((char *)&(B), cp, sizeof(int)); cp += sizeof(int)

updatedbm()
{
	DBM	*pwd;		/* DBM data base passwd */
	register char	*cp,	/* Data storage pointer */
			*xp;	/* String copy pointer */
	datum	key,		/* DBM key datum */
		data;		/* DBM data store datum */
	char	buf[512];	/* Data buffer */

	pwd = dbm_open(passwdfile, O_RDWR, 0);
	if (pwd == 0)
		return;
	cp = buf;
	/* Pack passwd entry in the form expected by the getpw* routines */
	SCOPY(theUser.pw_name);
	SCOPY(theUser.pw_passwd);
	BCOPY(theUser.pw_uid);
	BCOPY(theUser.pw_gid);
	BCOPY(theUser.pw_quota);
	SCOPY(theUser.pw_comment);
	SCOPY(theUser.pw_gecos);
	SCOPY(theUser.pw_dir);
	SCOPY(theUser.pw_shell);

	data.dptr = buf;
	data.dsize = cp - buf;
	key.dptr = theUser.pw_name;
	key.dsize = strlen(theUser.pw_name);
	if (dbm_store(pwd, key, data, DBM_REPLACE) < 0) {
		perror("dbm_store (name)");
		quit(1, "Can't store passwd entry (name key).\n");
	}
	key.dptr = (char *)&theUser.pw_uid;
	key.dsize = sizeof (int);
	if (dbm_store(pwd, key, data, DBM_REPLACE) < 0) {
		perror("dbm_store (uid)");
		quit(1, "Can't store passwd entry (uid key).\n");
	}
	dbm_close(pwd);
}
#endif
