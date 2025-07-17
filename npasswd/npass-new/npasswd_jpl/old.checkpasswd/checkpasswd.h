
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
 *	checkpasswd.h - Master include for checkpasswd
 * 
 *	@(#)checkpasswd.h	1.4 11/26/90 (cc.utexas.edu) /tmp_mnt/usr/share/src/private/ut/share/bin/passwd/checkpasswd/SCCS/s.checkpasswd.h
 */

#include <stdio.h>
#include <ctype.h>
#ifdef	SYSV
#include <string.h>
#define index strchr
#else
#include <strings.h>
#endif

/*
 *	Return codes from checkpasswd() and pwck_*
 *	Also used as exit codes from main()
 */
#define	PWCK_FAIL	-1	/* Failure during check process */
#define	PWCK_OK		0	/* Password is ok to use */
#define	PWCK_NULL	1 	/* Password is the null string */
#define	PWCK_OBVIOUS	2	/* Password is 'too obvious' */
#define	PWCK_FINGER	3	/* Password is part of users finger info */
#define	PWCK_INDICT	4	/* Password found in a dictionary */
#define	PWCK_ILLCHAR	5	/* Illegal character in password */
#define	PWCK_SHORT	6	/* Password too short */

/*
 *	Dictionary info
 */
typedef struct _dict {
	char	*dict_path,		/* Path to dictionary */
		*dict_desc;		/* Descriptive phrase */
	struct _dict  *dict_next;	/* Link to next dict */
} dictionary;
extern dictionary	*dictionaries; /* List of dictionaries to check */

/*
 *	This is the default dicitonary to look in
 *	If you have some DBM dictionaries, either repoint this
 *	define or comment it out and place dictionaries in
 *	the configuration file.
 */
#define	DEFAULT_DICT	"/usr/dict/words"	/* Default dictionary */

#ifndef	CONFIG_FILE
			/* Set configuration file name */
# ifdef	DEBUG
#	define	CONFIG_FILE	"checkpasswd.cf" 
# else
#	define	CONFIG_FILE	"/usr/adm/checkpasswd.cf"
# endif	/* DEBUG */
#endif	/* CONFIG_FILE */

/*
 *	Password preferences
 */
int	single_case,		/* Single-case passwords ok or not */
	print_only,		/* Printable characters only */
	run_length,		/* Maximum length of character runs */
	min_length,		/* Minimum password length */
	max_length;		/* Maximum effective length */

#define	sizeof_illegalcc	128
extern char	illegalcc[];		/* Control characters not allowed */

/*
 *	Misc inline subroutine macros
 */

/*	Single string comparasion */
#define try(P,C,V) { \
	if (_cistrcmp((P),(C)) == 0) \
		return(V); \
	}

/*	Multiple string comparasion */
#define mtry(P,C,V) { \
	int i; \
	if ((i = _instring((P),(C),(V))) != PWCK_OK) \
		return(i); \
}

/* Compact string compare */
#define	streq(X,S)	(_cistrncmp((X),(S), strlen(X)) == 0)


/*	End checkpasswd.h	*/
