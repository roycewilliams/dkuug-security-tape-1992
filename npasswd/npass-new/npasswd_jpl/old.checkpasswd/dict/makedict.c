
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
 *	makedict - Make DBM version of password dictionary
 */

#ifndef lint
static char sccsid[] = "@(#)makedict.c	1.2 10/4/89 (cc.utexas.edu) /usr/src/ut/bin/passwd/checkpasswd/dict/SCCS/s.makedict.c";
#endif

#ifdef  MDBM
#include "mdbm.h"
#define DBM		struct mdbm
#define DBM_CLOSE	mdbm_close
#endif

#ifdef	NDBM
#include <ndbm.h>
#define DBM_CLOSE	dbm_close
#endif


/*
 *	What cpp needs is a way for the programmer to issue an error
 *	message here and abort compilation
 */
#if	!defined(MDBM) && !defined(NDBM)
	"Either NDBM or MDBM must be defined"
#endif

#include <sys/file.h>
#include <stdio.h>

char	line[80];		/* Input buffer */

main(argc, argv)
int	argc;
char	*argv[];
{
	DBM	*dp;		/* Database pointer */
	int	recs = 0;	/* Record counter */
	datum	d,		/* Data datum */
		k;		/* Key datum */
#ifdef	SYSV
#define index strchr
#endif
	char	*index();

	if (argc < 2) {
		printf("Usage: makedict dbm-file < input\n");
		exit(1);
	}
#ifdef	NDBM
	dp = dbm_open(argv[1], O_RDWR, 0);
	if (dp == 0) {
		if ((dp = dbm_open(argv[1], O_RDWR|O_CREAT, 0644)) == 0) {
			perror(argv[1]);
			exit(1);
		}
	}
#endif
#ifdef	MDBM
	dp = mdbm_open(argv[1], O_RDWR, (int *)0, (int *)0, (char *)0);
	if (dp == 0) {
		if ((dp = mdbm_open(argv[1], O_RDWR|O_CREAT, 0644,
		     (int *)0, (int *)0, (char *)0)) == 0) {
			perror(argv[1]);
			exit(1);
		}
	}
#endif
	while (!feof(stdin)) {
		char	*p;

		(void) fgets(line, sizeof(line), stdin);
		if (p = index(line, '\n'))
			*p = 0;
		d.dptr = line;
		d.dsize = strlen(line);
#ifdef	MDBM
		mdbm_store(dp, d, d, 1);
#endif
#ifdef	NDBM
		dbm_store(dp, d, d, DBM_INSERT);
#endif
		recs++;
	}
	DBM_CLOSE(dp);
	printf("%s built, %d records\n", argv[1], recs);
}
