
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
 *	viewdict - view DBM dictionary data base
 */
#ifndef lint
static char sccsid[] = "@(#)viewdict.c	1.1 5/18/89 (cc.utexas.edu) /home/emx/u2/cc/clyde/src/new/passwd/checkpasswd/dict/SCCS/s.viewdict.c";
#endif

#ifdef  MDBM
#include "mdbm.h"
#define DBM		struct mdbm
#endif

#ifdef	NDBM
#include <ndbm.h>
#endif

#if	!defined(MDBM) && !defined(NDBM)
	"Either NDBM or MDBM must be defined"
#endif

#include <sys/file.h>
#include <stdio.h>

main(argc, argv)
int	argc;
char	*argv[];
{
	DBM	*dp;		/* Database pointer */
	datum	k;		/* Key datum */
	char	t[128];		/* Output buffer */

	if (argc < 2) {
		printf("Usage: viewdict dbm-dictionary\n");
		exit(1);
	}
#ifdef	NDBM
	dp = dbm_open(argv[1], O_RDWR, 0);
#endif
#ifdef	MDBM
	dp = mdbm_open(argv[1], O_RDONLY, 0, (int *)0, (int *)0, (char *)0);
#endif
	if (dp == 0) {
		perror(argv[1]);
		exit(1);
	}
/* 	printf("Dictionary %s\n", argv[1]); */
#ifdef	NDBM
	for (k = dbm_firstkey(dp); k.dptr != 0; k = dbm_nextkey(dp)) {
#endif
#ifdef	MDBM
	for (k = mdbm_firstkey(dp); k.dptr != 0; k = mdbm_nextkey(dp, k)) {
#endif
		(void) strncpy(t, k.dptr, k.dsize);
		t[k.dsize] = 0;
		printf("%s\n", t);
	}
	exit(0);
}
