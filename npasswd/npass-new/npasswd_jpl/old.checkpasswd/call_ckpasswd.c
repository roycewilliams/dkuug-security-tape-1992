
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
 *	Code which calls the standalone password check program
 */
#include <sys/types.h>
#include <sys/wait.h>

#ifndef	CHECKPASSWD
#define	CHECKPASSWD	"/usr/local/lib/checkpasswd"
#endif
/*
 *	checkpasswd - call password checker
 *
 *	Returns: 0 if password can not be used
 *		 1 if password can be used
 *		-1 if error
 */
checkpasswd(uid, newpw)
int	uid;		/* User id wanting new password */
char	*newpw;		/* Password wanted */
{
	int	pid,		/* Child pid */
		i,		/* Temp */
		ii,		/* Temp */
		fds[2];		/* Pipe */
	union wait	status; /* Child return status */
	char	pwbuf[128];	/* Password temp buffer */

#ifdef	DEBUG
	printf("checkpasswd %s\n", newpw);
#endif
	(void) sprintf(pwbuf, "%s\n", newpw);
	if (pipe(fds) < 0) {
		perror("password_ok pipe");
		return(-1);
	}
	if ((pid = fork()) == 0) {
		(void) close(0);
		(void) dup2(fds[0], 0);	/* stdin from pipe */
		(void) close(fds[0]);
		(void) close(1);
		(void) dup2(fds[1], 1);	/* stdin to pipe */
		(void) close(fds[1]);
		(void) setgid(getgid());	/* NO-OP if not su */
		(void) setuid(uid);		/* NO-OP if not su */
		(void) execl(CHECKPASSWD, "checkpasswd", "-o", 0);
		exit(-1);
	}
	if (pid < 0) {
		perror("checkpasswd fork");
		return(-1);
	}
	i = write(fds[1], pwbuf, strlen(pwbuf));
	(void) close(fds[1]);
	(void) sleep(1);
	bzero(pwbuf, sizeof(pwbuf));
	ii = read(fds[0], pwbuf, sizeof(pwbuf));
	(void) close(fds[0]);
	while (wait(&status) != pid);
	if (status.w_retcode == 255 || i <= 0 || ii < 0) {
		fprintf(stderr, "Checkpasswd error\n");
		return(-1);
	}
	if (status.w_retcode) {
		printf("%s\n", pwbuf);
		return(0);
	}
	return(1);
}
