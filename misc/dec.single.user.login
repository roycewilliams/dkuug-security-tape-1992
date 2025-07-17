From umd5!haven!purdue!mailrus!husc6!rutgers!psuvax1!psuvm!barilvm!bimacs!yedidya Wed Sep  6 17:37:16 EDT 1989
Article 18577 of comp.unix.wizards:
Path: umd5!haven!purdue!mailrus!husc6!rutgers!psuvax1!psuvm!barilvm!bimacs!yedidya
>From: yedidya@bimacs.BITNET (Yedidya Israel)
Newsgroups: comp.unix.wizards
Subject: SUMMERY: Single user security on DEC workstations.
Message-ID: <1053@bimacs.BITNET>
Date: 4 Sep 89 12:04:58 GMT
Organization: Math & CS, BarIlan U, Ramat-Gan, Israel
Lines: 181




In a previous article I asked:
>
>We have a few workstation of DEC running Ultrix3.0 with DECwindows.
>
>In order to prevent users from having root privileges (via b/2 on
>console) we put an "exec /bin/login" in /.profile.
>

Thanks to all of those who replied, these are the answers I got:

>From: Amos Shapir <amos@taux01.nsc.com<

You have encountered DEC's rather clumsy attempt to prevent root from
logging in, but that's the general idea: 'login root' is out, long
live 'su'.  The principle is that since 'su's are registered, you could
always find out who used the root account.

--
        Amos Shapir             amos@taux01.nsc.com or amos@nsc.nsc.com
National Semiconductor (Israel) P.O.B. 3007, Herzlia 46104, Israel
Tel. +972 52 522261  TWX: 33691, fax: +972-52-558322
34 48 E / 32 10 N                       (My other cpu is a NS32532)


>From: prl%iis.UUCP@cernvax
Date: 25 Aug 89  9:58 +0200

This may not give you the protection that you hope. Try booting the machine
and leaning on |C just before it starts the login shell; or leaning
on |C while it's doing fsck in multiuser.

Sun has changed init so that if console is set as non-secure in ttys,
then `/bin/login root' is run instead of /bin/sh in single-user mode.

Unfortunately, for the sufficiently subtle, this is no hinderance anyway.
I can send more details to postmaster or root on your machine, including
DEC's most unsatisfactory response. Fortunately, we don't have
any DEC workstations.

Replys to ...!uunet!mcvax!ethz!prl, prl@ethz.uucp, and prl@iis.ethz.ch
should work, depending on the mood of your mailer.


If you are running Ultrix 3.0, you should turn off setuid on /bin/login
or install 3.1 right now, if you are at all interested in security.



--
Peter Lamb
uucp:  uunet!mcvax!ethz!prl     eunet: prl@ethz.uucp    Tel:   +411 256 5241
Integrated Systems Laboratory
ETH-Zentrum, 8092 Zurich


>From: Carl-Lykke Pedersen <carllp@diku.dk>

We use the following program (called /.lockup) and calls it from
/.profile

It is not completly secure, but I hope you can use it.

Regards
Carl-Lykke

/* Written by Bruce G. Barnett <barnett@ge-crd.arpa> */
#include <stdio.h>
#include <signal.h>
#include <pwd.h>

struct  passwd *pwd;
struct  passwd *getpwuid();
char    *strcpy();
char    *crypt();
char    *getpass();
char    *pw;
char    pwbuf[10];
char    *rootpw = "DEFAULT_CRYPTED_PASSWD";


#define MESSAGE() fprintf(stderr, "\n\007\007\n%s\n%s\n%s\n%s\n\n", \
              "***********************************************************", \
              "***       THE SYSTEM IS IN AN INCONSISTENT STATE        ***", \
              "*** PLEASE, CONTACT THE COMPUTER DEPARTMENT IMMEDIATELY ***", \
              "***********************************************************")


main()
{
        int msg = 0;

        signal(SIGINT, SIG_IGN);
        signal(SIGQUIT, SIG_IGN);
        signal(SIGTSTP, SIG_IGN);

        /* Get the password entry for root                      */
        /* use 0 if you want to hard-wire the passwd for root   */
        /* else use getuid()                                    */

        pwd=getpwuid(0);
        if (pwd != NULL)
                rootpw = pwd->pw_passwd;

        while (1) {
                if (msg++ % 5 == 0)
                        MESSAGE();
                strcpy(pwbuf,getpass("Password:"));
                pw = crypt(pwbuf, rootpw);
                if (strcmp(pw, rootpw) == 0)
                        exit(0);
        }
}

>From: barnett@unclejack.crd.ge.com (Bruce Barnett)

We used to do this until it corrupted our file systems.

If a system crashed, and rebooted, and it could not automatically
repair the disks, it would go into single user mode.

When it executed login, it would wait for a password, not get one,
and terminated. Then the system would continue the reboot, going
into multi-user mode WITHOUT REPAIRING THE DISK!

Eventually the disk became very corrupted and we lost a lot of files.

My solution was to run a program lock.c instead of login:
lock.c:
#include <stdio.h>
#include <signal.h>
#include <pwd.h>

struct  passwd *pwd;
struct  passwd *getpwuid();
char    *strcpy();
char    *crypt();
char    *getpass();
char    *pw;
char    pwbuf[10];

main()
{

        signal(SIGINT, SIG_IGN);
        signal(SIGQUIT, SIG_IGN);
        signal(SIGTSTP, SIG_IGN);

/* get the password entry for root */

/* use 0 if you want to hard-wire the passwd for root */
/* else use getuid() */

        pwd=getpwuid(getuid());
        if (pwd == NULL )
          (void) fprintf(stderr,"Cannot get password entry for root");

        while ( 1) { /* forever */
            (void) strcpy(pwbuf,getpass("Password:"));
            pw = crypt(pwbuf, pwd->pw_passwd);
            if (strcmp(pw,pwd->pw_passwd) == 0 ) {
              return(0);
            }

        }
}

--
Bruce G. Barnett        <barnett@crd.ge.com>   uunet!crdgw1!barnett


--
| Israel Yedidya, Math & CS Department, Bar-Ilan U, Ramat-Gan, ISRAEL. |
+----------------------------------------------------------------------+
| Bitnet:   yedidya@bimacs                                             |
| Internet: yedidya@bimacs.biu.ac.il                                   |
| Arpa:     yedidya%bimacs.bitnet@cunyvm.cuny.edu                      |
| Uucp:     ...!uunet!mcvax!humus!bimacs!yedidya                       |
| Csnet:    yedidya%bimacs.bitnet%cunyvm.cuny.edu@csnet-relay          |
\----------------------------------------------------------------------/
 \--- If someone proves there is no God, I'll stop being religious ---/
  --------------------------------------------------------------------


