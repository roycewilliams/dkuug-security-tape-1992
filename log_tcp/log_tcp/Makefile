# @(#) Makefile 1.4 91/10/04 21:28:11

##############################
## Begin configuration options

# By default, logfile entries are written to the same file as used for
# sendmail transaction logs. Change the definition of the following macro
# if you disagree. See /usr/include/syslog.h for examples. Some syslog
# versions do not provide this flexibility.

FACILITY= LOG_MAIL

# To disable host access control, comment out the following macro definition.
# Note: host access control requires the strtok() and strchr() routines.

ACCESS	= -DHOSTS_ACCESS

# Disable the following macro definition if you wish to talk to hosts that
# pretend to have someone elses host name.

PARANOID= -DPARANOID

# If your system supports NIS or YP-style netgroups, enable the following
# macro definition.

NETGROUP= -DNETGROUP

# Some versions of apollo UNIX have a bug in the getpeername(2) routine.
# You have this bug if the front end reports that all UDP connections come
# from address 0.0.0.0. Compile with -DGETPEERNAME_BUG for a workaround.

BUGS	= -DGETPEERNAME_BUG

# Apollo Domain/OS offers both bsd and sys5 environments, sometimes
# on the same machine.  If your Apollo is primarily sys5.3 and also
# has bsd4.3, enable the following to build under bsd and run under
# either environment.

#SYSTYPE=  -A run,any -A sys,any

# If your C library does not have memcmp(3), compile with -Dmemcmp=bcmp.

CFLAGS	= -O -DFACILITY=$(FACILITY) $(ACCESS) $(PARANOID) $(NETGROUP) \
	$(BUGS) $(SYSTYPE)

# Include the file strcasecmp.o if it is not provided by your C library.
# The strcasecmp.c file provided with this package comes from BSD UNIX.

AUX_OBJ	= # strcasecmp.o

# Some System-V versions require that you explicitly specify the networking
# libraries (for example, -lnet or -linet).

LIBS	= # -lnet

## End configuration options
############################

TCPD_OBJ= tcpd.o fromhost.o hosts_access.o shell_cmd.o refuse.o
MISC_OBJ= miscd.o fromhost.o hosts_access.o shell_cmd.o refuse.o
TRY_OBJ	= try.o hosts_access.o shell_cmd.o

KIT	= README miscd.c tcpd.c fromhost.c hosts_access.c shell_cmd.c \
	refuse.c log_tcp.h try.c Makefile hosts_access.5 strcasecmp.c BLURB

all:	tcpd miscd try

tcpd:	$(TCPD_OBJ) $(AUX_OBJ)
	$(CC) $(CFLAGS) -o $@ $(TCPD_OBJ) $(AUX_OBJ) $(LIBS)

miscd:	$(MISC_OBJ) $(AUX_OBJ)
	$(CC) $(CFLAGS) -o $@ $(MISC_OBJ) $(AUX_OBJ) $(LIBS)

try:	$(TRY_OBJ) $(AUX_OBJ)
	$(CC) $(CFLAGS) -o $@ $(TRY_OBJ) $(AUX_OBJ)

fromhost: fromhost.c
	$(CC) $(CFLAGS) -DTEST -o fromhost fromhost.c
	rm -f fromhost.o

shar:	
	@shar $(KIT)

archive:
	$(ARCHIVE) $(KIT)

clean:
	rm -f tcpd miscd try fromhost *.o core

# Enable all bells and whistles for linting.

lint:
	lint -DFACILITY=LOG_MAIL -DHOSTS_ACCESS -DPARANOID -DNETGROUP \
	-DGETPEERNAME_BUG tcpd.c fromhost.c hosts_access.c shell_cmd.c refuse.c
	lint -DFACILITY=LOG_MAIL -DHOSTS_ACCESS -DPARANOID -DNETGROUP \
	-DGETPEERNAME_BUG miscd.c fromhost.c hosts_access.c shell_cmd.c refuse.c

# Compilation dependencies.

fromhost.o : fromhost.c log_tcp.h Makefile
hosts_access.o : hosts_access.c Makefile
miscd.o : miscd.c log_tcp.h Makefile
refuse.o : refuse.c log_tcp.h
shell_cmd.o : shell_cmd.c Makefile
strcasecmp.o : strcasecmp.c 
tcpd.o : tcpd.c log_tcp.h Makefile
try.o : try.c Makefile
