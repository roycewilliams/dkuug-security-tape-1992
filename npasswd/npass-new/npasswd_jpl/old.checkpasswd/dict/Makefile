
# --------------------------------------------------------------------  #
#                                                                       #
#                         Author: Clyde Hoover                          #
#                          Computation Center                           #
#                   The University of Texas at Austin                   #
#                          Austin, Texas 78712                          #
#                         clyde@emx.utexas.edu                          #
#                   uunet!cs.utexas.edu!ut-emx!clyde                    #
#                                                                       #
#This code may be distributed freely, provided this notice is retained. #
#                                                                       #
# --------------------------------------------------------------------  #
#
#	Makefile for checkpasswd auxillary programs
#
#	@(#)Makefile	1.1 5/18/89 (cc.utexas.edu)
#
DEBUG	= -g -DDEBUG
# Change the line below to $(DEBUG)
CFLAGS	= -O

# If building with MDBM, use these lines 
#ZLIB = ../mdbm/libmdbm.a
#ZFLAGS	= -DMDBM -I../mdbm $(ZLIB)

# If building with NDBM, use these lines 
ZLIB	=
ZFLAGS	= -DNDBM


all:	makedict viewdict

install::
	@echo No installation to be done

makedict:	makedict.c $(ZLIB)
	$(CC) $(CFLAGS) -o makedict makedict.c $(ZFLAGS)

viewdict:	viewdict.c $(ZLIB)
	$(CC) $(CFLAGS) -o viewdict viewdict.c $(ZFLAGS)

clean::
	-rm -f *.o a.out core makedict viewdict

../mdbm/libmdbm.a::
	(cd ../mdbm; make $(MFLAGS))
