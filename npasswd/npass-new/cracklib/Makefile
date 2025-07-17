# Makefile for glue library
SOURCES = checkpasswd.c goodpass.c
OBJECTS = checkpasswd.o goodpass.o
LIBNAME = checkpasswd.a

CONFIG_FILE = 

all:	$(LIBNAME)

clean:
	-rm *.o *.a core demo

$(LIBNAME): 	$(OBJECTS)
	-rm -f $(LIBNAME)
	ar cr $(LIBNAME) $(LIBMAIN) $(OBJECTS)
	ranlib $(LIBNAME)

demo: demo.o $(OBJECTS)
	cc demo.o $(OBJECTS) -o demo
