/*--------------------------------------------------------------------------
 Glue code to match crack's checker with npasswd
 Dan Kegel (dank@blacks.jpl.nasa.gov)
--------------------------------------------------------------------------*/
#include <string.h>
#include <malloc.h>
#include <varargs.h>
#include <stdio.h>

#ifndef	CONFIG_FILE /* Set configuration file name */
# ifdef	DEBUG
#	define	CONFIG_FILE	"checkpasswd.cf" 
# else
#	define	CONFIG_FILE	"/usr/adm/checkpasswd.cf"
# endif	/* DEBUG */
#endif	/* CONFIG_FILE */

static char configfile[256] = CONFIG_FILE;

/*--------------------------------------------------------------------------
 Password candidate sanity checker.
 Returns 1 if <pwd> is ok to use as a password
 0 if not & an appropriate error message is issued
--------------------------------------------------------------------------*/
checkpasswd(userid, password)
    int	userid;
    char *password;
{
    char *s;
    char *GoodPass();

    readconfig(configfile);

    if (password == 0 || *password == 0) {
	printf("Password is empty.\n");
	return 0;
    }

    s = GoodPass(password);
    if (s != NULL) {
	printf("%s\n", s);
	return 0;
    }
    return 1;
}

/*--------------------------------------------------------------------------
 set parameters for checkpasswd
 e.g setcheckpasswd("-c", <configfile>, 0);
--------------------------------------------------------------------------*/
void
setcheckpasswd(va_alist)
va_dcl		/* List of options */
{
    va_list	optlist;
    char	*optx;

    va_start(optlist);
    while (optx = va_arg(optlist, char *)) {
	if (*optx == '-') {
	    char c = *++optx;

	    switch (c) {
	    case 'c':	/* -c config-file */
		if (*++optx)
		    strcpy(configfile, optx);
		else {
		    optx = va_arg(optlist, char *);
		    if (optx)
			strcpy(configfile, optx);
		}
		break;
	    default:
		fprintf(stderr, "setcheckpasswd: Unknown option %c\n", c);
	    }
	}
    }
    va_end(optlist);
}

/*--------------------------------------------------------------------------
 Add a dictionary to the list of places to check.
--------------------------------------------------------------------------*/
static void
add_dict(fname)
    char *fname;
{
    extern char *dikshunarys[];
    char **d;
    char *fnamecopy;

    fnamecopy = malloc(strlen(fname)+1);
    strcpy(fnamecopy, fname);

    /* Find end of list */
    for (d=dikshunarys; *d; d++) ;
    /* Append this dictionary */
    *d++ = fnamecopy;
    *d = NULL;
}


#define BLANKS " \t\n"

/*--------------------------------------------------------------------------
 Read the configuration file 
 Only allowed command is 'dictionary dictname'.
 Returns 1 if success, 0 if not found and -1 if error
--------------------------------------------------------------------------*/
int
readconfig(filename)
char	*filename;
{
    char	buf[BUFSIZ];	/* Read buffer */
    FILE	*fp;		/* File pointer */
    int	lineno = 0;	/* Current line number in config file */
    static int done = 0;

    if (done) return 1;
    done = 1;

    if ((fp = fopen(filename, "r")) == NULL) {
#ifdef	DEBUG
	printf("No config file\n");
#endif
	/* Use default dictionary. */
	add_dict("/usr/dict/words");
	return(0);
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
	char *cmd, *arg;

	lineno++;

	cmd = strtok(buf, BLANKS);
	if (cmd == NULL || *cmd == '#') continue;
	arg = strtok(NULL, BLANKS);

	if (strcmp(cmd, "dictionary") == 0)
	    add_dict(arg);
	else
	    fprintf(stderr, "\"%s\", line %d: Unrecognized keyword '%s'.\n",
		filename, lineno, cmd);
    }
    (void) fclose(fp);
    return(1);
}
