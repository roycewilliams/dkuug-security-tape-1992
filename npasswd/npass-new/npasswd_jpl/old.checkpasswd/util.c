
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
 *	util.c - Miscellanous utility routines
 */
#ifndef lint
static char sccsid[] = "@(#)util.c	1.4 11/14/89 (cc.utexas.edu)";
#endif

#include "checkpasswd.h"

/*
 *	_instring - Compare all sub-strings
 *
 *	Returns:
 *		0 if match not found
 *		rc if match found
 */
_instring(s1, s2, rc)
char	*s1,		/* String to look for */
	*s2;		/* String to look for <s1> in */
int	rc;		/* What to return on match */
{
	int	l;		/* Temp */

	for (l = strlen(s1); *s2; s2++)
		if (_cistrncmp(s1, s2, l) == 0)
			return (rc);
	return(0);
}

/*
 *	_flipstring - reverse a string in place
 */
_flipstring(s)
char	*s;		/* String to reverse */
{
	char	*p,	/* Scratch */
		*t;	/* Scratch */
	char	*malloc();

	t = malloc(strlen(s) + 1);
	(void) strcpy(t, s);
	p = t;
	while (*p) p++;		/* Find end of string */
	--p;
	for (; *s; )
		*s++ = *p--;
	free(t);
}

/*
 *	Case indepedant string comparasion routines swiped from
 *	the source to MIT Hesiod.
 *	Since these routines are publicly available,
 *	I presume to redistribute them is not in violation of copyright.
 */

/*
 * Copyright (c) 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * This array is designed for mapping upper and lower case letter
 * together for a case independent comparison.  The mappings are
 * based upon ascii character sequences.
 */
static
char charmap[] = {
	'\000', '\001', '\002', '\003', '\004', '\005', '\006', '\007',
	'\010', '\011', '\012', '\013', '\014', '\015', '\016', '\017',
	'\020', '\021', '\022', '\023', '\024', '\025', '\026', '\027',
	'\030', '\031', '\032', '\033', '\034', '\035', '\036', '\037',
	'\040', '\041', '\042', '\043', '\044', '\045', '\046', '\047',
	'\050', '\051', '\052', '\053', '\054', '\055', '\056', '\057',
	'\060', '\061', '\062', '\063', '\064', '\065', '\066', '\067',
	'\070', '\071', '\072', '\073', '\074', '\075', '\076', '\077',
	'\100', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
	'\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
	'\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
	'\170', '\171', '\172', '\133', '\134', '\135', '\136', '\137',
	'\140', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
	'\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
	'\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
	'\170', '\171', '\172', '\173', '\174', '\175', '\176', '\177',
	'\200', '\201', '\202', '\203', '\204', '\205', '\206', '\207',
	'\210', '\211', '\212', '\213', '\214', '\215', '\216', '\217',
	'\220', '\221', '\222', '\223', '\224', '\225', '\226', '\227',
	'\230', '\231', '\232', '\233', '\234', '\235', '\236', '\237',
	'\240', '\241', '\242', '\243', '\244', '\245', '\246', '\247',
	'\250', '\251', '\252', '\253', '\254', '\255', '\256', '\257',
	'\260', '\261', '\262', '\263', '\264', '\265', '\266', '\267',
	'\270', '\271', '\272', '\273', '\274', '\275', '\276', '\277',
	'\300', '\341', '\342', '\343', '\344', '\345', '\346', '\347',
	'\350', '\351', '\352', '\353', '\354', '\355', '\356', '\357',
	'\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
	'\370', '\371', '\372', '\333', '\334', '\335', '\336', '\337',
	'\340', '\341', '\342', '\343', '\344', '\345', '\346', '\347',
	'\350', '\351', '\352', '\353', '\354', '\355', '\356', '\357',
	'\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
	'\370', '\371', '\372', '\373', '\374', '\375', '\376', '\377',
};

/*
 *	cistrcmp - case independant string compare
 */
_cistrcmp(s1, s2)
register char *s1, *s2;
{
	register char *cm = charmap;

	while (cm[*s1] == cm[*s2++])
		if (*s1++=='\0')
			return(0);
	return(cm[*s1] - cm[*--s2]);
}

/*
 *	cistrncmp - case independant string compare
 */
_cistrncmp(s1, s2, n)
register char *s1, *s2;
register n;
{
	register char *cm = charmap;

	while (--n >= 0 && cm[*s1] == cm[*s2++])
		if (*s1++ == '\0')
			return(0);
	return(n<0 ? 0 : cm[*s1] - cm[*--s2]);
}
/* end of UCB copyrighted code 	*/

/*
 *	_ctran - produce printable version of any ASCII character
 */
char *
_ctran (c)
char	c;		/* Character to represent */
{
	static char	cbuf[8];	/* Return value buffer */
	char	*p = cbuf;		/* Pointer to cbuf */
	char	chr = c & 0177;		/* Scratch */

	if (c & 0200) {		/* Meta char - weird but what the hey */
		*p++ = 'M';
		*p++ = '-';
	}
	if (chr >= ' ' && chr <= '~') {
		*p++ = chr;
		*p++ = 0;
		return (cbuf);
	}
	if (chr == 0177)
		return("DEL");
	*p++ = '^';
	*p++ = chr + '@';
	*p++ = 0;
	return (cbuf);
}

/*
 *	The following routines are used by the configuration file processor.
 */

/*
 *	decode_boolean - decode a boolean value
 */
static
decode_boolean(s)
char	*s;
{
	return(*s == '1'
		| streq(s, "true")
		| streq(s, "yes")
		| streq(s, "on"));
}

/*
 *	decode_int - decode an integer value
 */
static
decode_int(s)
char	*s;		/* String to decode */
{
	int	t;	/* Temp */

	if (xatoi(s, (char *)0, &t))
		return(t);
	fprintf(stderr, "Bad numeric value '%s'\n", s);
	return(-1);
}

/*
 *	Is argument an octal digit?
 */
static int	octdigit(c)
char	c;
{
	return (c >= '0' && c <= '7');
}

/*
 *	Is argument a decimal digit?
 */
static int	decdigit(c)
char	c;
{
	return (c >= '0' && c <= '9');
}

/*
 *	Is argument a hexidecimal digit?
 */
static int	hexdigit(c)
char	c;
{
	return (decdigit(c) |
		(c >= 'a' &&  c <= 'f') |
		(c >= 'A' && c <= 'F'));
}

/*
 *	xatoi - Smart 'atoi' recognizes decimal, octal and hex constants
 */
static
xatoi(ip, ipp, iv)
char	*ip,		/* Pointer to number string */
	**ipp;		/* Stash pointer to end of string */ /* RETURN VALUE */
int	*iv;		/* RETURN VALUE */
{
	int	(*func)() = decdigit,	/* Function to check char */
		base = 10;		/* Conversion base */
	int	t = 0,			/* Return value */
		mult = 1;		/* Sign of result */
	char	*fcc = ip;		/* First char position */

	if (*ip == '-') {		/* Negative number? */
		ip++;
		mult = -1;
	}
	if (*ip == '0') { 	/* Leading '0'? */
		ip++;
		if (*ip == 'x' || *ip == 'X') {	/* Hex */
			base = 16;
			func = hexdigit;
			ip++;			/* Skip 'x' */
		}
		else {
			base = 8;		/* Octal */
			func = octdigit;
		}
	}
	while (*ip && (*func)(*ip)) {
		t *= base;
		if (decdigit(*ip))
			t += (*ip - '0');
		else
			t += (*ip >= 'a' ? *ip - 0x57 : *ip - 0x37);
		ip++;
	}
	if (ip == fcc)		/* Nothing processed */
		return(0);
	if (ipp)		/* Stash new pointer location */
		*ipp = ip;
	*iv = (t * mult);
	return(1);
}

/*
 *	decode_string - Copy string, converting backslash escapes
 *	Can handle most of the C backslash escape sequences
 */
static
decode_string(dst, src, len)
char	*dst,		/* Destination */
	*src;		/* Source */
int	len;
{
	int	t;		/* Temp */
	char	*dstx = dst;	/* Pointer to start of destination */
	char	quote = 0;	/* Quote character */

	if (*src == '"' || *src == '\'')
		quote = *src++;

#define	putxchar(P) *dst++ = (P)
	for (; *src && (dst - dstx) < len; ) {
		if (*src == '\\') {
			src++;
			switch(*src) {
			case 'a':	putxchar('\007'); src++; break;
			case 'b':	putxchar('\b'); src++; break;
			case 'f':	putxchar('\f'); src++; break;
			case 'n':	putxchar('\n'); src++; break;
			case 'r':	putxchar('\r'); src++; break;
			case 't':	putxchar('\t'); src++; break;
			case '\\':	putxchar('\\'); src++; break;
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
			case 'x':
				if (xatoi(src, &src, &t))
					putxchar(t & 0xff);
				break;
			default:
				if (quote && *src == quote)
					*dst++ = *src++;
				break;
			}
			continue;
		}
		else if (*src == '^') {	/* ^C = control-c */
			src++;
			if (isupper(*src))
				putxchar(*src - '@');
			else if (islower(*src))
				putxchar(*src - '`');
			else switch (*src) {
			     case '[':	putxchar('\033'); break;
			     case '\\':	putxchar('\034'); break;
			     case ']':	putxchar('\035'); break;
			     case '^':	putxchar('\036'); break;
			     case '-':	putxchar('\037'); break;
			}
			src++;
			continue;
		}
		else if (quote && *src == quote)
			break;
		*dst++ = *src++;
	}
#undef	putxchar
	*dst = 0;
}

static char	*default_dicts[] = {    /* List of default dictionaries */
#ifdef  DEFAULT_DICT
	DEFAULT_DICT,
#endif
	0
};

/*
 *	readconfig - Read the configuration file 
 *		Returns 1 if success, 0 if not found and -1 if error
 */
readconfig(filename)
char	*filename;
{
	char	buf[BUFSIZ];	/* Read buffer */
	FILE	*fp;		/* File pointer */
	char	**p;		/* Scratch */
	int	lineno = 0;	/* Current line number in config file */
	extern int	standalone;	/* Am I a standalone application? */

	/* "Load" default directories */
	for (p = default_dicts; *p; p++)
		add_dict(*p);

	if ((fp = fopen(filename, "r")) == NULL) {
#ifdef	DEBUG
		printf("No config file\n");
#endif
		return(0);
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char	*key,		/* Key on line */
			*data;		/* Data on line */

		lineno++;
		if (buf[0] == '\n')		/* Empty line */
			continue;
		if (key = index(buf, '\n'))
			*key = 0;
		for (data = buf; *data && *data <= ' '; data++);
		if (*data == '#')
			continue;
		key = data;
		for (; *data && *data > ' '; data++);	/* Skip to end */
		if (*data)
			*data++ = 0;
		else {
			if (standalone)
				printf("\"%s\", line %d: Incomplete line.\n",
					filename, lineno);
			continue;
		}
		for (; *data && *data <= ' '; data++);	/* Skip whitespace */
		if (streq(key, "dictionary"))
			add_dict(data);
		else if (streq(key, "singlecase"))
			single_case = decode_boolean(data);
		else if (streq(key, "minlength"))
			min_length = decode_int(data);
		else if (streq(key, "maxlength"))
			max_length = decode_int(data);
		else if (streq(key, "printonly"))
			print_only = decode_boolean(data);
		else if (streq(key, "badchars")) {
			char	xcc[BUFSIZ];
			char	append = 0;

			if (*data == '+')	/* Add data to existing list */
				append = *data++;
			decode_string(xcc, data, BUFSIZ);
			if (xcc[0] == 0)
				continue;
			if (append)
				(void) strcat(illegalcc, xcc);
			else
				(void) strncpy(illegalcc, xcc, sizeof_illegalcc);
		}
		else {
			if (standalone)
				printf("\"%s\", line %d: Unrecognized keyword '%s'.\n",
					filename, lineno, key);
		}
	}
	(void) fclose(fp);
	return(1);
}

/*
 *	add_dict - Add a dictionary to the search list
 *
 *	Arguments:
 *		The rest of the line from the configuration file
 *		which contains the path to the dictionary and optionally
 *		a descriptive phrase
 */
static
add_dict(line)
char	*line;		/* RHS of config line */
{
	dictionary	*dx,	/* Tail of directory list */
			*dn;	/* New entry */
	char	*tx,		/* Scratch */
		*p;		/* Scratch */
	char	*calloc();

#ifdef	DEBUG
	printf("Add dictionary '%s'\n", line);
#endif
	dn = (dictionary *)calloc(sizeof(dictionary), 1);
	if (dictionaries == 0)
		dictionaries = dn;

	for (dx = dictionaries; dx->dict_next ; dx = dx->dict_next);

	tx = malloc(strlen(line) + 1);
	(void) strcpy(tx, line);
	p = tx;
	while (*p && *p > ' ') p++;
	if (*p)
		*p++ = 0;
	dn->dict_path = tx;
	dn->dict_desc = p;
	dx->dict_next = dn;
	dn->dict_next = 0;
}
/*	End util.c */
