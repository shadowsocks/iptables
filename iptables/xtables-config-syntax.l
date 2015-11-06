%{
/*
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This software has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <string.h>
#include "xtables-config-parser.h"
%}

%option yylineno
%option noinput
%option nounput

ws		[ \t]+
comment         #.*$
nl		[\n\r]

is_on		[o|O][n|N]
is_off		[o|O][f|F][f|F]
integer		[\-\+]?[0-9]+
string		[a-zA-Z][a-zA-Z0-9\.\-\_]*

%%
"family"		{ return T_FAMILY; }
"table"			{ return T_TABLE; }
"chain"			{ return T_CHAIN; }
"hook"			{ return T_HOOK; }
"prio"			{ return T_PRIO; }

{integer}		{ yylval.val = atoi(yytext); return T_INTEGER; }
{string}		{ yylval.string = strdup(yytext); return T_STRING; }

{comment}	;
{ws}		;
{nl}		;

<<EOF>>		{ yyterminate(); }

.		{ return yytext[0]; }

%%

int
yywrap()
{
	return 1;
}
