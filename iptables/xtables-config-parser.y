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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <libiptc/linux_list.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>

#include <netinet/in.h>
#include <linux/netfilter.h>

extern char *yytext;
extern int yylineno;

static LIST_HEAD(xtables_stack);

struct stack_elem {
	struct list_head	head;
	int			token;
	size_t			size;
	char			data[];
};

static void *stack_push(int token, size_t size)
{
	struct stack_elem *e;

	e = calloc(1, sizeof(struct stack_elem) + size);

	e->token = token;
	e->size = size;

	list_add(&e->head, &xtables_stack);

	return e->data;
}

static struct stack_elem *stack_pop(void)
{
	struct stack_elem *e;

	e = list_entry(xtables_stack.next, struct stack_elem, head);

	if (&e->head == &xtables_stack)
		return NULL;

	list_del(&e->head);
	return e;
}

static inline void stack_put_i32(void *data, int value)
{
	memcpy(data, &value, sizeof(int));
}

static inline void stack_put_str(void *data, const char *str)
{
	memcpy(data, str, strlen(str));
}

static void stack_free(struct stack_elem *e)
{
	free(e);
}

%}

%union {
	int	val;
	char	*string;
}

%token T_FAMILY
%token T_TABLE
%token T_CHAIN
%token T_HOOK
%token T_PRIO

%token <string> T_STRING
%token <val>	T_INTEGER

%%

configfile	:
		| lines
		;

lines		: line
		| lines line
		;

line		: family
		;

family		: T_FAMILY T_STRING '{' tables '}'
		{
			void *data = stack_push(T_FAMILY, strlen($2)+1);
			stack_put_str(data, $2);
		}
		;

tables		: table
		| tables table
		;

table		: T_TABLE T_STRING '{' chains '}'
		{
			/* added in reverse order to pop it in order */
			void *data = stack_push(T_TABLE, strlen($2)+1);
			stack_put_str(data, $2);
		}
		;

chains		: chain
		| chains chain
		;

chain		: T_CHAIN T_STRING T_HOOK T_STRING T_PRIO T_INTEGER
		{
			/* added in reverse order to pop it in order */
			void *data = stack_push(T_PRIO, sizeof(int32_t));
			stack_put_i32(data, $6);
			data = stack_push(T_HOOK, strlen($4)+1);
			stack_put_str(data, $4);
			data = stack_push(T_CHAIN, strlen($2)+1);
			stack_put_str(data, $2);
		}
		;

%%

int __attribute__((noreturn))
yyerror(char *msg)
{
	fprintf(stderr, "parsing config file in line (%d), symbol '%s': %s\n",
			 yylineno, yytext, msg);
	exit(EXIT_FAILURE);
}

static int hooknametonum(const char *hookname)
{
	if (strcmp(hookname, "NF_INET_LOCAL_IN") == 0)
		return NF_INET_LOCAL_IN;
	else if (strcmp(hookname, "NF_INET_FORWARD") == 0)
		return NF_INET_FORWARD;
	else if (strcmp(hookname, "NF_INET_LOCAL_OUT") == 0)
		return NF_INET_LOCAL_OUT;
	else if (strcmp(hookname, "NF_INET_PRE_ROUTING") == 0)
		return NF_INET_PRE_ROUTING;
	else if (strcmp(hookname, "NF_INET_POST_ROUTING") == 0)
		return NF_INET_POST_ROUTING;

	return -1;
}

static int32_t familytonumber(const char *family)
{
	if (strcmp(family, "ipv4") == 0)
		return AF_INET;
	else if (strcmp(family, "ipv6") == 0)
		return AF_INET6;

	return -1;
}

int xtables_config_parse(char *filename, struct nftnl_table_list *table_list,
			 struct nftnl_chain_list *chain_list)
{
	FILE *fp;
	struct stack_elem *e;
	struct nftnl_table *table = NULL;
	struct nftnl_chain *chain = NULL;
	int prio = 0;
	int32_t family = 0;

	fp = fopen(filename, "r");
	if (!fp)
		return -1;

	yyrestart(fp);
	yyparse();
	fclose(fp);

	for (e = stack_pop(); e != NULL; e = stack_pop()) {
		switch(e->token) {
		case T_FAMILY:
			family = familytonumber(e->data);
			if (family == -1)
				return -1;
			break;
		case T_TABLE:
			table = nftnl_table_alloc();
			if (table == NULL)
				return -1;

			nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, family);
			nftnl_table_set(table, NFTNL_TABLE_NAME, e->data);
			/* This is intentionally prepending, instead of
			 * appending, since the elements in the stack are in
			 * the reverse order that chains appear in the
			 * configuration file.
			 */
			nftnl_table_list_add(table, table_list);
			break;
		case T_PRIO:
			memcpy(&prio, e->data, sizeof(int32_t));
			break;
		case T_CHAIN:
			chain = nftnl_chain_alloc();
			if (chain == NULL)
				return -1;

			nftnl_chain_set(chain, NFTNL_CHAIN_TABLE,
				(char *)nftnl_table_get(table, NFTNL_TABLE_NAME));
			nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY,
				nftnl_table_get_u32(table, NFTNL_TABLE_FAMILY));
			nftnl_chain_set_s32(chain, NFTNL_CHAIN_PRIO, prio);
			nftnl_chain_set(chain, NFTNL_CHAIN_NAME, e->data);
			/* Intentionally prepending, instead of appending */
			nftnl_chain_list_add(chain, chain_list);
			break;
		case T_HOOK:
			nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM,
						hooknametonum(e->data));
			break;
		default:
			printf("unknown token type %d\n", e->token);
			break;
		}
		stack_free(e);
	}

	return 0;
}
