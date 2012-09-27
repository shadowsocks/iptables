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
#include <libnftables/table.h>
#include <libnftables/chain.h>

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
	memcpy(data, str, strlen(str)+1);
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

line		: table
		;

table		: T_TABLE T_STRING T_PRIO T_INTEGER '{' chains '}'
		{
			/* added in reverse order to pop it in order */
			void *data = stack_push(T_PRIO, sizeof(int32_t));
			stack_put_i32(data, $4);
			data = stack_push(T_TABLE, strlen($2));
			stack_put_str(data, $2);
		}
		;

chains		: chain
		| chains chain
		;

chain		: T_CHAIN T_STRING T_HOOK T_STRING
		{
			/* added in reverse order to pop it in order */
			void *data = stack_push(T_HOOK, strlen($4));
			stack_put_str(data, $4);
			data = stack_push(T_CHAIN, strlen($2));
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

int xtables_config_parse(char *filename, struct nft_table_list *table_list,
			 struct nft_chain_list *chain_list)
{
	FILE *fp;
	struct stack_elem *e;
	struct nft_table *table = NULL;
	struct nft_chain *chain = NULL;
	int prio = 0;

	fp = fopen(filename, "r");
	if (!fp)
		return -1;

	yyrestart(fp);
	yyparse();
	fclose(fp);

	for (e = stack_pop(); e != NULL; e = stack_pop()) {
		switch(e->token) {
		case T_TABLE:
			table = nft_table_alloc();
			if (table == NULL) {
				perror("nft_table_alloc");
				return -1;
			}
			nft_table_attr_set(table, NFT_TABLE_ATTR_NAME, e->data);
			nft_table_list_add(table, table_list);
			break;
		case T_PRIO:
			prio = *((int32_t *)e->data);
			break;
		case T_CHAIN:
			chain = nft_chain_alloc();
			if (chain == NULL) {
				perror("nft_chain_alloc");
				return -1;
			}
			nft_chain_attr_set(chain, NFT_CHAIN_ATTR_TABLE,
				(char *)nft_table_attr_get(table, NFT_TABLE_ATTR_NAME));
			nft_chain_attr_set(chain, NFT_CHAIN_ATTR_NAME, e->data);
			nft_chain_list_add(chain, chain_list);
			break;
		case T_HOOK:
			nft_chain_attr_set_u32(chain, NFT_CHAIN_ATTR_HOOKNUM,
						hooknametonum(e->data));
			nft_chain_attr_set_s32(chain, NFT_CHAIN_ATTR_PRIO, prio);
			break;
		default:
			printf("unknown token type %d\n", e->token);
			break;
		}
		stack_free(e);
	}

	return 0;
}
