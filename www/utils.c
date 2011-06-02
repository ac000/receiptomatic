/*
 * utils.c
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

/* FastCGI stdio wrappers */
#include <fcgi_stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include "common.h"
#include "utils.h"

/*
 * Function comes from: http://www.geekhideout.com/urlcode.shtml
 * Will replace with g_uri_unescape_string() from glib when we have
 * glib 2.16
 *
 * Converts a hex character to its integer value
 */
static char from_hex(char ch)
{
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/*
 * Function comes from: http://www.geekhideout.com/urlcode.shtml
 * Will replace with g_uri_unescape_string() from glib when we have
 * glib 2.16
 *
 * Returns a url-decoded version of str
 *
 * IMPORTANT: be sure to free() the returned string after use
 */
static char *url_decode(char *str)
{
	char *pstr = str;
	char *buf = malloc(strlen(str) + 1);
	char *pbuf = buf;

	while (*pstr) {
		if (*pstr == '%') {
			if (pstr[1] && pstr[2]) {
				*pbuf++ = from_hex(pstr[1]) << 4 |
							from_hex(pstr[2]);
				pstr += 2;
			}
		} else if (*pstr == '+') {
			*pbuf++ = ' ';
		} else {
			*pbuf++ = *pstr;
		}
		pstr++;
	}
	*pbuf = '\0';

	return buf;
}

/*
 * Create a hash table of field name=value pairs for a mysql row result set.
 */
GHashTable *get_dbrow(MYSQL_RES *res)
{
	int num_fields;
	int i;
	MYSQL_ROW row;
	MYSQL_FIELD *fields;
	GHashTable *db_row;

	db_row  = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);

	num_fields = mysql_num_fields(res);
	fields = mysql_fetch_fields(res);
	row = mysql_fetch_row(res);
	for (i = 0; i < num_fields; i++) {
		d_fprintf(debug_log, "Adding key: %s with value: %s to "
						"hash table\n",
						fields[i].name, row[i]);
		g_hash_table_insert(db_row, g_strdup(fields[i].name),
							g_strdup(row[i]));
	}

	return db_row;
}

/*
 * Create a GList of GHashTables of name=value pairs.
 *
 * This is will most likely be used when needing to send POST
 * array values, e,g
 *
 * 	form0[name]
 * 	form0[email]
 *
 * If you need to send singular items also, then you should make them
 * a single entity array. i.e, don't mix array's and non-array's.
 */
GList *get_avars(char *query)
{
	char *token;
	char *idx;
	char *lidx = "\0";
	char *subtoken;
	char *saveptr1 = NULL;
	char *saveptr2 = NULL;
	char *string;
	GHashTable *query_values;
	GList *avars = NULL;

	query_values = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);

	string = strdupa(query);
	for (;;) {
		char *key;
		char *value;

		token = strtok_r(string, "&", &saveptr1);
		if (token == NULL)
			break;

		/* get the array name */
		subtoken = strtok_r(token, "%", &saveptr2);
		idx = strdupa(subtoken);
		if (strcmp(idx, lidx) != 0) {
			if (lidx[0] != '\0') {
				avars = g_list_append(avars, query_values);
				query_values = g_hash_table_new_full(
							g_str_hash,
							g_str_equal,
							g_free, g_free);
			}
		}
		lidx = idx;
		token = NULL;

		/* get the array index */
		subtoken = strtok_r(token, "=", &saveptr2);
		key = alloca(strlen(subtoken));
		memset(key, 0, strlen(subtoken));
		strncpy(key, subtoken + 2, strlen(subtoken + 2) - 3);
		token = NULL;

		/* get the array value */
		subtoken = strtok_r(token, "=", &saveptr2);
		if (!subtoken) { /* Maybe there is no value */
			value = malloc(1);
			value[0] = '\0';
		} else {
			value = url_decode(subtoken);
		}
		string = NULL;

		g_hash_table_replace(query_values, g_strdup(key),
							g_strdup(value));
		d_fprintf(debug_log, "Adding key: %s with value: %s to hash "
							"table\n", key, value);

		free(value);
	}
	avars = g_list_append(avars, query_values);
	d_fprintf(debug_log, "Added %d elements to the list\n",
							g_list_length(avars));

	return avars;
}

/*
 * Given a GList and index and a key, return the coresponding value from
 * the hash table contained within.
 */
char *get_avar(GList *avars, int index, char *key)
{
	char *val;
	GHashTable *vars;

	vars = g_list_nth_data(avars, index);
	val = g_hash_table_lookup(vars, key);

	return val;
}

/*
 * Free's the given hash table.
 */
void free_avars(GList *avars)
{
	GHashTable *query_vars;
	int i;
	int size;

	size = g_list_length(avars);
	for (i = 0; i < size; i++) {
		query_vars = g_list_nth_data(avars, i);
		g_hash_table_destroy(query_vars);
	}
	g_list_free(avars);
}

/*
 * Create a hash table of name=value pairs, generated from GET and POST
 * data.
 */
GHashTable *get_vars(char *query)
{
	char *string;
	char *token;
	char *subtoken;
	char *saveptr1 = NULL;
	char *saveptr2 = NULL;
	GHashTable *query_values;

	query_values = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);

	string = strdupa(query);
	for (;;) {
		char *key;
		char *value;

		token = strtok_r(string, "&", &saveptr1);
		if (token == NULL)
			break;

		subtoken = strtok_r(token, "=", &saveptr2);
		key = subtoken;
		token = NULL;
		subtoken = strtok_r(token, "=", &saveptr2);
		if (subtoken == NULL)
			*value = '\0';
		else
			value = url_decode(subtoken);

		d_fprintf(debug_log, "Adding key: %s with value: %s to hash "
							"table\n", key, value);
		g_hash_table_replace(query_values, g_strdup(key),
							g_strdup(value));

		string = NULL;
	}

	return query_values;
}

/*
 * Given a key name, return its value from the given hash table.
 */
char *get_var(GHashTable *vars, char *key)
{
	char *val;

	val = g_hash_table_lookup(vars, key);
	if (!val) {
		d_fprintf(debug_log, "Unknown var: %s\n", key);
		return "\0";
	}

	return val;
}

/*
 * Free's the given hash table.
 */
void free_vars(GHashTable *vars)
{
	if (vars != NULL)
		g_hash_table_destroy(vars);
}
