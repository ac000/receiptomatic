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
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

#include <glib.h>

#include <mhash.h>

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
	char *buf;
	char *pbuf;

	buf = malloc(strlen(str) + 1);
	if (!buf) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	pbuf = buf;

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
	unsigned int num_fields;
	unsigned int i;
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
 * This will most likely be used when needing to send POST
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
		if (subtoken != NULL)
			value = url_decode(subtoken);
		else
			value = NULL;

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
 * Sets the GET / POST variable list.
 */
GHashTable *set_vars(void)
{
	char buf[BUF_SIZE];

	memset(buf, 0, sizeof(buf));

	if (strcmp(env_vars.request_method, "GET") == 0 &&
					strlen(env_vars.query_string) > 0) {
		snprintf(buf, BUF_SIZE, "%s", env_vars.query_string);
	} else if (strcmp(env_vars.request_method, "POST") == 0) {
		fread(buf, sizeof(buf) - 1, 1, stdin);
		if (!strstr(buf, "=") && !strstr(buf, "&"))
			goto out2;
	} else {
		goto out2;
	}

	return get_vars(buf);
out2:
	return NULL;
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
		if (subtoken != NULL)
			value = url_decode(subtoken);
		else
			value = NULL;

		d_fprintf(debug_log, "Adding key: %s with value: %s to hash "
							"table\n", key, value);
		g_hash_table_replace(query_values, g_strdup(key),
							g_strdup(value));
		free(value);

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

/*
 * Fill out a structure with various environment variables
 * sent to the application.
 */
void set_env_vars(void)
{
	if (getenv("REQUEST_URI"))
		env_vars.request_uri = strdup(getenv("REQUEST_URI"));
	else
		env_vars.request_uri = NULL;

	if (getenv("REQUEST_METHOD"))
		env_vars.request_method = strdup(getenv("REQUEST_METHOD"));
	else
		env_vars.request_method = NULL;

	if (getenv("HTTP_COOKIE"))
		env_vars.http_cookie = strdup(getenv("HTTP_COOKIE"));
	else
		env_vars.http_cookie = NULL;

	if (getenv("HTTP_USER_AGENT"))
		env_vars.http_user_agent = strdup(getenv("HTTP_USER_AGENT"));
	else
		env_vars.http_user_agent = NULL;

	if (getenv("HTTP_X_FORWARDED_FOR"))
		env_vars.http_x_forwarded_for = strdup(getenv(
						"HTTP_X_FORWARDED_FOR"));
	else
		env_vars.http_x_forwarded_for = NULL;

	if (getenv("QUERY_STRING"))
		env_vars.query_string = strdup(getenv("QUERY_STRING"));
	else
		env_vars.query_string = NULL;
}

/*
 * Free's the custom fields list.
 */
void free_fields(struct field_names *fields)
{
	free(fields->receipt_date);
	free(fields->department);
	free(fields->employee_number);
	free(fields->reason);
	free(fields->po_num);
	free(fields->cost_codes);
	free(fields->account_codes);
	free(fields->supplier_name);
	free(fields->supplier_town);
	free(fields->vat_number);
	free(fields->gross_amount);
	free(fields->net_amount);
	free(fields->vat_amount);
	free(fields->vat_rate);
	free(fields->currency);
	free(fields->payment_method);
}

/*
 * Generate a somewhat hard to guess string to hash for the users
 * activation key. We use the following:
 *
 *	email_addr|getpid()-tv_sec.tv_usec
 */
char *generate_activation_key(char *email_addr)
{
	unsigned char *hash;
	char hash_src[384];
	char shash[65];
	char ht[3];
	int hbs;
	int i;
	struct timeval tv;
	MHASH td;

	td = mhash_init(MHASH_SHA256);
	gettimeofday(&tv, NULL);
	snprintf(hash_src, sizeof(hash_src), "%s|%d-%ld.%ld", email_addr,
							getpid(), tv.tv_sec,
							tv.tv_usec);
	mhash(td, hash_src, strlen(hash_src));
	hash = mhash_end(td);
	memset(shash, 0, sizeof(shash));
	hbs = mhash_get_block_size(MHASH_SHA256);
	for (i = 0; i < hbs; i++) {
		sprintf(ht, "%.2x", hash[i]);
		strncat(shash, ht, 2);
	}
	free(hash);

	return strdup(shash);
}

/*
 * Send an account activation email to the required user.
 */
void send_activation_mail(char *name, char *address, char *key)
{
	FILE *fp = popen(MAIL_CMD, "w");

	fprintf(fp, "Reply-to: %s\n", MAIL_REPLY_TO);
	fprintf(fp, "From: %s\n", MAIL_FROM);
	fprintf(fp, "Subject: %s\n", MAIL_SUBJECT);
	fprintf(fp, "To: %s <%s>\n", name, address);
	fputs("Content-type: text/plain\n\n", fp);
	fputs("Your account has been created and awaits activation.\n\n", fp);
	fputs("Please follow the below url to complete your account setup.\n",
									fp);
	fputs("Note that this activation key is valid for 24 hours.\n\n", fp);
	fprintf(fp, "%s/activate_user/?key=%s\n", BASE_URL, key);

	pclose(fp);
}

/*
 * Hash a given password using either the SHA256 or SHA512 alogorithm.
 */
char *generate_password_hash(int hash_type, char *password)
{
	static const char salt_chars[64] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	char salt[21];
	int i;

	memset(salt, 0, sizeof(salt));

	if (hash_type == SHA256)
		strcpy(salt, "$5$");
	else
		strcpy(salt, "$6$");

	for (i = 3; i < 19; i++) {
		int r;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		srandom(tv.tv_sec * tv.tv_usec);
		r = random() % 64; /* 0 - 63 */
		salt[i] = salt_chars[r];
	}
	strcat(salt, "$");

	return crypt(password, salt);
}

/*
 * Given a user ID, delete their session(s) from the tokyo cabinet
 * session file.
 */
void delete_user_session(unsigned int uid)
{
	char suid[11];
	const char *rbuf;
	int i;
	int rsize;
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOWRITER);

	snprintf(suid, sizeof(suid), "%u", uid);
	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "uid", TDBQCNUMEQ, suid);
	res = tctdbqrysearch(qry);
	for (i = 0; i < tclistnum(res); i++) {
		rbuf = tclistval(res, i, &rsize);
		tctdbout(tdb, rbuf, strlen(rbuf));
	}

	tclistdel(res);
	tctdbqrydel(qry);
	tctdbclose(tdb);
	tctdbdel(tdb);
}

/*
 * Given a username, check if an account for it already exists.
 *
 * 0 - not exists
 * 1 - exists
 */
int user_already_exists(char *username)
{
	char sql[SQL_MAX];
	char *user;
	int ret = 0;
	MYSQL *conn;
	MYSQL_RES *res;

	conn = db_conn();

	user = alloca(strlen(username) * 2 + 1);
	mysql_real_escape_string(conn, user, username, strlen(username));
	snprintf(sql, SQL_MAX, "SELECT username FROM passwd WHERE "
						"username = '%s'", user);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) > 0)
		ret = 1;

	mysql_free_result(res);
	mysql_close(conn);

	return ret;
}

/*
 * Calculate the page_number to show and the where in the results
 * set to show from.
 *
 * This is used in the results pagination code.
 */
void get_page_pagination(char *req_page_no, int rpp, int *page_no, int *from)
{
	*page_no = atoi(req_page_no);

	if (*page_no < 2) {
		/* Reset to values for showing the first page */
		*page_no = 1;
		*from = 0;
	} else {
		*from = *page_no * rpp - rpp;
	}
}
