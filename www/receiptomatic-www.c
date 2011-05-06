/*
 * receiptomatic-www.c
 *
 * Copyright (C) 2011 OpenTech Labs, Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#define _XOPEN_SOURCE		/* for strptime(), crypt() */

/* FastCGI stdio wrappers */
#include <fcgi_stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <ctype.h>	/* can be removed once switched to g_url_decode() */
#include <alloca.h>

/* SQLite, for the sessions */
#include <sqlite3.h>

/* MySQL */
#include <my_global.h>
#include <mysql.h>

/* Hashing algorithms */
#include <mhash.h>

/* File magic library */
#include <magic.h>

#include <glib.h>

/* HTML template library */
#include <ctemplate.h>

#include "receiptomatic-www.h"
#include "../db/db_config.h"


/* Initialise the default receipt tag field names */
static const struct field_names field_names = {
	"Receipt Date",
	"Department",
	"Employee Number",
	"Reason",
	"PO Num",
	"Cost Code(s)",
	"Account Code(s)",
	"Supplier Name",
	"Supplier Town",
	"VAT Number",
	"Gross Amount",
	"Net Amount",
	"VAT Amount",
	"VAT Rate",
	"Currency",
	"Payment Method"
};

static FILE *access_log;
static FILE *sql_log;
static FILE *error_log;
static FILE *debug_log;

#define NR_PROCS	5	/* Number of processes to fork at startup */
#define BUF_SIZE	4096
#define SQL_MAX		8192
#define IMAGE_PATH	"/data/www/opentechlabs.net/receiptomatic/receipt_images"
#define SESSION_DB	"/dev/shm/receiptomatic-www-sessions.sqlite"
#define SESSION_CHECK	60 * 60		/* Check for old sessions every hour */
#define SESSION_EXPIRY	60 * 60 * 4	/* 4 hours */

#define GRID_SIZE	9
#define ROW_SIZE	3
#define COL_SIZE	3

/*
 * Wrapper around fprintf(). It will prepend the text passed it with
 * seconds.microseconds pid function:
 *
 * e.g if you call it like: d_fprintf(debug, "This is a test\n");
 * You will get:
 *
 * 	1304600723.663486 1843 main: This is a test
 */
#define d_fprintf(stream, fmt, ...) \
	do { \
		struct timeval tv; \
		gettimeofday(&tv, NULL); \
		fprintf(stream, "%ld.%ld %d %s: " fmt, tv.tv_sec, tv.tv_usec, \
				getpid(), __FUNCTION__, ##__VA_ARGS__); \
		fflush(stream); \
	} while (0)


/*
 * Function comes from: http://www.geekhideout.com/urlcode.shtml
 * Will replace with g_uri_unescape_string() from glib when we have
 * glib 2.16
 *
 * Converts a hex character to its integer value
 */
char from_hex(char ch)
{
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/*
 * Function comes from: http://www.geekhideout.com/urlcode.shtml
 * Will replace with g_uri_unescape_string() from glib when we have
 * glib 2.16
 *
 * Converts an integer value to its hex character
 */
char to_hex(char code)
{
	static char hex[] = "0123456789abcdef";

	return hex[code & 15];
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
char *url_decode(char *str)
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
 * Opens a up a MySQL connection and returns the connection handle.
 */
static MYSQL *db_conn()
{
	MYSQL *conn;

	conn = mysql_init(NULL);
	mysql_real_connect(conn, opt_hostname, opt_user_name,
					opt_password, opt_db_name,
					opt_port_num, opt_socket_name,
					opt_flags);

	return conn;
}

/*
 * Stores custom image tag field names for a user in the database.
 */
static void update_fmap(struct session *current_session, char *query)
{
	MYSQL *conn;
	char sql[SQL_MAX];
	char *username;
	char *receipt_date;
	char *department;
	char *employee_number;
	char *reason;
	char *po_num;
	char *cost_codes;
	char *account_codes;
	char *supplier_name;
	char *supplier_town;
	char *vat_number;
	char *gross_amount;
	char *net_amount;
	char *vat_amount;
	char *vat_rate;
	char *currency;
	char *payment_method;
	GHashTable *qvars;

	qvars = get_vars(query);

	conn = db_conn();

	username = alloca(strlen(current_session->username) * 2 + 1);
	mysql_real_escape_string(conn, username, current_session->username,
					strlen(current_session->username));

	receipt_date = alloca(strlen(get_var(qvars, "receipt_date")) * 2 + 1);
	mysql_real_escape_string(conn, receipt_date, get_var(
					qvars, "receipt_date"), strlen(
					get_var(qvars, "receipt_date")));

	department = alloca(strlen(get_var(qvars, "department")) * 2 + 1);
	mysql_real_escape_string(conn, department, get_var(
					qvars, "department"), strlen(
					get_var(qvars, "department")));

	employee_number = alloca(strlen(get_var(
					qvars, "employee_number")) * 2 + 1);
	mysql_real_escape_string(conn, employee_number, get_var(
					qvars, "employee_number"), strlen(
					get_var(qvars, "employee_number")));

	reason = alloca(strlen(get_var(qvars, "reason")) * 2 + 1);
	mysql_real_escape_string(conn, reason, get_var(
					qvars, "reason"), strlen(
					get_var(qvars, "reason")));

	po_num = alloca(strlen(get_var(qvars, "po_num")) * 2 + 1);
	mysql_real_escape_string(conn, po_num, get_var(
					qvars, "po_num"), strlen(
					get_var(qvars, "po_num")));

	cost_codes = alloca(strlen(get_var(qvars, "cost_codes")) * 2 + 1);
        mysql_real_escape_string(conn, cost_codes, get_var(
                                        qvars, "cost_codes"), strlen(
                                        get_var(qvars, "cost_codes")));

        account_codes = alloca(strlen(get_var(
					qvars, "account_codes")) * 2 + 1);
        mysql_real_escape_string(conn, account_codes, get_var(
                                        qvars, "account_codes"), strlen(
                                        get_var(qvars, "account_codes")));

	supplier_name = alloca(strlen(get_var(
					qvars, "supplier_name")) * 2 + 1);
	mysql_real_escape_string(conn, supplier_name, get_var(
					qvars, "supplier_name"), strlen(
					get_var(qvars, "supplier_name")));

	supplier_town = alloca(strlen(get_var(
					qvars, "supplier_town")) * 2 + 1);
	mysql_real_escape_string(conn, supplier_town, get_var(
					qvars, "supplier_town"), strlen(
					get_var(qvars, "supplier_town")));

	vat_number = alloca(strlen(get_var(qvars, "vat_number")) * 2 + 1);
	mysql_real_escape_string(conn, vat_number, get_var(
					qvars, "vat_number"), strlen(
					get_var(qvars, "vat_number")));

	gross_amount = alloca(strlen(get_var(qvars, "gross_amount")) * 2 + 1);
	mysql_real_escape_string(conn, gross_amount, get_var(
					qvars, "gross_amount"), strlen(
					get_var(qvars, "gross_amount")));

	net_amount = alloca(strlen(get_var(qvars, "net_amount")) * 2 + 1);
	mysql_real_escape_string(conn, net_amount, get_var(
					qvars, "net_amount"), strlen(
					get_var(qvars, "net_amount")));

	vat_amount = alloca(strlen(get_var(qvars, "vat_amount")) * 2 + 1);
	mysql_real_escape_string(conn, vat_amount, get_var(
					qvars, "vat_amount"), strlen(
					get_var(qvars, "vat_amount")));

	vat_rate = alloca(strlen(get_var(qvars, "vat_rate")) * 2 + 1);
	mysql_real_escape_string(conn, vat_rate, get_var(
					qvars, "vat_rate"), strlen(
					get_var(qvars, "vat_rate")));

	currency = alloca(strlen(get_var(qvars, "currency")) * 2 + 1);
	mysql_real_escape_string(conn, currency, get_var(
					qvars, "currency"), strlen(
					get_var(qvars, "currency")));

	payment_method = alloca(strlen(get_var(qvars, "payment_method"))
								* 2 + 1);
	mysql_real_escape_string(conn, payment_method, get_var(
					qvars, "payment_method"), strlen(
					get_var(qvars, "payment_method")));

	snprintf(sql, SQL_MAX, "REPLACE INTO field_names VALUES ('%s', '%s', "
					"'%s', '%s', '%s', '%s', '%s', "
					"'%s', '%s', '%s', '%s', '%s', "
					"'%s', '%s', '%s', '%s', '%s')",
					username, receipt_date, department,
					employee_number, reason, po_num,
					cost_codes, account_codes,
					supplier_name, supplier_town,
					vat_number, gross_amount, net_amount,
					vat_amount, vat_rate, currency,
					payment_method);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));

	free_vars(qvars);
	mysql_close(conn);
}

/*
 * Get the users custom image tag field names for display.
 */
static void set_custom_field_names(struct session *current_session,
						struct field_names *fields)
{
	char sql[SQL_MAX];
	char *username;
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;

	conn = db_conn();
	username = alloca(strlen(current_session->username) * 2 + 1);
	mysql_real_escape_string(conn, username, current_session->username,
					strlen(current_session->username));
	snprintf(sql, SQL_MAX, "SELECT * FROM field_names WHERE username = "
							"'%s'", username);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) < 1)
		goto out;

	row = mysql_fetch_row(res);

	if (strlen(row[1]) > 0)
		fields->receipt_date = row[1];

	if (strlen(row[2]) > 0)
		fields->department = row[2];

	if (strlen(row[3]) > 0)
		fields->employee_number = row[3];

	if (strlen(row[4]) > 0)
		fields->reason = row[4];

	if (strlen(row[5]) > 0)
		fields->po_num = row[5];

	if (strlen(row[6]) > 0)
		fields->cost_codes = row[6];

	if (strlen(row[7]) > 0)
		fields->account_codes = row[7];

	if (strlen(row[8]) > 0)
		fields->supplier_name = row[8];

	if (strlen(row[9]) > 0)
		fields->supplier_town = row[9];

	if (strlen(row[10]) > 0)
		fields->vat_number = row[10];

	if (strlen(row[11]) > 0)
		fields->gross_amount = row[11];

	if (strlen(row[12]) > 0)
		fields->net_amount = row[12];

	if (strlen(row[13]) > 0)
		fields->vat_amount = row[13];

	if (strlen(row[14]) > 0)
		fields->vat_rate = row[14];

	if (strlen(row[15]) > 0)
		fields->currency = row[15];

	if (strlen(row[16]) > 0)
		fields->payment_method = row[16];

out:
	mysql_free_result(res);
	mysql_close(conn);
}

/*
 * Create a hash table of field name=value pairs for a mysql row result set.
 */
static GHashTable *get_dbrow(MYSQL_RES *res)
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
 * Create a hash table of name=value pairs, generated from GET and POST
 * data.
 */
static GHashTable *get_vars(char *query)
{
	int i;
	int j = 0;
	int str_len;
	char buf[255];
	char key[255];
	char *val;
	GHashTable *query_values;

	query_values = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);

	memset(buf, 0, 255);
	str_len = strlen(query);
	for (i = 0; i <= str_len; i++) {
		if (query[i] == '=') {
			strcpy(key, buf);
			memset(buf, 0, 255);
			j = 0;
		} else if (query[i] == '&' || query[i] == '\0') {
			val = url_decode(buf);
			d_fprintf(debug_log, "Adding key: %s with value: %s "
						"to hash table\n", key, val);
			g_hash_table_replace(query_values, g_strdup(key),
								g_strdup(val));
			memset(buf, 0, 255);
			free(val);
			j = 0;
		} else {
			buf[j++] = query[i];
		}
	}

	return query_values;
}

/*
 * Given a key name, return its value from the given hash table.
 */
static char *get_var(GHashTable *vars, char *key)
{
	char *val;

	val = g_hash_table_lookup(vars, key);
	if (!val) {
		fprintf(error_log, "Unknown var: %s\n", key);
		return "\0";
	}

	return val;
}

/*
 * Free's the given hash table.
 */
static void free_vars(GHashTable *vars)
{
	if (vars != NULL)
		g_hash_table_destroy(vars);
}

/*
 * Sets up the current_session structure. This contains various bits of
 * information pertaining to the users session.
 */
static void set_current_session(struct session *current_session, char *cookies,
							char *request_uri)
{
	sqlite3 *db;
	char sql[SQL_MAX];
	char session_id[65];
	char **results;
	int rows;
	int columns;

	/*
	 * Don't assume the order we get the cookies back is the
	 * same order as we sent them.
	 */
        if (strncmp(cookies, "session_id", 10) == 0)
                strncpy(session_id, cookies + 11, 64);
        else
                strncpy(session_id, cookies + 88, 64);

	session_id[64] = '\0';

	sqlite3_open(SESSION_DB, &db);
	snprintf(sql, SQL_MAX, "SELECT * FROM sessions WHERE session_id = "
							"'%s'", session_id);
	sqlite3_get_table(db, sql, &results, &rows, &columns, NULL);

	current_session->uid = atoi(results[columns + 0]);
	current_session->username = strdup(results[columns + 1]);
	current_session->name = strdup(results[columns + 2]);
	current_session->u_email = strdup(results[columns + 3]);
	current_session->login_at = atol(results[columns + 4]);
	current_session->last_seen = time(NULL);
	current_session->origin_ip = strdup(results[columns + 6]);
	current_session->client_id = strdup(results[columns + 7]);
	current_session->request_id = create_session_id();
	current_session->session_id = strdup(results[columns + 9]);
	current_session->restrict_ip = atoi(results[columns + 10]);

	snprintf(sql, SQL_MAX, "UPDATE sessions SET request_id = '%s', "
						"last_seen = '%ld' WHERE "
						"session_id = '%s'",
						current_session->request_id,
						current_session->last_seen,
						session_id);
	sqlite3_exec(db, sql, NULL, NULL, NULL);
	/*
	 * OK, don't know why but without this some of the above sql
	 * leaks into stdin. Seen on /prefs/fmap/ POST data.
	 */
	memset(sql, 0, SQL_MAX);

	/* See the comment in is_logged_in() about the below */
#if 0
	d_fprintf(debug_log, "Sending cookie for next request: %s\n",
						current_session->request_id);
	printf("Set-Cookie: request_id=deleted; "
				"expires=Thu, 01-Jan-1970 00:00:01 GMT; "
				"path=/; httponly\r\n");
	printf("Set-Cookie: request_id=%s; path=/; httponly\r\n",
						current_session->request_id);
#endif
	sqlite3_free_table(results);
	sqlite3_close(db);
}

/*
 * Generate a session_id used to identify a users session.
 * It generates a SHA-256 from random dara.
 */
static char *create_session_id()
{
	int fd;
	int i;
	int hbs;
	char buf[1024];
	char shash[65];
	unsigned char *hash;
	char ht[3];
	MHASH td;

	fd = open("/dev/urandom", O_RDONLY);
	read(fd, buf, 1024);
	close(fd);

	td = mhash_init(MHASH_SHA256);
	mhash(td, &buf, 1024);
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
 * Create a new user session. This is done upon each successful login.
 */
static void create_session(GHashTable *credentials, char *http_user_agent,
						char *http_x_forwarded_for)
{
	char *request_id;
	char *session_id;
	int restrict_ip = 0;
	char sql[SQL_MAX];
	char *username;
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;
	sqlite3 *db;

	conn = db_conn();

	username = alloca(strlen(get_var(credentials, "username")) * 2 + 1);
	mysql_real_escape_string(conn, username, get_var(
						credentials, "username"),
						strlen(get_var(credentials,
						"username")));
	snprintf(sql, SQL_MAX, "SELECT uid, name, u_email FROM passwd WHERE "
						"username = '%s'", username);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);

	request_id = create_session_id();
	session_id = create_session_id();

	if (strcmp(get_var(credentials, "restrict_ip"), "true") == 0) {
		d_fprintf(debug_log, "Restricting session to origin ip "
								"address\n");
		restrict_ip = 1;
	}

	sqlite3_open(SESSION_DB, &db);
	snprintf(sql, SQL_MAX, "INSERT INTO sessions VALUES (%d, '%s', '%s', "
					"'%s', %ld, %d, '%s', '%s', '%s', "
					"'%s', %d)",
					atoi(row[0]),
					get_var(credentials, "username"),
					row[1], row[2], (long)time(NULL), 0,
					http_x_forwarded_for,
					http_user_agent,
					request_id, session_id, restrict_ip);
	sqlite3_exec(db, sql, NULL, NULL, NULL);
	sqlite3_close(db);

	printf("Set-Cookie: session_id=%s; path=/; httponly\r\n", session_id);
	printf("Set-Cookie: request_id=%s; path=/; httponly\r\n", request_id);

	mysql_close(conn);
	mysql_free_result(res);
	free(request_id);
	free(session_id);
}

/*
 * This checks if a user is currently logged in. It is called at the start
 * of each request.
 *
 * There are upto four checks performed:
 *
 * 1) The session_id cookie from the browser is checked with the stored
 *    session_id generated at login.
 * 2) The client_id from the browser (currently the user agent string) is
 *    checked against the stored client_id.
 * 3) The request_id cookie from the browser is checked with the stored
 *    request_id, generated per request.
 *
 * 4) Optionally (enabled by default on the login screen) a check is made
 *    on the requesting ip address against the stored origin_ip that was
 *    used at login.
 *
 * If any of these checks fail, the request is denined and the user is
 * punted to the login screen.
 */
static int is_logged_in(char *cookies, char *client_id, char *remote_ip,
							char *request_uri)
{
	char sql[SQL_MAX];
	char session_id[65];
	char request_id[65];
	sqlite3 *db;
	char **results;
	int rows;
	int columns;
	int ret = 0;

	if (!cookies)
		goto out2;

	/*
	 * Don't assume the order we get the cookies back is the
	 * same order as we sent them.
	 */
	if (strncmp(cookies, "session_id", 10) == 0) {
		strncpy(session_id, cookies + 11, 64);
		strncpy(request_id, cookies + 88, 64);
	} else {
		strncpy(request_id, cookies + 11, 64);
		strncpy(session_id, cookies + 88, 64);
	}
	session_id[64] = '\0';
	request_id[64] = '\0';

	sqlite3_open(SESSION_DB, &db);
	snprintf(sql, SQL_MAX, "SELECT * FROM sessions WHERE session_id = "
							"'%s'", session_id);
	sqlite3_get_table(db, sql, &results, &rows, &columns, NULL);
	if (rows == 0)
		goto out;

	/* restrict_ip */
	if (atoi(results[columns + 10]) == 1) {
		/* origin_ip */
		if (strcmp(results[columns + 6], remote_ip) != 0)
			goto out;
	}
	/* client_id */
	if (strcmp(results[columns + 7], client_id) != 0)
		goto out;
	/*
	 * Skip the request_id check for now. It seems that often the
	 * browser will not store the new cookie before sending a
	 * request with the old one.
	 */
	ret = 1;
	goto out;

	d_fprintf(debug_log, "request_id (b) %s\n", request_id);
	d_fprintf(debug_log, "request_id (d) %s\n", results[columns + 8]);
	/* request_id */
	if (strcmp(results[columns + 8], request_id) == 0) {
		ret = 1;
		goto out;
	}
out:
	sqlite3_close(db);
	sqlite3_free_table(results);
out2:
	return ret;
}

/*
 * Authenticates the user. Takes their password, crypt()'s it using
 * the salt from their password entry and compares the result with
 * their stored password.
 */
static int check_auth(GHashTable *credentials)
{
	int ret = -1;
	char sql[SQL_MAX];
	char *username;
	char *enc_passwd;
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;

	conn = db_conn();
	username = alloca(strlen(get_var(credentials, "username")) * 2 + 1);
	mysql_real_escape_string(conn, username, get_var(
						credentials, "username"),
						strlen(get_var(credentials,
						"username")));
	snprintf(sql, SQL_MAX, "SELECT password FROM passwd WHERE username "
							"= '%s'", username);
	mysql_real_query(conn, sql, strlen(sql));
	d_fprintf(sql_log, "%s\n", sql);
	res = mysql_store_result(conn);

	if (mysql_num_rows(res) < 1)
		goto out;

	row = mysql_fetch_row(res);

	enc_passwd = crypt(get_var(credentials, "password"), row[0]);
	if (strcmp(enc_passwd, row[0]) == 0)
		ret = 0;

out:
	mysql_free_result(res);
	mysql_close(conn);

	return ret;
}

/*
 * Takes the form data from /receipts/ and enters it into the database
 */
static void tag_image(struct session *current_session, char *query)
{
	char sql[SQL_MAX];
	char *image_id;
	char *username;
	char *employee_number;
	char *department;
	char *po_num;
	char *cost_codes;
	char *account_codes;
	char *supplier_town;
	char *supplier_name;
	char *currency;
	char *gross_amount;
	char *vat_amount;
	char *net_amount;
	char *vat_rate;
	char *vat_number;
	char *reason;
	char *payment_method;
	struct tm tm;
	char secs[11];
	MYSQL *conn;
	MYSQL_RES *res;
	GHashTable *qvars = NULL;

	qvars = get_vars(query);

	/* Prevent users from tagging other users receipts */
	if (!tag_info_allowed(current_session, get_var(qvars, "image_id")))
		goto out2;

	conn = db_conn();
	image_id = alloca(strlen(get_var(qvars, "image_id")) * 2 + 1);
	mysql_real_escape_string(conn, image_id, get_var(qvars, "image_id"),
					strlen(get_var(qvars, "image_id")));
	/*
	 * Prevent images from being tagged multiple times.
	 * Perhaps due to re-POSTing.
	 */
	snprintf(sql, SQL_MAX, "SELECT id FROM tags WHERE id = '%s'",
								image_id);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) > 0)
		goto out;

	username = alloca(strlen(current_session->username) * 2 + 1);
	mysql_real_escape_string(conn, username, current_session->username,
					strlen(current_session->username));

	employee_number = alloca(strlen(get_var(qvars,
					"employee_number")) * 2 + 1);
	mysql_real_escape_string(conn, employee_number, get_var(
					qvars, "employee_number"), strlen(
					get_var(qvars, "employee_number")));

	department = alloca(strlen(get_var(qvars, "department")) * 2 + 1);
	mysql_real_escape_string(conn, department, get_var(
					qvars, "department"), strlen(
					get_var(qvars, "department")));

	po_num = alloca(strlen(get_var(qvars, "po_num")) * 2 + 1);
	mysql_real_escape_string(conn, po_num, get_var(
					qvars, "po_num"), strlen(
					get_var(qvars, "po_num")));

	cost_codes = alloca(strlen(get_var(qvars, "cost_codes")) * 2 + 1);
	mysql_real_escape_string(conn, cost_codes, get_var(
					qvars, "cost_codes"), strlen(
					get_var(qvars, "cost_codes")));

	account_codes = alloca(strlen(get_var(qvars,
					"account_codes")) * 2 + 1);
	mysql_real_escape_string(conn, account_codes, get_var(
					qvars, "account_codes"), strlen(
					get_var(qvars, "account_codes")));

	supplier_town = alloca(strlen(get_var(qvars,
					"supplier_town")) * 2 + 1);
	mysql_real_escape_string(conn, supplier_town, get_var(
					qvars, "supplier_town"), strlen(
					get_var(qvars, "supplier_town")));

	supplier_name = alloca(strlen(get_var(qvars,
					"supplier_name")) * 2 + 1);
	mysql_real_escape_string(conn, supplier_name, get_var(
					qvars, "supplier_name"), strlen(
					get_var(qvars, "supplier_name")));

	currency = alloca(strlen(get_var(qvars, "currency")) * 2 + 1);
	mysql_real_escape_string(conn, currency, get_var(
					qvars, "currency"), strlen(
					get_var(qvars, "currency")));

	gross_amount = alloca(strlen(get_var(qvars, "gross_amount")) * 2 + 1);
	mysql_real_escape_string(conn, gross_amount, get_var(
					qvars, "gross_amount"), strlen(
					get_var(qvars, "gross_amount")));

	vat_amount = alloca(strlen(get_var(qvars, "vat_amount")) * 2 + 1);
	mysql_real_escape_string(conn, vat_amount, get_var(
					qvars, "vat_amount"), strlen(
					get_var(qvars, "vat_amount")));

	net_amount = alloca(strlen(get_var(qvars, "net_amount")) * 2 + 1);
	mysql_real_escape_string(conn, net_amount, get_var(
					qvars, "net_amount"), strlen(
					get_var(qvars, "net_amount")));

	vat_rate = alloca(strlen(get_var(qvars, "vat_rate")) * 2 + 1);
	mysql_real_escape_string(conn, vat_rate, get_var(
					qvars, "vat_rate"), strlen(
					get_var(qvars, "vat_rate")));

	vat_number = alloca(strlen(get_var(qvars, "vat_number")) * 2 + 1);
	mysql_real_escape_string(conn, vat_number, get_var(
					qvars, "vat_number"), strlen(
					get_var(qvars, "vat_number")));

	reason = alloca(strlen(get_var(qvars, "reason")) * 2 + 1);
	mysql_real_escape_string(conn, reason, get_var(
					qvars, "reason"), strlen(
					get_var(qvars, "reason")));

	memset(&tm, 0, sizeof(tm));
	strptime(get_var(qvars, "receipt_date"), "%Y-%m-%d", &tm);
	strftime(secs, sizeof(secs), "%s", &tm);

	payment_method = alloca(strlen(get_var(qvars, "payment_method"))
								* 2 + 1);
	mysql_real_escape_string(conn, payment_method, get_var(
					qvars, "payment_method"), strlen(
					get_var(qvars, "payment_method")));

	snprintf(sql, SQL_MAX, "INSERT INTO tags VALUES ('%s', '%s', %ld, "
				"'%s', '%s', '%s', '%s', '%s', '%s', '%s', "
				"'%s', %.2f, %.2f, %.2f, %.2f, '%s', %ld, "
				"'%s', '%s')",
				image_id, username, time(NULL),
				employee_number, department, po_num,
				cost_codes, account_codes, supplier_town,
				supplier_name, currency,
				strtof(gross_amount, NULL),
				strtof(vat_amount, NULL),
				strtof(net_amount, NULL),
				strtof(vat_rate, NULL),
				vat_number, atol(secs), reason,
				payment_method);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));

	snprintf(sql, SQL_MAX, "UPDATE images SET processed = 1 WHERE id "
							"= '%s'", image_id);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_query(conn, sql);

out:
	mysql_free_result(res);
	mysql_close(conn);
out2:
	free_vars(qvars);
}

/*
 * Checks the users permission to access receipt tag information.
 */
static int tag_info_allowed(struct session *current_session, char *image_id)
{
	char sql[SQL_MAX];
	char *s_image_id;
	char *u_email;
	int ret = 0;
	MYSQL *conn;
	MYSQL_RES *res;

	conn = db_conn();

	s_image_id = alloca(strlen(image_id) * 2 + 1);
	mysql_real_escape_string(conn, s_image_id, image_id, strlen(image_id));

	u_email = alloca(strlen(current_session->u_email) * 2 + 1);
	mysql_real_escape_string(conn, u_email, current_session->u_email,
					strlen(current_session->u_email));

	snprintf(sql, SQL_MAX, "SELECT path FROM images WHERE id = '%s' AND "
					"who = '%s'", s_image_id, u_email);

	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) > 0)
		ret = 1;

	mysql_free_result(res);
	mysql_close(conn);

	return ret;
}

/*
 * Determine if access to an image is allowed. It checks the u_email against
 * the start of the image path after IMAGE_PATH/.
 */
static int image_access_allowed(struct session *current_session, char *path)
{
	int ret = 0;

	if (strncmp(path + strlen(IMAGE_PATH) + 1, current_session->u_email,
				strlen(current_session->u_email)) == 0)
		ret = 1;

	return ret;
}

/*
 * /login/
 *
 * HTML is in templates/login.tmpl
 *
 * Display the login screen.
 */
static void login(char *http_user_agent, char *http_x_forwarded_for)
{
	int ret = 1;
	char buf[80] = "\0";
	TMPL_varlist *vl = NULL;

	fread(buf, sizeof(buf) - 1, 1, stdin);
	if (strstr(buf, "=") && strstr(buf, "&")) {
		GHashTable *credentials;

		credentials = get_vars(buf);
		ret = check_auth(credentials);
		if (ret == 0) {
			create_session(credentials, http_user_agent,
					http_x_forwarded_for);

			printf("Location: http://ri.opentechlabs.net/receipts/"
								"\r\n\r\n");
		}
		free_vars(credentials);
	}

	if (ret == -1)
		vl = TMPL_add_var(0, "logged_in", "no", NULL);

	printf("Content-Type: text/html\r\n\r\n");
	TMPL_write("templates/login.tmpl", NULL, NULL, vl, stdout, error_log);
	TMPL_free_varlist(vl);
}

/*
 * /logout/
 *
 * HTML is in templates/logout.tmpl
 *
 * Clean up a users session. Remove thier entry from the sessions db and
 * set the session_id browser cookie to expired.
 */
static void logout(struct session *current_session)
{
	char sql[SQL_MAX];
	sqlite3 *db;

	snprintf(sql, SQL_MAX, "DELETE FROM sessions WHERE session_id = '%s'",
						current_session->session_id);
	sqlite3_open(SESSION_DB, &db);
	sqlite3_exec(db, sql, NULL, NULL, NULL);
	sqlite3_close(db);

	/* Immediately expire the session cookies */
	printf("Set-Cookie: session_id=deleted; "
				"expires=Thu, 01-Jan-1970 00:00:01 GMT; "
				"path=/; httponly\r\n");
	printf("Set-Cookie: request_id=deleted; "
				"expires=Thu, 01-Jan-1970 00:00:01 GMT; "
				"path=/; httponly\r\n");
	printf("Content-Type: text/html\r\n\r\n");
	TMPL_write("templates/logout.tmpl", NULL, NULL, NULL, stdout,
								error_log);
}

/*
 * /get_image/
 *
 * As the images aren't stored under the control of the webserver (don't
 * want users seeing other users receipts). The application needs to get
 * the image and send it through to the client.
 */
static void get_image(struct session *current_session, char *image)
{
	int fd;
	ssize_t bytes_read = 1;
	char buf[BUF_SIZE];
	char path[PATH_MAX];
	char image_path[PATH_MAX];
	struct stat sb;
	magic_t cookie;
	const char *mime_type;

	snprintf(path, PATH_MAX, "%s/%s", IMAGE_PATH, image + 11);
	realpath(path, image_path);

	/* Don't let users access other user images */
	if (!image_access_allowed(current_session, image_path)) {
		printf("Status: 401 Unauthorized\r\n\r\n");
		d_fprintf(access_log, "Access denied to %s for %s\n", image,
						current_session->username);
		return;
	}

	fd = open(image_path, O_RDONLY);
	fstat(fd, &sb);

	cookie = magic_open(MAGIC_MIME);
	magic_load(cookie, "/usr/share/file/magic");
	mime_type = magic_file(cookie, image_path);

	printf("Cache-Control: private\r\n");
	printf("Content-Type: %s\r\n", mime_type);
	printf("Content-Length: %ld\n\n", sb.st_size);
	d_fprintf(access_log, "Sending image: %s\n", image);

	while (bytes_read > 0) {
		bytes_read = read(fd, &buf, BUF_SIZE);
		fwrite(buf, bytes_read, 1, stdout);
	}
	magic_close(cookie);
	close(fd);
}

/*
 * /full_image/
 *
 * Allows the user to download the image to view at full size outside
 * the browser.
 */
static void full_image(struct session *current_session, char *image)
{
	int fd;
	ssize_t bytes_read = 1;
	char buf[BUF_SIZE];
	char path[PATH_MAX];
	char image_path[PATH_MAX];
	struct stat sb;

	snprintf(path, PATH_MAX, "%s/%s", IMAGE_PATH, image + 12);
	realpath(path, image_path);

	/* Don't let users access other user images */
	if (!image_access_allowed(current_session, image_path)) {
		printf("Status: 401 Unauthorized\r\n\r\n");
		d_fprintf(access_log, "Access denied to %s for %s\n", image,
						current_session->username);
		return;
	}

	fd = open(image_path, O_RDONLY);
	fstat(fd, &sb);

	printf("Cache-Control: private\r\n");
	printf("Content-Type: application/download\r\n");
	printf("Content-Transfer-Encoding: binary\r\n");
	printf("Content-Length: %ld\r\n", sb.st_size);
	printf("Content-Disposition: filename = %s\r\n\r\n", image + 12);

	while (bytes_read > 0) {
		bytes_read = read(fd, &buf, BUF_SIZE);
		fwrite(buf, bytes_read, 1, stdout);
	}
	close(fd);
}

/*
 * /prefs/fmap/
 *
 * HTML is in templates/prefs_fmap.tmpl
 *
 * Change the image tag field names.
 */
static void prefs_fmap(struct session *current_session)
{
	char buf[SQL_MAX];
	struct field_names fields;
	TMPL_varlist *vl = NULL;

	fread(buf, SQL_MAX - 1, 1, stdin);
	if (strstr(buf, "=") && strstr(buf, "&"))
		update_fmap(current_session, buf);

	vl = TMPL_add_var(vl, "name", current_session->name, NULL);

	fields = field_names;
	set_custom_field_names(current_session, &fields);

	if (strlen(buf) > 1)
		vl = TMPL_add_var(vl, "fields_updated", "yes", NULL);

	vl = TMPL_add_var(vl, "receipt_date", field_names.receipt_date, NULL);
	vl = TMPL_add_var(vl, "alt_receipt_date",
					!strcmp(field_names.receipt_date,
					fields.receipt_date) ? "":
					fields.receipt_date, NULL);

	vl = TMPL_add_var(vl, "department", field_names.department, NULL);
	vl = TMPL_add_var(vl, "alt_department",
					!strcmp(field_names.department,
					fields.department) ? "" :
					fields.department, NULL);

	vl = TMPL_add_var(vl, "employee_number", field_names.employee_number,
									NULL);
	vl = TMPL_add_var(vl, "alt_employee_number",
					!strcmp(field_names.employee_number,
					fields.employee_number) ? "" :
					fields.employee_number, NULL);

	vl = TMPL_add_var(vl, "reason", field_names.reason, NULL);
	vl = TMPL_add_var(vl, "alt_reason",
					!strcmp(field_names.reason,
					fields.reason) ? "" :
					fields.reason, NULL);

	vl = TMPL_add_var(vl, "po_num", field_names.po_num, NULL);
	vl = TMPL_add_var(vl, "alt_po_num",
					!strcmp(field_names.po_num,
					fields.po_num) ? "" :
					fields.po_num, NULL);

	vl = TMPL_add_var(vl, "cost_codes", field_names.cost_codes, NULL);
	vl = TMPL_add_var(vl, "alt_cost_codes",
					!strcmp(field_names.cost_codes,
					fields.cost_codes) ? "" :
					fields.cost_codes, NULL);

	vl = TMPL_add_var(vl, "account_codes", field_names.account_codes,
								NULL);
	vl = TMPL_add_var(vl, "alt_account_codes",
					!strcmp(field_names.account_codes,
					fields.account_codes) ? "" :
					fields.account_codes, NULL);

	vl = TMPL_add_var(vl, "supplier_name", field_names.supplier_name,
								NULL);
	vl = TMPL_add_var(vl, "alt_supplier_name",
					!strcmp(field_names.supplier_name,
					fields.supplier_name) ? "" :
					fields.supplier_name, NULL);

	vl = TMPL_add_var(vl, "supplier_town", field_names.supplier_town,
									NULL);
	vl = TMPL_add_var(vl, "alt_supplier_town",
					!strcmp(field_names.supplier_town,
					fields.supplier_town) ? "" :
					fields.supplier_town, NULL);

	vl = TMPL_add_var(vl, "vat_number", field_names.vat_number, NULL);
	vl = TMPL_add_var(vl, "alt_vat_number",
					!strcmp(field_names.vat_number,
					fields.vat_number) ? "" :
					fields.vat_number, NULL);

	vl = TMPL_add_var(vl, "gross_amount", field_names.gross_amount, NULL);
	vl = TMPL_add_var(vl, "alt_gross_amount",
					!strcmp(field_names.gross_amount,
					fields.gross_amount) ? "" :
					fields.gross_amount, NULL);

	vl = TMPL_add_var(vl, "net_amount", field_names.net_amount, NULL);
	vl = TMPL_add_var(vl, "alt_net_amount",
					!strcmp(field_names.net_amount,
					fields.net_amount) ? "" :
					fields.net_amount, NULL);

	vl = TMPL_add_var(vl, "vat_amount", field_names.vat_amount, NULL);
	vl = TMPL_add_var(vl, "alt_vat_amount",
					!strcmp(field_names.vat_amount,
					fields.vat_amount) ? "" :
					fields.vat_amount, NULL);

	vl = TMPL_add_var(vl, "vat_rate", field_names.vat_rate, NULL);
	vl = TMPL_add_var(vl, "alt_vat_rate",
					!strcmp(field_names.vat_rate,
					fields.vat_rate) ? "" :
					fields.vat_rate, NULL);

	vl = TMPL_add_var(vl, "currency", field_names.currency, NULL);
	vl = TMPL_add_var(vl, "alt_currency",
					!strcmp(field_names.currency,
					fields.currency) ? "" :
					fields.currency, NULL);

	vl = TMPL_add_var(vl, "payment_method", field_names.payment_method,
									NULL);
	vl = TMPL_add_var(vl, "alt_payment_method",
					!strcmp(field_names.payment_method,
					fields.payment_method) ? "" :
					fields.payment_method, NULL);

	printf("Content-Type: text/html\r\n\r\n");
	TMPL_write("templates/prefs_fmap.tmpl", NULL, NULL, vl, stdout,
								error_log);
	TMPL_free_varlist(vl);
}

/*
 * /receipt_info/
 *
 * HTML is in templates/receipt_info.tmpl
 *
 * Displays the logged information for a given receipt.
 */
static void receipt_info(struct session *current_session, char *query)
{
	char sql[SQL_MAX];
	char tbuf[60];
	char *image_id;
	struct field_names fields;
	time_t secs;
	MYSQL *conn;
	MYSQL_RES *res;
	GHashTable *qvars = NULL;
	GHashTable *db_row = NULL;
	TMPL_varlist *vl = NULL;

	vl = TMPL_add_var(vl, "name", current_session->name, NULL);

	qvars = get_vars(query);
	if (!tag_info_allowed(current_session, get_var(qvars, "image_id"))) {
		vl = TMPL_add_var(vl, "show_info", "no", NULL);
		goto out;
	}

	conn = db_conn();

	image_id = alloca(strlen(get_var(qvars, "image_id")) * 2 + 1);
	mysql_real_escape_string(conn, image_id, get_var(qvars, "image_id"),
					strlen(get_var(qvars, "image_id")));
	snprintf(sql, SQL_MAX, "SELECT images.timestamp AS images_timestamp, "
				"images.path, images.name, tags.timestamp AS "
				"tags_timestamp, tags.employee_number, "
				"tags.department, tags.po_num, "
				"tags.cost_codes, tags.account_codes, "
				"tags.supplier_name, tags.supplier_town, "
				"tags.currency, tags.gross_amount, "
				"tags.vat_amount, tags.net_amount, "
				"tags.vat_rate, tags.vat_number, "
				"tags.receipt_date, tags.reason, "
				"tags.payment_method FROM images "
				"INNER JOIN tags ON (images.id = tags.id) "
				"WHERE images.id = '%s' LIMIT 1", image_id);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);

	if (mysql_num_rows(res) == 0) {
		vl = TMPL_add_var(vl, "show_info", "no", NULL);
		goto out;
	}

	fields = field_names;
	set_custom_field_names(current_session, &fields);
	db_row = get_dbrow(res);

	/* image url */
	vl = TMPL_add_var(vl, "image_path", get_var(db_row, "path"), NULL);
	vl = TMPL_add_var(vl, "image_name", get_var(db_row, "name"), NULL);

	/* image upload timestamp */
	secs = atol(get_var(db_row, "images_timestamp"));
	strftime(tbuf, sizeof(tbuf), "%a %b %e %H:%M %Y %z", localtime(&secs));
	vl = TMPL_add_var(vl, "images_timestamp", tbuf, NULL);

	/* image tag timestamp */
	secs = atol(get_var(db_row, "tags_timestamp"));
	strftime(tbuf, sizeof(tbuf), "%a %b %e %H:%M %Y %z", localtime(&secs));
	vl = TMPL_add_var(vl, "tags_timestamp", tbuf, NULL);

	vl = TMPL_add_var(vl, "fields.department", fields.department, NULL);
	vl = TMPL_add_var(vl, "department", get_var(db_row, "department"),
								NULL);

	vl = TMPL_add_var(vl, "fields.employee_number", fields.employee_number,
									NULL);
	vl = TMPL_add_var(vl, "employee_number", get_var(db_row,
						"employee_number"), NULL);

	vl = TMPL_add_var(vl, "fields.cost_codes", fields.cost_codes, NULL);
	vl = TMPL_add_var(vl, "cost_codes", get_var(db_row, "cost_codes"),
									NULL);

	vl = TMPL_add_var(vl, "fields.account_codes", fields.account_codes,
									NULL);
	vl = TMPL_add_var(vl, "account_codes", get_var(db_row,
						"account_codes"), NULL);

	vl = TMPL_add_var(vl, "fields.po_num", fields.po_num, NULL);
	vl = TMPL_add_var(vl, "po_num",get_var(db_row, "po_num"), NULL);

	vl = TMPL_add_var(vl, "fields.supplier_name", fields.supplier_name,
								NULL);
	vl = TMPL_add_var(vl, "supplier_name", get_var(db_row,
						"supplier_name"), NULL);

	vl = TMPL_add_var(vl, "fields.supplier_town", fields.supplier_town,
									NULL);
	vl = TMPL_add_var(vl, "supplier_town", get_var(db_row,
						"supplier_town"), NULL);

	vl = TMPL_add_var(vl, "fields.currency", fields.currency, NULL);
	vl = TMPL_add_var(vl, "currency", get_var(db_row, "currency"), NULL);

	vl = TMPL_add_var(vl, "fields.gross_amount", fields.gross_amount,
									NULL);
	vl = TMPL_add_var(vl, "gross_amount", get_var(db_row,
						"gross_amount"), NULL);

	vl = TMPL_add_var(vl, "fields.vat_amount", fields.vat_amount, NULL);
	vl = TMPL_add_var(vl, "vat_amount", get_var(db_row,
						"vat_amount"), NULL);

	vl = TMPL_add_var(vl, "fields.net_amount", fields.net_amount, NULL);
	vl = TMPL_add_var(vl, "net_amount", get_var(db_row,
						"net_amount"), NULL);

	vl = TMPL_add_var(vl, "fields.vat_rate", fields.vat_rate, NULL);
	vl = TMPL_add_var(vl, "vat_rate", get_var(db_row, "vat_rate"), NULL);

	vl = TMPL_add_var(vl, "fields.vat_number", fields.vat_number, NULL);
	vl = TMPL_add_var(vl, "vat_number", get_var(db_row,
							"vat_number"), NULL);

	vl = TMPL_add_var(vl, "fields.reason", fields.reason, NULL);
	vl = TMPL_add_var(vl, "reason", get_var(db_row, "reason"), NULL);

	vl = TMPL_add_var(vl, "fields.receipt_date", fields.receipt_date,
									NULL);
	secs = atol(get_var(db_row, "receipt_date"));
	strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
	vl = TMPL_add_var(vl, "receipt_date", tbuf, NULL);

	vl = TMPL_add_var(vl, "fields.payment_method", fields.payment_method,
									NULL);
	vl = TMPL_add_var(vl, "payment_method", get_var(db_row,
						"payment_method"), NULL);

	free_vars(db_row);

out:
	printf("Cache-Control: private\r\n");
	printf("Content-Type: text/html\r\n\r\n");
	TMPL_write("templates/receipt_info.tmpl", NULL, NULL, vl, stdout,
								error_log);
	TMPL_free_varlist(vl);
	mysql_free_result(res);
	mysql_close(conn);
	free_vars(qvars);
}

/*
 * /tagged_receipts/
 *
 * Displays a gallery of previously tagged receipts.
 */
static void tagged_receipts(struct session *current_session, char *query)
{
	int i;
	int c = 1;		/* column number */
	int from = 0;
	int page_no = 1;
	char page[10];
	int nr_rows;
	char sql[SQL_MAX];
	char *u_email;
	MYSQL *conn;
	MYSQL_RES *res;
	GHashTable *qvars = NULL;
	struct field_names fields;
	TMPL_varlist *vl = NULL;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;

	if (strlen(query) > 0) {
		qvars = get_vars(query);
		page_no = atoi(get_var(qvars, "page_no"));
		if (page_no < 1)
			page_no = 1;
		/* Determine the LIMIT offset to start from in the SQL */
		from = page_no * GRID_SIZE - GRID_SIZE;
	}

	ml = TMPL_add_var(ml, "name", current_session->name, NULL);

	conn = db_conn();
	u_email = alloca(strlen(current_session->u_email) * 2 + 1);
	mysql_real_escape_string(conn, u_email, current_session->u_email,
					strlen(current_session->u_email));
	snprintf(sql, SQL_MAX, "SELECT tags.receipt_date, images.id, "
				"images.path, images.name FROM tags "
				"INNER JOIN images ON (tags.id = images.id) "
				"WHERE images.processed = 1 AND images.who = "
				"'%s' ORDER BY tags.timestamp LIMIT %d, %d",
				u_email, from, GRID_SIZE);
	d_fprintf(sql_log, "%s\n", sql);

	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);

	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0) {
		ml = TMPL_add_var(ml, "receipts", "no", NULL);
		goto out;
	}

	fields = field_names;
	set_custom_field_names(current_session, &fields);
	ml = TMPL_add_var(ml, "receipts", "yes", NULL);
	/* Draw gallery grid */
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		time_t secs;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);

		vl = TMPL_add_var(NULL, "id", get_var(db_row, "id"), NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "image_path", get_var(db_row, "path"),
									NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "image_name", get_var(db_row, "name"),
									NULL);
		loop = TMPL_add_varlist(loop, vl);

		secs = atol(get_var(db_row, "receipt_date"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = TMPL_add_var(vl, "fields.receipt_date",
						fields.receipt_date, NULL);
                loop = TMPL_add_varlist(loop, vl);
		vl = TMPL_add_var(vl, "receipt_date", tbuf, NULL);
                loop = TMPL_add_varlist(loop, vl);

		/* We want a 3 x 3 grid */
		if (c == COL_SIZE) /* Close off row */
			vl = TMPL_add_var(vl, "close_row", "yes", NULL);
		else
			vl = TMPL_add_var(vl, "close_row", "no", NULL);
		loop = TMPL_add_varlist(loop, vl);

		if (c == COL_SIZE && i < nr_rows) { /* Start a new row */
			vl = TMPL_add_var(vl, "new_row", "yes", NULL);
			c = 0;
		} else {
			vl = TMPL_add_var(vl, "new_row", "no", NULL);
		}
		loop = TMPL_add_varlist(loop, vl);
		c++;
		free_vars(db_row);
	}
	snprintf(page, 10, "%d", page_no - 1);
	ml = TMPL_add_var(ml, "prev_page", page, NULL);
	snprintf(page, 10, "%d", page_no + 1);
        ml = TMPL_add_var(ml, "next_page", page, NULL);
	TMPL_add_varlist(loop, vl);
	ml = TMPL_add_loop(ml, "table", loop);

out:
	printf("Cache-Control: private\r\n");
	printf("Content-Type: text/html\r\n\r\n");
	TMPL_write("templates/tagged_receipts.tmpl", NULL, NULL, ml, stdout,
								error_log);
	TMPL_free_varlist(ml);
	mysql_free_result(res);
	mysql_close(conn);
	free_vars(qvars);
}

/*
 * /receipts/
 *
 * HTML is in templates/receipts.tmpl
 *
 * Main page of the application. Displays any un-tagged images and
 * a form for each to enter its data.
 */
static void receipts(struct session *current_session)
{
	int i;
	int nr_rows;
	char sql[SQL_MAX];
	char buf[SQL_MAX];
	char *u_email;
	MYSQL *conn;
	MYSQL_RES *res;
	struct field_names fields;
	TMPL_varlist *vl = NULL;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;

	fread(buf, SQL_MAX - 1, 1, stdin);
	if (strstr(buf, "=") && strstr(buf, "&"))
		tag_image(current_session, buf);

	/* Display the user's name at the top of the page */
	ml = TMPL_add_var(ml, "name", current_session->name, NULL);

	conn = db_conn();
	u_email = alloca(strlen(current_session->u_email) * 2 + 1);
	mysql_real_escape_string(conn, u_email, current_session->u_email,
					strlen(current_session->u_email));
	snprintf(sql, SQL_MAX, "SELECT id, timestamp, path, name FROM images "
						"WHERE processed = 0 AND "
						"who = '%s'", u_email);
	d_fprintf(sql_log, "%s\n", sql);

	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);

	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0) {
		ml = TMPL_add_var(ml, "receipts", "no", NULL);
		goto out;
	}

	fields = field_names;
	set_custom_field_names(current_session, &fields);
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		time_t secs;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		/*
		 * This first vl call needs a NULL entry or you only get
		 * the last receipt entry.
		 */
		vl = TMPL_add_var(NULL, "image_path", get_var(db_row, "path"),
									NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "image_name", get_var(db_row, "name"),
									NULL);
		loop = TMPL_add_varlist(loop, vl);

		secs = atol(get_var(db_row, "timestamp"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e %H:%M %Y %z",
							localtime(&secs));
		vl = TMPL_add_var(vl, "timestamp", tbuf, NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.department", fields.department,
									NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.employee_number",
						fields.employee_number, NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.cost_codes", fields.cost_codes,
									NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.account_codes",
						fields.account_codes, NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.po_num", fields.po_num, NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.supplier_name",
						fields.supplier_name, NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.supplier_town",
						fields.supplier_town, NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.currency", fields.currency,
									NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.gross_amount",
						fields.gross_amount, NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.vat_amount", fields.vat_amount,
									NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.net_amount", fields.net_amount,
									NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.vat_rate", fields.vat_rate,
									NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.vat_number", fields.vat_number,
									NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.reason", fields.reason, NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.receipt_date",
						fields.receipt_date, NULL);
		loop = TMPL_add_varlist(loop, vl);

		vl = TMPL_add_var(vl, "fields.payment_method",
						fields.payment_method, NULL);
		loop = TMPL_add_varlist(loop, vl);

		/* image_id for hidden input field */
		vl = TMPL_add_var(vl, "id", get_var(db_row, "id"), NULL);
		loop = TMPL_add_varlist(loop, vl);

		free_vars(db_row);
	}
	TMPL_add_varlist(loop, vl);
	ml = TMPL_add_loop(ml, "table", loop);

out:
	printf("Cache-Control: private\r\n");
	printf("Content-Type: text/html\r\n\r\n");
	TMPL_write("templates/receipts.tmpl", NULL, NULL, ml, stdout,
								error_log);
	TMPL_free_varlist(ml);
	mysql_free_result(res);
	mysql_close(conn);
}

/*
 * /env/
 *
 * Displays the environment list.
 */
static void env()
{
	extern char **environ;

	printf("Content-Type: text/html\r\n\r\n");
	printf("<html>\n");
	printf("<head>\n");
	printf("<link href = \"/static/css/main.css\" rel = \"stylesheet\" "
						"type = \"text/css\" />\n");
	printf("</head>\n");
	printf("<body>\n");

	for ( ; *environ != NULL; environ++)
		printf("%s<br />\n", *environ);

	printf("</body>\n");
	printf("</html>\n");
}

/*
 * Main application. This is where the requests come in and routed.
 */
static void handle_request()
{
	struct session current_session;
	int logged_in = 0;
	char *request_uri;
	char *http_cookie = "\0";	/* we might not get any cookies */
	char *http_user_agent;
	char *http_x_forwarded_for;
	char *query_string;

	request_uri = strdupa(getenv("REQUEST_URI"));;
	if (getenv("HTTP_COOKIE"))
		http_cookie = strdupa(getenv("HTTP_COOKIE"));
	http_user_agent = strdupa(getenv("HTTP_USER_AGENT"));
	http_x_forwarded_for = strdupa(getenv("HTTP_X_FORWARDED_FOR"));
	query_string = strdupa(getenv("QUERY_STRING"));

	d_fprintf(access_log, "Got request from %s for %s\n",
							http_x_forwarded_for,
							request_uri);
	d_fprintf(debug_log, "Cookies: %s\n", http_cookie);

	memset(&current_session, 0, sizeof(current_session));
	if (strstr(request_uri, "/login/")) {
		login(http_user_agent, http_x_forwarded_for);
		goto out;
	}

	logged_in = is_logged_in(http_cookie, http_user_agent,
							http_x_forwarded_for,
							request_uri);
	if (!logged_in) {
		printf("Location: http://ri.opentechlabs.net/login/\r\n\r\n");
		goto out;
	}
	set_current_session(&current_session, http_cookie, request_uri);

	if (strstr(request_uri, "/receipts/")) {
		receipts(&current_session);
		goto out;
	}

	if (strstr(request_uri, "/tagged_receipts/")) {
		tagged_receipts(&current_session, query_string);
		goto out;
	}

	if (strstr(request_uri, "/receipt_info/")) {
		receipt_info(&current_session, query_string);
		goto out;
	}

	if (strstr(request_uri, "/get_image/")) {
		get_image(&current_session, request_uri);
		goto out;
	}

	if (strstr(request_uri, "/full_image/")) {
		full_image(&current_session, request_uri);
		goto out;
	}

	if (strstr(request_uri, "/env/")) {
		env();
		goto out;
	}

	if (strstr(request_uri, "/prefs/fmap/")) {
		prefs_fmap(&current_session);
		goto out;
	}

	if (strstr(request_uri, "/logout/")) {
		logout(&current_session);
		goto out;
	}

	/* Default location */
	printf("Location: http://ri.opentechlabs.net/login/\r\n\r\n");

out:
	free(current_session.username);
	free(current_session.name);
	free(current_session.u_email);
	free(current_session.origin_ip);
	free(current_session.client_id);
	free(current_session.request_id);
	free(current_session.session_id);
}

/*
 * Main program loop. This sits in accept() waiting for connections.
 */
static void accept_request()
{
	/*
	 * We use SIGUSR1 to dump the session state which we only want
	 * handled by the parent process. Ignore it in the children.
	 */
	signal(SIGUSR1, SIG_IGN);
	/*
	 * We use SIGRTMIN to clear out old sessions. This signal is
	 * produced by a timer. We only want this signal handled in the
	 * parent so ignore it in the children.
	 */
	signal(SIGRTMIN, SIG_IGN);

	while (FCGI_Accept() >= 0) {
		handle_request();
		FCGI_Finish();
	}

	/* If we get here, something went wrong */
	_exit(EXIT_FAILURE);
}

/*
 * Create nr server processes.
 */
static void create_server(int nr)
{
	int i;
	pid_t pid;

	for (i = 0; i < nr; i++) {
		pid = fork();
		if (pid == 0)   /* child */
			accept_request();
	}
}

/*
 * Callback function called from dump_session_state()
 */
static int __dump_session_state(void *arg, int argc, char **argv, char **column)
{
	fprintf(debug_log, "\tuid         : %s\n", argv[0]);
	fprintf(debug_log, "\tusername    : %s\n", argv[1]);
	fprintf(debug_log, "\tname        : %s\n", argv[2]);
	fprintf(debug_log, "\tu_email     : %s\n", argv[3]);
	fprintf(debug_log, "\tlogin_at    : %s\n", argv[4]);
	fprintf(debug_log, "\tlast_seen   : %s\n", argv[5]);
	fprintf(debug_log, "\torigin_ip   : %s\n", argv[6]);
	fprintf(debug_log, "\tclient_id   : %s\n", argv[7]);
	fprintf(debug_log, "\trequest_id  : %s\n", argv[8]);
	fprintf(debug_log, "\tsession_id  : %s\n", argv[9]);
	fprintf(debug_log, "\trestrict_ip : %s\n\n", argv[10]);

	return 0;
}

/*
 * Dumps session state upon receiving a SIGUSR1
 */
static void dump_session_state()
{
	sqlite3 *db;

	sqlite3_open(SESSION_DB, &db);
	sqlite3_exec(db, "SELECT * FROM sessions", __dump_session_state,
								NULL, NULL);
	sqlite3_close(db);
	fflush(debug_log);
}

/*
 * Clear out old sessions that haven't been accessed (last_seen) since
 * SESSION_EXPIRY ago.
 */
static void clear_old_sessions()
{
	sqlite3 *db;
	char sql[SQL_MAX];
	time_t now;

	d_fprintf(debug_log, "Clearing old sessions\n");

	now = time(NULL);
	snprintf(sql, SQL_MAX, "DELETE FROM sessions WHERE last_seen < %ld",
							now - SESSION_EXPIRY);
	sqlite3_open(SESSION_DB, &db);
	sqlite3_exec(db, sql, NULL, NULL, NULL);
	sqlite3_close(db);
}

/*
 * Sets up a timer to clear old sessions. Fires every SESSION_CHECK seconds.
 */
static void init_clear_session_timer()
{
	timer_t timerid;
	struct sigevent sev;
	struct itimerspec its;
	struct sigaction action;

	memset(&action, 0, sizeof(&action));
	action.sa_flags = SA_RESTART;
	action.sa_sigaction = clear_old_sessions;
	sigemptyset(&action.sa_mask);
	sigaction(SIGRTMIN, &action, NULL);

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGRTMIN;
	sev.sigev_value.sival_ptr = &timerid;
	timer_create(CLOCK_REALTIME, &sev, &timerid);

	its.it_value.tv_sec = SESSION_CHECK;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	timer_settime(timerid, 0, &its, NULL);
}

/*
 * Sets up the sessions database. If it doesn't exist, it creates it.
 */
static void initialise_session_db()
{
	char sql[SQL_MAX];
	sqlite3 *db;

	sqlite3_open(SESSION_DB, &db);
	snprintf(sql, SQL_MAX, "CREATE TABLE IF NOT EXISTS sessions ("
						"uid INTEGER, "
						"username VARCHAR(255), "
						"name VARCHAR(255), "
						"u_email VARCHAR(255), "
						"login_at INTEGER, "
						"last_seen INTEGER, "
						"origin_ip VARCHAR(64), "
						"client_id VARCHAR(255), "
						"request_id VARCHAR(64), "
						"session_id VARCHAR(64), "
						"restrict_ip INTEGER)");
	sqlite3_exec(db, sql, NULL, NULL, NULL);
	sqlite3_close(db);
}

int main(int argc, char *argv[])
{
	struct sigaction action;
	int status;

	mysql_library_init(0, NULL, NULL);

	access_log = fopen("/tmp/receiptomatic-www.access.log", "w");
	error_log = fopen("/tmp/receiptomatic-www.error.log", "w");
	sql_log = fopen("/tmp/receiptomatic-www.sql.log", "w");
	debug_log = fopen("/tmp/receiptomatic-www.debug.log", "w");

	/* Setup signal handler for USR1 to dump session state */
	memset(&action, 0, sizeof(&action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = dump_session_state;
	action.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &action, NULL);

	initialise_session_db();
	init_clear_session_timer();

	/* Pre-fork NR_PROCS processes */
	create_server(NR_PROCS);

	for (;;) {
		waitpid(-1, &status, 0);
		/*
		 * If a process dies, create a new one.
		 *
		 * However, don't create new processes if we get a
		 * SIGTERM or SIGKILL signal as that will stop the
		 * thing from being shutdown.
		 */
		if (WIFSIGNALED(status) && (WTERMSIG(status) != SIGTERM &&
						WTERMSIG(status) != SIGKILL))
			create_server(1);
	}

	mysql_library_end();
	fclose(access_log);
	fclose(error_log);
	fclose(sql_log);
	fclose(debug_log);

	exit(EXIT_SUCCESS);
}
