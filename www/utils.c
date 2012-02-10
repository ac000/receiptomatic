/*
 * utils.c
 *
 * Copyright (C) 2011-2012	OpenTech Labs
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

#include <gmime/gmime.h>

#include <mhash.h>

#include "common.h"
#include "utils.h"

/* Structure to hold information about uploaded files via POST */
struct file_info {
	char *orig_file_name;
	char *temp_file_name;
	char *name;
	char *mime_type;
} file_info;
struct file_info file_info;

/* Linked list to store file_info structures. */
GList *u_files;
/*
 * Linked list to hold hash tables of name=value pairs of POST array
 * variables.
 */
GList *avars;
/* Hash table to hold name=value pairs of POST/GET variables. */
GHashTable *qvars;

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
 * Free's the avars GList
 */
void free_avars(void)
{
	GHashTable *query_vars;
	unsigned int i;
	unsigned int size;

	size = g_list_length(avars);
	for (i = 0; i < size; i++) {
		query_vars = g_list_nth_data(avars, i);
		g_hash_table_destroy(query_vars);
	}
	g_list_free(avars);
}

/*
 * Free's the given GHashTable
 */
void free_vars(GHashTable *vars)
{
	if (vars != NULL)
		g_hash_table_destroy(vars);
}

/*
 * Free's the u_files GList
 */
void free_u_files(void)
{
	unsigned int i;
	unsigned int size;
	struct file_info *file_info;

	if (!u_files)
		return;

	size = g_list_length(u_files);
	for (i = 0; i < size; i++) {
		file_info = g_list_nth_data(u_files, i);
		free(file_info->orig_file_name);
		free(file_info->temp_file_name);
		free(file_info->name);
		free(file_info->mime_type);
	}
	g_list_free(u_files);
}

/*
 * Add's a name=value pair to the GList (avars) of array POST
 * variables.
 *
 * These ones come from data POST'd as multipart/form-data
 *
 * This data is _not_ % encoded and does not require to be run
 * through url_decode. It also means we need to split on [ and
 * not its %value.
 *
 * The finalize parameter should be given as 0 while adding items.
 * Once your done, call this function with NULL and 1 as its arguments,
 * this will ensure that the last GHashTable is added to the GList.
 */
static void add_multipart_avar(const char *name, char *value, int finalize)
{
	char *token;
	char *idx;
	static char lidx[128] = "\0";
	char *string;
	char *key;
	static GHashTable *query_values = NULL;

	if (finalize) {
		avars = g_list_append(avars, query_values);
		memset(lidx, '\0', sizeof(lidx));
		return;
	}

	string = strdupa(name);

	token = strtok(string, "[");
	idx = strdupa(token);
	if (strcmp(idx, lidx) != 0) {
		if (lidx[0] != '\0')
			avars = g_list_append(avars, query_values);
		query_values = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);
	}
	strncpy(lidx, idx, 127);
	token = NULL;

	token = strtok(token, "=");
	key = alloca(strlen(token));
	memset(key, 0, strlen(token));
	strncpy(key, token, strlen(token) - 1);

	d_fprintf(debug_log, "Adding key: %s with value: %s\n", key, value);
	g_hash_table_replace(query_values, g_strdup(key), g_strdup(value));
}

/*
 * Add's a name=value pair to the GHashTable (qvars) of name=value
 * pairs of data POST'd with multipart/form-data.
 *
 * This data is _not_ % encoded and does not require to be run
 * through url_decode.
 */
static void add_multipart_var(const char *name, char *value)
{
	d_fprintf(debug_log, "Adding key: %s with value: %s\n", name, value);
	if (!qvars)
		qvars = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);
	g_hash_table_replace(qvars, g_strdup(name), g_strdup(value));
}

/*
 * Add's a name=value pair to the GList (avars) of POST array variables.
 *
 * This is data that has been POST'd as x-www-form-urlencoded
 *
 * The finalize parameter should be given as 0 while adding items.
 * Once your done, call this function with NULL and 1 as its arguments,
 * this will ensure that the last GHashTable is added to the GList.
 */
static void add_avar(char *qvar, int finalize)
{
	char *token;
	char *idx;
	static char lidx[128] = "\0";
	char *string;
	char *key;
	char *value;
	static GHashTable *query_values = NULL;

	if (finalize) {
		avars = g_list_append(avars, query_values);
		memset(lidx, '\0', sizeof(lidx));
		return;
	}

	string = strdupa(qvar);

	token = strtok(string, "%");
	idx = strdupa(token);
	if (strcmp(idx, lidx) != 0) {
		if (lidx[0] != '\0')
			avars = g_list_append(avars, query_values);
		query_values = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);
	}
	strncpy(lidx, idx, sizeof(lidx) - 1);
	token = NULL;

	token = strtok(token, "=");
	key = alloca(strlen(token));
	memset(key, 0, strlen(token));
	strncpy(key, token + 2, strlen(token + 2) - 3);
	token = NULL;

	token = strtok(token, "=");
	if (token)
		value = url_decode(token);
	else
		value = url_decode("");

	d_fprintf(debug_log, "Adding key: %s with value: %s\n", key, value);
	g_hash_table_replace(query_values, g_strdup(key), g_strdup(value));
	free(value);
}

/*
 * Add's a name=value pair to the GHashTable (qvars) of name=value
 * pairs of data from GET or POST (x-www-form-urlencoded)
 */
static void add_var(char *qvar)
{
	char *string;
	char *token;
	char *key;
	char *value;

	if (!qvars)
		qvars = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);

	string = strdupa(qvar);

	token = strtok(string, "=");
	key = token;
	token = NULL;

	token = strtok(token, "=");
	if (token)
		value = url_decode(token);
	else
		value = url_decode("");

	d_fprintf(debug_log, "Adding key: %s with value: %s\n", key, value);
	g_hash_table_replace(qvars, g_strdup(key), g_strdup(value));
	free(value);
}

/*
 * Determine whether a POST/GET variable is an array variable or not
 * and call the appropriate function to add it to the right data
 * structure.
 *
 * Array variables go to avars.
 * Non array variables go to qvars.
 */
static void process_vars(char *query)
{
	char *token;
	char *saveptr1 = NULL;
	char *string;
	int avars = 0;

	string = strdupa(query);
	for (;;) {
		token = strtok_r(string, "&", &saveptr1);
		if (token == NULL)
			break;

		if (strstr(token, "%5D=")) {
			add_avar(token, 0);
			avars = 1;
		} else {
			add_var(token);
		}
		string = NULL;
	}
	if (avars)
		add_avar(NULL, 1);
}

/*
 * Extract data from POST multipart/form-data
 *
 * This will extract files and variable name/data pairs.
 */
static void process_mime_part(GMimeObject *part, gpointer user_data)
{
	const GMimeContentType *content_type;
	GMimeStream *stream;
	GMimeDataWrapper *content;
	GMimeDisposition *disposition;
	char buf[BUF_SIZE];

	content_type = g_mime_object_get_content_type(part);
	disposition = g_mime_disposition_new(g_mime_object_get_header(part,
						"Content-Disposition"));

	if (g_mime_disposition_get_parameter(disposition, "filename")) {
		char temp_name[] = "/tmp/u_files/pgv-XXXXXX";
		struct file_info *file_info;
		int fd;

		fd = mkstemp(temp_name);

		file_info = malloc(sizeof(struct file_info));
		file_info->orig_file_name = strdup(
					g_mime_disposition_get_parameter(
					disposition, "filename"));
		file_info->temp_file_name = strdup(temp_name);
		file_info->name = strdup(g_mime_disposition_get_parameter(
					disposition, "name"));
		file_info->mime_type = strdup(g_mime_content_type_to_string(
					content_type));

		stream = g_mime_stream_fs_new(fd);
		content = g_mime_part_get_content_object((GMimePart *)part);
		g_mime_data_wrapper_write_to_stream(content, stream);
		g_mime_stream_flush(stream);
		g_object_unref(stream);
		close(fd);

		u_files = g_list_append(u_files, file_info);
	} else {
		ssize_t bytes;

		stream = g_mime_stream_mem_new();
		content = g_mime_part_get_content_object((GMimePart *)part);
		bytes = g_mime_data_wrapper_write_to_stream(content, stream);

		g_mime_stream_seek(stream, 0, GMIME_STREAM_SEEK_SET);
		memset(buf, 0, sizeof(buf));
		bytes = g_mime_stream_read(stream, buf, BUF_SIZE);

		if (strstr(g_mime_disposition_get_parameter(
						disposition, "name"), "["))
			add_multipart_avar(g_mime_disposition_get_parameter(
						disposition, "name"), buf, 0);
		else
			add_multipart_var(g_mime_disposition_get_parameter(
						disposition, "name"), buf);

		g_object_unref(stream);
	}
}

/*
 * Handle POST multipart/form-data
 *
 * This reads the data and saves it to a temporary file adding a
 * "Content-Type: " header that's needed by gmime.
 *
 * process_mime_part() is called for each part of the data.
 */
static void process_mime(void)
{
	char buf[BUF_SIZE];
	char temp_name[] = "/tmp/u_files/pgv-XXXXXX";
	FILE *ofp;
	int fd;
	GMimeStream *stream;
	GMimeParser *parser;
	GMimeObject *parts;

	g_mime_init(0);

	fd = mkstemp(temp_name);
	ofp = fdopen(fd, "w");
	fprintf(ofp, "Content-Type: %s\r\n", getenv("CONTENT_TYPE"));
	while (!feof(stdin)) {
		memset(buf, 0, BUF_SIZE);
		fread(buf, BUF_SIZE, 1, stdin);
		fwrite(buf, BUF_SIZE, 1, ofp);
	}
	fclose(ofp);

	fd = open(temp_name, O_RDONLY);
	stream = g_mime_stream_fs_new(fd);
	parser = g_mime_parser_new_with_stream(stream);
	parts = g_mime_parser_construct_part(parser);

	g_mime_multipart_foreach((GMimeMultipart *)parts,
				(GMimePartFunc)process_mime_part, NULL);

	g_object_unref(stream);
	g_object_unref(parser);
	close(fd);
	unlink(temp_name);
	g_mime_shutdown();
}

/*
 * Determine what type of data we got sent and build the POST/GET
 * variable data structures. avars, qvars & u_files
 *
 * We currently handle three types of data
 *
 * GET
 * POST x-www-form-urlencoded
 * POST multipart/form-data
 */
void set_vars(void)
{
	char buf[BUF_SIZE];

	memset(buf, 0, sizeof(buf));

	if (strstr(env_vars.request_method, "GET") &&
					strlen(env_vars.query_string) > 0) {
		snprintf(buf, BUF_SIZE, "%s", env_vars.query_string);
		process_vars(buf);
	} else if (strstr(env_vars.request_method, "POST")) {
		if (strstr(env_vars.content_type, "x-www-form-urlencoded")) {
			fread(buf, sizeof(buf) - 1, 1, stdin);
			process_vars(buf);
		} else if (strstr(env_vars.content_type,
						"multipart/form-data")) {
			process_mime();
			add_multipart_avar(NULL, NULL, 1);
		}
	}
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
 * Given an index and a key, return the coresponding value from
 * the hash table contained within the avars GList.
 */
char *get_avar(int index, char *key)
{
	char *val;
	GHashTable *vars;

	vars = g_list_nth_data(avars, index);
	val = g_hash_table_lookup(vars, key);

	return val;
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

	if (getenv("CONTENT_TYPE"))
		env_vars.content_type = strdup(getenv("CONTENT_TYPE"));
	else
		env_vars.content_type = NULL;

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

/*
 * Simple anti-xss mechanism.
 *
 * Escape the HTML characters listed here: https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet#RULE_.231_-_HTML_Escape_Before_Inserting_Untrusted_Data_into_HTML_Element_Content
 *
 * This is run as an output filter in libctemplate.
 *
 * We don't use TMPL_encode_entity from libctemplate, as we do some
 * different things and it saves messing with the external library.
 *
 * I'm taking the, 'Be generous in what you accept, but strict in
 * what you send.', philosophy.
 */
void de_xss(const char *value, FILE *out)
{
	for (; *value != 0; value++) {
		switch (*value) {
		case '&':
			fputs("&amp;", out);
			break;
		case '<':
			fputs("&lt;", out);
			break;
		case '>':
			fputs("&gt;", out);
			break;
		case '"':
			fputs("&quot;", out);
			break;
		case '\'':
			fputs("&#x27;", out);
			break;
		case '/':
			fputs("&#x2F;", out);
			break;
		default:
			fputc(*value, out);
			break;
		}
	}
}

/*
 * A function similar to de_xss, but returns a dynamically allocated
 * string that must be free'd.
 */
char *xss_safe_string(const char *string)
{
	char *safe_string;

	safe_string = malloc(1);
	memset(safe_string, 0, 1);

	for (; *string != '\0'; string++) {
		switch (*string) {
		case '&':
			safe_string = realloc(safe_string, strlen(safe_string)
									+ 6);
			if (!safe_string)
				goto out_fail;
			strcat(safe_string, "&amp;");
			break;
		case '<':
			safe_string = realloc(safe_string, strlen(safe_string)
									+ 5);
			if (!safe_string)
				goto out_fail;
			strcat(safe_string, "&lt;");
			break;
		case '>':
			safe_string = realloc(safe_string, strlen(safe_string)
									+ 5);
			if (!safe_string)
				goto out_fail;
			strcat(safe_string, "&gt;");
			break;
		case '"':
			safe_string = realloc(safe_string, strlen(safe_string)
									+ 7);
			if (!safe_string)
				goto out_fail;
			strcat(safe_string, "&quot;");
			break;
		case '\'':
			safe_string = realloc(safe_string, strlen(safe_string)
									+ 7);
			if (!safe_string)
				goto out_fail;
			strcat(safe_string, "&#x27;");
			break;
		case '/':
			safe_string = realloc(safe_string, strlen(safe_string)
									+ 7);
			if (!safe_string)
				goto out_fail;
			strcat(safe_string, "&#x2F;");
			break;
		default:
			safe_string = realloc(safe_string, strlen(safe_string)
									+ 2);
			if (!safe_string)
				goto out_fail;
			strncat(safe_string, string, 1);
			break;
		}
	}

	return safe_string;

out_fail:
	d_fprintf(error_log, "%s: Could not realloc(). Exiting.\n", __func__);
	_exit(EXIT_FAILURE);
}
