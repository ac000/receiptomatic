/*
 * utils.c
 *
 * Copyright (C) 2011-2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2016, 2020	Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fcgiapp.h>

#include <glib.h>

#include <gmime/gmime.h>

#include <mhash.h>

/* HTML template library */
#include <flate.h>

#include "common.h"
#include "utils.h"

struct quark {
	GHashTable *q;
	int last;
};
static struct quark quarks;

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
 * A simplified version of GLibs GQuark.
 *
 * Maps strings to integers starting at 0. The same string will map to the
 * same integer.
 */
static int quark_from_string(const char *str)
{
	gpointer q;

	if (!quarks.q) {
		quarks.q = g_hash_table_new_full(g_str_hash, g_str_equal,
				g_free, NULL);
		quarks.last = -1;
	}

	q = g_hash_table_lookup(quarks.q, str);
	if (!q) {
		quarks.last++;
		g_hash_table_insert(quarks.q, g_strdup(str),
				GINT_TO_POINTER(quarks.last));

		return quarks.last;
	} else {
		return GPOINTER_TO_INT(q);
	}
}

/*
 * Function comes from: http://www.geekhideout.com/urlcode.shtml
 *
 * Converts a hex character to its integer value
 */
static char from_hex(char ch)
{
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/*
 * Function comes from: http://www.geekhideout.com/urlcode.shtml
 *
 * Returns a url-decoded version of str
 *
 * Note that we don't use glibs g_uri_unescape_string() as it doesn't
 * transform the '+' character back into a space.
 *
 * IMPORTANT: be sure to free() the returned string after use
 */
static char *url_decode(const char *str)
{
	char *buf;
	char *pbuf;

	buf = malloc(strlen(str) + 1);
	if (!buf) {
		perror("malloc");
		_exit(EXIT_FAILURE);
	}
	pbuf = buf;

	while (*str) {
		if (*str == '%') {
			if (str[1] && str[2]) {
				*pbuf++ = from_hex(str[1]) << 4 |
							from_hex(str[2]);
				str += 2;
			}
		} else if (*str == '+') {
			*pbuf++ = ' ';
		} else {
			*pbuf++ = *str;
		}
		str++;
	}
	*pbuf = '\0';

	return buf;
}

/*
 * Given a hostname like host.example.com it returns just 'host'
 */
char *get_tenant(const char *host, char *tenant)
{
	char *str;

	if (!MULTI_TENANT || !host) {
		/*
		 * We are either not in multi-tenancy mode and/or being run
		 * due to a signal handler.
		 */
		strcpy(tenant, "");
		goto out;
	}

	str = strdupa(host);
	snprintf(tenant, TENANT_MAX + 1, "%s", strsep(&str, "."));

out:
	return tenant;
}

/*
 * Generates a hash of the specified type, using /dev/urandom as a
 * source of entropy.
 *
 * It places the resultant hash in hash and also returns a pointer
 * to it.
 */
char *generate_hash(char *hash, int type)
{
	int fd;
	int i;
	int hbs;
	int hash_len;
	ssize_t bytes_read;
	char buf[ENTROPY_SIZE];
	char ht[3];
	unsigned char *xhash;
	MHASH td;

	fd = open("/dev/urandom", O_RDONLY);
	bytes_read = read(fd, &buf, sizeof(buf));
	close(fd);

	if (bytes_read < (ssize_t)sizeof(buf)) {
		/*
		 * If we couldn't read the required amount, something is
		 * seriously wrong. Log it and exit.
		 */
		d_fprintf(error_log, "Couldn't read sufficient data from "
				"/dev/urandom\n");
		_exit(EXIT_FAILURE);
	}

	switch (type) {
	case SHA1:
		td = mhash_init(MHASH_SHA1);
		hbs = mhash_get_block_size(MHASH_SHA1);
		hash_len = SHA1_LEN;
		break;
	case SHA256:
		td = mhash_init(MHASH_SHA256);
		hbs = mhash_get_block_size(MHASH_SHA256);
		hash_len = SHA256_LEN;
		break;
	default:
		td = mhash_init(MHASH_SHA1);
		hbs = mhash_get_block_size(MHASH_SHA1);
		hash_len = SHA1_LEN;
	}
	mhash(td, &buf, sizeof(buf));
	xhash = mhash_end(td);

	memset(hash, 0, hash_len + 1);
	for (i = 0; i < hbs; i++) {
		sprintf(ht, "%.2x", xhash[i]);
		strncat(hash, ht, 3);
	}
	free(xhash);

	return hash;
}

/*
 * Free's the avars GList
 */
void free_avars(void)
{
	unsigned int i;
	unsigned int size;

	if (quarks.q) {
		g_hash_table_destroy(quarks.q);
		quarks.q = NULL;
	}

	if (!avars)
		return;

	size = g_list_length(avars);
	for (i = 0; i < size; i++) {
		GHashTable *query_vars;

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

	if (!u_files)
		return;

	size = g_list_length(u_files);
	for (i = 0; i < size; i++) {
		struct file_info *file_info;

		file_info = g_list_nth_data(u_files, i);
		unlink(file_info->temp_file_name);
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
 */
static void add_multipart_avar(const char *name, const char *value)
{
	char *token;
	char *string;
	GHashTable *ht;
	bool new = false;
	int qidx;

	string = strdupa(name);

	token = strtok(string, "[");
	qidx = quark_from_string(token);
	/*
	 * Look for an existing hash table for this variable index. We
	 * use qidx - 1 for the array position as GQuark's start at 1
	 */
	ht = g_list_nth_data(avars, qidx);
	if (!ht) {
		/* New array index, new hash table */
		ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
				g_free);
		new = true;
	}

	token = NULL;
	token = strtok(token, "=");

	d_fprintf(debug_log, "Adding key: %s with value: %s\n", token, value);
	g_hash_table_replace(ht, g_strdup(token), g_strdup(value));
	if (new)
		avars = g_list_append(avars, ht);
}

/*
 * Add's a name=value pair to the GHashTable (qvars) of name=value
 * pairs of data POST'd with multipart/form-data.
 *
 * This data is _not_ % encoded and does not require to be run
 * through url_decode.
 */
static void add_multipart_var(const char *name, const char *value)
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
 */
static void add_avar(const char *qvar)
{
	char *token;
	char *string;
	char *key;
	char *value;
	GHashTable *ht;
	bool new = false;
	int qidx;

	string = strdupa(qvar);

	token = strtok(string, "%");
	qidx = quark_from_string(token);
	/*
	 * Look for an existing hash table for this variable index. We
	 * use qidx - 1 for the array position as GQuark's start at 1
	 */
	ht = g_list_nth_data(avars, qidx);
	if (!ht) {
		/* New array index, new hash table */
		ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
				free);
		new = true;
	}

	token = NULL;
	token = strtok(token, "=");
	key = alloca(strlen(token));
	memset(key, 0, strlen(token));
	snprintf(key, strlen(token + 2) - 2, "%s", token + 2);

	token = NULL;
	token = strtok(token, "=");
	if (token)
		value = url_decode(token);
	else
		value = strdup("");

	d_fprintf(debug_log, "Adding key: %s with value: %s\n", key, value);
	g_hash_table_replace(ht, g_strdup(key), value);
	if (new)
		avars = g_list_append(avars, ht);
}

/*
 * Add's a name=value pair to the GHashTable (qvars) of name=value
 * pairs of data from GET or POST (x-www-form-urlencoded)
 */
static void add_var(const char *qvar)
{
	char *string;
	char *token;
	char *key;
	char *value;

	if (!qvars)
		qvars = g_hash_table_new_full(g_str_hash, g_str_equal,
				g_free, free);

	string = strdupa(qvar);

	token = strtok(string, "=");
	key = token;
	token = NULL;

	token = strtok(token, "=");
	if (token)
		value = url_decode(token);
	else
		value = strdup("");

	d_fprintf(debug_log, "Adding key: %s with value: %s\n", key, value);
	g_hash_table_replace(qvars, g_strdup(key), value);
}

/*
 * Determine whether a POST/GET variable is an array variable or not
 * and call the appropriate function to add it to the right data
 * structure.
 *
 * Array variables go to avars.
 * Non array variables go to qvars.
 */
static void process_vars(const char *query)
{
	char *token;
	char *saveptr1 = NULL;
	char *string;

	string = strdupa(query);
	token = strtok_r(string, "&", &saveptr1);
	while (token != NULL) {
		if (strstr(token, "%5D="))
			add_avar(token);
		else
			add_var(token);
		token = strtok_r(NULL, "&", &saveptr1);
	}
}

/*
 * Extract data from POST multipart/form-data
 *
 * This will extract files and variable name/data pairs.
 */
static void process_mime_part(GMimeObject *parent __unused, GMimeObject *part,
			      gpointer user_data __unused)
{
	GMimeContentType *content_type;
	GMimeStream *stream;
	GMimeDataWrapper *content;
	GMimeContentDisposition *disposition;
	const char *dfname;
	const char *dname;

	content_type = g_mime_object_get_content_type(part);
	disposition = g_mime_content_disposition_new_from_string(
			g_mime_object_get_header(part, "Content-Disposition"));

	dname = g_mime_content_disposition_get_parameter(disposition, "name");
	dfname = g_mime_content_disposition_get_parameter(disposition,
			"filename");
	if (dfname) {
		char temp_name[] = "/tmp/u_files/pgv-XXXXXX";
		struct file_info *file_info;
		int fd;
		mode_t smask;

		/* Ensure we create the file restrictively */
		smask = umask(0077);
		fd = mkstemp(temp_name);
		umask(smask);

		file_info = malloc(sizeof(struct file_info));
		memset(file_info, 0, sizeof(struct file_info));
		snprintf(file_info->orig_file_name,
				sizeof(file_info->orig_file_name), "%s",
				dfname);
		strcpy(file_info->temp_file_name, temp_name);
		file_info->name = strdup(dname);
		file_info->mime_type = strdup(g_mime_content_type_to_string(
					content_type));

		stream = g_mime_stream_fs_new(fd);
		content = g_mime_part_get_content_object((GMimePart *)part);
		g_mime_data_wrapper_write_to_stream(content, stream);
		g_mime_stream_flush(stream);
		close(fd);

		u_files = g_list_append(u_files, file_info);
	} else {
		char *buf;
		ssize_t bytes;

		stream = g_mime_stream_mem_new();
		content = g_mime_part_get_content_object((GMimePart *)part);
		bytes = g_mime_data_wrapper_write_to_stream(content, stream);

		buf = malloc(bytes + 1);
		g_mime_stream_seek(stream, 0, GMIME_STREAM_SEEK_SET);
		g_mime_stream_read(stream, buf, bytes);
		buf[bytes] = '\0';

		if (strstr(dname, "["))
			add_multipart_avar(dname, buf);
		else
			add_multipart_var(dname, buf);
		free(buf);
	}

	g_object_unref(content);
	g_object_unref(stream);
	g_object_unref(disposition);
}

/*
 * Handle POST multipart/form-data
 *
 * process_mime_part() is called for each part of the data.
 */
static void process_mime(void)
{
	char *data;
	off_t size = 0;
	off_t content_length = env_vars.content_length;
	int bytes_read;
	GMimeStream *stream;
	GMimeParser *parser;
	GMimeObject *parts;

	if (!content_length)
		return;

	data = calloc(content_length, 1);
	do {
		bytes_read = fcgx_gs(data + size, BUF_SIZE);
		size += bytes_read;
	} while (bytes_read > 0);

	g_mime_init(0);
	stream = g_mime_stream_mem_new();
	/* We need to add the Content-Type header, for gmime */
	g_mime_stream_printf(stream, "Content-Type: %s\r\n",
			env_vars.content_type);
	g_mime_stream_write(stream, data, size);
	free(data);
	g_mime_stream_seek(stream, 0, GMIME_STREAM_SEEK_SET);

	parser = g_mime_parser_new_with_stream(stream);
	parts = g_mime_parser_construct_part(parser);
	g_mime_multipart_foreach((GMimeMultipart *)parts,
			(GMimeObjectForeachFunc)process_mime_part, NULL);

	g_object_unref(parts);
	g_object_unref(stream);
	g_object_unref(parser);
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

	if (IS_SET(env_vars.query_string)) {
		snprintf(buf, BUF_SIZE, "%s", env_vars.query_string);
		process_vars(buf);
	}
	if (strstr(env_vars.content_type, "x-www-form-urlencoded")) {
		fcgx_gs(buf, sizeof(buf) - 1);
		process_vars(buf);
	} else if (strstr(env_vars.content_type, "multipart/form-data")) {
		process_mime();
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
const char *get_avar(int index, const char *key)
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
const char *get_var(GHashTable *vars, const char *key)
{
	char *val;

	if (!vars)
		goto out_err;

	val = g_hash_table_lookup(vars, key);
	if (!val)
		goto out_err;

	return val;

out_err:
	d_fprintf(debug_log, "Unknown var: %s\n", key);
	return "\0";
}

/*
 * Fill out a structure with various environment variables
 * sent to the application.
 */
void set_env_vars(void)
{
	if (fcgx_param("REQUEST_URI"))
		env_vars.request_uri = strdup(fcgx_param("REQUEST_URI"));
	else
		env_vars.request_uri = NULL;

	if (fcgx_param("REQUEST_METHOD"))
		env_vars.request_method = strdup(fcgx_param("REQUEST_METHOD"));
	else
		env_vars.request_method = NULL;

	if (fcgx_param("CONTENT_TYPE"))
		env_vars.content_type = strdup(fcgx_param("CONTENT_TYPE"));
	else
		env_vars.content_type = NULL;

	if (fcgx_param("CONTENT_LENGTH"))
		env_vars.content_length = atoll(fcgx_param("CONTENT_LENGTH"));
	else
		env_vars.content_length = 0;

	if (fcgx_param("HTTP_COOKIE"))
		env_vars.http_cookie = strdup(fcgx_param("HTTP_COOKIE"));
	else
		env_vars.http_cookie = NULL;

	if (fcgx_param("HTTP_USER_AGENT"))
		env_vars.http_user_agent = strdup(fcgx_param(
					"HTTP_USER_AGENT"));
	else
		/*
		 * In case it's (null), we still need at least an empty
		 * string for checking against in is_logged_in()
		 */
		env_vars.http_user_agent = strdup("");

	if (fcgx_param("HTTP_X_FORWARDED_FOR") &&
	    IS_SET(fcgx_param("HTTP_X_FORWARDED_FOR")))
		env_vars.remote_addr = strdup(fcgx_param(
					"HTTP_X_FORWARDED_FOR"));
	else
		env_vars.remote_addr = strdup(fcgx_param("REMOTE_ADDR"));

	if (fcgx_param("HTTP_X_FORWARDED_HOST"))
		env_vars.host = strdup(fcgx_param("HTTP_X_FORWARDED_HOST"));
	else if (fcgx_param("HTTP_HOST"))
		env_vars.host = strdup(fcgx_param("HTTP_HOST"));
	else
		env_vars.host = strdup("");

	if (fcgx_param("REMOTE_PORT"))
		env_vars.remote_port = atoi(fcgx_param("REMOTE_PORT"));
	else
		env_vars.remote_port = 0;

	if (fcgx_param("QUERY_STRING"))
		env_vars.query_string = strdup(fcgx_param("QUERY_STRING"));
	else
		env_vars.query_string = NULL;
}

/*
 * Free's the custom fields list.
 */
void free_fields(void)
{
	free(fields.receipt_date);
	free(fields.department);
	free(fields.employee_number);
	free(fields.reason);
	free(fields.po_num);
	free(fields.cost_codes);
	free(fields.account_codes);
	free(fields.supplier_name);
	free(fields.supplier_town);
	free(fields.vat_number);
	free(fields.gross_amount);
	free(fields.net_amount);
	free(fields.vat_amount);
	free(fields.vat_rate);
	free(fields.currency);
	free(fields.payment_method);
}

/*
 * Free's the http environment structure.
 */
void free_env_vars(void)
{
	free(env_vars.request_uri);
	free(env_vars.request_method);
	free(env_vars.content_type);
	free(env_vars.http_cookie);
	free(env_vars.http_user_agent);
	free(env_vars.remote_addr);
	free(env_vars.host);
	free(env_vars.query_string);
}

/*
 * Free's the user session structure.
 */
void free_user_session(void)
{
	free(user_session.username);
	free(user_session.name);
	free(user_session.client_id);
	free(user_session.user_hdr);
}

/*
 * Send an account activation email to the required user.
 */
void send_activation_mail(const char *name, const char *address,
			  const char *key)
{
	FILE *fp = popen(MAIL_CMD, "w");

	fprintf(fp, "Reply-To: %s\r\n", MAIL_REPLY_TO);
	fprintf(fp, "From: %s\r\n", MAIL_FROM);
	fprintf(fp, "Subject: %s\r\n", MAIL_SUBJECT);
	fprintf(fp, "To: %s <%s>\r\n", name, address);
	fputs("Content-Type: text/plain; charset=us-ascii\r\n", fp);
	fputs("Content-Transfer-Encoding: 7bit\r\n", fp);
	fputs("\r\n", fp);

	fputs("Your account has been created and awaits activation.\r\n", fp);
	fputs("\r\n", fp);
	fputs("Please follow the below url to complete your account setup."
			"\r\n", fp);
	fputs("Note that this activation key is valid for 24 hours.\r\n", fp);
	fputs("\r\n", fp);
	fprintf(fp, "https://%s/activate_user/?key=%s\r\n", env_vars.host,
			key);

	pclose(fp);
}

/*
 * Hash a given password using either the SHA256 or SHA512 alogorithm.
 */
char *generate_password_hash(int hash_type, const char *password)
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
		long r;
		struct timespec tp;

		clock_gettime(CLOCK_REALTIME, &tp);
		srandom(tp.tv_sec * tp.tv_nsec);
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
		const char *rbuf;

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
 */
bool user_already_exists(const char *username)
{
	char *user;
	bool ret = false;
	MYSQL_RES *res;

	user = make_mysql_safe_string(username);
	res = sql_query("SELECT username FROM passwd WHERE username = '%s'",
			user);
	if (mysql_num_rows(res) > 0)
		ret = true;

	mysql_free_result(res);
	free(user);

	return ret;
}

/*
 * Calculate the page_number to show and the where in the results
 * set to show from.
 *
 * This is used in the results pagination code.
 */
void get_page_pagination(struct pagination *pn)
{
	pn->page_no = pn->requested_page;

	if (pn->page_no < 2) {
		/* Reset to values for showing the first page */
		pn->page_no = 1;
		pn->from = 0;
	} else {
		pn->from = (pn->page_no - 1) * pn->rows_per_page;
	}
}

/*
 * Create the next / prev page navigation links.
 */
void do_pagination(Flate *f, const struct pagination *pn)
{
	int nr_pages = pn->nr_pages;

	if (IS_MULTI_PAGE(nr_pages)) {
		char page_no[12];
		int rqpage = pn->page_no;

		if (IS_FIRST_PAGE(rqpage)) {
			/* Wrap around to end */
			snprintf(page_no, sizeof(page_no), "%d", nr_pages);
			lf_set_var(f, "prev_page", page_no, NULL);
		} else if (!IS_FIRST_PAGE(rqpage)) {
			snprintf(page_no, sizeof(page_no), "%d", rqpage - 1);
			lf_set_var(f, "prev_page", page_no, NULL);
		}
		if (IS_LAST_PAGE(rqpage, nr_pages)) {
			/* Wrap around to start */
			lf_set_var(f, "next_page", "1", NULL);
		} else if (!IS_LAST_PAGE(rqpage, nr_pages)) {
			snprintf(page_no, sizeof(page_no), "%d", rqpage + 1);
			lf_set_var(f, "next_page", page_no, NULL);
		}
		lf_set_var(f, "multi_page", "", NULL);
	}
}

/*
 * Create a zebra list with alternating highlighted rows.
 *
 * Even numbered rows are highligted.
 */
void do_zebra(Flate *f, unsigned long row, const char *zebra)
{
	lf_set_var(f, "zebra", (row % 2) ? "" : zebra, NULL);
}

#define STR_ALLOC_SZ	512
/*
 * Simple anti-xss mechanism.
 *
 * Escape the HTML characters listed here: https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet#RULE_.231_-_HTML_Escape_Before_Inserting_Untrusted_Data_into_HTML_Element_Content
 *
 * This can be used as a format function to lf_set_var()
 */
char *de_xss(const char *string)
{
	char *safe_string = malloc(STR_ALLOC_SZ);
	size_t alloc = STR_ALLOC_SZ;

	safe_string[0] = '\0';
	for (; *string != '\0'; string++) {
		if (strlen(safe_string) + 7 > alloc) {
			safe_string = realloc(safe_string,
					alloc + STR_ALLOC_SZ);
			if (!safe_string)
				goto out_fail;
			alloc += STR_ALLOC_SZ;
		}
		switch (*string) {
		case '&':
			strcat(safe_string, "&amp;");
			break;
		case '<':
			strcat(safe_string, "&lt;");
			break;
		case '>':
			strcat(safe_string, "&gt;");
			break;
		case '"':
			strcat(safe_string, "&quot;");
			break;
		case '\'':
			strcat(safe_string, "&#x27;");
			break;
		case '/':
			strcat(safe_string, "&#x2F;");
			break;
		default:
			strncat(safe_string, string, 1);
		}
	}

	return safe_string;

out_fail:
	d_fprintf(error_log, "%s: Could not realloc(). Exiting.\n", __func__);
	_exit(EXIT_FAILURE);
}
