/*
 * url_helpers.c
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>
#include <alloca.h>

/* Hashing algorithms */
#include <mhash.h>

#include <glib.h>

#include "common.h"
#include "utils.h"

/*
 * Given a username return the real name, which should be free'd.
 */
char *username_to_name(char *username)
{
	char sql[SQL_MAX];
	char *who;
	char *name;
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;

	conn = db_conn();

	who = alloca(strlen(username) * 2 + 1);
	mysql_real_escape_string(conn, who, username, strlen(username));

	snprintf(sql, SQL_MAX, "SELECT name FROM passwd WHERE username = '%s'",
									who);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);

	name = strdup(row[0]);

	mysql_free_result(res);
	mysql_close(conn);

	return name;
}

/*
 * This checks if a user is currently logged in. It is called at the start
 * of each request.
 *
 * There are upto three checks performed:
 *
 * 1) The session_id cookie from the browser is checked with the stored
 *    session_id generated at login.
 * 2) The client_id from the browser (currently the user agent string) is
 *    checked against the stored client_id.
 *
 * 4) Optionally (enabled by default on the login screen) a check is made
 *    on the requesting ip address against the stored origin_ip that was
 *    used at login.
 *
 * If any of these checks fail, the request is denied and the user is
 * punted to the login screen.
 */
int is_logged_in(char *cookies, char *client_id, char *remote_ip,
							char *request_uri)
{
	char session_id[65];
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	TCMAP *cols;
	int rsize;
	int ret = 0;
	const char *rbuf;

	if (!cookies)
		goto out3;

	strncpy(session_id, cookies + 11, 64);
	session_id[64] = '\0';

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOREADER);

	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ, session_id);
	res = tctdbqrysearch(qry);
	if (tclistnum(res) == 0)
		goto out2;

	rbuf = tclistval(res, 0, &rsize);
	cols = tctdbget(tdb, rbuf, rsize);
	tcmapiterinit(cols);

	/* restrict_ip */
	if (atoi(tcmapget2(cols, "restrict_ip")) == 1) {
		/* origin_ip */
		if (strcmp(tcmapget2(cols, "origin_ip"), remote_ip) != 0)
			goto out;
	}
	/* client_id */
	if (strcmp(tcmapget2(cols, "client_id"), client_id) != 0)
		goto out;

	/* We got here, all checks are OK */
	ret = 1;

out:
	tcmapdel(cols);
out2:
	tctdbqrydel(qry);
	tclistdel(res);
	tctdbclose(tdb);
	tctdbdel(tdb);
out3:
	return ret;
}

/*
 * Authenticates the user. Takes their password, crypt()'s it using
 * the salt from their password entry and compares the result with
 * their stored password.
 */
int check_auth(GHashTable *credentials)
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
 * Checks that an image/receipt id belongs to a specified user.
 */
int is_users_receipt(struct session *current_session, char *id)
{
	char sql[SQL_MAX];
	char *s_id;
	char *username;
	MYSQL *conn;
	MYSQL_RES *res;
	int ret = 0;

	conn = db_conn();

	s_id = alloca(strlen(id) * 2 + 1);
	mysql_real_escape_string(conn, s_id, id, strlen(id));

	username = alloca(strlen(current_session->username) * 2 + 1);
	mysql_real_escape_string(conn, username, current_session->username,
					strlen(current_session->username));

	snprintf(sql, SQL_MAX, "SELECT id FROM images WHERE id = '%s' AND "
					"username = '%s'", s_id, username);

	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) > 0)
		ret = 1;

	mysql_free_result(res);
	mysql_close(conn);

	return ret;
}

/*
 * Checks the users permission to access receipt tag information.
 */
int tag_info_allowed(struct session *current_session, char *image_id)
{
	char sql[SQL_MAX];
	char *s_image_id;
	char *username;
	int ret = 0;
	MYSQL *conn;
	MYSQL_RES *res;

	/* Approvers can see all tags */
	if (current_session->type & APPROVER) {
		ret = 1;
		goto out;
	}

	conn = db_conn();

	s_image_id = alloca(strlen(image_id) * 2 + 1);
	mysql_real_escape_string(conn, s_image_id, image_id, strlen(image_id));

	username = alloca(strlen(current_session->username) * 2 + 1);
	mysql_real_escape_string(conn, username, current_session->username,
					strlen(current_session->username));

	snprintf(sql, SQL_MAX, "SELECT path FROM images WHERE id = '%s' AND "
						"username = '%s'", s_image_id,
						username);

	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) > 0)
		ret = 1;

	mysql_free_result(res);
	mysql_close(conn);

out:
	return ret;
}

/*
 * Determine if access to an image is allowed. It checks for /UID/ at the
 * start of the image path after IMAGE_PATH.
 */
int image_access_allowed(struct session *current_session, char *path)
{
	int ret = 0;
	char uidir[PATH_MAX];

	memset(uidir, 0, sizeof(uidir));
	snprintf(uidir, sizeof(uidir), "/%d/", current_session->uid);

	/* Approvers can see all images */
	if (current_session->type & APPROVER)
		ret = 1;
	else if (strncmp(path + strlen(IMAGE_PATH), uidir, strlen(uidir)) == 0)
		ret = 1;

	return ret;
}

/*
 * Sets up the current_session structure. This contains various bits of
 * information pertaining to the users session.
 */
void set_current_session(struct session *current_session, char *cookies,
							char *request_uri)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	TCMAP *cols;
	int rsize;
	int primary_key_size;
	char pkbuf[256];
	char session_id[65];
	char login_at[21];
	char last_seen[21];
	char uid[11];
	char restrict_ip[2];
	char type[3];
	const char *rbuf;

	/*
	 * Don't assume the order we get the cookies back is the
	 * same order as we sent them.
	 */
        if (strncmp(cookies, "session_id", 10) == 0)
                strncpy(session_id, cookies + 11, 64);
        else
                strncpy(session_id, cookies + 88, 64);

	session_id[64] = '\0';

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOREADER | TDBOWRITER);

	/* Get the users stored session */
	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ, session_id);
	res = tctdbqrysearch(qry);

	rbuf = tclistval(res, 0, &rsize);
	cols = tctdbget(tdb, rbuf, rsize);
	tcmapiterinit(cols);

	current_session->uid = atoi(tcmapget2(cols, "uid"));
	current_session->username = strdup(tcmapget2(cols, "username"));
	current_session->name = strdup(tcmapget2(cols, "name"));
	current_session->login_at = atol(tcmapget2(cols, "login_at"));
	current_session->last_seen = time(NULL);
	current_session->origin_ip = strdup(tcmapget2(cols, "origin_ip"));
	current_session->client_id = strdup(tcmapget2(cols, "client_id"));
	current_session->session_id = strdup(tcmapget2(cols, "session_id"));
	current_session->restrict_ip = atoi(tcmapget2(cols, "restrict_ip"));
	current_session->type = atoi(tcmapget2(cols, "type"));

	tcmapdel(cols);
	tclistdel(res);
	tctdbqrydel(qry);

	/*
	 * We want to update the last_seen timestamp in the users session.
	 * This entails removing the old session first then storing the new
	 * updated session.
	 */
	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ, session_id);
	res = tctdbqrysearch(qry);
	rbuf = tclistval(res, 0, &rsize);
	tctdbout(tdb, rbuf, strlen(rbuf));

	tclistdel(res);
	tctdbqrydel(qry);

	primary_key_size = sprintf(pkbuf, "%ld", (long)tctdbgenuid(tdb));
	snprintf(login_at, 21, "%ld", current_session->login_at);
	snprintf(last_seen, 21, "%ld", current_session->last_seen);
	snprintf(uid, 11, "%u", current_session->uid);
	snprintf(restrict_ip, 2, "%d", current_session->restrict_ip);
	snprintf(type, 3, "%d", current_session->type);
	cols = tcmapnew3("uid", uid, "username", current_session->username,
				"name", current_session->name, "login_at",
				login_at, "last_seen", last_seen, "origin_ip",
				current_session->origin_ip, "client_id",
				current_session->client_id, "session_id",
				current_session->session_id, "restrict_ip",
				restrict_ip, "type", type, NULL);
	tctdbput(tdb, pkbuf, primary_key_size, cols);

	tcmapdel(cols);

	tctdbclose(tdb);
	tctdbdel(tdb);
}

/*
 * Generate a session_id used to identify a users session.
 * It generates a SHA-256 from random dara.
 */
char *create_session_id(void)
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
void create_session(GHashTable *credentials, char *http_user_agent,
						char *http_x_forwarded_for)
{
	char *session_id;
	char restrict_ip[2] = "0\0";
	char sql[SQL_MAX];
	char pkbuf[256];
	char timestamp[21];
	char *username;
	int primary_key_size;
	MYSQL *conn;
	MYSQL_RES *res;
	TCTDB *tdb;
	TCMAP *cols;
	GHashTable *db_row = NULL;

	conn = db_conn();

	username = alloca(strlen(get_var(credentials, "username")) * 2 + 1);
	mysql_real_escape_string(conn, username, get_var(
						credentials, "username"),
						strlen(get_var(credentials,
						"username")));
	snprintf(sql, SQL_MAX, "SELECT uid, name, type FROM passwd WHERE "
						"username = '%s'", username);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	db_row = get_dbrow(res);

	session_id = create_session_id();

	if (strcmp(get_var(credentials, "restrict_ip"), "true") == 0) {
		d_fprintf(debug_log, "Restricting session to origin ip "
								"address\n");
		restrict_ip[0] = '1';
	}

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOWRITER | TDBOCREAT);
	primary_key_size = sprintf(pkbuf, "%ld", (long)tctdbgenuid(tdb));
	snprintf(timestamp, 21, "%ld", (long)time(NULL));
	cols = tcmapnew3("uid", get_var(db_row, "uid"), "username",
					get_var(credentials, "username"),
					"name", get_var(db_row, "name"),
					"login_at", timestamp, "last_seen",
					timestamp, "origin_ip",
					http_x_forwarded_for, "client_id",
					http_user_agent, "session_id",
					session_id, "restrict_ip", restrict_ip,
					"type", get_var(db_row, "type"), NULL);
	tctdbput(tdb, pkbuf, primary_key_size, cols);
	tcmapdel(cols);
	tctdbclose(tdb);
	tctdbdel(tdb);

	printf("Set-Cookie: session_id=%s; path=/; httponly\r\n", session_id);

	mysql_close(conn);
	mysql_free_result(res);
	free_vars(db_row);
	free(session_id);
}

/*
 * Checks the amounts given on the receipt tally up.
 *
 * We need to allow for a 0.01 deviation due to different VAT rounding
 * that suppliers do.
 *
 * Some will ceil the vat e.g a vat amount of 1.77450 will become 1.78
 * Others will floor the vat e.g a vat amount of 1.6660 will become 1.66
 *
 */
int check_amounts(double gross, double net, double vat, double vr)
{
	int ret = 0;

	if (net + vat < gross - 0.01 || net + vat > gross + 0.01)
		ret = -1;

	if (round(net * (vr / 100 + 1) * 100) / 100 < gross - 0.01 ||
				round(net * (vr / 100 + 1) * 100 /
				100 > gross + 0.01))
		ret = -1;

	if (net == 0.0 || gross == 0.0)
		ret = -1;

	return ret;
}

/*
 * Get the users custom image tag field names for display.
 */
void set_custom_field_names(struct session *current_session,
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
 * Stores custom image tag field names for a user in the database.
 */
void update_fmap(struct session *current_session, char *query)
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
 * Takes the form data from /process_receipt/ and enters it into the database.
 */
void tag_image(struct session *current_session, GHashTable *qvars)
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

	conn = db_conn();

	image_id = alloca(strlen(get_var(qvars, "image_id")) * 2 + 1);
	mysql_real_escape_string(conn, image_id, get_var(qvars, "image_id"),
					strlen(get_var(qvars, "image_id")));

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

	snprintf(sql, SQL_MAX, "REPLACE INTO tags VALUES ('%s', '%s', %ld, "
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

	mysql_close(conn);
}