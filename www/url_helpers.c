/*
 * url_helpers.c
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>
#include <alloca.h>

/* Hashing algorithms */
#include <mhash.h>

/* HTML template library */
#include <ctemplate.h>

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
int is_logged_in(void)
{
	char session_id[65];
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	TCMAP *cols;
	int rsize;
	int ret = 0;
	const char *rbuf;

	if (!env_vars.http_cookie)
		goto out3;

	snprintf(session_id, sizeof(session_id), "%s",
						env_vars.http_cookie + 11);

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
		if (strcmp(tcmapget2(cols, "origin_ip"),
					env_vars.http_x_forwarded_for) != 0)
			goto out;
	}
	/* client_id */
	if (strcmp(tcmapget2(cols, "client_id"),
					env_vars.http_user_agent) != 0)
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
int check_auth(void)
{
	int ret = -1;
	char sql[SQL_MAX];
	char *username;
	char *enc_passwd;
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;

	conn = db_conn();
	username = alloca(strlen(get_var(qvars, "username")) * 2 + 1);
	mysql_real_escape_string(conn, username, get_var(qvars, "username"),
						strlen(get_var(qvars,
						"username")));
	snprintf(sql, SQL_MAX, "SELECT password, enabled FROM passwd WHERE "
						"username = '%s'", username);
	mysql_real_query(conn, sql, strlen(sql));
	d_fprintf(sql_log, "%s\n", sql);
	res = mysql_store_result(conn);

	if (mysql_num_rows(res) < 1)
		goto out;

	row = mysql_fetch_row(res);

	if (atoi(row[1]) == 0) {
		ret = -2;
		goto out;
	}

	enc_passwd = crypt(get_var(qvars, "password"), row[0]);
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
int is_users_receipt(char *id)
{
	char sql[SQL_MAX];
	char *s_id;
	MYSQL *conn;
	MYSQL_RES *res;
	int ret = 0;

	conn = db_conn();

	s_id = alloca(strlen(id) * 2 + 1);
	mysql_real_escape_string(conn, s_id, id, strlen(id));

	snprintf(sql, SQL_MAX, "SELECT id FROM images WHERE id = '%s' AND "
							"uid = %u", s_id,
							user_session.uid);

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
int tag_info_allowed(char *image_id)
{
	char sql[SQL_MAX];
	char *s_image_id;
	int ret = 0;
	MYSQL *conn;
	MYSQL_RES *res;

	/* Approvers can see all tags */
	if (user_session.capabilities & APPROVER) {
		ret = 1;
		goto out;
	}

	conn = db_conn();

	s_image_id = alloca(strlen(image_id) * 2 + 1);
	mysql_real_escape_string(conn, s_image_id, image_id, strlen(image_id));

	snprintf(sql, SQL_MAX, "SELECT path FROM images WHERE id = '%s' AND "
							"uid = %u", s_image_id,
							user_session.uid);

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
int image_access_allowed(char *path)
{
	int ret = 0;
	char uidir[PATH_MAX];

	memset(uidir, 0, sizeof(uidir));
	snprintf(uidir, sizeof(uidir), "/%d/", user_session.uid);

	/* Approvers can see all images */
	if (user_session.capabilities & APPROVER)
		ret = 1;
	else if (strncmp(path + strlen(IMAGE_PATH), uidir, strlen(uidir)) == 0)
		ret = 1;

	return ret;
}

/*
 * Sets up the user_session structure. This contains various bits of
 * information pertaining to the users session.
 */
void set_user_session(void)
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
	char sid[11];
	char restrict_ip[2];
	char capabilities[4];
	char user_hdr[1025];
	char *xss_string;
	const char *rbuf;

	/*
	 * Don't assume the order we get the cookies back is the
	 * same order as we sent them.
	 */
	if (strncmp(env_vars.http_cookie, "session_id", 10) == 0)
		snprintf(session_id, sizeof(session_id), "%s",
						env_vars.http_cookie + 11);
	else
		snprintf(session_id, sizeof(session_id), "%s",
						env_vars.http_cookie + 88);

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOREADER | TDBOWRITER);

	/* Get the users stored session */
	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ, session_id);
	res = tctdbqrysearch(qry);

	rbuf = tclistval(res, 0, &rsize);
	cols = tctdbget(tdb, rbuf, rsize);
	tcmapiterinit(cols);

	user_session.sid = atoi(tcmapget2(cols, "sid"));
	user_session.uid = atoi(tcmapget2(cols, "uid"));
	user_session.username = strdup(tcmapget2(cols, "username"));
	user_session.name = strdup(tcmapget2(cols, "name"));
	user_session.login_at = atol(tcmapget2(cols, "login_at"));
	user_session.last_seen = time(NULL);
	user_session.origin_ip = strdup(tcmapget2(cols, "origin_ip"));
	user_session.client_id = strdup(tcmapget2(cols, "client_id"));
	user_session.session_id = strdup(tcmapget2(cols, "session_id"));
	user_session.restrict_ip = atoi(tcmapget2(cols, "restrict_ip"));
	user_session.capabilities = atoi(tcmapget2(cols, "capabilities"));

	tcmapdel(cols);
	tclistdel(res);
	tctdbqrydel(qry);

	/*
	 * Set the user header banner, which displays the users name, uid and
	 * whether they are an Approver and or Admin.
	 */
	xss_string = xss_safe_string(user_session.name);
	snprintf(user_hdr, sizeof(user_hdr), "<big><big> %s</big></big><small>"
				"<span class = \"lighter\"> (%d) </span>"
				"</small>", xss_string, user_session.uid);
	free(xss_string);
	if (user_session.capabilities & APPROVER &&
					user_session.capabilities & ADMIN)
		strncat(user_hdr, "<span class = \"t_red\">(Approver / Admin)"
					"</span>", 1024 - strlen(user_hdr));
	else if (user_session.capabilities & APPROVER)
		strncat(user_hdr, "<span class = \"t_red\">(Approver)"
					"</span>", 1024 - strlen(user_hdr));
	else if (user_session.capabilities & ADMIN)
		strncat(user_hdr, "<span class = \"t_red\">(Admin)"
					"</span>", 1024 - strlen(user_hdr));
	strncat(user_hdr, "&nbsp;", 1024 - strlen(user_hdr));
	user_session.user_hdr = strdup(user_hdr);

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
	snprintf(login_at, sizeof(login_at), "%ld", user_session.login_at);
	snprintf(last_seen, sizeof(last_seen), "%ld",
						user_session.last_seen);
	snprintf(uid, sizeof(uid), "%u", user_session.uid);
	snprintf(sid, sizeof(sid), "%u", user_session.sid);
	snprintf(restrict_ip, sizeof(restrict_ip), "%d",
						user_session.restrict_ip);
	snprintf(capabilities, sizeof(capabilities), "%d",
						user_session.capabilities);
	cols = tcmapnew3("sid", sid, "uid", uid, "username",
				user_session.username, "name",
				user_session.name, "login_at",
				login_at, "last_seen", last_seen, "origin_ip",
				user_session.origin_ip, "client_id",
				user_session.client_id, "session_id",
				user_session.session_id, "restrict_ip",
				restrict_ip, "capabilities", capabilities,
				NULL);
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
	ssize_t bytes_read;
	char buf[1024];
	char shash[65];
	unsigned char *hash;
	char ht[3];
	MHASH td;

	fd = open("/dev/urandom", O_RDONLY);
	bytes_read = read(fd, buf, 1024);
	close(fd);
	/*
	 * If we couldn't read the required amount, something is
	 * seriously wrong. Log it and exit.
	 */
	if (bytes_read < 1024) {
		d_fprintf(error_log, "Couldn't read sufficient data from "
							"/dev/urandom\n");
		_exit(EXIT_FAILURE);
	}

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
void create_session(unsigned int sid)
{
	char *session_id;
	char restrict_ip[2] = "0\0";
	char sql[SQL_MAX];
	char pkbuf[256];
	char timestamp[21];
	char ssid[11];
	char *username;
	int primary_key_size;
	MYSQL *conn;
	MYSQL_RES *res;
	TCTDB *tdb;
	TCMAP *cols;
	GHashTable *db_row = NULL;

	conn = db_conn();

	username = alloca(strlen(get_var(qvars, "username")) * 2 + 1);
	mysql_real_escape_string(conn, username, get_var(
						qvars, "username"),
						strlen(get_var(qvars,
						"username")));
	snprintf(sql, SQL_MAX, "SELECT uid, name, capabilities FROM passwd "
						"WHERE username = '%s'",
						username);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	db_row = get_dbrow(res);

	session_id = create_session_id();

	if (strcmp(get_var(qvars, "restrict_ip"), "true") == 0) {
		d_fprintf(debug_log, "Restricting session to origin ip "
								"address\n");
		restrict_ip[0] = '1';
	}

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOWRITER | TDBOCREAT);
	primary_key_size = sprintf(pkbuf, "%ld", (long)tctdbgenuid(tdb));
	snprintf(timestamp, sizeof(timestamp), "%ld", (long)time(NULL));
	snprintf(ssid, sizeof(ssid), "%u", sid);
	cols = tcmapnew3("sid", ssid, "uid", get_var(db_row, "uid"),
					"username", get_var(qvars, "username"),
					"name", get_var(db_row, "name"),
					"login_at", timestamp,
					"last_seen", timestamp, "origin_ip",
					env_vars.http_x_forwarded_for,
					"client_id", env_vars.http_user_agent,
					"session_id", session_id,
					"restrict_ip", restrict_ip,
					"capabilities", get_var(db_row,
					"capabilities"), NULL);
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
 * Set the default tag field names.
 */
void set_default_field_names(struct field_names *fields)
{
	fields->receipt_date = strdup(DFN_RECEIPT_DATE);
	fields->department = strdup(DFN_DEPARTMENT);
	fields->employee_number = strdup(DFN_EMPLOYEE_NUMBER);
	fields->reason = strdup(DFN_REASON);
	fields->po_num = strdup(DFN_PO_NUM);
	fields->cost_codes = strdup(DFN_COST_CODES);
	fields->account_codes = strdup(DFN_ACCOUNT_CODES);
	fields->supplier_name = strdup(DFN_SUPPLIER_NAME);
	fields->supplier_town = strdup(DFN_SUPPLIER_TOWN);
	fields->vat_number = strdup(DFN_VAT_NUMBER);
	fields->gross_amount = strdup(DFN_GROSS_AMOUNT);
	fields->net_amount = strdup(DFN_NET_AMOUNT);
	fields->vat_amount = strdup(DFN_VAT_AMOUNT);
	fields->vat_rate = strdup(DFN_VAT_RATE);
	fields->currency = strdup(DFN_CURRENCY);
	fields->payment_method = strdup(DFN_PAYMENT_METHOD);
}

/*
 * Get the users custom image tag field names for display.
 */
void set_custom_field_names(struct field_names *fields)
{
	char sql[SQL_MAX];
	MYSQL *conn;
	MYSQL_RES *res;
	GHashTable *db_row = NULL;

	set_default_field_names(fields);

	conn = db_conn();
	snprintf(sql, SQL_MAX, "SELECT * FROM field_names WHERE uid = %u",
							user_session.uid);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_query(conn, sql);
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) < 1)
		goto out;

	db_row = get_dbrow(res);

	if (strlen(get_var(db_row, "receipt_date")) > 0) {
		free(fields->receipt_date);
		fields->receipt_date = strdup(get_var(db_row, "receipt_date"));
	}
	if (strlen(get_var(db_row, "department")) > 0) {
		free(fields->department);
		fields->department = strdup(get_var(db_row, "department"));
	}
	if (strlen(get_var(db_row, "employee_number")) > 0) {
		free(fields->employee_number);
		fields->employee_number = strdup(get_var(db_row,
							"employee_number"));
	}
	if (strlen(get_var(db_row, "reason")) > 0) {
		free(fields->reason);
		fields->reason = strdup(get_var(db_row, "reason"));
	}
	if (strlen(get_var(db_row, "po_num")) > 0) {
		free(fields->po_num);
		fields->po_num = strdup(get_var(db_row, "po_num"));
	}
	if (strlen(get_var(db_row, "cost_codes")) > 0) {
		free(fields->cost_codes);
		fields->cost_codes = strdup(get_var(db_row, "cost_codes"));
	}
	if (strlen(get_var(db_row, "account_codes")) > 0) {
		free(fields->account_codes);
		fields->account_codes = strdup(get_var(db_row,
							"account_codes"));
	}
	if (strlen(get_var(db_row, "supplier_name")) > 0) {
		free(fields->supplier_name);
		fields->supplier_name = strdup(get_var(db_row,
							"supplier_name"));
	}
	if (strlen(get_var(db_row, "supplier_town")) > 0) {
		free(fields->supplier_town);
		fields->supplier_town = strdup(get_var(db_row,
							"supplier_town"));
	}
	if (strlen(get_var(db_row, "vat_number")) > 0) {
		free(fields->vat_number);
		fields->vat_number = strdup(get_var(db_row, "vat_number"));
	}
	if (strlen(get_var(db_row, "gross_amount")) > 0) {
		free(fields->gross_amount);
		fields->gross_amount = strdup(get_var(db_row, "gross_amount"));
	}
	if (strlen(get_var(db_row, "net_amount")) > 0) {
		free(fields->net_amount);
		fields->net_amount = strdup(get_var(db_row, "net_amount"));
	}
	if (strlen(get_var(db_row, "vat_amount")) > 0) {
		free(fields->vat_amount);
		fields->vat_amount = strdup(get_var(db_row, "vat_amount"));
	}
	if (strlen(get_var(db_row, "vat_rate")) > 0) {
		free(fields->vat_rate);
		fields->vat_rate = strdup(get_var(db_row, "vat_rate"));
	}
	if (strlen(get_var(db_row, "currency")) > 0) {
		free(fields->currency);
		fields->currency = strdup(get_var(db_row, "currency"));
	}
	if (strlen(get_var(db_row, "payment_method")) > 0) {
		free(fields->payment_method);
		fields->payment_method = strdup(get_var(db_row,
							"payment_method"));
	}

	free_vars(db_row);

out:
	mysql_free_result(res);
	mysql_close(conn);
}

/*
 * Stores custom image tag field names for a user in the database.
 */
void update_fmap(void)
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

	conn = db_conn();

	username = alloca(strlen(user_session.username) * 2 + 1);
	mysql_real_escape_string(conn, username, user_session.username,
					strlen(user_session.username));

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

	snprintf(sql, SQL_MAX, "REPLACE INTO field_names VALUES (%u, '%s', "
					"'%s', '%s', '%s', '%s', '%s', '%s', "
					"'%s', '%s', '%s', '%s', '%s', "
					"'%s', '%s', '%s', '%s', '%s')",
					user_session.uid, username,
					receipt_date, department,
					employee_number, reason, po_num,
					cost_codes, account_codes,
					supplier_name, supplier_town,
					vat_number, gross_amount, net_amount,
					vat_amount, vat_rate, currency,
					payment_method);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));
	mysql_close(conn);
}

/*
 * Takes the form data from /process_receipt/ and enters it into the database.
 */
void tag_image(void)
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

	username = alloca(strlen(user_session.username) * 2 + 1);
	mysql_real_escape_string(conn, username, user_session.username,
					strlen(user_session.username));

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

	snprintf(sql, SQL_MAX, "REPLACE INTO tags VALUES ('%s', %u, '%s', "
				"%ld, '%s', '%s', '%s', '%s', '%s', '%s', "
				"'%s', '%s', %.2f, %.2f, %.2f, %.2f, '%s', "
				"%ld, '%s', '%s')",
				image_id, user_session.uid, username,
				time(NULL), employee_number, department,
				po_num, cost_codes, account_codes,
				supplier_town, supplier_name, currency,
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

/*
 * Add a new user to the system.
 */
int do_add_user(unsigned char capabilities)
{
	char sql[SQL_MAX];
	char *key;
	char *email_addr;
	char *name;
	int ret = 0;
	time_t tm;
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;

	/* Check if the user is already in the system. */
	if (user_already_exists(get_var(qvars, "email1"))) {
		ret = -10;
		goto out;
	}

	conn = db_conn();

	email_addr = alloca(strlen(get_var(qvars, "email1")) * 2 + 1);
	mysql_real_escape_string(conn, email_addr, get_var(qvars, "email1"),
					strlen(get_var(qvars, "email1")));
	name = alloca(strlen(get_var(qvars, "name")) * 2 + 1);
	mysql_real_escape_string(conn, name, get_var(qvars, "name"),
					strlen(get_var(qvars, "name")));

	key = generate_activation_key(email_addr);

	/* We need to be sure a new uid isn't inserted here */
	mysql_query(conn, "LOCK TABLES passwd WRITE");
	mysql_query(conn, "SELECT MAX(uid) FROM passwd");
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);

	snprintf(sql, SQL_MAX, "INSERT INTO passwd VALUES (%d, '%s', '!!', "
						"'%s', %d, 0, 0, '')",
						atoi(row[0]) + 1, email_addr,
						name, capabilities);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));
	mysql_query(conn, "UNLOCK TABLES");

	tm = time(NULL);
	snprintf(sql, SQL_MAX, "INSERT INTO activations VALUES ('%s', '%s', "
						"%ld)", email_addr, key,
						tm + 86400);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));

	send_activation_mail(name, email_addr, key);

	free(key);
	mysql_free_result(res);
	mysql_close(conn);

out:
	return ret;
}

/*
 * Update a users settings.
 */
void do_update_user(void)
{
	char sql[SQL_MAX];
	char *hash;
	char *username;
	char *name;
	char *d_reason;
	unsigned char capabilities = 0;
	unsigned int uid;
	int enabled = 0;
	int activated = 0;
	MYSQL *conn;

	conn = db_conn();
	uid = atoi(get_var(qvars, "uid"));

	if (strlen(get_var(qvars, "pass1")) > 0) {
		hash = generate_password_hash(SHA512, get_var(qvars, "pass1"));
	} else {
		MYSQL_RES *res;
		MYSQL_ROW row;

		snprintf(sql, SQL_MAX, "SELECT password FROM passwd WHERE "
							"uid = %u", uid);
		d_fprintf(sql_log, "%s\n", sql);
		mysql_query(conn, sql);
		res = mysql_store_result(conn);
		row = mysql_fetch_row(res);
		hash = malloc(strlen(row[0]) + 1);
		if (!hash) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(hash, strlen(row[0]) + 1, "%s", row[0]);
		mysql_free_result(res);
	}

	username = alloca(strlen(get_var(qvars, "email1")) * 2 + 1);
	mysql_real_escape_string(conn, username, get_var(qvars, "email1"),
					strlen(get_var(qvars, "email1")));
	name = alloca(strlen(get_var(qvars, "name")) * 2 + 1);
	mysql_real_escape_string(conn, name, get_var(qvars, "name"),
					strlen(get_var(qvars, "name")));
	d_reason = alloca(strlen(get_var(qvars, "d_reason")) * 2 + 1);
	mysql_real_escape_string(conn, d_reason, get_var(qvars, "d_reason"),
					strlen(get_var(qvars, "d_reason")));

	if (strlen(get_var(qvars, "ap_card")) > 0 ||
				strlen(get_var(qvars, "ap_cash")) > 0 ||
				strlen(get_var(qvars, "ap_cheque")) > 0 ||
				strlen(get_var(qvars, "ap_self")) > 0) {
		capabilities |= APPROVER;
		if (strlen(get_var(qvars, "ap_card")) > 0)
			capabilities |= APPROVER_CARD;
		if (strlen(get_var(qvars, "ap_cash")) > 0)
			capabilities |= APPROVER_CASH;
		if (strlen(get_var(qvars, "ap_cheque")) > 0)
			capabilities |= APPROVER_CHEQUE;
		if (strlen(get_var(qvars, "ap_self")) > 0)
			capabilities |= APPROVER_SELF;
	}
	if (strlen(get_var(qvars, "is_admin")) > 0)
		capabilities |= ADMIN;

	if (atoi(get_var(qvars, "enabled")) == 1)
		enabled = 1;
	if (atoi(get_var(qvars, "activated")) == 1)
		activated = 1;

	snprintf(sql, SQL_MAX, "REPLACE INTO passwd VALUES (%d, '%s', '%s', "
						"'%s', %d, %d, %d, '%s')",
						uid, username, hash, name,
						capabilities, enabled,
						activated, d_reason);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));

	mysql_close(conn);
	free(hash);

	if (!enabled)
		delete_user_session(uid);
}

/*
 * Update a users settings, by a user.
 */
void do_edit_user(void)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	TCMAP *cols;
	int rsize;
	int primary_key_size;
	char pkbuf[256];
	const char *rbuf;
	char sql[SQL_MAX];
	char login_at[21];
	char last_seen[21];
	char uid[11];
	char sid[11];
	char restrict_ip[2];
	char capabilities[4];
	char *hash;
	char *username;
	char *name;
	MYSQL *conn;

	conn = db_conn();

	if (strlen(get_var(qvars, "pass1")) > 0) {
		hash = generate_password_hash(SHA512, get_var(qvars, "pass1"));
	} else {
		MYSQL_RES *res;
		MYSQL_ROW row;

		snprintf(sql, SQL_MAX, "SELECT password FROM passwd WHERE "
							"uid = %u",
							user_session.uid);
		d_fprintf(sql_log, "%s\n", sql);
		mysql_query(conn, sql);
		res = mysql_store_result(conn);
		row = mysql_fetch_row(res);
		hash = malloc(strlen(row[0]) + 1);
		if (!hash) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(hash, strlen(row[0]) + 1, "%s", row[0]);
		mysql_free_result(res);
	}

	username = alloca(strlen(get_var(qvars, "email1")) * 2 + 1);
	mysql_real_escape_string(conn, username, get_var(qvars, "email1"),
					strlen(get_var(qvars, "email1")));
	name = alloca(strlen(get_var(qvars, "name")) * 2 + 1);
	mysql_real_escape_string(conn, name, get_var(qvars, "name"),
					strlen(get_var(qvars, "name")));

	snprintf(sql, SQL_MAX, "REPLACE INTO passwd VALUES (%d, '%s', '%s', "
						"'%s', %d, 1, 1, '')",
						user_session.uid, username,
						hash, name,
						user_session.capabilities);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));

	mysql_close(conn);
	free(hash);

	/*
	 * We want to update the users session.entry. This entails removing
	 * the old session first then storing the updated session.
	 */
	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOREADER | TDBOWRITER);

	snprintf(uid, sizeof(uid), "%u", user_session.uid);
	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "uid", TDBQCNUMEQ, uid);
	res = tctdbqrysearch(qry);
	rbuf = tclistval(res, 0, &rsize);
	tctdbout(tdb, rbuf, strlen(rbuf));

	tclistdel(res);
	tctdbqrydel(qry);

	primary_key_size = sprintf(pkbuf, "%ld", (long)tctdbgenuid(tdb));
	snprintf(sid, sizeof(sid), "%u", user_session.sid);
	snprintf(login_at, sizeof(login_at), "%ld", user_session.login_at);
	snprintf(last_seen, sizeof(last_seen), "%ld", time(NULL));
	snprintf(restrict_ip, sizeof(restrict_ip), "%d",
						user_session.restrict_ip);
	snprintf(capabilities, sizeof(capabilities), "%d",
						user_session.capabilities);
	name = alloca(strlen(get_var(qvars, "name")) + 1);
	sprintf(name, "%s", get_var(qvars, "name"));
	username = alloca(strlen(get_var(qvars, "email1")) + 1);
	sprintf(username, "%s", get_var(qvars, "email1"));
	cols = tcmapnew3("sid", sid, "uid", uid, "username", username,
				"name", name, "login_at", login_at,
				"last_seen", last_seen,
				"origin_ip", user_session.origin_ip,
				"client_id", user_session.client_id,
				"session_id", user_session.session_id,
				"restrict_ip", restrict_ip,
				"capabilities", capabilities, NULL);
	tctdbput(tdb, pkbuf, primary_key_size, cols);

	tcmapdel(cols);

	tctdbclose(tdb);
	tctdbdel(tdb);
}

/*
 * Activate a users account in the system.
 */
void do_activate_user(char *uid, char *key, char *password)
{
	char sql[SQL_MAX];
	char *hash;
	MYSQL *conn;

	hash = generate_password_hash(SHA512, password);

	conn = db_conn();
	snprintf(sql, SQL_MAX, "UPDATE passwd SET password = '%s', "
				"activated = 1, enabled = 1 WHERE uid = %s",
				hash, uid);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_query(conn, sql);

	snprintf(sql, SQL_MAX, "DELETE FROM activations WHERE akey = '%s'",
									key);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));

	mysql_close(conn);
	free(hash);
}

/*
 * Send the specified template to the user.
 */
void send_template(char *template, TMPL_varlist *varlist,
						TMPL_fmtlist *fmtlist)
{
	printf("Cache-Control: private\r\n");
	printf("Content-Type: text/html\r\n\r\n");
	TMPL_write(template, NULL, fmtlist, varlist, stdout, error_log);
	fflush(error_log);
}
