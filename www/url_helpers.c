/*
 * url_helpers.c
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU Affero General Public License version 3.
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
#include <netdb.h>

/* Hashing algorithms */
#include <mhash.h>

/* HTML template library */
#include <ctemplate.h>

#include <glib.h>

#include "common.h"
#include "utils.h"
#include "audit.h"

/*
 * Given a username return the real name, which should be free'd.
 */
char *username_to_name(const char *username)
{
	char *who;
	char *name;
	MYSQL_RES *res;
	MYSQL_ROW row;

	who = make_mysql_safe_string(username);
	res = sql_query("SELECT name FROM passwd WHERE username = '%s'", who);
	row = mysql_fetch_row(res);

	name = strdup(row[0]);

	mysql_free_result(res);
	free(who);

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
bool is_logged_in(void)
{
	char session_id[SID_LEN + 1];
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	TCMAP *cols;
	int rsize;
	const char *rbuf;
	bool login_ok = false;

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
					env_vars.remote_addr) != 0)
			goto out;
	}
	/* client_id */
	if (strcmp(tcmapget2(cols, "client_id"),
					env_vars.http_user_agent) != 0)
		goto out;

	/* We got here, all checks are OK */
	login_ok = true;

out:
	tcmapdel(cols);
out2:
	tctdbqrydel(qry);
	tclistdel(res);
	tctdbclose(tdb);
	tctdbdel(tdb);
out3:
	return login_ok;
}

/*
 * Authenticates the user. Takes their password, crypt()'s it using
 * the salt from their password entry and compares the result with
 * their stored password.
 */
int check_auth(void)
{
	int ret = -1;
	char *username;
	char *enc_passwd;
	MYSQL_RES *res;
	MYSQL_ROW row;

	username = make_mysql_safe_string(get_var(qvars, "username"));
	res = sql_query("SELECT password, enabled FROM passwd WHERE username "
			"= '%s'", username);
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
	free(username);

	return ret;
}

/*
 * Checks that an image/receipt id belongs to a specified user.
 */
bool is_users_receipt(const char *id)
{
	char *s_id;
	MYSQL_RES *res;
	bool users_recpt = false;

	s_id = make_mysql_safe_string(id);
	res = sql_query("SELECT id FROM images WHERE id = '%s' AND uid = %u",
			s_id, user_session.uid);
	if (mysql_num_rows(res) > 0)
		users_recpt = true;

	mysql_free_result(res);
	free(s_id);

	return users_recpt;
}

/*
 * Checks the users permission to access receipt tag information.
 */
bool tag_info_allowed(const char *image_id)
{
	char *s_image_id;
	bool tag_allowed = false;
	MYSQL_RES *res;

	/* Approvers can see all tags */
	if (IS_APPROVER()) {
		tag_allowed = true;
		goto out;
	}

	s_image_id = make_mysql_safe_string(image_id);
	res = sql_query("SELECT path FROM images WHERE id = '%s' AND uid = %u",
			s_image_id, user_session.uid);
	if (mysql_num_rows(res) > 0)
		tag_allowed = true;

	mysql_free_result(res);
	free(s_image_id);

out:
	return tag_allowed;
}

/*
 * Determine if access to an image is allowed. It checks for /[tenant/]UID/
 * at the start of the image path after IMAGE_PATH.
 */
bool image_access_allowed(const char *path)
{
	bool access_allowed = false;
	char userdir[PATH_MAX];

	memset(userdir, 0, sizeof(userdir));
	snprintf(userdir, sizeof(userdir), "/%s%s%u/",
			(MULTI_TENANT) ? user_session.tenant : "",
			(MULTI_TENANT) ? "/" : "", user_session.uid);

	/* In a non-multi-tenant, approvers can see all images */
	if (IS_APPROVER() && !MULTI_TENANT) {
		access_allowed = true;
	} else if (IS_APPROVER()) {
		char *str;
		char *ptenant;

		str = strdupa(path + strlen(IMAGE_PATH) + 1);
		ptenant = strsep(&str, "/");
		if (ptenant && strcmp(ptenant, user_session.tenant) == 0)
			access_allowed = true;
	} else if (strncmp(path + strlen(IMAGE_PATH), userdir,
				strlen(userdir)) == 0) {
		access_allowed = true;
	}

	return access_allowed;
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
	char session_id[SID_LEN + 1];
	char login_at[21];
	char last_seen[21];
	char uid[11];
	char sid[21];
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

	memset(&user_session, 0, sizeof(user_session));
	snprintf(user_session.tenant, sizeof(user_session.tenant), "%s",
			tcmapget2(cols, "tenant"));
	user_session.sid = strtoull(tcmapget2(cols, "sid"), NULL, 10);
	user_session.uid = atoi(tcmapget2(cols, "uid"));
	user_session.username = strdup(tcmapget2(cols, "username"));
	user_session.name = strdup(tcmapget2(cols, "name"));
	user_session.login_at = atol(tcmapget2(cols, "login_at"));
	user_session.last_seen = time(NULL);
	snprintf(user_session.origin_ip, sizeof(user_session.origin_ip), "%s",
			tcmapget2(cols, "origin_ip"));
	user_session.client_id = strdup(tcmapget2(cols, "client_id"));
	snprintf(user_session.session_id, sizeof(user_session.session_id),
			"%s", tcmapget2(cols, "session_id"));
	snprintf(user_session.csrf_token, sizeof(user_session.csrf_token),
			"%s", tcmapget2(cols, "csrf_token"));
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
	if (IS_APPROVER() && IS_ADMIN())
		strncat(user_hdr, "<span class = \"t_red\">(Approver / Admin)"
					"</span>", 1024 - strlen(user_hdr));
	else if (IS_APPROVER())
		strncat(user_hdr, "<span class = \"t_red\">(Approver)"
					"</span>", 1024 - strlen(user_hdr));
	else if (IS_ADMIN())
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
	snprintf(sid, sizeof(sid), "%llu", user_session.sid);
	snprintf(restrict_ip, sizeof(restrict_ip), "%d",
						user_session.restrict_ip);
	snprintf(capabilities, sizeof(capabilities), "%d",
						user_session.capabilities);
	cols = tcmapnew3("tenant", user_session.tenant,
			"sid", sid,
			"uid", uid,
			"username", user_session.username,
			"name", user_session.name,
			"login_at", login_at,
			"last_seen", last_seen,
			"origin_ip", user_session.origin_ip,
			"client_id", user_session.client_id,
			"session_id", user_session.session_id,
			"csrf_token", user_session.csrf_token,
			"restrict_ip", restrict_ip,
			"capabilities", capabilities,
			NULL);
	tctdbput(tdb, pkbuf, primary_key_size, cols);

	tcmapdel(cols);

	tctdbclose(tdb);
	tctdbdel(tdb);
}

/*
 * Generate a session_id used to identify a users session.
 * It generates a SHA-256 from random data.
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
 * This will create a SHA-256 token for use in forms to help prevent
 * against CSRF attacks.
 */
static void generate_csrf_token(char *csrf_token)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	TCMAP *cols;
	int rsize;
	int primary_key_size;
	char pkbuf[256];
	char login_at[21];
	char last_seen[21];
	char uid[11];
	char sid[21];
	char restrict_ip[2];
	char capabilities[4];
	const char *rbuf;

	/*
	 * We want to set a new CSRF token in the users session.
	 * This entails removing the old session first then storing
	 * the new updated session.
	 */
	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOREADER | TDBOWRITER);

	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ,
						user_session.session_id);
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
	snprintf(sid, sizeof(sid), "%llu", user_session.sid);
	snprintf(restrict_ip, sizeof(restrict_ip), "%d",
						user_session.restrict_ip);
	snprintf(capabilities, sizeof(capabilities), "%d",
						user_session.capabilities);
	generate_hash(csrf_token, SHA256);
	cols = tcmapnew3("tenant", user_session.tenant,
			"sid", sid,
			"uid", uid,
			"username", user_session.username,
			"name", user_session.name,
			"login_at", login_at,
			"last_seen", last_seen,
			"origin_ip", user_session.origin_ip,
			"client_id", user_session.client_id,
			"session_id", user_session.session_id,
			"csrf_token", csrf_token,
			"restrict_ip", restrict_ip,
			"capabilities", capabilities,
			NULL);
	tctdbput(tdb, pkbuf, primary_key_size, cols);

	tcmapdel(cols);

	tctdbclose(tdb);
	tctdbdel(tdb);
}

/*
 * Given a template varlist, this will add a csrf token variable.
 */
void add_csrf_token(TMPL_varlist *varlist)
{
	char csrf_token[CSRF_LEN + 1];

	generate_csrf_token(csrf_token);
	varlist = TMPL_add_var(varlist, "csrf_token", csrf_token,
							(char *)NULL);
}

/*
 * Checks if a valid csrf token has been presented.
 *
 * Returns:
 *	true, for yes
 *	false, for no
 */
bool valid_csrf_token(void)
{
	if (strcmp(get_var(qvars, "csrf_token"),
				user_session.csrf_token) == 0)
		return true;
	else
		return false;
}

/*
 * Adds last login information to the page. Time and location of
 * last login.
 *
 * If this is the users first login, then "First login" is simply
 * displayed.
 */
void display_last_login(TMPL_varlist *varlist)
{
	char host[NI_MAXHOST];
	time_t login;

	login = get_last_login(host);
	if (login > 0) {
		char tbuf[32];

		strftime(tbuf, 32, "%a %b %e %H:%M %Y", localtime(&login));
		varlist = add_html_var(varlist, "last_login", tbuf);
		varlist = add_html_var(varlist, "last_login_from", host);
	} else {
		varlist = add_html_var(varlist, "last_login", "First login");
	}
}

/*
 * Create a new user session. This is done upon each successful login.
 */
void create_session(unsigned long long sid)
{
	char session_id[SID_LEN + 1];
	char restrict_ip[2] = "0\0";
	char pkbuf[256];
	char timestamp[21];
	char ssid[21];
	char tenant[TENANT_MAX + 1];
	char *username;
	int primary_key_size;
	MYSQL_RES *res;
	TCTDB *tdb;
	TCMAP *cols;
	GHashTable *db_row = NULL;

	username = make_mysql_safe_string(get_var(qvars, "username"));
	res = sql_query("SELECT uid, name, capabilities FROM passwd WHERE "
			"username = '%s'", username);
	db_row = get_dbrow(res);

	get_tenant(env_vars.host, tenant);
	generate_hash(session_id, SHA256);

	if (strcmp(get_var(qvars, "restrict_ip"), "true") == 0) {
		d_fprintf(debug_log, "Restricting session to origin ip "
								"address\n");
		restrict_ip[0] = '1';
	}

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOWRITER | TDBOCREAT);
	primary_key_size = sprintf(pkbuf, "%ld", (long)tctdbgenuid(tdb));
	snprintf(timestamp, sizeof(timestamp), "%ld", (long)time(NULL));
	snprintf(ssid, sizeof(ssid), "%llu", sid);
	cols = tcmapnew3("tenant", tenant,
			"sid", ssid,
			"uid", get_var(db_row, "uid"),
			"username", get_var(qvars, "username"),
			"name", get_var(db_row, "name"),
			"login_at", timestamp,
			"last_seen", timestamp,
			"origin_ip", env_vars.remote_addr,
			"client_id", env_vars.http_user_agent,
			"session_id", session_id,
			"csrf_token", "\0",
			"restrict_ip", restrict_ip,
			"capabilities", get_var(db_row, "capabilities"),
			NULL);
	tctdbput(tdb, pkbuf, primary_key_size, cols);
	tcmapdel(cols);
	tctdbclose(tdb);
	tctdbdel(tdb);

	printf("Set-Cookie: session_id=%s; path=/; httponly\r\n", session_id);

	mysql_free_result(res);
	free_vars(db_row);
	free(username);
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
void set_default_field_names(void)
{
	fields.receipt_date = strdup(DFN_RECEIPT_DATE);
	fields.department = strdup(DFN_DEPARTMENT);
	fields.employee_number = strdup(DFN_EMPLOYEE_NUMBER);
	fields.reason = strdup(DFN_REASON);
	fields.po_num = strdup(DFN_PO_NUM);
	fields.cost_codes = strdup(DFN_COST_CODES);
	fields.account_codes = strdup(DFN_ACCOUNT_CODES);
	fields.supplier_name = strdup(DFN_SUPPLIER_NAME);
	fields.supplier_town = strdup(DFN_SUPPLIER_TOWN);
	fields.vat_number = strdup(DFN_VAT_NUMBER);
	fields.gross_amount = strdup(DFN_GROSS_AMOUNT);
	fields.net_amount = strdup(DFN_NET_AMOUNT);
	fields.vat_amount = strdup(DFN_VAT_AMOUNT);
	fields.vat_rate = strdup(DFN_VAT_RATE);
	fields.currency = strdup(DFN_CURRENCY);
	fields.payment_method = strdup(DFN_PAYMENT_METHOD);
}

/*
 * Get the users custom image tag field names for display.
 */
void set_custom_field_names(void)
{
	MYSQL_RES *res;
	GHashTable *db_row = NULL;

	set_default_field_names();

	res = sql_query("SELECT * FROM field_names WHERE uid = %u",
			user_session.uid);
	if (mysql_num_rows(res) < 1)
		goto out;

	db_row = get_dbrow(res);

	if (IS_SET(get_var(db_row, "receipt_date"))) {
		free(fields.receipt_date);
		fields.receipt_date = strdup(get_var(db_row, "receipt_date"));
	}
	if (IS_SET(get_var(db_row, "department"))) {
		free(fields.department);
		fields.department = strdup(get_var(db_row, "department"));
	}
	if (IS_SET(get_var(db_row, "employee_number"))) {
		free(fields.employee_number);
		fields.employee_number = strdup(get_var(db_row,
					"employee_number"));
	}
	if (IS_SET(get_var(db_row, "reason"))) {
		free(fields.reason);
		fields.reason = strdup(get_var(db_row, "reason"));
	}
	if (IS_SET(get_var(db_row, "po_num"))) {
		free(fields.po_num);
		fields.po_num = strdup(get_var(db_row, "po_num"));
	}
	if (IS_SET(get_var(db_row, "cost_codes"))) {
		free(fields.cost_codes);
		fields.cost_codes = strdup(get_var(db_row, "cost_codes"));
	}
	if (IS_SET(get_var(db_row, "account_codes"))) {
		free(fields.account_codes);
		fields.account_codes = strdup(get_var(db_row,
					"account_codes"));
	}
	if (IS_SET(get_var(db_row, "supplier_name"))) {
		free(fields.supplier_name);
		fields.supplier_name = strdup(get_var(db_row,
					"supplier_name"));
	}
	if (IS_SET(get_var(db_row, "supplier_town"))) {
		free(fields.supplier_town);
		fields.supplier_town = strdup(get_var(db_row,
					"supplier_town"));
	}
	if (IS_SET(get_var(db_row, "vat_number"))) {
		free(fields.vat_number);
		fields.vat_number = strdup(get_var(db_row, "vat_number"));
	}
	if (IS_SET(get_var(db_row, "gross_amount"))) {
		free(fields.gross_amount);
		fields.gross_amount = strdup(get_var(db_row, "gross_amount"));
	}
	if (IS_SET(get_var(db_row, "net_amount"))) {
		free(fields.net_amount);
		fields.net_amount = strdup(get_var(db_row, "net_amount"));
	}
	if (IS_SET(get_var(db_row, "vat_amount"))) {
		free(fields.vat_amount);
		fields.vat_amount = strdup(get_var(db_row, "vat_amount"));
	}
	if (IS_SET(get_var(db_row, "vat_rate"))) {
		free(fields.vat_rate);
		fields.vat_rate = strdup(get_var(db_row, "vat_rate"));
	}
	if (IS_SET(get_var(db_row, "currency"))) {
		free(fields.currency);
		fields.currency = strdup(get_var(db_row, "currency"));
	}
	if (IS_SET(get_var(db_row, "payment_method"))) {
		free(fields.payment_method);
		fields.payment_method = strdup(get_var(db_row,
					"payment_method"));
	}

	free_vars(db_row);

out:
	mysql_free_result(res);
}

/*
 * Stores custom image tag field names for a user in the database.
 */
void update_fmap(void)
{
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

	username = make_mysql_safe_string(user_session.username);
	receipt_date = make_mysql_safe_string(get_var(qvars, "receipt_date"));
	department = make_mysql_safe_string(get_var(qvars, "department"));
	employee_number = make_mysql_safe_string(
			get_var(qvars, "employee_number"));
	reason = make_mysql_safe_string(get_var(qvars, "reason"));
	po_num = make_mysql_safe_string(get_var(qvars, "po_num"));
	cost_codes = make_mysql_safe_string(get_var(qvars, "cost_codes"));
	account_codes = make_mysql_safe_string(
			get_var(qvars, "account_codes"));
	supplier_name = make_mysql_safe_string(
			get_var(qvars, "supplier_name"));
	supplier_town = make_mysql_safe_string(
			get_var(qvars, "supplier_town"));
	vat_number = make_mysql_safe_string(get_var(qvars, "vat_number"));
	gross_amount = make_mysql_safe_string(get_var(qvars, "gross_amount"));
	net_amount = make_mysql_safe_string(get_var(qvars, "net_amount"));
	vat_amount = make_mysql_safe_string(get_var(qvars, "vat_amount"));
	vat_rate = make_mysql_safe_string(get_var(qvars, "vat_rate"));
	currency = make_mysql_safe_string(get_var(qvars, "currency"));
	payment_method = make_mysql_safe_string(
			get_var(qvars, "payment_method"));

	sql_query("REPLACE INTO field_names VALUES (%u, '%s', '%s', '%s', "
			"'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', "
			"'%s', '%s', '%s', '%s', '%s', '%s')",
			user_session.uid, username, receipt_date, department,
			employee_number, reason, po_num, cost_codes,
			account_codes, supplier_name, supplier_town,
			vat_number, gross_amount, net_amount, vat_amount,
			vat_rate, currency, payment_method);
	free(username);
	free(receipt_date);
	free(department);
	free(employee_number);
	free(reason);
	free(po_num);
	free(cost_codes);
	free(account_codes);
	free(supplier_name);
	free(supplier_town);
	free(vat_number);
	free(gross_amount);
	free(net_amount);
	free(vat_amount);
	free(vat_rate);
	free(currency);
	free(payment_method);
}

/*
 * Takes the form data from /process_receipt/ and enters it into the database.
 */
void tag_image(void)
{
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
	double gross_amount;
	double vat_amount;
	double net_amount;
	double vat_rate;
	char *vat_number;
	char *reason;
	char *payment_method;
	struct tm tm;
	char secs[11];

	image_id = make_mysql_safe_string(get_var(qvars, "image_id"));
	username = make_mysql_safe_string(user_session.username);
	employee_number = make_mysql_safe_string(
			get_var(qvars, "employee_number"));
	department = make_mysql_safe_string(get_var(qvars, "department"));
	po_num = make_mysql_safe_string(get_var(qvars, "po_num"));
	cost_codes = make_mysql_safe_string(get_var(qvars, "cost_codes"));
	account_codes = make_mysql_safe_string(
			get_var(qvars, "account_codes"));
	supplier_town = make_mysql_safe_string(
			get_var(qvars, "supplier_town"));
	supplier_name = make_mysql_safe_string(
			get_var(qvars, "supplier_name"));
	currency = make_mysql_safe_string(get_var(qvars, "currency"));
	gross_amount = strtod(get_var(qvars, "gross_amount"), NULL);
	vat_amount = strtod(get_var(qvars, "vat_amount"), NULL);
	net_amount = strtod(get_var(qvars, "net_amount"), NULL);
	vat_rate = strtod(get_var(qvars, "vat_rate"), NULL);
	vat_number = make_mysql_safe_string(get_var(qvars, "vat_number"));
	reason = make_mysql_safe_string(get_var(qvars, "reason"));

	memset(&tm, 0, sizeof(tm));
	strptime(get_var(qvars, "receipt_date"), "%Y-%m-%d", &tm);
	strftime(secs, sizeof(secs), "%s", &tm);

	payment_method = make_mysql_safe_string(
			get_var(qvars, "payment_method"));

	sql_query("REPLACE INTO tags VALUES ('%s', %u, '%s', %ld, '%s', "
				"'%s', '%s', '%s', '%s', '%s', '%s', '%s', "
				"%.2f, %.2f, %.2f, %.2f, '%s', %ld, '%s', "
				"'%s')",
				image_id, user_session.uid, username,
				time(NULL), employee_number, department,
				po_num, cost_codes, account_codes,
				supplier_town, supplier_name, currency,
				gross_amount, vat_amount, net_amount,
				vat_rate, vat_number, atol(secs), reason,
				payment_method);
	sql_query("UPDATE images SET tagged = 1 WHERE id = '%s'", image_id);

	free(image_id);
	free(username);
	free(employee_number);
	free(department);
	free(po_num);
	free(cost_codes);
	free(account_codes);
	free(supplier_town);
	free(supplier_name);
	free(currency);
	free(vat_number);
	free(reason);
	free(payment_method);
}

/*
 * Add a new user to the system.
 */
int do_add_user(unsigned char capabilities)
{
	char key[SHA256_LEN + 1];
	char *email_addr;
	char *name;
	int ret = 0;
	time_t tm;
	MYSQL_RES *res;
	MYSQL_ROW row;

	/* Check if the user is already in the system. */
	if (user_already_exists(get_var(qvars, "email1"))) {
		ret = -10;
		goto out;
	}

	email_addr = make_mysql_safe_string(get_var(qvars, "email1"));
	name = make_mysql_safe_string(get_var(qvars, "name"));

	generate_hash(key, SHA256);

	/* We need to be sure a new uid isn't inserted here */
	sql_query("LOCK TABLES passwd WRITE");
	res = sql_query("SELECT MAX(uid) FROM passwd");
	row = mysql_fetch_row(res);

	sql_query("INSERT INTO passwd VALUES (%d, '%s', '!!', '%s', %d, 0, 0, "
			"'')",
			atoi(row[0]) + 1, email_addr, name, capabilities);
	sql_query("UNLOCK TABLES");

	tm = time(NULL);
	sql_query("INSERT INTO activations VALUES ('%s', '%s', %ld)",
			email_addr, key, tm + KEY_EXP);

	send_activation_mail(name, email_addr, key);

	mysql_free_result(res);
	free(email_addr);
	free(name);

out:
	return ret;
}

/*
 * Update a users settings.
 */
void do_update_user(void)
{
	char *hash;
	char *username;
	char *name;
	char *d_reason;
	unsigned char capabilities = 0;
	unsigned int uid;
	int enabled = 0;
	int activated = 0;

	uid = atoi(get_var(qvars, "uid"));

	if (IS_SET(get_var(qvars, "pass1"))) {
		hash = generate_password_hash(SHA512, get_var(qvars, "pass1"));
	} else {
		MYSQL_RES *res;
		MYSQL_ROW row;

		res = sql_query("SELECT password FROM passwd WHERE uid = %u",
				uid);
		row = mysql_fetch_row(res);
		hash = malloc(strlen(row[0]) + 1);
		if (!hash) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(hash, strlen(row[0]) + 1, "%s", row[0]);
		mysql_free_result(res);
	}

	username = make_mysql_safe_string(get_var(qvars, "email1"));
	name = make_mysql_safe_string(get_var(qvars, "name"));
	d_reason = make_mysql_safe_string(get_var(qvars, "d_reason"));

	if (IS_SET(get_var(qvars, "ap_card")) ||
	    IS_SET(get_var(qvars, "ap_cash")) ||
	    IS_SET(get_var(qvars, "ap_cheque")) ||
	    IS_SET(get_var(qvars, "ap_self"))) {
		capabilities |= APPROVER;
		if (IS_SET(get_var(qvars, "ap_card")))
			capabilities |= APPROVER_CARD;
		if (IS_SET(get_var(qvars, "ap_cash")))
			capabilities |= APPROVER_CASH;
		if (IS_SET(get_var(qvars, "ap_cheque")))
			capabilities |= APPROVER_CHEQUE;
		if (IS_SET(get_var(qvars, "ap_self")))
			capabilities |= APPROVER_SELF;
	}
	if (IS_SET(get_var(qvars, "is_admin")))
		capabilities |= ADMIN;

	if (atoi(get_var(qvars, "enabled")) == 1)
		enabled = 1;
	if (atoi(get_var(qvars, "activated")) == 1)
		activated = 1;

	sql_query("REPLACE INTO passwd VALUES (%d, '%s', '%s', '%s', %d, %d, "
			"%d, '%s')",
			uid, username, hash, name, capabilities, enabled,
			activated, d_reason);

	free(hash);
	free(username);
	free(name);
	free(d_reason);

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
	char login_at[21];
	char last_seen[21];
	char uid[11];
	char sid[21];
	char restrict_ip[2];
	char capabilities[4];
	char *hash;
	char *username;
	char *name;

	if (IS_SET(get_var(qvars, "pass1"))) {
		hash = generate_password_hash(SHA512, get_var(qvars, "pass1"));
	} else {
		MYSQL_RES *res;
		MYSQL_ROW row;

		res = sql_query("SELECT password FROM passwd WHERE uid = %u",
				user_session.uid);
		row = mysql_fetch_row(res);
		hash = malloc(strlen(row[0]) + 1);
		if (!hash) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(hash, strlen(row[0]) + 1, "%s", row[0]);
		mysql_free_result(res);
	}

	username = make_mysql_safe_string(get_var(qvars, "email1"));
	name = make_mysql_safe_string(get_var(qvars, "name"));
	sql_query("REPLACE INTO passwd VALUES (%d, '%s', '%s', '%s', %d, 1, "
			"1, '')",
			user_session.uid, username, hash, name,
			user_session.capabilities);

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
	snprintf(sid, sizeof(sid), "%llu", user_session.sid);
	snprintf(login_at, sizeof(login_at), "%ld", user_session.login_at);
	snprintf(last_seen, sizeof(last_seen), "%ld", time(NULL));
	snprintf(restrict_ip, sizeof(restrict_ip), "%d",
						user_session.restrict_ip);
	snprintf(capabilities, sizeof(capabilities), "%d",
						user_session.capabilities);
	name = realloc(name, strlen(get_var(qvars, "name")) + 1);
	sprintf(name, "%s", get_var(qvars, "name"));
	username = realloc(username, strlen(get_var(qvars, "email1")) + 1);
	sprintf(username, "%s", get_var(qvars, "email1"));
	cols = tcmapnew3("tenant", user_session.tenant,
			"sid", sid,
			"uid", uid,
			"username", username,
			"name", name,
			"login_at", login_at,
			"last_seen", last_seen,
			"origin_ip", user_session.origin_ip,
			"client_id", user_session.client_id,
			"session_id", user_session.session_id,
			"csrf_token", user_session.csrf_token,
			"restrict_ip", restrict_ip,
			"capabilities", capabilities,
			NULL);
	tctdbput(tdb, pkbuf, primary_key_size, cols);

	tcmapdel(cols);

	tctdbclose(tdb);
	tctdbdel(tdb);
	free(username);
	free(name);
}

/*
 * Activate a users account in the system.
 */
void do_activate_user(const char *uid, const char *key, const char *password)
{
	char *hash;

	hash = generate_password_hash(SHA512, password);

	sql_query("UPDATE passwd SET password = '%s', activated = 1, "
			"enabled = 1 WHERE uid = %s", hash, uid);
	sql_query("DELETE FROM activations WHERE akey = '%s'", key);

	free(hash);
}

/*
 * Gather users receipts stats and set html template variables
 *
 * If the uid is < 0, then gather overall stats.
 *
 * Which is why uid is passed in as long long, when it is generally an
 * unsigned int, we need to be able to pass in -1, long long should cover
 * this and the max unsigned int value.
 */
void gather_receipt_stats_for_user(long long uid, TMPL_varlist *varlist)
{
	unsigned long i;
	unsigned long nr_rows;
	MYSQL_RES *res;
	TMPL_loop *loop = NULL;

	/* Total of approved receipts */
	if (uid > -1)
		res = sql_query("SELECT tags.currency, COUNT(*) AS "
				"nr_rows, SUM(tags.gross_amount) AS "
				"gross_total FROM images INNER JOIN tags ON "
				"(images.id = tags.id) WHERE images.uid = %u "
				"AND images.approved = %d GROUP BY currency",
				(unsigned int)uid, APPROVED);
	else
		res = sql_query("SELECT tags.currency, COUNT(*) AS "
				"nr_rows, SUM(tags.gross_amount) AS "
				"gross_total FROM images INNER JOIN tags ON "
				"(images.id = tags.id) WHERE "
				"images.approved = %d GROUP BY currency",
				APPROVED);
	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		GHashTable *db_row = NULL;
		TMPL_varlist *ll = NULL;

		db_row = get_dbrow(res);
		ll = add_html_var(ll, "nr_rows", get_var(db_row, "nr_rows"));
		ll = add_html_var(ll, "currency", get_var(db_row, "currency"));
		ll = add_html_var(ll, "total", get_var(db_row, "gross_total"));
		loop = TMPL_add_varlist(loop, ll);
		free_vars(db_row);
	}
	varlist = TMPL_add_loop(varlist, "approved", loop);
	mysql_free_result(res);

	/* Total of rejected receipts */
	if (uid > -1)
		res = sql_query("SELECT tags.currency, COUNT(*) AS "
				"nr_rows, SUM(tags.gross_amount) AS "
				"gross_total FROM images INNER JOIN tags ON "
				"(images.id = tags.id) WHERE images.uid = %u "
				"AND images.approved = %d GROUP BY currency",
				(unsigned int)uid, REJECTED);
	else
		res = sql_query("SELECT tags.currency, COUNT(*) AS "
				"nr_rows, SUM(tags.gross_amount) AS "
				"gross_total FROM images INNER JOIN tags ON "
				"(images.id = tags.id) WHERE "
				"images.approved = %d GROUP BY currency",
				REJECTED);
	nr_rows = mysql_num_rows(res);
	loop = NULL;
	for (i = 0; i < nr_rows; i++) {
		GHashTable *db_row = NULL;
		TMPL_varlist *ll = NULL;

		db_row = get_dbrow(res);
		ll = add_html_var(ll, "nr_rows", get_var(db_row, "nr_rows"));
		ll = add_html_var(ll, "currency", get_var(db_row, "currency"));
		ll = add_html_var(ll, "total", get_var(db_row, "gross_total"));
		loop = TMPL_add_varlist(loop, ll);
		free_vars(db_row);
	}
	varlist = TMPL_add_loop(varlist, "rejects", loop);
	mysql_free_result(res);

	/* Total of pending receipts */
	if (uid > -1)
		res = sql_query("SELECT tags.currency, COUNT(*) AS "
				"nr_rows, SUM(tags.gross_amount) AS "
				"gross_total FROM images INNER JOIN tags ON "
				"(images.id = tags.id) WHERE images.uid = %u "
				"AND images.approved = %d GROUP BY currency",
				(unsigned int)uid, PENDING);
	else
		res = sql_query("SELECT tags.currency, COUNT(*) AS "
				"nr_rows, SUM(tags.gross_amount) AS "
				"gross_total FROM images INNER JOIN tags ON "
				"(images.id = tags.id) WHERE "
				"images.approved = %d GROUP BY currency",
				PENDING);
	nr_rows = mysql_num_rows(res);
	loop = NULL;
	for (i = 0; i < nr_rows; i++) {
		GHashTable *db_row = NULL;
		TMPL_varlist *ll = NULL;

		db_row = get_dbrow(res);
		ll = add_html_var(ll, "nr_rows", get_var(db_row, "nr_rows"));
		ll = add_html_var(ll, "currency", get_var(db_row, "currency"));
		ll = add_html_var(ll, "total", get_var(db_row, "gross_total"));
		loop = TMPL_add_varlist(loop, ll);
		free_vars(db_row);
	}
	varlist = TMPL_add_loop(varlist, "pending", loop);
	mysql_free_result(res);

	/* Number of un-tagged receipts */
	if (uid > -1)
		res = sql_query("SELECT COUNT(*) AS nr_rows FROM images "
				"WHERE uid = %u AND tagged = 0",
				(unsigned int)uid);
	else
		res = sql_query("SELECT COUNT(*) AS nr_rows FROM images "
				"WHERE tagged = 0");
	if (mysql_num_rows(res) > 0) {
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		varlist = add_html_var(varlist, "untagged",
						get_var(db_row, "nr_rows"));
		free_vars(db_row);
	}
	mysql_free_result(res);
}

/*
 * Send the specified template to the user.
 */
void send_template(const char *template, TMPL_varlist *varlist,
						TMPL_fmtlist *fmtlist)
{
	printf("Cache-Control: private\r\n");
	printf("Content-Type: text/html\r\n\r\n");
	TMPL_write(template, NULL, fmtlist, varlist, stdout, error_log);
	fflush(error_log);
}

/*
 * Given a request URI and the URI we are checking for.
 * Return:
 *     true for a match and
 *     false for no match.
 */
bool match_uri(const char *request_uri, const char *match)
{
	size_t rlen;
	size_t mlen = strlen(match);
	const char *request;
	char *req = strdupa(request_uri);

	/*
	 * Handle URLs in the form /something/?key=value by stripping
	 * everything from the ? onwards and matching on the initial part.
	 */
	if (strchr(request_uri, '?'))
		request = strtok(req, "?");
	else
		request = request_uri;

	rlen = strlen(request);

	/*
	 * The image URLs are a bit different, we only want to match on
	 * the first /.../ part and they don't contain a ?.
	 */
	if (strstr(request, "/get_image/") && strstr(match, "/get_image/"))
		return true;
	else if (strncmp(request, match, mlen) == 0 && rlen == mlen)
		return true;
	else
		return false;
}
