/*
 * url_helpers.c
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
#include <stdint.h>
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
#include <flate.h>

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
 * Process changes to the list of pending account activations
 */
void process_activation_changes(void)
{
	unsigned int i;
	unsigned int list_size;

	list_size = g_list_length(avars);
	for (i = 0; i < list_size; i++) {
		const char *action = get_avar(i, "action");
		const char *akey = get_avar(i, "akey");

		if (strcmp(action, "leave") == 0) {
			continue;
		} else if (strcmp(action, "renew") == 0) {
			sql_query("UPDATE activations SET expires = '%ld'"
					"WHERE akey = '%s'",
					time(NULL) + KEY_EXP, akey);
		} else {
			sql_query("DELETE FROM activations WHERE akey = "
					"'%s' LIMIT 1", akey);
			sql_query("DELETE FROM passwd WHERE uid = %u LIMIT 1",
					atoi(get_avar(i, "uid")));
		}
	}
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
int do_add_user(u8 capabilities)
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

	sql_query("INSERT INTO passwd VALUES (%d, '%s', '!!', '%s', %u, 0, 0, "
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
	u8 capabilities = 0;
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

	sql_query("REPLACE INTO passwd VALUES (%d, '%s', '%s', '%s', %u, %d, "
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
		MYSQL_RES *mres;
		MYSQL_ROW row;

		mres = sql_query("SELECT password FROM passwd WHERE uid = %u",
				 user_session.uid);
		row = mysql_fetch_row(mres);
		hash = malloc(strlen(row[0]) + 1);
		if (!hash) {
			perror("malloc");
			exit(EXIT_FAILURE);
		}
		snprintf(hash, strlen(row[0]) + 1, "%s", row[0]);
		mysql_free_result(mres);
	}

	username = make_mysql_safe_string(get_var(qvars, "email1"));
	name = make_mysql_safe_string(get_var(qvars, "name"));
	sql_query("REPLACE INTO passwd VALUES (%d, '%s', '%s', '%s', %u, 1, "
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
	snprintf(capabilities, sizeof(capabilities), "%u",
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
 */
void gather_receipt_stats_for_user(unsigned int uid, int whom, Flate *f)
{
	unsigned long i;
	unsigned long nr_rows;
	MYSQL_RES *res;

	/* Total of approved receipts */
	if (whom == STATS_USER)
		res = sql_query("SELECT tags.currency, COUNT(*) AS "
				"nr_rows, SUM(tags.gross_amount) AS "
				"gross_total FROM images INNER JOIN tags ON "
				"(images.id = tags.id) WHERE images.uid = %u "
				"AND images.approved = %d GROUP BY currency",
				uid, APPROVED);
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

		db_row = get_dbrow(res);
		lf_set_var(f, "nr_rows", get_var(db_row, "nr_rows"), NULL);
		lf_set_var(f, "currency", get_var(db_row, "currency"), NULL);
		lf_set_var(f, "total", get_var(db_row, "gross_total"), NULL);
		lf_set_row(f, "approved");
		free_vars(db_row);
	}
	mysql_free_result(res);

	/* Total of rejected receipts */
	if (whom == STATS_USER)
		res = sql_query("SELECT tags.currency, COUNT(*) AS "
				"nr_rows, SUM(tags.gross_amount) AS "
				"gross_total FROM images INNER JOIN tags ON "
				"(images.id = tags.id) WHERE images.uid = %u "
				"AND images.approved = %d GROUP BY currency",
				uid, REJECTED);
	else
		res = sql_query("SELECT tags.currency, COUNT(*) AS "
				"nr_rows, SUM(tags.gross_amount) AS "
				"gross_total FROM images INNER JOIN tags ON "
				"(images.id = tags.id) WHERE "
				"images.approved = %d GROUP BY currency",
				REJECTED);
	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		lf_set_var(f, "nr_rows", get_var(db_row, "nr_rows"), NULL);
		lf_set_var(f, "currency", get_var(db_row, "currency"), NULL);
		lf_set_var(f, "total", get_var(db_row, "gross_total"), NULL);
		lf_set_row(f, "rejects");
		free_vars(db_row);
	}
	mysql_free_result(res);

	/* Total of pending receipts */
	if (whom == STATS_USER)
		res = sql_query("SELECT tags.currency, COUNT(*) AS "
				"nr_rows, SUM(tags.gross_amount) AS "
				"gross_total FROM images INNER JOIN tags ON "
				"(images.id = tags.id) WHERE images.uid = %u "
				"AND images.approved = %d GROUP BY currency",
				uid, PENDING);
	else
		res = sql_query("SELECT tags.currency, COUNT(*) AS "
				"nr_rows, SUM(tags.gross_amount) AS "
				"gross_total FROM images INNER JOIN tags ON "
				"(images.id = tags.id) WHERE "
				"images.approved = %d GROUP BY currency",
				PENDING);
	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		lf_set_var(f, "nr_rows", get_var(db_row, "nr_rows"), NULL);
		lf_set_var(f, "currency", get_var(db_row, "currency"), NULL);
		lf_set_var(f, "total", get_var(db_row, "gross_total"), NULL);
		lf_set_row(f, "pending");
		free_vars(db_row);
	}
	mysql_free_result(res);

	/* Number of un-tagged receipts */
	if (whom == STATS_USER)
		res = sql_query("SELECT COUNT(*) AS nr_rows FROM images "
				"WHERE uid = %u AND tagged = 0", uid);
	else
		res = sql_query("SELECT COUNT(*) AS nr_rows FROM images "
				"WHERE tagged = 0");
	if (mysql_num_rows(res) > 0) {
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		lf_set_var(f, "untagged", get_var(db_row, "nr_rows"), NULL);
		free_vars(db_row);
	}
	mysql_free_result(res);
}

/*
 * Send the specified template to the user.
 */
void send_template(Flate *f)
{
	fcgx_p("Cache-Control: private\r\n");
	lf_send(f, "text/html", fcgx_out);
	fflush(error_log);
}

/*
 * Wrapper around send_template() to just send a plain html page.
 */
void send_page(char *file)
{
	Flate *f = NULL;

	lf_set_tmpl(&f, file);
	send_template(f);
	lf_free(f);
}
