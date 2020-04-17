/*
 * url_handlers.c
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
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdbool.h>
#include <setjmp.h>

#include <mhash.h>

/* File magic library */
#include <magic.h>

#include <glib.h>

/* HTML template library */
#include <flate.h>

#include "common.h"
#include "utils.h"
#include "data_extraction.h"
#include "url_helpers.h"
#include "url_handlers.h"
#include "audit.h"
#include "csrf.h"

/*
 * /login/
 *
 * HTML is in templates/login.tmpl
 *
 * Display the login screen.
 */
static void login(void)
{
	int ret = 1;
	Flate *f = NULL;

	if (qvars) {
		ret = check_auth();
		if (ret == 0) {
			unsigned long long sid;

			sid = log_login();
			create_session(sid);
			fcgx_p("Location: /receipts/\r\n\r\n");
			return; /* Successful login */
		}
	}

	lf_set_tmpl(&f, "templates/login.tmpl");
	if (ret == -1)
		lf_set_var(f, "auth_fail", "", NULL);
	if (ret == -2)
		lf_set_var(f, "acc_disab", "", NULL);
	if (ret == -3)
		lf_set_var(f, "ipacl_deny", "", NULL);
	lf_set_var(f, "rip", env_vars.remote_addr, de_xss);

	send_template(f);
	lf_free(f);
}

/*
 * /logout/
 *
 * HTML is in templates/logout.tmpl
 *
 * Clean up a users session. Remove their entry from the sessions db and
 * set the session_id browser cookie to expired.
 */
static void logout(void)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	int rsize;
	const char *rbuf;

	tdb = tctdbnew();
	tctdbopen(tdb, cfg->session_db, TDBOWRITER);

	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "session_id", TDBQCSTREQ,
			user_session.session_id);
	res = tctdbqrysearch(qry);
	rbuf = tclistval(res, 0, &rsize);
	tctdbout(tdb, rbuf, strlen(rbuf));

	tclistdel(res);
	tctdbqrydel(qry);

	tctdbclose(tdb);
	tctdbdel(tdb);

	/* Immediately expire the session cookies */
	fcgx_p("Set-Cookie: session_id=deleted; "
	       "expires=Thu, 01 Jan 1970 00:00:01 GMT; path=/; httponly\r\n");
	send_page("templates/logout.tmpl");
}

/*
 * /delete_image/
 *
 * HTML is in templates/delete_image.tmpl
 *
 * Given an image_id, this will delete an image from the filesystem and
 * from the images table in the database.
 *
 * It will only delete images that are un-tagged.
 */
static void delete_image(void)
{
	char path[PATH_MAX];
	char image_path[PATH_MAX];
	char userdir[PATH_MAX];
	char *image_id;
	bool headers_sent = false;
	MYSQL_RES *res;
	GHashTable *db_row = NULL;
	Flate *f = NULL;

	if (!qvars)
		goto out2;

	image_id = make_mysql_safe_string(get_var(qvars, "image_id"));
	/* Only allow to delete images that are un-tagged */
	res = sql_query("SELECT path, name FROM images WHERE id = '%s' AND "
			"tagged = 0", image_id);
	if (mysql_num_rows(res) == 0)
		goto out1;

	db_row = get_dbrow(res);

	snprintf(path, PATH_MAX, "%s/%s/%s", cfg->image_path,
		 get_var(db_row, "path"), get_var(db_row, "name"));
	if (!realpath(path, image_path))
		goto out1;

	lf_set_tmpl(&f, "templates/delete_image.tmpl");
	lf_set_var(f, "image_path", get_var(db_row, "path"), NULL);
	lf_set_var(f, "image_name", get_var(db_row, "name"), NULL);
	lf_set_var(f, "image_id", get_var(qvars, "image_id"), NULL);

	memset(userdir, 0, sizeof(userdir));
	snprintf(userdir, sizeof(userdir), "/%s%s%u/",
		 cfg->multi_tenant ? user_session.tenant : "",
		 cfg->multi_tenant ? "/" : "", user_session.uid);
	/* Is it one of the users images? */
	if (strncmp(image_path + strlen(cfg->image_path), userdir,
		    strlen(userdir)) != 0)
		goto out1;

	if (strcmp(get_var(qvars, "confirm"), "yes") == 0) {
		if (!valid_csrf_token())
			goto out1;

		/* remove the full image */
		unlink(image_path);

		/* remove the small image */
		snprintf(path, PATH_MAX, "%s/%s/small/%s", cfg->image_path,
			 get_var(db_row, "path"), get_var(db_row, "name"));
		if (!realpath(path, image_path))
			goto out1;

		unlink(image_path);

		/* remove the medium image */
		snprintf(path, PATH_MAX, "%s/%s/medium/%s", cfg->image_path,
			 get_var(db_row, "path"), get_var(db_row, "name"));
		if (!realpath(path, image_path))
			goto out1;

		unlink(image_path);

		sql_query("DELETE FROM images WHERE id = '%s'", image_id);
		/* We don't want to display the delete_image page again */
		goto out1;
	}

	add_csrf_token(f);
	send_template(f);
	headers_sent = true;

out1:
	mysql_free_result(res);
	free(image_id);
	free_vars(db_row);
	lf_free(f);
out2:
	if (!headers_sent)
		fcgx_p("Location: /receipts/\r\n\r\n");
}

/*
 * /get_image/
 *
 * As the images aren't stored under the control of the webserver (don't
 * want users seeing other users receipts). The application needs to get
 * the image and send it through to the client.
 */
static void get_image(void)
{
	int fd;
	ssize_t bytes_read;
	char buf[BUF_SIZE];
	char path[PATH_MAX];
	char image_path[PATH_MAX];
	struct stat sb;
	magic_t cookie;
	const char *mime_type;

	snprintf(path, PATH_MAX,
		 "%s/%s", cfg->image_path, env_vars.request_uri + 11);
	if (!realpath(path, image_path))
		return;

	/* Don't let users access other user images */
	if (!image_access_allowed(image_path)) {
		fcgx_p("Status: 401 Unauthorized\r\n\r\n");
		d_fprintf(access_log, "Access denied to %s for %s\n",
			  env_vars.request_uri, user_session.username);
		return;
	}

	fd = open(image_path, O_RDONLY);
	if (fd == -1) {
		d_fprintf(error_log, "Could not open %s\n", image_path);
		return;
	}
	fstat(fd, &sb);

	cookie = magic_open(MAGIC_MIME);
	magic_load(cookie, "/usr/share/file/magic");
	mime_type = magic_file(cookie, image_path);

	fcgx_p("Cache-Control: private\r\n");
	fcgx_p("Content-Type: %s\r\n", mime_type);
	fcgx_p("Content-Length: %ld\r\n", sb.st_size);
	if (!strstr(image_path, "medium")) {
		/* We're going for the full size image for download */
		fcgx_p("Content-Transfer-Encoding: binary\r\n");
		fcgx_p("Content-Disposition: attachment; filename = %s\r\n",
		       basename(image_path));
	}
	fcgx_p("\r\n");
	d_fprintf(debug_log, "Sending image: %s\n", env_vars.request_uri);

	do {
		bytes_read = read(fd, &buf, BUF_SIZE);
		fcgx_ps(buf, bytes_read);
	} while (bytes_read > 0);

	magic_close(cookie);
	close(fd);
}

/*
 * /admin/
 *
 * HTML is in templates/admin.tmpl
 *
 * Admin index page.
 */
static void admin(void)
{
	Flate *f = NULL;

	if (!IS_ADMIN())
		return;

	lf_set_tmpl(&f, "templates/admin.tmpl");
	ADD_HDR(f);
	send_template(f);
	lf_free(f);
}

/*
 * /admin/list_users/
 *
 * HTML is in templates/admin_list_users.tmpl
 *
 * List users in the system.
 */
static void admin_list_users(void)
{
	unsigned long nr_rows;
	unsigned long i;
	MYSQL_RES *res;
	Flate *f = NULL;
	struct pagination pn = { .rows_per_page = 15, .requested_page = 1,
				 .from = 0, .nr_pages = 0, .page_no = 1 };

	if (!IS_ADMIN())
		return;

	lf_set_tmpl(&f, "templates/admin_list_users.tmpl");
	ADD_HDR(f);

	if (qvars) {
		pn.requested_page = atoi(get_var(qvars, "page_no"));
		get_page_pagination(&pn);
	}

	res = sql_query("SELECT (SELECT COUNT(*) FROM passwd) AS nrows, uid, "
			"username, name, capabilities, enabled, activated "
			"FROM passwd LIMIT %d, %d", pn.from, pn.rows_per_page);
	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		char caps[33] = "\0";
		u8 capabilities;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		pn.nr_pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
			(float)pn.rows_per_page);

		lf_set_var(f, "uid", get_var(db_row, "uid"), NULL);
		lf_set_var(f, "username", get_var(db_row, "username"), de_xss);
		lf_set_var(f, "name", get_var(db_row, "name"), de_xss);

		/* Pretty print the set of capabilities */
		capabilities = atoi(get_var(db_row, "capabilities"));
		if (capabilities & APPROVER)
			strcat(caps, "Approver -");
		if (capabilities & APPROVER_CARD)
			strcat(caps, " Card");
		if (capabilities & APPROVER_CASH)
			strcat(caps, " Cash");
		if (capabilities & APPROVER_CHEQUE)
			strcat(caps, " Cheque");
		if (capabilities & APPROVER_SELF)
			strcat(caps, " Self");
		lf_set_var(f, "capabilities", caps, NULL);

		if (capabilities & ADMIN)
			lf_set_var(f, "admin", "", NULL);
		else
			lf_set_var(f, "not_admin", "", NULL);

		if (atoi(get_var(db_row, "enabled")) == 1)
			lf_set_var(f, "enabled", "", NULL);
		else
			lf_set_var(f, "not_enabled", "no", NULL);

		if (atoi(get_var(db_row, "activated")) == 1)
			lf_set_var(f, "activated", "", NULL);
		else
			lf_set_var(f, "not_activated", "", NULL);

		do_zebra(f, i, "listzebra");
		lf_set_row(f, "table");
		free_vars(db_row);
	}
	do_pagination(f, &pn);

	send_template(f);
	lf_free(f);
	mysql_free_result(res);
}

/*
 * /admin/add_user/
 *
 * HTML is in templates/admin_add_user.tmpl
 *
 * Add a user to the system.
 */
static void admin_add_user(void)
{
	u8 capabilities = 0;
	bool form_err = false;
	Flate *f = NULL;

	if (!IS_ADMIN())
		return;

	/* Prevent CSRF attack */
	if (IS_POST() && !valid_csrf_token())
		return;

	lf_set_tmpl(&f, "templates/admin_add_user.tmpl");
	ADD_HDR(f);

	if (!qvars)
		goto out;

	if (!IS_SET(get_var(qvars, "name"))) {
		form_err = true;
		lf_set_var(f, "name_error", "", NULL);
	}
	lf_set_var(f, "name", get_var(qvars, "name"), de_xss);

	if ((!IS_SET(get_var(qvars, "email1")) &&
	     !IS_SET(get_var(qvars, "email2"))) ||
	    (strcmp(get_var(qvars, "email1"),
		    get_var(qvars, "email2")) != 0)) {
		form_err = true;
		lf_set_var(f, "email_error", "", NULL);
	}
	lf_set_var(f, "email1", get_var(qvars, "email1"), de_xss);
	lf_set_var(f, "email2", get_var(qvars, "email2"), de_xss);

	if (IS_SET(get_var(qvars, "ap_card")) ||
	    IS_SET(get_var(qvars, "ap_cash")) ||
	    IS_SET(get_var(qvars, "ap_cheque")) ||
	    IS_SET(get_var(qvars, "ap_self"))) {
		capabilities |= APPROVER;
		if (IS_SET(get_var(qvars, "ap_card"))) {
			capabilities |= APPROVER_CARD;
			lf_set_var(f, "ap_card", "checked", NULL);
		}
		if (IS_SET(get_var(qvars, "ap_cash"))) {
			capabilities |= APPROVER_CASH;
			lf_set_var(f, "ap_cash", "checked", NULL);
		}
		if (IS_SET(get_var(qvars, "ap_cheque"))) {
			capabilities |= APPROVER_CHEQUE;
			lf_set_var(f, "ap_cheque", "checked", NULL);
		}
		if (IS_SET(get_var(qvars, "ap_self"))) {
			capabilities |= APPROVER_SELF;
			lf_set_var(f, "ap_self", "checked", NULL);
		}
	}
	if (IS_SET(get_var(qvars, "is_admin"))) {
		capabilities |= ADMIN;
		lf_set_var(f, "is_admin", "checked", NULL);
	}

	if (!form_err) {
		int ret;

		ret = do_add_user(capabilities);
		if (ret == -10) {
			/*
			 * Tried to add an already existing user.
			 * Tell the admin.
			 */
			lf_set_var(f, "dup_user", "", NULL);
		} else {
			fcgx_p("Location: /admin/add_user/\r\n\r\n");
			goto out2;
		}
	}

out:
	add_csrf_token(f);
	send_template(f);
out2:
	lf_free(f);
}

/*
 * /admin/edit_user/
 *
 * HTML is in templates/admin_edit_user.tmpl
 *
 * Edit a users settings.
 */
static void admin_edit_user(void)
{
	unsigned int uid;
	bool form_err = false;
	bool pass_err = false;
	Flate *f = NULL;

	if (!IS_ADMIN())
		return;

	if (!qvars)
		return;

	uid = atoi(get_var(qvars, "uid"));
	lf_set_tmpl(&f, "templates/admin_edit_user.tmpl");

	/* If we got a POST, update user settings before showing them. */
	if (IS_POST() && valid_csrf_token()) {
		if ((!IS_SET(get_var(qvars, "email1")) &&
		     !IS_SET(get_var(qvars, "email2"))) ||
		    (strcmp(get_var(qvars, "email1"),
			    get_var(qvars, "email2")) != 0)) {
			lf_set_var(f, "email_error", "", NULL);
			form_err = true;
		}
		if (strlen(get_var(qvars, "pass1")) > 7 &&
		    strlen(get_var(qvars, "pass2")) > 7) {
			if (strcmp(get_var(qvars, "pass1"),
				   get_var(qvars, "pass2")) != 0) {
				lf_set_var(f, "pass_err_mismatch", "", NULL);
				form_err = true;
				pass_err = true;
			}
		} else if (IS_SET(get_var(qvars, "pass1")) ||
			   IS_SET(get_var(qvars, "pass2"))) {
			/*
			 * If the password fields are > 0 in length, then we
			 * at least tried to update it.
			 */
			lf_set_var(f, "pass_err_length", "", NULL);
			form_err = true;
			pass_err =true;
		}

		if (pass_err)
			lf_set_var(f, "pass_error", "", NULL);

		if (!form_err) {
			do_update_user();
			fcgx_p("Location: /admin/edit_user/?uid=%u&updated=yes"
			       "\r\n\r\n", uid);
		}
	}
	ADD_HDR(f);

	lf_set_var(f, "uid", get_var(qvars, "uid"), NULL);

	/*
	 * If form_err is false, then either we got a GET and just want
	 * to show the users settings from the database. Or we got a POST
	 * and successfully updated the users settings and want to show them.
	 *
	 * Else we tried to update the users settings but made some mistake
	 * and need to re-edit them in which case we need show the values
	 * from the POST'd form and not the database.
	 */
	if (!form_err) {
		u8 capabilities;
		GHashTable *db_row = NULL;
		MYSQL_RES *res;

		res = sql_query("SELECT username, name, capabilities, "
				"enabled, activated, d_reason FROM passwd "
				"WHERE uid = %u", uid);
		if (mysql_num_rows(res) == 0)
			goto mysql_cleanup;

		db_row = get_dbrow(res);

		if (IS_SET(get_var(qvars, "updated")))
			lf_set_var(f, "updated", "", NULL);

		lf_set_var(f, "username", get_var(db_row, "username"), de_xss);
		lf_set_var(f, "email1", get_var(db_row, "username"), de_xss);
		lf_set_var(f, "email2", get_var(db_row, "username"), de_xss);
		lf_set_var(f, "name", get_var(db_row, "name"), de_xss);
		if (atoi(get_var(db_row, "enabled")) == 1)
			lf_set_var(f, "is_enabled", "checked", NULL);
		else
			lf_set_var(f, "not_enabled", "", NULL);
		if (atoi(get_var(db_row, "activated")) == 1)
			lf_set_var(f, "is_activated", "", NULL);
		else
			lf_set_var(f, "not_activated", "", NULL);
		lf_set_var(f, "d_reason", get_var(db_row, "d_reason"), de_xss);

		capabilities = atoi(get_var(db_row, "capabilities"));
		if (capabilities & APPROVER_CARD)
			lf_set_var(f, "ap_card", "checked", NULL);
		if (capabilities & APPROVER_CASH)
			lf_set_var(f, "ap_cash", "checked", NULL);
		if (capabilities & APPROVER_CHEQUE)
			lf_set_var(f, "ap_cheque", "checked", NULL);
		if (capabilities & APPROVER_SELF)
			lf_set_var(f, "ap_self", "checked", NULL);

		if (capabilities & ADMIN)
			lf_set_var(f, "is_admin", "checked", NULL);

		free_vars(db_row);
mysql_cleanup:
		mysql_free_result(res);
	} else {
		lf_set_var(f, "username", get_var(qvars, "email1"), de_xss);
		lf_set_var(f, "email1", get_var(qvars, "email1"), de_xss);
		lf_set_var(f, "email2", get_var(qvars, "email2"), de_xss);
		lf_set_var(f, "name", get_var(qvars, "name"), de_xss);

		if (atoi(get_var(qvars, "enabled")) == 1)
			lf_set_var(f, "is_enabled", "checked", NULL);
		else
			lf_set_var(f, "not_enabled", "", NULL);
		if (atoi(get_var(qvars, "activated")) == 1)
			lf_set_var(f, "is_activated", "", NULL);
		else
			lf_set_var(f, "not_activated", "", NULL);

		if (atoi(get_var(qvars, "ap_card")) == 1)
			lf_set_var(f, "ap_card", "checked", NULL);
		if (atoi(get_var(qvars, "ap_cash")) == 1)
			lf_set_var(f, "ap_cash", "checked", NULL);
		if (atoi(get_var(qvars, "ap_cheque")) == 1)
			lf_set_var(f, "ap_cheque", "checked", NULL);
		if (atoi(get_var(qvars, "ap_self")) == 1)
			lf_set_var(f, "ap_self", "checked", NULL);

		if (atoi(get_var(qvars, "is_admin")) == 1)
			lf_set_var(f, "is_admin", "checked", NULL);
	}

	add_csrf_token(f);
	send_template(f);
	lf_free(f);
}

/*
 * /admin/stats/
 *
 * HTML is in templates/admin_stats.tmpl
 *
 * Show overall receipt stats for the system.
 */
static void admin_stats(void)
{
	Flate *f = NULL;

	if (!IS_ADMIN())
		return;

	lf_set_tmpl(&f, "templates/admin_stats.tmpl");
	ADD_HDR(f);

	/* Gather stats covering _all_ users */
	gather_receipt_stats_for_user(0, STATS_ALL, f);

	send_template(f);
	lf_free(f);
}

/*
 * /admin/user_stats/
 *
 * HTML is in templates/admin_user_stats.tmpl
 *
 * Show receipt stats for a specified user.
 */
static void admin_user_stats(void)
{
	unsigned int uid;
	GHashTable *db_row = NULL;
	MYSQL_RES *res;
	Flate *f = NULL;

	if (!IS_ADMIN() || !qvars)
		return;

	lf_set_tmpl(&f, "templates/admin_user_stats.tmpl");
	ADD_HDR(f);

	uid = atoi(get_var(qvars, "uid"));

	res = sql_query("SELECT name FROM passwd WHERE uid = %u", uid);
	if (mysql_num_rows(res) == 0)
		goto out;

	gather_receipt_stats_for_user(uid, STATS_USER, f);
	db_row = get_dbrow(res);
	lf_set_var(f, "uid", get_var(qvars, "uid"), NULL);
	lf_set_var(f, "name", get_var(db_row, "name"), de_xss);
	free_vars(db_row);

	send_template(f);

out:
	mysql_free_result(res);
	lf_free(f);
}

/*
 * /admin/pending_activations/
 *
 * HTML is in templates/admin_pending_activations.tmpl
 *
 * List currently pending user account activations.
 */
static void admin_pending_activations(void)
{
	unsigned long nr_rows;
	unsigned long i;
	MYSQL_RES *res;
	Flate *f = NULL;
	struct pagination pn = { .rows_per_page = 15, .requested_page = 1,
				 .from = 0, .nr_pages = 0, .page_no = 1 };

	if (!IS_ADMIN())
		return;

	if (IS_POST() && valid_csrf_token() && avars)
		process_activation_changes();

	lf_set_tmpl(&f, "templates/admin_pending_activations.tmpl");
	ADD_HDR(f);

	if (qvars) {
		pn.requested_page = atoi(get_var(qvars, "page_no"));
		get_page_pagination(&pn);
	}

	res = sql_query("SELECT (SELECT COUNT(*) FROM activations INNER JOIN "
			"passwd ON (activations.user = passwd.username)) AS "
			"nrows, passwd.name, passwd.uid, activations.user, "
			"activations.expires, activations.akey FROM "
			"activations INNER JOIN passwd ON "
			"(activations.user = passwd.username) LIMIT "
			"%d, %d", pn.from, pn.rows_per_page);
	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		char item[3];
		time_t secs;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		/*
		 * Due to the SQL above always returning at least one row,
		 * we need to see if nrows is 0, which would indicate there
		 * aren't any pending activations.
		 */
		if (strcmp(get_var(db_row, "nrows"), "0") == 0) {
			free_vars(db_row);
			break;
		}

		pn.nr_pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
				(float)pn.rows_per_page);

		lf_set_var(f, "name", get_var(db_row, "name"), de_xss);
		lf_set_var(f, "username", get_var(db_row, "user"), de_xss);
		secs = atol(get_var(db_row, "expires"));
		if (time(NULL) > secs)
			lf_set_var(f, "expired", "", NULL);
		strftime(tbuf, sizeof(tbuf), "%F %H:%M:%S", localtime(&secs));
		lf_set_var(f, "expires", tbuf, NULL);

		lf_set_var(f, "uid", get_var(db_row, "uid"), NULL);
		lf_set_var(f, "akey", get_var(db_row, "akey"), NULL);
		snprintf(item, sizeof(item), "%hhu", (u8)i);
		lf_set_var(f, "item", item, NULL);

		do_zebra(f, i, "listzebra");
		lf_set_row(f, "table");
		free_vars(db_row);
	}
	add_csrf_token(f);
	do_pagination(f, &pn);

	send_template(f);
	lf_free(f);
	mysql_free_result(res);
}

/*
 * /activate_user/
 *
 * HTML is in templates/activate_user.tmpl
 *
 * Activate a users account.
 */
static void activate_user(void)
{
	char *key;
	MYSQL_RES *res;
	GHashTable *db_row = NULL;
	bool activated = false;
	Flate *f = NULL;

	lf_set_tmpl(&f, "templates/activate_user.tmpl");
	if (!qvars) {
		lf_set_var(f, "key_error", "", NULL);
		goto out2;
	}

	key = make_mysql_safe_string(get_var(qvars, "key"));
	res = sql_query("SELECT uid, name, user, expires FROM passwd "
			"INNER JOIN activations ON (passwd.username = "
			"activations.user) WHERE activations.akey = '%s'",
			key);
	if (mysql_num_rows(res) == 0) {
		lf_set_var(f, "key_error", "", NULL);
		goto out;
	}

	db_row = get_dbrow(res);
	lf_set_var(f, "name", get_var(db_row, "name"), de_xss);

	/* Check if the activation key has expired. */
	if (time(NULL) > atol(get_var(db_row, "expires"))) {
		lf_set_var(f, "expired", "", NULL);
		lf_set_var(f, "email", get_var(db_row, "user"), de_xss);
		goto out;
	}
	lf_set_var(f, "key", get_var(qvars, "key"), de_xss);

	/*
	 * The user is trying to set a password, do some sanity
	 * checking on it,
	 *
	 * The user needs to enter the password twice, make sure they match.
	 * Also make sure that the password is at least 8 characters long.
	 */
	if (IS_POST()) {
		if (strlen(get_var(qvars, "pass1")) > 7 &&
		    strlen(get_var(qvars, "pass2")) > 7) {
			if (strcmp(get_var(qvars, "pass1"),
				   get_var(qvars, "pass2")) == 0) {
				do_activate_user(get_var(db_row, "uid"), key,
						 get_var(qvars, "pass1"));
				lf_set_var(f, "activated", "", NULL);
				activated = true;
			} else {
				lf_set_var(f, "pass_err_mismatch", "", NULL);
			}
		} else {
			lf_set_var(f, "pass_err_length", "", NULL);
		}
	}

	if (!activated)
		lf_set_var(f, "not_activated", "", NULL);

out:
	mysql_free_result(res);
	free_vars(db_row);
	free(key);
out2:
	send_template(f);
	lf_free(f);
}

/*
 * /generate_new_key/
 *
 * HTML is in templates/generate_new_key.tmpl
 *
 * Generate a new activation key and send it to the user.
 */
static void generate_new_key(void)
{
	char *email_addr;
	char key[SHA256_LEN + 1];
	time_t tm;
	MYSQL_RES *res;
	Flate *f = NULL;

	if (!qvars)
		return;

	email_addr = make_mysql_safe_string(get_var(qvars, "email"));
	res = sql_query("SELECT user FROM activations WHERE user = '%s'",
			email_addr);
	if (mysql_num_rows(res) == 0)
		goto out;

	generate_hash(key, SHA256);
	tm = time(NULL);
	sql_query("REPLACE INTO activations VALUES ('%s', '%s', %ld)",
		  email_addr, key, tm + KEY_EXP);

	send_activation_mail(get_var(qvars, "name"), email_addr, key);

	lf_set_tmpl(&f, "templates/generate_new_key.tmpl");
	lf_set_var(f, "email", email_addr, de_xss);
	send_template(f);
	lf_free(f);

out:
	mysql_free_result(res);
	free(email_addr);
}

/*
 * /forgotten_password/
 *
 * HTML is in templates/forgotten_password.tmpl
 *
 * Allow a user to set a new password, if they have forgotten it.
 */
static void forgotten_password(void)
{
	char *email_addr;
	char key[SHA256_LEN + 1];
	time_t tm;
	MYSQL_RES *res;
	Flate *f = NULL;

	lf_set_tmpl(&f, "templates/forgotten_password.tmpl");
	if (!qvars) {
		lf_set_var(f, "reset", "", NULL);
		goto out;
	}

	lf_set_var(f, "email", get_var(qvars, "email"), de_xss);

	email_addr = make_mysql_safe_string(get_var(qvars, "email"));
	res = sql_query("SELECT username FROM passwd WHERE username = '%s'",
			email_addr);
	if (mysql_num_rows(res) == 0) {
		lf_set_var(f, "reset", "", NULL);
		lf_set_var(f, "user_error", "", NULL);
		goto mysql_cleanup;
	}

	generate_hash(key, SHA256);
	tm = time(NULL);
	sql_query("INSERT INTO activations VALUES ('%s', '%s', %ld)",
		  email_addr, key, tm + KEY_EXP);

	send_activation_mail(get_var(qvars, "name"), email_addr, key);
	lf_set_var(f, "sent", "", NULL);

mysql_cleanup:
	mysql_free_result(res);
	free(email_addr);
out:
	send_template(f);
	lf_free(f);
}

/*
 * /prefs/
 *
 * HTML is in templates/prefs.tmpl
 */
static void prefs(void)
{
	Flate *f = NULL;

	lf_set_tmpl(&f, "templates/prefs.tmpl");
	ADD_HDR(f);
	send_template(f);
	lf_free(f);
}

/*
 * /prefs/fmap/
 *
 * HTML is in templates/prefs_fmap.tmpl
 *
 * Change the image tag field names.
 */
static void prefs_fmap(void)
{
	Flate *f = NULL;

	lf_set_tmpl(&f, "templates/prefs_fmap.tmpl");

	if (IS_POST() && valid_csrf_token()) {
		update_fmap();
		fcgx_p("Location: /prefs/fmap/?updated=yes\r\n\r\n");
		return;
	} else if (IS_GET() && IS_SET(get_var(qvars, "updated"))) {
		lf_set_var(f, "fields_updated", "", NULL);
	}

	ADD_HDR(f);

	set_custom_field_names();
	lf_set_var(f, "receipt_date", DFN_RECEIPT_DATE, NULL);
	lf_set_var(f, "alt_receipt_date",
		   !strcmp(DFN_RECEIPT_DATE, fields.receipt_date) ? "" :
			fields.receipt_date, de_xss);

	lf_set_var(f, "department", DFN_DEPARTMENT, NULL);
	lf_set_var(f, "alt_department",
		   !strcmp(DFN_DEPARTMENT, fields.department) ? "" :
			fields.department, de_xss);

	lf_set_var(f, "employee_number", DFN_EMPLOYEE_NUMBER, NULL);
	lf_set_var(f, "alt_employee_number",
		   !strcmp(DFN_EMPLOYEE_NUMBER, fields.employee_number) ?
			"" : fields.employee_number, de_xss);

	lf_set_var(f, "reason", DFN_REASON, NULL);
	lf_set_var(f, "alt_reason",
		   !strcmp(DFN_REASON, fields.reason) ? "" :
			fields.reason, de_xss);

	lf_set_var(f, "po_num", DFN_PO_NUM, NULL);
	lf_set_var(f, "alt_po_num",
		   !strcmp(DFN_PO_NUM, fields.po_num) ? "" :
			fields.po_num, de_xss);

	lf_set_var(f, "cost_codes", DFN_COST_CODES, NULL);
	lf_set_var(f, "alt_cost_codes",
		   !strcmp(DFN_COST_CODES, fields.cost_codes) ? "" :
			fields.cost_codes, de_xss);

	lf_set_var(f, "account_codes", DFN_ACCOUNT_CODES, NULL);
	lf_set_var(f, "alt_account_codes",
		   !strcmp(DFN_ACCOUNT_CODES, fields.account_codes) ? "" :
			fields.account_codes, de_xss);

	lf_set_var(f, "supplier_name", DFN_SUPPLIER_NAME, NULL);
	lf_set_var(f, "alt_supplier_name",
		   !strcmp(DFN_SUPPLIER_NAME, fields.supplier_name) ? "" :
			fields.supplier_name, de_xss);

	lf_set_var(f, "supplier_town", DFN_SUPPLIER_TOWN, NULL);
	lf_set_var(f, "alt_supplier_town",
		   !strcmp(DFN_SUPPLIER_TOWN, fields.supplier_town) ? "" :
			fields.supplier_town, de_xss);

	lf_set_var(f, "vat_number", DFN_VAT_NUMBER, NULL);
	lf_set_var(f, "alt_vat_number",
		   !strcmp(DFN_VAT_NUMBER, fields.vat_number) ? "" :
			fields.vat_number, de_xss);

	lf_set_var(f, "gross_amount", DFN_GROSS_AMOUNT, NULL);
	lf_set_var(f, "alt_gross_amount",
		   !strcmp(DFN_GROSS_AMOUNT, fields.gross_amount) ? "" :
			fields.gross_amount, de_xss);

	lf_set_var(f, "net_amount", DFN_NET_AMOUNT, NULL);
	lf_set_var(f, "alt_net_amount",
		   !strcmp(DFN_NET_AMOUNT, fields.net_amount) ? "" :
			fields.net_amount, de_xss);

	lf_set_var(f, "vat_amount", DFN_VAT_AMOUNT, NULL);
	lf_set_var(f, "alt_vat_amount",
		   !strcmp(DFN_VAT_AMOUNT, fields.vat_amount) ? "" :
			fields.vat_amount, de_xss);

	lf_set_var(f, "vat_rate", DFN_VAT_RATE, NULL);
	lf_set_var(f, "alt_vat_rate",
		   !strcmp(DFN_VAT_RATE, fields.vat_rate) ? "" :
			fields.vat_rate, de_xss);

	lf_set_var(f, "currency", DFN_CURRENCY, NULL);
	lf_set_var(f, "alt_currency",
		   !strcmp(DFN_CURRENCY, fields.currency) ? "" :
			fields.currency, de_xss);

	lf_set_var(f, "payment_method", DFN_PAYMENT_METHOD, NULL);
	lf_set_var(f, "alt_payment_method",
		   !strcmp(DFN_PAYMENT_METHOD, fields.payment_method) ?
			"" : fields.payment_method, de_xss);
	free_fields();

	add_csrf_token(f);
	send_template(f);
	lf_free(f);
}

/*
 * /prefs/edit_user/
 *
 * HTML is in templates/prefs_edit_user.tmpl
 *
 * Allow users to change their details.
 */
static void prefs_edit_user(void)
{
	bool form_err = false;
	Flate *f = NULL;

	lf_set_tmpl(&f, "templates/prefs_edit_user.tmpl");
	/*
	 * If we got POST data, update the users settings before
	 * showing them.
	 */
	if (IS_POST() && valid_csrf_token()) {
		bool pass_err = false;

		if ((!IS_SET(get_var(qvars, "email1")) &&
		     !IS_SET(get_var(qvars, "email2"))) ||
		    (strcmp(get_var(qvars, "email1"),
			    get_var(qvars, "email2")) != 0)) {
			lf_set_var(f, "email_error", "", NULL);
			form_err = true;
		} else if (strcmp(user_session.username,
				  get_var(qvars, "email1")) != 0) {
			if (user_already_exists(get_var(qvars, "email1"))) {
				lf_set_var(f, "user_exists", "", NULL);
				form_err = true;
			}
		}
		if (strlen(get_var(qvars, "pass1")) > 7 &&
		    strlen(get_var(qvars, "pass2")) > 7) {
			if (strcmp(get_var(qvars, "pass1"),
				   get_var(qvars, "pass2")) != 0) {
				lf_set_var(f, "pass_err_mismatch", "", NULL);
				form_err = true;
				pass_err = true;
			}
		/*
		 * If the password fields are > 0 in length, then we tried
		 * to update it.
		 */
		} else if (IS_SET(get_var(qvars, "pass1")) ||
			   IS_SET(get_var(qvars, "pass2"))) {
			lf_set_var(f, "pass_err_length", "", NULL);
			form_err = true;
			pass_err = true;
		}

		if (pass_err)
			lf_set_var(f, "pass_error", "", NULL);

		if (!form_err) {
			do_edit_user();
			/* After the update we want to re-GET */
			fcgx_p("Location: /prefs/edit_user/?updated=yes"
			       "\r\n\r\n");
			return;
		}
	} else {
		if (IS_SET(get_var(qvars, "updated")))
			lf_set_var(f, "updated", "", NULL);
	}

	/*
	 * If form_err is still false, then either we got a GET and just want
	 * to show the users settings from the database. Or we got a POST
	 * and successfully updated the users settings and want to show them.
	 *
	 * Else we tried to update the users settings but made some mistake
	 * and need to re-edit them in which case we need show the values
	 * from the POST'd form.
	 */
	if (!form_err) {
		MYSQL_RES *res;
		GHashTable *db_row = NULL;

		res = sql_query("SELECT username, name FROM passwd WHERE "
				"uid = %u", user_session.uid);
		db_row = get_dbrow(res);

		lf_set_var(f, "username", get_var(db_row, "username"), de_xss);
		lf_set_var(f, "email1", get_var(db_row, "username"), de_xss);
		lf_set_var(f, "email2", get_var(db_row, "username"), de_xss);
		lf_set_var(f, "name", get_var(db_row, "name"), de_xss);

		free_vars(db_row);
		mysql_free_result(res);
	} else {
		lf_set_var(f, "username", get_var(qvars, "email1"), de_xss);
		lf_set_var(f, "email1", get_var(qvars, "email1"), de_xss);
		lf_set_var(f, "email2", get_var(qvars, "email2"), de_xss);
		lf_set_var(f, "name", get_var(qvars, "name"), de_xss);
	}

	ADD_HDR(f);

	add_csrf_token(f);
	send_template(f);
	lf_free(f);
}

/*
 * /do_extract_data/
 */
static void do_extract_data(void)
{
	int fd;
	char temp_name[] = "/tmp/receiptomatic-www-XXXXXX";

	if (!IS_APPROVER())
		return;

	fd = mkstemp(temp_name);

	if (strcmp(get_var(qvars, "whence"), "now") == 0)
		extract_data_now(fd);

	send_receipt_data(fd);

	unlink(temp_name);
	close(fd);
}

/*
 * /extract_data/
 *
 * HTML is in templates/extract_data.tmpl
 *
 * Allows an approver to extract approved receipt data.
 */
static void extract_data(void)
{
	Flate *f = NULL;

	if (!IS_APPROVER())
		return;

	lf_set_tmpl(&f, "templates/extract_data.tmpl");
	ADD_HDR(f);

	send_template(f);
	lf_free(f);
}

/*
 * /process_receipt_approval/
 *
 * Processes the form data from /approve_receipts/
 */
static void process_receipt_approval(void)
{
	char *username;
	unsigned int list_size;
	unsigned int i;

	if (!IS_APPROVER())
		return;

	/* Prevent CSRF attack */
	if (!(valid_csrf_token() && avars))
		return;

	username = make_mysql_safe_string(user_session.username);
	sql_query("LOCK TABLES reviewed WRITE, images WRITE,tags READ");

	list_size = g_list_length(avars);
	for (i = 0; i < list_size; i++) {
		const char *action = get_avar(i, "approved_status");
		char *reason = "";
		char *image_id;
		bool skip = false;
		MYSQL_RES *res;

		image_id = make_mysql_safe_string(get_avar(i, "id"));

		if (get_avar(i, "reason"))
			reason = make_mysql_safe_string(get_avar(i, "reason"));

		/* Can user approve their own receipts? */
		if (!(user_session.capabilities & APPROVER_SELF)) {
			res = sql_query("SELECT id FROM images WHERE id = "
					"'%s' AND uid = %u",
					image_id, user_session.uid);
			if (mysql_num_rows(res) > 0)
				skip = true;
			mysql_free_result(res);
		}
		/* Can user approve card transactions? */
		if (!(user_session.capabilities & APPROVER_CARD)) {
			res = sql_query("SELECT id FROM tags WHERE id = "
					"'%s' AND payment_method = 'card'",
					image_id);
			if (mysql_num_rows(res) > 0)
				skip = true;
			mysql_free_result(res);
		}
		/* Can user approve cash transactions? */
		if (!(user_session.capabilities & APPROVER_CASH)) {
			res = sql_query("SELECT id FROM tags WHERE id = "
					"'%s' AND payment_method = 'cash'",
					image_id);
			if (mysql_num_rows(res) > 0)
				skip = true;
			mysql_free_result(res);
		}
		/* Can user approve cheque transactions? */
		if (!(user_session.capabilities & APPROVER_CHEQUE)) {
			res = sql_query("SELECT id FROM tags WHERE id = "
					"'%s' AND payment_method = 'cheque'",
					image_id);
			if (mysql_num_rows(res) > 0)
				skip = true;
			mysql_free_result(res);
		}

		/* Make sure this reciept hasn't already been processed */
		res = sql_query("SELECT status from reviewed WHERE id = '%s'",
				image_id);
		if (mysql_num_rows(res) > 0)
			skip = true; /* This receipt is already done */
		mysql_free_result(res);

		/* Make sure it is a valid tagged-receipt */
		res = sql_query("SELECT id FROM tags WHERE id = '%s'",
				image_id);
		if (mysql_num_rows(res) == 0)
			skip = true; /* Not a valid receipt */
		mysql_free_result(res);

		if (skip)
			goto cont;
		if (action[0] == 'a') { /* approved */
			sql_query("INSERT INTO reviewed VALUES ("
				  "'%s', %u, '%s', %ld, %d, '%s')",
				  image_id, user_session.uid, username,
				  time(NULL), APPROVED, reason);
			sql_query("UPDATE images SET approved = %d WHERE id = "
				  "'%s'", APPROVED, image_id);
		} else if (action[0] == 'r') { /* rejected */
			sql_query("INSERT INTO reviewed VALUES ("
				  "'%s', %u, '%s', %ld, %d, '%s')",
				  image_id, user_session.uid, username,
				  time(NULL), REJECTED, reason);
			sql_query("UPDATE images SET approved = %d WHERE id "
				  "= '%s'", REJECTED, image_id);
		}
cont:
		free(image_id);
		if (IS_SET(reason))
			free(reason);
	}
	sql_query("UNLOCK TABLES");
	free(username);

	fcgx_p("Location: /approve_receipts/\r\n\r\n");
}

/*
 * /approve_receipts/
 *
 * HTML is in templates/approve_receipts.tmpl
 *
 * Allows an approver to approve or reject receipts.
 */
static void approve_receipts(void)
{
	char pmsql[128];
	char assql[512];
	static const char *pm = "tags.payment_method = ";
	static const char *cash = "'cash'";
	static const char *card = "'card'";
	static const char *cheque = "'cheque'";
	const char *join;
	MYSQL_RES *res;
	Flate *f = NULL;
	unsigned long i;
	unsigned long nr_rows;
	struct pagination pn = { .rows_per_page = APPROVER_ROWS,
				 .requested_page = 1, .from = 0, .nr_pages = 0,
				 .page_no = 1 };

	if (!IS_APPROVER())
		return;

	lf_set_tmpl(&f, "templates/approve_receipts.tmpl");
	ADD_HDR(f);

	memset(pmsql, 0, sizeof(pmsql));
	/*
	 * Prepare the payment_method sql clause depending on the users
	 * approver capabilities.
	 */
	if (user_session.capabilities & APPROVER_CASH) {
		strcat(pmsql, pm);
		strcat(pmsql, cash);
	}
	if (user_session.capabilities & APPROVER_CARD) {
		if (IS_SET(pmsql))
			join = " OR ";
		else
			join = "";
		strcat(pmsql, join);
		strcat(pmsql, pm);
		strcat(pmsql, card);
	}
	if (user_session.capabilities & APPROVER_CHEQUE) {
		if (IS_SET(pmsql))
			join = " OR ";
		else
			join = "";
		strcat(pmsql, join);
		strcat(pmsql, pm);
		strcat(pmsql, cheque);
	}
	/*
	 * If we get here but pmsql is empty then it means even though we
	 * are an approver, we don't seem to have any actual approver
	 * capabilities. This is likely due to an incorrect capabilities
	 * entry in the passwd table.
	 *
	 * This shouldn't happen. If it does, just log the fact to the
	 * error log and return (to avoid a segfault due to the subsequent
	 * incomplete SQL query).
	 */
	if (!IS_SET(pmsql)) {
		d_fprintf(error_log,
			  "User %u seems to have an invalid capability "
			  "setting in the passwd table.\n", user_session.uid);
		return;
	}

	memset(assql, 0, sizeof(assql));
	/* If the user isn't APPROVER_SELF, don't show them their receipts */
	if (!(user_session.capabilities & APPROVER_SELF))
		sprintf(assql, "AND images.uid != %u", user_session.uid);
	else
		assql[0] = '\0';

	if (qvars) {
		pn.requested_page = atoi(get_var(qvars, "page_no"));
		get_page_pagination(&pn);
	}

	res = sql_query("SELECT (SELECT COUNT(*) FROM images INNER JOIN "
			"tags ON (images.id = tags.id) WHERE "
			"images.approved = 1 AND (%s) %s) AS nrows, "
			"images.id, images.username, images.timestamp AS "
			"its, images.path, images.name, tags.username, "
			"tags.timestamp AS tts, tags.employee_number, "
			"tags.department, tags.po_num, tags.cost_codes, "
			"tags.account_codes, tags.supplier_town, "
			"tags.supplier_name, tags.currency, "
			"tags.gross_amount, tags.vat_amount, "
			"tags.net_amount, tags.vat_rate, tags.vat_number, "
			"tags.receipt_date, tags.reason, tags.payment_method "
			"FROM images INNER JOIN tags ON (images.id = tags.id) "
			"WHERE images.approved = 1 AND (%s) %s LIMIT %d, %d",
			pmsql, assql, pmsql, assql, pn.from, APPROVER_ROWS);
	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0)
		goto out;

	lf_set_var(f, "receipts", "", NULL);
	add_csrf_token(f);

	set_custom_field_names();
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		char *name;
		char item[3];
		time_t secs;
		double gross;
		double net;
		double vat;
		double vr;
		int ret;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);

		pn.nr_pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
				(float)pn.rows_per_page);

		lf_set_var(f, "image_path", get_var(db_row, "path"), NULL);
		lf_set_var(f, "image_name", get_var(db_row, "name"), NULL);

		name = username_to_name(get_var(db_row, "username"));
		lf_set_var(f, "name", name, de_xss);
		free(name);

		secs = atol(get_var(db_row, "its"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		lf_set_var(f, "images_timestamp", tbuf, NULL);

		secs = atol(get_var(db_row, "tts"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		lf_set_var(f, "tags_timestamp", tbuf, NULL);
		lf_set_var(f, "f.department", fields.department, de_xss);
		lf_set_var(f, "department", get_var(db_row, "department"),
			   de_xss);
		lf_set_var(f, "f.employee_number", fields.employee_number,
			   de_xss);
		lf_set_var(f, "employee_number",
			   get_var(db_row, "employee_number"), de_xss);
		lf_set_var(f, "f.cost_codes", fields.cost_codes, de_xss);
		lf_set_var(f, "cost_codes",
			   get_var(db_row, "cost_codes"), de_xss);
		lf_set_var(f, "f.account_codes", fields.account_codes, de_xss);
		lf_set_var(f, "account_codes",
			   get_var(db_row, "account_codes"), de_xss);
		lf_set_var(f, "f.po_num", fields.po_num, de_xss);
		lf_set_var(f, "po_num", get_var(db_row, "po_num"), de_xss);
		lf_set_var(f, "f.supplier_name", fields.supplier_name, de_xss);
		lf_set_var(f, "supplier_name",
			   get_var(db_row, "supplier_name"), de_xss);
		lf_set_var(f, "f.supplier_town", fields.supplier_town, de_xss);
		lf_set_var(f, "supplier_town",
			   get_var(db_row, "supplier_town"), de_xss);
		lf_set_var(f, "f.currency", fields.currency, de_xss);
		lf_set_var(f, "currency", get_var(db_row, "currency"), de_xss);
		lf_set_var(f, "f.gross_amount", fields.gross_amount, de_xss);
		lf_set_var(f, "gross_amount", get_var(db_row, "gross_amount"),
			   NULL);
		lf_set_var(f, "f.vat_amount", fields.vat_amount, de_xss);
		lf_set_var(f, "vat_amount", get_var(db_row, "vat_amount"),
			   NULL);
		lf_set_var(f, "f.net_amount", fields.net_amount, de_xss);
		lf_set_var(f, "net_amount", get_var(db_row, "net_amount"),
			   NULL);
		lf_set_var(f, "f.vat_rate", fields.vat_rate, de_xss);
		lf_set_var(f, "vat_rate", get_var(db_row, "vat_rate"), NULL);

		/* Sanity check the amounts */
		gross = strtod(get_var(db_row, "gross_amount"), NULL);
		net = strtod(get_var(db_row, "net_amount"), NULL);
		vat = strtod(get_var(db_row, "vat_amount"), NULL);
		vr = strtod(get_var(db_row, "vat_rate"), NULL);
		ret = check_amounts(gross, net, vat, vr);
		if (ret < 0)
			lf_set_var(f, "amnt_err", "", NULL);
		else
			lf_set_var(f, "amnt_ok", "", NULL);

		lf_set_var(f, "f.vat_number", fields.vat_number, de_xss);
		lf_set_var(f, "vat_number", get_var(db_row, "vat_number"),
			   de_xss);
		lf_set_var(f, "f.receipt_date", fields.receipt_date, de_xss);

		secs = atol(get_var(db_row, "receipt_date"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		lf_set_var(f, "receipt_date", tbuf, NULL);
		lf_set_var(f, "f.payment_method", fields.payment_method,
			   de_xss);
		lf_set_var(f, "payment_method",
			   get_var(db_row, "payment_method"), NULL);
		lf_set_var(f, "f.reason", fields.reason, de_xss);
		lf_set_var(f, "reason", get_var(db_row, "reason"), de_xss);
		lf_set_var(f, "id", get_var(db_row, "id"), NULL);

		snprintf(item, sizeof(item), "%hhu", (u8)i);
		lf_set_var(f, "item", item, NULL);

		lf_set_row(f, "table");
		free_vars(db_row);
	}
	free_fields();
	do_pagination(f, &pn);

out:
	send_template(f);
	lf_free(f);
	mysql_free_result(res);
}

/*
 * /reviewed_receipts/
 *
 * HTML is in templates/reviewed_receipts.tmpl
 *
 * Displays previously reviewed receipts.
 */
static void reviewed_receipts(void)
{
	unsigned long nr_rows;
	unsigned long i;
	int c = 1;		/* column number */
	MYSQL_RES *res;
	Flate *f = NULL;
	struct pagination pn = { .rows_per_page = GRID_SIZE,
				 .requested_page = 1, .from = 0, .nr_pages = 0,
				 .page_no = 1 };

	if (!IS_APPROVER())
		return;

	lf_set_tmpl(&f, "templates/reviewed_receipts.tmpl");
	ADD_HDR(f);

	if (qvars) {
		pn.requested_page = atoi(get_var(qvars, "page_no"));
		get_page_pagination(&pn);
	}

	res = sql_query("SELECT (SELECT COUNT(*) FROM reviewed INNER JOIN "
			"images ON (reviewed.id = images.id)) AS nrows, "
			"reviewed.timestamp AS ats, images.id, images.path, "
			"images.name, images.timestamp AS its, "
			"reviewed.status, passwd.name AS user, passwd.uid "
			"FROM reviewed INNER JOIN images ON "
			"(reviewed.id = images.id) INNER JOIN passwd ON "
			"(images.uid = passwd.uid) ORDER BY "
			"reviewed.timestamp DESC LIMIT %d, %d",
			pn.from, GRID_SIZE);
	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0)
		goto out;

	set_custom_field_names();
	lf_set_var(f, "receipts", "", NULL);

	/* Draw gallery grid */
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		time_t secs;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);

		pn.nr_pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
				(float)pn.rows_per_page);
		d_fprintf(debug_log, "pn.nr_pages : %d\n", pn.nr_pages);

		lf_set_var(f, "id", get_var(db_row, "id"), NULL);
		lf_set_var(f, "image_path", get_var(db_row, "path"), de_xss);
		lf_set_var(f, "image_name", get_var(db_row, "name"), de_xss);
		lf_set_var(f, "user", get_var(db_row, "user"), de_xss);
		lf_set_var(f, "uid", get_var(db_row, "uid"), NULL);

		secs = atol(get_var(db_row, "ats"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		lf_set_var(f, "review_date", "Review Date", NULL);
		lf_set_var(f, "apdate", tbuf, NULL);

		secs = atol(get_var(db_row, "its"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		lf_set_var(f, "f.receipt_date", fields.receipt_date, de_xss);
		lf_set_var(f, "rdate", tbuf, NULL);

		if (atoi(get_var(db_row, "status")) == REJECTED)
			lf_set_var(f, "rejected", "", NULL);
		else
			lf_set_var(f, "approved", "", NULL);

		if (c == COL_SIZE)
			lf_set_var(f, "close_row", "", NULL);

		if (c == COL_SIZE && i < nr_rows) {
			lf_set_var(f, "new_row", "", NULL);
			c = 0;
		}
		c++;

		lf_set_row(f, "table");
		free_vars(db_row);
	}
	free_fields();
	do_pagination(f, &pn);

out:
	send_template(f);
	lf_free(f);
	mysql_free_result(res);
}

/*
 * /receipt_info/
 *
 * HTML is in templates/receipt_info.tmpl
 *
 * Displays the logged information for a given receipt.
 */
static void receipt_info(void)
{
	char tbuf[60];
	char *image_id;
	time_t secs;
	MYSQL_RES *res;
	GHashTable *db_row = NULL;
	Flate *f = NULL;

	lf_set_tmpl(&f, "templates/receipt_info.tmpl");
	ADD_HDR(f);

	if (!tag_info_allowed(get_var(qvars, "image_id")))
		goto out2;

	image_id = make_mysql_safe_string(get_var(qvars, "image_id"));
	res = sql_query("SELECT (SELECT passwd.name FROM passwd INNER JOIN "
			"reviewed ON (reviewed.r_uid = passwd.uid) WHERE "
			"reviewed.id = '%s') AS reviewed_by_n, reviewed.r_uid "
			"AS reviewed_by_u, images.timestamp AS "
			"images_timestamp, images.path, images.name, "
			"images.approved, tags.timestamp AS tags_timestamp, "
			"tags.employee_number, tags.department, tags.po_num, "
			"tags.cost_codes, tags.account_codes, "
			"tags.supplier_name, tags.supplier_town, "
			"tags.currency, tags.gross_amount, tags.vat_amount, "
			"tags.net_amount, tags.vat_rate, tags.vat_number, "
			"tags.receipt_date, tags.reason, tags.payment_method, "
			"reviewed.reason AS r_reason, reviewed.timestamp AS "
			"a_time, passwd.name AS user, passwd.uid FROM images "
			"INNER JOIN tags ON (images.id = tags.id) LEFT JOIN "
			"reviewed ON (reviewed.id = tags.id) INNER JOIN "
			"passwd ON (images.uid = passwd.uid) WHERE "
			"images.id = '%s' LIMIT 1", image_id, image_id);
	if (mysql_num_rows(res) == 0)
		goto out1;

	db_row = get_dbrow(res);
	set_custom_field_names();
	lf_set_var(f, "show_info", "", NULL);

	/* image url */
	lf_set_var(f, "image_path", get_var(db_row, "path"), NULL);
	lf_set_var(f, "image_name", get_var(db_row, "name"), NULL);

	lf_set_var(f, "r_user", get_var(db_row, "user"), de_xss);
	lf_set_var(f, "r_uid", get_var(db_row, "uid"), NULL);
	lf_set_var(f, "id", image_id, NULL);

	/* image upload timestamp */
	secs = atol(get_var(db_row, "images_timestamp"));
	strftime(tbuf, sizeof(tbuf), "%a %b %e %H:%M %Y %z", localtime(&secs));
	lf_set_var(f, "images_timestamp", tbuf, NULL);

	/* image tag timestamp */
	secs = atol(get_var(db_row, "tags_timestamp"));
	strftime(tbuf, sizeof(tbuf), "%a %b %e %H:%M %Y %z", localtime(&secs));
	lf_set_var(f, "tags_timestamp", tbuf, NULL);

	lf_set_var(f, "f.department", fields.department, de_xss);
	lf_set_var(f, "department", get_var(db_row, "department"), de_xss);
	lf_set_var(f, "f.employee_number", fields.employee_number, de_xss);
	lf_set_var(f, "employee_number", get_var(db_row, "employee_number"),
		   de_xss);
	lf_set_var(f, "f.cost_codes", fields.cost_codes, de_xss);
	lf_set_var(f, "cost_codes", get_var(db_row, "cost_codes"), de_xss);
	lf_set_var(f, "f.account_codes", fields.account_codes, de_xss);
	lf_set_var(f, "account_codes", get_var(db_row, "account_codes"),
		   de_xss);
	lf_set_var(f, "f.po_num", fields.po_num, de_xss);
	lf_set_var(f, "po_num", get_var(db_row, "po_num"), de_xss);
	lf_set_var(f, "f.supplier_name", fields.supplier_name, de_xss);
	lf_set_var(f, "supplier_name", get_var(db_row, "supplier_name"),
		   de_xss);
	lf_set_var(f, "f.supplier_town", fields.supplier_town, de_xss);
	lf_set_var(f, "supplier_town", get_var(db_row, "supplier_town"),
		   de_xss);
	lf_set_var(f, "f.currency", fields.currency, de_xss);
	lf_set_var(f, "currency", get_var(db_row, "currency"), de_xss);
	/*
	 * To get the right currency 'selected' in the drop down, yeah
	 * there must be a better way...
	 */
	if (strcmp(get_var(db_row, "currency"), "GBP") == 0)
		lf_set_var(f, "GBP", "", NULL);
	else if (strcmp(get_var(db_row, "currency"), "USD") == 0)
		lf_set_var(f, "USD", "", NULL);
	else if (strcmp(get_var(db_row, "currency"), "EUR") == 0)
		lf_set_var(f, "EUR", "", NULL);
	lf_set_var(f, "f.gross_amount", fields.gross_amount, de_xss);
	lf_set_var(f, "gross_amount", get_var(db_row, "gross_amount"), NULL);
	lf_set_var(f, "f.vat_amount", fields.vat_amount, de_xss);
	lf_set_var(f, "vat_amount", get_var(db_row, "vat_amount"), NULL);
	lf_set_var(f, "f.net_amount", fields.net_amount, de_xss);
	lf_set_var(f, "net_amount", get_var(db_row, "net_amount"), NULL);
	lf_set_var(f, "f.vat_rate", fields.vat_rate, de_xss);
	lf_set_var(f, "vat_rate", get_var(db_row, "vat_rate"), NULL);
	lf_set_var(f, "f.vat_number", fields.vat_number, de_xss);
	lf_set_var(f, "vat_number", get_var(db_row, "vat_number"), de_xss);
	lf_set_var(f, "f.reason", fields.reason, de_xss);
	lf_set_var(f, "reason", get_var(db_row, "reason"), de_xss);
	lf_set_var(f, "f.receipt_date", fields.receipt_date, de_xss);

	secs = atol(get_var(db_row, "receipt_date"));
	strftime(tbuf, sizeof(tbuf), "%a %b %d, %Y", localtime(&secs));
	lf_set_var(f, "receipt_date", tbuf, NULL);

	lf_set_var(f, "f.payment_method", fields.payment_method, de_xss);
	lf_set_var(f, "payment_method", get_var(db_row, "payment_method"),
		   NULL);
	/*
	 * To get the right payment method 'selected' in the drop down,
	 * yeah there must be a better way...
	 */
	if (strcmp(get_var(db_row, "payment_method"), "Card") == 0)
		lf_set_var(f, "card", "", NULL);
	else if (strcmp(get_var(db_row, "payment_method"), "Cash") == 0)
		lf_set_var(f, "cash", "", NULL);
	else if (strcmp(get_var(db_row, "payment_method"), "Cheque") == 0)
		lf_set_var(f, "cheque", "", NULL);

	if (atoi(get_var(db_row, "approved")) == REJECTED)
		lf_set_var(f, "rejected", "", NULL);
	else if (atoi(get_var(db_row, "approved")) == PENDING)
		lf_set_var(f, "pending", "", NULL);
	else
		lf_set_var(f, "approved", "", NULL);

	/* Only PENDING receipts of the user are editable */
	if (atoi(get_var(db_row, "approved")) == PENDING &&
	    (unsigned)atoi(get_var(db_row, "uid")) == user_session.uid) {
		if (strcmp(get_var(qvars, "edit"), "true") == 0) {
			lf_set_var(f, "edit", "", NULL);
			/*
			 * Put the date into the same format that it should be
			 * entered by the user (YYYY-MM-DD).
			 */
			strftime(tbuf, sizeof(tbuf), "%Y-%m-%d",
							localtime(&secs));
			lf_set_var(f, "receipt_date", tbuf, NULL);
		} else {
			lf_set_var(f, "showedit", "", NULL);
			lf_set_var(f, "noedit", "", NULL);
		}
	} else if (atoi(get_var(db_row, "approved")) == APPROVED ||
		   atoi(get_var(db_row, "approved")) == REJECTED) {
		/*
		 * The receipt has either been APPROVED or REJECTED
		 * Display the approval/rejection date/time and
		 * reason for rejection.
		 */
		secs = atol(get_var(db_row, "a_time"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e %H:%M %Y %z",
			 localtime(&secs));
		lf_set_var(f, "a_time", tbuf, NULL);
		lf_set_var(f, "reject_reason", get_var(db_row, "r_reason"),
			   de_xss);
		/* Only approvers can see who approved/rejected receipts */
		if (IS_APPROVER()) {
			lf_set_var(f, "reviewed_by_n",
				   get_var(db_row, "reviewed_by_n"), de_xss);
			lf_set_var(f, "reviewed_by_u",
				   get_var(db_row, "reviewed_by_u"), de_xss);
		}

		lf_set_var(f, "noedit", "", NULL);
	}
	add_csrf_token(f);

	free_vars(db_row);
	free_fields();

out1:
	mysql_free_result(res);
	free(image_id);
out2:
	send_template(f);
	lf_free(f);
}

/*
 * /tagged_receipts/
 *
 * Displays a gallery of previously tagged receipts.
 */
static void tagged_receipts(void)
{
	unsigned long nr_rows;
	unsigned long i;
	int c = 1;		/* column number */
	MYSQL_RES *res;
	Flate *f = NULL;
	struct pagination pn = { .rows_per_page = GRID_SIZE,
				 .requested_page = 1, .from = 0, .nr_pages = 0,
				 .page_no = 1 };

	lf_set_tmpl(&f, "templates/tagged_receipts.tmpl");
	ADD_HDR(f);

	if (qvars) {
		pn.requested_page = atoi(get_var(qvars, "page_no"));
		get_page_pagination(&pn);
	}

	res = sql_query("SELECT (SELECT COUNT(*) FROM tags INNER JOIN images "
			"ON (tags.id = images.id) WHERE images.tagged = 1 AND "
			"images.uid = %u) AS nrows, tags.receipt_date, "
			"images.id, images.path, images.name, "
			"images.approved, reviewed.timestamp FROM tags "
			"INNER JOIN images ON (tags.id = images.id) "
			"LEFT JOIN reviewed ON (tags.id = reviewed.id) WHERE "
			"images.tagged = 1 AND images.uid = %u ORDER BY "
			"tags.timestamp DESC LIMIT %d, %d",
			user_session.uid, user_session.uid, pn.from,
			GRID_SIZE);
	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0)
		goto out;

	set_custom_field_names();
	lf_set_var(f, "receipts", "", NULL);

	/* Draw gallery grid */
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		time_t secs;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);

		pn.nr_pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
				(float)pn.rows_per_page);

		lf_set_var(f, "id", get_var(db_row, "id"), NULL);
		lf_set_var(f, "image_path", get_var(db_row, "path"), NULL);
		lf_set_var(f, "image_name", get_var(db_row, "name"), NULL);

		secs = atol(get_var(db_row, "receipt_date"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		lf_set_var(f, "f.receipt_date", fields.receipt_date, de_xss);
		lf_set_var(f, "receipt_date", tbuf, NULL);
		/* If the receipt been reviewed, display its reviewed date */
		if (IS_SET(get_var(db_row, "timestamp"))) {
			secs = atol(get_var(db_row, "timestamp"));
			strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y",
							localtime(&secs));
			lf_set_var(f, "reviewed_date", tbuf, NULL);
		}

		if (atoi(get_var(db_row, "approved")) == REJECTED)
			lf_set_var(f, "rejected", "", NULL);
		else if (atoi(get_var(db_row, "approved")) == PENDING)
			lf_set_var(f, "pending", "", NULL);
		else
			lf_set_var(f, "approved", "", NULL);

		/* We want a 3 x 3 grid */
		if (c == COL_SIZE) /* Close off row */
			lf_set_var(f, "close_row", "", NULL);

		if (c == COL_SIZE && i < nr_rows) { /* Start a new row */
			lf_set_var(f, "new_row", "", NULL);
			c = 0;
		}
		c++;

		lf_set_row(f, "table");
		free_vars(db_row);
	}
	free_fields();
	do_pagination(f, &pn);

out:
	send_template(f);
	lf_free(f);
	mysql_free_result(res);
}

/*
 * /process_receipt/
 *
 * HTML is in templates/process_receipt.tmpl
 *
 * Processes receipt tag information as entered into /receipts/ or
 * /receipt_info/
 *
 * Users can only tag/edit their own receipts and only receipts that
 * are PENDING.
 */
static void process_receipt(void)
{
	char secs[11];
	char *image_id;
	struct tm tm;
	bool tag_error = false;
	int ret;
	double gross;
	double net;
	double vat;
	double vr;
	Flate *f = NULL;
	MYSQL_RES *res;

	if (!qvars)
		return;

	/* Prevent CSRF attack */
	if (!valid_csrf_token())
		return;

	/* Prevent users from tagging other users receipts */
	if (!is_users_receipt(get_var(qvars, "image_id")))
		return;

	/* Receipt must be in PENDING status */
	image_id = make_mysql_safe_string(get_var(qvars, "image_id"));
	res = sql_query("SELECT id FROM images WHERE id = '%s' AND approved "
			"= %d", get_var(qvars, "image_id"), PENDING);
	if (mysql_num_rows(res) == 0)
		goto out;

	lf_set_tmpl(&f, "templates/process_receipt.tmpl");

	lf_set_var(f, "image_id", get_var(qvars, "image_id"), de_xss);
	lf_set_var(f, "image_path", get_var(qvars, "image_path"), de_xss);
	lf_set_var(f, "image_name", get_var(qvars, "image_name"), de_xss);
	set_custom_field_names();

	if (!IS_SET(get_var(qvars, "department"))) {
		tag_error = true;
		lf_set_var(f, "e.department", "", NULL);
	}
	lf_set_var(f, "f.department", fields.department, de_xss);
	lf_set_var(f, "department", get_var(qvars, "department"), de_xss);

	if (!IS_SET(get_var(qvars, "employee_number"))) {
		tag_error = true;
		lf_set_var(f, "e.employee_number", "", NULL);
	}
	lf_set_var(f, "f.employee_number", fields.employee_number, de_xss);
	lf_set_var(f, "employee_number", get_var(qvars, "employee_number"),
		   de_xss);

	if (!IS_SET(get_var(qvars, "cost_codes"))) {
		tag_error = true;
		lf_set_var(f, "e.cost_codes", "", NULL);
	}
	lf_set_var(f, "f.cost_codes", fields.cost_codes, de_xss);
	lf_set_var(f, "cost_codes", get_var(qvars, "cost_codes"), de_xss);

	if (!IS_SET(get_var(qvars, "account_codes"))) {
		tag_error = true;
		lf_set_var(f, "e.account_codes", "", NULL);
	}
	lf_set_var(f, "f.account_codes", fields.account_codes, de_xss);
	lf_set_var(f, "account_codes", get_var(qvars, "account_codes"), de_xss);

	if (!IS_SET(get_var(qvars, "po_num"))) {
		tag_error = true;
		lf_set_var(f, "e.po_num", "", NULL);
	}
	lf_set_var(f, "f.po_num", fields.po_num, de_xss);
	lf_set_var(f, "po_num", get_var(qvars, "po_num"), de_xss);

	if (!IS_SET(get_var(qvars, "supplier_name"))) {
		tag_error = true;
		lf_set_var(f, "e.supplier_name", "", NULL);
	}
	lf_set_var(f, "f.supplier_name", fields.supplier_name, de_xss);
	lf_set_var(f, "supplier_name", get_var(qvars, "supplier_name"), de_xss);

	if (!IS_SET(get_var(qvars, "supplier_town"))) {
		tag_error = true;
		lf_set_var(f, "e.supplier_town", "", NULL);
	}
	lf_set_var(f, "f.supplier_town", fields.supplier_town, de_xss);
	lf_set_var(f, "supplier_town", get_var(qvars, "supplier_town"), de_xss);

	lf_set_var(f, "f.currency", fields.currency, de_xss);
	lf_set_var(f, "currency", get_var(qvars, "currency"), de_xss);

	gross = strtod(get_var(qvars, "gross_amount"), NULL);
	net = strtod(get_var(qvars, "net_amount"), NULL);
	vat = strtod(get_var(qvars, "vat_amount"), NULL);
	vr = strtod(get_var(qvars, "vat_rate"), NULL);
	ret = check_amounts(gross, net, vat, vr);
	if (ret < 0) {
		tag_error = true;
		lf_set_var(f, "e.amounts", "", NULL);
	}
	lf_set_var(f, "f.gross_amount", fields.gross_amount, de_xss);
	lf_set_var(f, "gross_amount", get_var(qvars, "gross_amount"), de_xss);
	lf_set_var(f, "f.net_amount", fields.net_amount, de_xss);
	lf_set_var(f, "net_amount", get_var(qvars, "net_amount"), de_xss);
	lf_set_var(f, "f.vat_amount", fields.vat_amount, de_xss);
	lf_set_var(f, "vat_amount", get_var(qvars, "vat_amount"), de_xss);
	lf_set_var(f, "f.vat_rate", fields.vat_rate, de_xss);
	lf_set_var(f, "vat_rate", get_var(qvars, "vat_rate"), de_xss);

	if (!IS_SET(get_var(qvars, "vat_number"))) {
		tag_error = true;
		lf_set_var(f, "e.vat_number", "", NULL);
	}
	lf_set_var(f, "f.vat_number", fields.vat_number, de_xss);
	lf_set_var(f, "vat_number", get_var(qvars, "vat_number"), de_xss);

	lf_set_var(f, "f.reason", fields.reason, de_xss);
	lf_set_var(f, "reason", get_var(qvars, "reason"), de_xss);

	memset(&tm, 0, sizeof(tm));
	strptime(get_var(qvars, "receipt_date"), "%Y-%m-%d", &tm);
	strftime(secs, sizeof(secs), "%s", &tm);
	if (strtol(secs, NULL, 10) < time(NULL) - MAX_RECEIPT_AGE ||
	    strtol(secs, NULL, 10) > time(NULL)) {
		tag_error = true;
		lf_set_var(f, "e.receipt_date", "", NULL);
	}
	lf_set_var(f, "f.receipt_date", fields.receipt_date, de_xss);
	lf_set_var(f, "receipt_date", get_var(qvars, "receipt_date"), de_xss);

	lf_set_var(f, "f.payment_method", fields.payment_method, de_xss);
	lf_set_var(f, "payment_method", get_var(qvars, "payment_method"),
		   de_xss);

	if (!tag_error) {
		tag_image();
		if (strstr(get_var(qvars, "from"), "receipt_info"))
			fcgx_p("Location: /receipt_info/?image_id=%s\r\n\r\n",
			       get_var(qvars, "image_id"));
		else
			fcgx_p("Location: /receipts/\r\n\r\n");
	} else {
		if (strstr(get_var(qvars, "from"), "receipt_info"))
			lf_set_var(f, "from", "receipt_info", NULL);
		add_csrf_token(f);
		send_template(f);
	}
	lf_free(f);
	free_fields();

out:
	mysql_free_result(res);
	free(image_id);
}

/*
 * /stats/
 *
 * HTML is in templates/stats.tmpl
 *
 * Display some simple stats about users receipts.
 */
static void stats(void)
{
	Flate *f = NULL;

	lf_set_tmpl(&f, "templates/stats.tmpl");
	ADD_HDR(f);

	gather_receipt_stats_for_user(user_session.uid, STATS_USER, f);

	send_template(f);
	lf_free(f);
}

/*
 * /receipts/
 *
 * HTML is in templates/receipts.tmpl
 *
 * Main page of the application. Displays any un-tagged images and
 * a form for each to enter its data.
 */
static void receipts(void)
{
	unsigned long i;
	unsigned long nr_rows;
	MYSQL_RES *res;
	Flate *f = NULL;

	lf_set_tmpl(&f, "templates/receipts.tmpl");
	ADD_HDR(f);
	/*
	 * Display the users last login time and location, we only show
	 * this on the /receipts/ page.
	 */
	display_last_login(f);

	res = sql_query("SELECT id, timestamp, path, name FROM images WHERE "
			"tagged = 0 AND uid = %u", user_session.uid);
	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0)
		goto out;

	lf_set_var(f, "receipts", "", NULL);
	add_csrf_token(f);

	set_custom_field_names();
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		time_t secs;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);

		lf_set_var(f, "image_path", get_var(db_row, "path"), NULL);
		lf_set_var(f, "image_name", get_var(db_row, "name"), NULL);
		secs = atol(get_var(db_row, "timestamp"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e %H:%M %Y %z",
			 localtime(&secs));
		lf_set_var(f, "timestamp", tbuf, NULL);
		lf_set_var(f, "f.department", fields.department, de_xss);
		lf_set_var(f, "f.employee_number", fields.employee_number,
			   de_xss);
		lf_set_var(f, "f.cost_codes", fields.cost_codes, de_xss);
		lf_set_var(f, "f.account_codes", fields.account_codes, de_xss);
		lf_set_var(f, "f.po_num", fields.po_num, de_xss);
		lf_set_var(f, "f.supplier_name", fields.supplier_name, de_xss);
		lf_set_var(f, "f.supplier_town", fields.supplier_town, de_xss);
		lf_set_var(f, "f.currency", fields.currency, de_xss);
		lf_set_var(f, "f.gross_amount", fields.gross_amount, de_xss);
		lf_set_var(f, "f.vat_amount", fields.vat_amount, de_xss);
		lf_set_var(f, "f.net_amount", fields.net_amount, de_xss);
		lf_set_var(f, "f.vat_rate", fields.vat_rate, de_xss);
		lf_set_var(f, "f.vat_number", fields.vat_number, de_xss);
		lf_set_var(f, "f.reason", fields.reason, de_xss);
		lf_set_var(f, "f.receipt_date", fields.receipt_date, de_xss);
		lf_set_var(f, "f.payment_method", fields.payment_method,
			   de_xss);
		/* image_id for hidden input field */
		lf_set_var(f, "id", get_var(db_row, "id"), NULL);

		lf_set_row(f, "table");
		free_vars(db_row);
	}
	free_fields();

out:
	send_template(f);
	lf_free(f);
	mysql_free_result(res);
}

/*
 * /env/
 *
 * Displays the environment list.
 */
static void print_env(void)
{
	fcgx_p("Content-Type: text/html\r\n\r\n");
	fcgx_p("<html>\n");
	fcgx_p("<head>\n");
	fcgx_p("<link href = \"/static/css/main.css\" rel = \"stylesheet\" "
	       "type = \"text/css\" />\n");
	fcgx_p("</head>\n");
	fcgx_p("<body>\n");

	for ( ; *fcgx_envp != NULL; fcgx_envp++)
		fcgx_p("%s<br />\n", *fcgx_envp);

	fcgx_p("</body>\n");
	fcgx_p("</html>\n");
}

static char *request_uri;
/*
 * Given a URI we are checking for against request_uri
 * Return:
 *     true for a match and
 *     false for no match.
 */
static bool match_uri(const char *uri)
{
	size_t rlen;
	size_t mlen = strlen(uri);
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
	if ((strstr(request, "/get_image/") && strstr(uri, "/get_image/")) ||
	    (strncmp(request, uri, mlen) == 0 && rlen == mlen))
		return true;

	return false;
}

static jmp_buf env;
/*
 * This is the main URI mapping/routing function.
 *
 * Takes a URI string to match and the function to run if it matches
 * request_uri.
 */
static inline void uri_map(const char *uri, void (uri_handler)(void))
{
	if (match_uri(uri)) {
		uri_handler();
		longjmp(env, 1);
	}
}

/*
 * Main application. This is where the requests come in and routed.
 */
void handle_request(void)
{
	bool logged_in = false;
	struct timespec stp;
	struct timespec etp;

	clock_gettime(CLOCK_REALTIME, &stp);

	qvars = NULL;
	avars = NULL;
	u_files = NULL;

	set_env_vars();
	set_vars();
	request_uri = strdupa(env_vars.request_uri);

	/* Initialise the database connection */
	conn = db_conn();
	if (!conn)
		goto out2;

	/* Return from non-authenticated URIs and goto 'out2' */
	if (setjmp(env))
		goto out2;

	/*
	 * Some routes need to come before the login / session stuff as
	 * they can't be logged in and have no session.
	 */
	uri_map("/activate_user/", activate_user);
	uri_map("/generate_new_key/", generate_new_key);
	uri_map("/forgotten_password/", forgotten_password);
	uri_map("/login/", login);

	logged_in = is_logged_in();
	if (!logged_in) {
		fcgx_p("Location: /login/\r\n\r\n");
		goto out2;
	}

	/* Logged in, set-up the user_session structure */
	set_user_session();

	/* Return from authenticated URIs and goto 'out' */
	if (setjmp(env))
		goto out;

	/* Add new url handlers after here */
	uri_map("/receipts/", receipts);
	uri_map("/process_receipt/", process_receipt);
	uri_map("/tagged_receipts/", tagged_receipts);
	uri_map("/receipt_info/", receipt_info);
	uri_map("/approve_receipts/", approve_receipts);
	uri_map("/process_receipt_approval/", process_receipt_approval);
	uri_map("/reviewed_receipts/", reviewed_receipts);
	uri_map("/extract_data/", extract_data);
	uri_map("/do_extract_data/", do_extract_data);
	uri_map("/get_image/", get_image);
	uri_map("/delete_image/", delete_image);
	uri_map("/prefs/fmap/", prefs_fmap);
	uri_map("/prefs/edit_user/", prefs_edit_user);
	uri_map("/prefs/", prefs);
	uri_map("/admin/list_users/", admin_list_users);
	uri_map("/admin/add_user/", admin_add_user);
	uri_map("/admin/edit_user/", admin_edit_user);
	uri_map("/admin/user_stats/", admin_user_stats);
	uri_map("/admin/stats/", admin_stats);
	uri_map("/admin/pending_activations/", admin_pending_activations);
	uri_map("/admin/", admin);
	uri_map("/stats/", stats);
	uri_map("/logout/", logout);
	uri_map("/print_env/", print_env);

	/* Default location */
	fcgx_p("Location: /login/\r\n\r\n");

out:
	free_user_session();

out2:
	free_vars(qvars);
	free_avars();
	free_u_files();
	clock_gettime(CLOCK_REALTIME, &etp);
	d_fprintf(access_log, "Got request from %s for %s (%s), %ums\n",
		  env_vars.remote_addr, request_uri, env_vars.request_method,
		  (unsigned int)((etp.tv_sec * 1000 +etp.tv_nsec / NS_MSEC) -
				 (stp.tv_sec * 1000 + stp.tv_nsec / NS_MSEC)));
	free_env_vars();
	mysql_close(conn);
}
