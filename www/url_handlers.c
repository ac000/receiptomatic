/*
 * url_handlers.c
 *
 * Copyright (C) 2011-2013	OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdbool.h>

#include <mhash.h>

/* File magic library */
#include <magic.h>

#include <glib.h>

/* HTML template library */
#include <ctemplate.h>

#include "common.h"
#include "utils.h"
#include "data_extraction.h"
#include "url_helpers.h"
#include "url_handlers.h"
#include "audit.h"

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
	unsigned long long sid;
	TMPL_varlist *vl = NULL;

	if (qvars) {
		ret = check_auth();
		if (ret == 0) {
			sid = log_login();
			create_session(sid);
			fcgx_p("Location: /receipts/\r\n\r\n");
			return; /* Successful login */
		}
	}

	if (ret == -1)
		vl = add_html_var(vl, "logged_in", "no");
	if (ret == -2)
		vl = add_html_var(vl, "enabled", "no");

	send_template("templates/login.tmpl", vl, NULL);
	TMPL_free_varlist(vl);
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
	tctdbopen(tdb, SESSION_DB, TDBOWRITER);

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
				"expires=Thu, 01 Jan 1970 00:00:01 GMT; "
				"path=/; httponly\r\n");
	send_template("templates/logout.tmpl", NULL, NULL);
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
	TMPL_varlist *vl = NULL;

	if (!qvars)
		goto out2;

	image_id = make_mysql_safe_string(get_var(qvars, "image_id"));
	/* Only allow to delete images that are un-tagged */
	res = sql_query("SELECT path, name FROM images WHERE id = '%s' AND "
			"tagged = 0", image_id);
	if (mysql_num_rows(res) == 0)
		goto out1;

	db_row = get_dbrow(res);

	snprintf(path, PATH_MAX, "%s/%s/%s", IMAGE_PATH,
						get_var(db_row, "path"),
						get_var(db_row, "name"));
	if (!realpath(path, image_path))
		goto out1;

	vl = add_html_var(vl, "image_path", get_var(db_row, "path"));
	vl = add_html_var(vl, "image_name", get_var(db_row, "name"));
	vl = add_html_var(vl, "image_id", get_var(qvars, "image_id"));

	memset(userdir, 0, sizeof(userdir));
	snprintf(userdir, sizeof(userdir), "/%s%s%u/",
			(MULTI_TENANT) ? user_session.tenant : "",
			(MULTI_TENANT) ? "/" : "", user_session.uid);
	/* Is it one of the users images? */
	if (strncmp(image_path + strlen(IMAGE_PATH), userdir, strlen(userdir))
			!= 0)
		goto out1;

	if (strcmp(get_var(qvars, "confirm"), "yes") == 0) {
		if (!valid_csrf_token())
			goto out1;

		/* remove the full image */
		unlink(image_path);

		/* remove the small image */
		snprintf(path, PATH_MAX, "%s/%s/small/%s", IMAGE_PATH,
						get_var(db_row, "path"),
						get_var(db_row, "name"));
		if (!realpath(path, image_path))
			goto out1;

		unlink(image_path);

		/* remove the medium image */
		snprintf(path, PATH_MAX, "%s/%s/medium/%s", IMAGE_PATH,
						get_var(db_row, "path"),
						get_var(db_row, "name"));
		if (!realpath(path, image_path))
			goto out1;

		unlink(image_path);

		sql_query("DELETE FROM images WHERE id = '%s'", image_id);
		/* We don't want to display the delete_image page again */
		goto out1;
	}

	add_csrf_token(vl);
	send_template("templates/delete_image.tmpl", vl, NULL);
	headers_sent = true;

out1:
	mysql_free_result(res);
	free(image_id);
	free_vars(db_row);
	TMPL_free_varlist(vl);
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

	snprintf(path, PATH_MAX, "%s/%s", IMAGE_PATH, env_vars.request_uri
									+ 11);
	if (!realpath(path, image_path))
		return;

	/* Don't let users access other user images */
	if (!image_access_allowed(image_path)) {
		fcgx_p("Status: 401 Unauthorized\r\n\r\n");
		d_fprintf(access_log, "Access denied to %s for %s\n",
							env_vars.request_uri,
							user_session.username);
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
	} while (bytes_read == BUF_SIZE);

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
	TMPL_varlist *vl = NULL;

	if (!IS_ADMIN())
		return;

	ADD_HDR(vl);
	send_template("templates/admin.tmpl", vl, NULL);
	TMPL_free_varlist(vl);
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
	int rpp = 15;	/* Rows Per Page to display */
	unsigned long nr_rows;
	unsigned long i;
	int nr_pages = 0;
	int page = 1;
	int from = 0;
	MYSQL_RES *res;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;
	TMPL_fmtlist *fmtlist;

	if (!IS_ADMIN())
		return;

	ADD_HDR(ml);

	if (qvars)
		get_page_pagination(get_var(qvars, "page_no"), rpp, &page,
									&from);

	res = sql_query("SELECT (SELECT COUNT(*) FROM passwd) AS nrows, uid, "
			"username, name, capabilities, enabled, activated "
			"FROM passwd LIMIT %d, %d", from, rpp);
	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		char caps[33] = "\0";
		unsigned char capabilities;
		GHashTable *db_row = NULL;
		TMPL_varlist *vl = NULL;

		db_row = get_dbrow(res);
		nr_pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
								(float)rpp);

		vl = do_zebra(vl, i);
		vl = add_html_var(vl, "uid", get_var(db_row, "uid"));
		vl = add_html_var(vl, "username", get_var(db_row, "username"));
		vl = add_html_var(vl, "name", get_var(db_row, "name"));

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
		vl = add_html_var(vl, "capabilities", caps);

		if (capabilities & ADMIN)
			vl = add_html_var(vl, "admin", "yes");
		else
			vl = add_html_var(vl, "admin", "no");

		if (atoi(get_var(db_row, "enabled")) == 1)
			vl = add_html_var(vl, "enabled", "yes");
		else
			vl = add_html_var(vl, "enabled", "no");

		if (atoi(get_var(db_row, "activated")) == 1)
			vl = add_html_var(vl, "activated", "yes");
		else
			vl = add_html_var(vl, "activated", "no");

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "table", loop);
	do_pagination(ml, page, nr_pages);

	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/admin_list_users.tmpl", ml, fmtlist);
	TMPL_free_varlist(ml);
	TMPL_free_fmtlist(fmtlist);
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
	unsigned char capabilities = 0;
	bool form_err = false;
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist;

	if (!IS_ADMIN())
		return;

	/* Prevent CSRF attack */
	if (IS_POST() && !valid_csrf_token())
		return;

	ADD_HDR(vl);

	if (!qvars)
		goto out;

	if (!IS_SET(get_var(qvars, "name"))) {
		form_err = true;
		vl = add_html_var(vl, "name_error", "yes");
	}
	vl = add_html_var(vl, "name", get_var(qvars, "name"));

	if ((!IS_SET(get_var(qvars, "email1")) &&
	     !IS_SET(get_var(qvars, "email2"))) ||
	    (strcmp(get_var(qvars, "email1"),
		    get_var(qvars, "email2")) != 0)) {
		form_err = true;
		vl = add_html_var(vl, "email_error", "yes");
	}
	vl = add_html_var(vl, "email1", get_var(qvars, "email1"));
	vl = add_html_var(vl, "email2", get_var(qvars, "email2"));

	if (IS_SET(get_var(qvars, "ap_card")) ||
	    IS_SET(get_var(qvars, "ap_cash")) ||
	    IS_SET(get_var(qvars, "ap_cheque")) ||
	    IS_SET(get_var(qvars, "ap_self"))) {
		capabilities |= APPROVER;
		if (IS_SET(get_var(qvars, "ap_card"))) {
			capabilities |= APPROVER_CARD;
			vl = add_html_var(vl, "ap_card", "yes");
		}
		if (IS_SET(get_var(qvars, "ap_cash"))) {
			capabilities |= APPROVER_CASH;
			vl = add_html_var(vl, "ap_cash", "yes");
		}
		if (IS_SET(get_var(qvars, "ap_cheque"))) {
			capabilities |= APPROVER_CHEQUE;
			vl = add_html_var(vl, "ap_cheque", "yes");
		}
		if (IS_SET(get_var(qvars, "ap_self"))) {
			capabilities |= APPROVER_SELF;
			vl = add_html_var(vl, "ap_self", "yes");
		}
	}
	if (IS_SET(get_var(qvars, "is_admin"))) {
		capabilities |= ADMIN;
		vl = add_html_var(vl, "is_admin", "yes");
	}

	if (!form_err) {
		int ret;

		ret = do_add_user(capabilities);
		if (ret == -10) {
			/*
			 * Tried to add an already existing user.
			 * Tell the admin.
			 */
			vl = add_html_var(vl, "dup_user", "yes");
		} else {
			fcgx_p("Location: /admin/add_user/\r\n\r\n");
			goto out2;
		}
	}

out:
	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/admin_add_user.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);

out2:
	TMPL_free_varlist(vl);
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
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist;

	if (!IS_ADMIN())
		return;

	if (!qvars)
		return;

	uid = atoi(get_var(qvars, "uid"));

	/* If we got a POST, update user settings before showing them. */
	if (IS_POST() && valid_csrf_token()) {
		if ((!IS_SET(get_var(qvars, "email1")) &&
		     !IS_SET(get_var(qvars, "email2"))) ||
		    (strcmp(get_var(qvars, "email1"),
			    get_var(qvars, "email2")) != 0)) {
			vl = add_html_var(vl, "email_error", "yes");
			form_err = true;
		}
		if (strlen(get_var(qvars, "pass1")) > 7 &&
		    strlen(get_var(qvars, "pass2")) > 7) {
			if (strcmp(get_var(qvars, "pass1"),
						get_var(qvars, "pass2")) != 0) {
				vl = add_html_var(vl, "pass_error",
						"mismatch");
				form_err = true;
			}
		} else if (IS_SET(get_var(qvars, "pass1")) &&
			   IS_SET(get_var(qvars, "pass2"))) {
			/*
			 * If the password fields are > 0 in length, then we
			 * at least tried to update it.
			 */
			vl = add_html_var(vl, "pass_error", "length");
			form_err = true;
		}

		if (!form_err) {
			do_update_user();
			fcgx_p("Location: /admin/edit_user/?uid=%u&updated=yes"
					"\r\n\r\n", uid);
		}
	}
	ADD_HDR(vl);

	vl = add_html_var(vl, "uid", get_var(qvars, "uid"));

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
		unsigned char capabilities;
		GHashTable *db_row = NULL;
		MYSQL_RES *res;

		res = sql_query("SELECT username, name, capabilities, "
				"enabled, activated, d_reason FROM passwd "
				"WHERE uid = %u", uid);
		if (mysql_num_rows(res) == 0)
			goto mysql_cleanup;

		db_row = get_dbrow(res);

		if (IS_SET(get_var(qvars, "updated")))
			vl = add_html_var(vl, "updated", "yes");

		vl = add_html_var(vl, "username", get_var(db_row, "username"));
		vl = add_html_var(vl, "email1", get_var(db_row, "username"));
		vl = add_html_var(vl, "email2", get_var(db_row, "username"));
		vl = add_html_var(vl, "name", get_var(db_row, "name"));
		if (atoi(get_var(db_row, "enabled")) == 1)
			vl = add_html_var(vl, "is_enabled", "yes");
		if (atoi(get_var(db_row, "activated")) == 1)
			vl = add_html_var(vl, "is_activated", "yes");
		vl = add_html_var(vl, "d_reason", get_var(db_row, "d_reason"));

		capabilities = atoi(get_var(db_row, "capabilities"));
		if (capabilities & APPROVER_CARD)
			vl = add_html_var(vl, "ap_card", "yes");
		if (capabilities & APPROVER_CASH)
			vl = add_html_var(vl, "ap_cash", "yes");
		if (capabilities & APPROVER_CHEQUE)
			vl = add_html_var(vl, "ap_cheque", "yes");
		if (capabilities & APPROVER_SELF)
			vl = add_html_var(vl, "ap_self", "yes");

		if (capabilities & ADMIN)
			vl = add_html_var(vl, "is_admin", "yes");

		free_vars(db_row);
mysql_cleanup:
		mysql_free_result(res);
	} else {
		vl = add_html_var(vl, "username", get_var(qvars, "email1"));
		vl = add_html_var(vl, "email1", get_var(qvars, "email1"));
		vl = add_html_var(vl, "email2", get_var(qvars, "email2"));
		vl = add_html_var(vl, "name", get_var(qvars, "name"));

		if (atoi(get_var(qvars, "enabled")) == 1)
			vl = add_html_var(vl, "is_enabled", "yes");
		if (atoi(get_var(qvars, "activated")) == 1)
			vl = add_html_var(vl, "is_activated", "yes");

		if (atoi(get_var(qvars, "ap_card")) == 1)
			vl = add_html_var(vl, "ap_card", "yes");
		if (atoi(get_var(qvars, "ap_cash")) == 1)
			vl = add_html_var(vl, "ap_cash", "yes");
		if (atoi(get_var(qvars, "ap_cheque")) == 1)
			vl = add_html_var(vl, "ap_cheque", "yes");
		if (atoi(get_var(qvars, "ap_self")) == 1)
			vl = add_html_var(vl, "ap_self", "yes");

		if (atoi(get_var(qvars, "is_admin")) == 1)
			vl = add_html_var(vl, "is_admin", "yes");
	}

	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/admin_edit_user.tmpl", vl, fmtlist);
	TMPL_free_fmtlist(fmtlist);
	TMPL_free_varlist(vl);
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
	TMPL_varlist *vl = NULL;

	if (!IS_ADMIN())
		return;

	ADD_HDR(vl);

	/* Gather stats covering _all_ users */
	gather_receipt_stats_for_user(-1, vl);

	send_template("templates/admin_stats.tmpl", vl, NULL);
	TMPL_free_varlist(vl);
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
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist;

	if (!IS_ADMIN() || !qvars)
		return;

	ADD_HDR(vl);

	uid = atoi(get_var(qvars, "uid"));

	res = sql_query("SELECT name FROM passwd WHERE uid = %u", uid);
	if (mysql_num_rows(res) == 0)
		goto out;

	gather_receipt_stats_for_user(uid, vl);
	db_row = get_dbrow(res);
	vl = add_html_var(vl, "uid", get_var(qvars, "uid"));
	vl = add_html_var(vl, "name", get_var(db_row, "name"));
	free_vars(db_row);

	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/admin_user_stats.tmpl", vl, fmtlist);

out:
	mysql_free_result(res);
	TMPL_free_varlist(vl);
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
	int rpp = 15;	/* Rows Per Page to display */
	unsigned long nr_rows;
	unsigned long i;
	int nr_pages = 0;
	int page = 1;
	int from = 0;
	MYSQL_RES *res;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;
	TMPL_fmtlist *fmtlist;

	if (!IS_ADMIN())
		return;

	if (IS_POST() && valid_csrf_token() && avars)
		process_activation_changes();

	ADD_HDR(ml);

	if (qvars)
		get_page_pagination(get_var(qvars, "page_no"), rpp, &page,
				&from);

	res = sql_query("SELECT (SELECT COUNT(*) FROM activations INNER JOIN "
			"passwd ON (activations.user = passwd.username)) AS "
			"nrows, passwd.name, passwd.uid, activations.user, "
			"activations.expires, activations.akey FROM "
			"activations INNER JOIN passwd ON "
			"(activations.user = passwd.username) LIMIT "
			"%d, %d", from, rpp);

	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		char item[3];
		time_t secs;
		GHashTable *db_row = NULL;
		TMPL_varlist *vl = NULL;

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

		nr_pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
				(float)rpp);

		vl = do_zebra(vl, i);
		vl = add_html_var(vl, "name", get_var(db_row, "name"));
		vl = add_html_var(vl, "username", get_var(db_row, "user"));
		secs = atol(get_var(db_row, "expires"));
		if (time(NULL) > secs)
			vl = add_html_var(vl, "expired", "yes");
		strftime(tbuf, sizeof(tbuf), "%F %H:%M:%S", localtime(&secs));
		vl = add_html_var(vl, "expires", tbuf);

		vl = add_html_var(vl, "uid", get_var(db_row, "uid"));
		vl = add_html_var(vl, "akey", get_var(db_row, "akey"));
		snprintf(item, sizeof(item), "%lu", i);
		vl = add_html_var(vl, "item", item);

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "table", loop);
	add_csrf_token(ml);
	do_pagination(ml, page, nr_pages);

	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/admin_pending_activations.tmpl", ml, fmtlist);
	TMPL_free_varlist(ml);
	TMPL_free_fmtlist(fmtlist);
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
	TMPL_varlist *vl = NULL;

	if (!qvars) {
		vl = add_html_var(vl, "key_error", "yes");
		goto out2;
	}

	key = make_mysql_safe_string(get_var(qvars, "key"));
	res = sql_query("SELECT uid, name, user, expires FROM passwd "
			"INNER JOIN activations ON (passwd.username = "
			"activations.user) WHERE activations.akey = '%s'",
			key);
	if (mysql_num_rows(res) == 0) {
		vl = add_html_var(vl, "key_error", "yes");
		goto out;
	}

	db_row = get_dbrow(res);
	vl = add_html_var(vl, "name", get_var(db_row, "name"));

	/* Check if the activation key has expired. */
	if (time(NULL) > atol(get_var(db_row, "expires"))) {
		vl = add_html_var(vl, "expired", "yes");
		vl = add_html_var(vl, "email", get_var(db_row, "user"));
		goto out;
	}
	vl = add_html_var(vl, "key", get_var(qvars, "key"));

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
				vl = add_html_var(vl, "activated", "yes");
			} else {
				vl = add_html_var(vl, "password_error",
						"mismatch");
			}
		} else {
			vl = add_html_var(vl, "password_error", "length");
		}
	}

out:
	mysql_free_result(res);
	free_vars(db_row);
	free(key);

out2:
	send_template("templates/activate_user.tmpl", vl, NULL);
	TMPL_free_varlist(vl);
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
	TMPL_varlist *vl = NULL;

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

	vl = add_html_var(vl, "email", email_addr);

out:
	send_template("templates/generate_new_key.tmpl", vl, NULL);
	TMPL_free_varlist(vl);

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
	TMPL_varlist *vl = NULL;

	if (!qvars)
		goto out;

	vl = add_html_var(vl, "email", get_var(qvars, "email"));

	email_addr = make_mysql_safe_string(get_var(qvars, "email"));
	res = sql_query("SELECT username FROM passwd WHERE username = '%s'",
			email_addr);
	if (mysql_num_rows(res) == 0) {
		vl = add_html_var(vl, "user_error", "yes");
		goto mysql_cleanup;
	}

	generate_hash(key, SHA256);
	tm = time(NULL);
	sql_query("INSERT INTO activations VALUES ('%s', '%s', %ld)",
			email_addr, key, tm + KEY_EXP);

	send_activation_mail(get_var(qvars, "name"), email_addr, key);
	vl = add_html_var(vl, "sent", "yes");

mysql_cleanup:
	mysql_free_result(res);
	free(email_addr);

out:
	send_template("templates/forgotten_password.tmpl", vl, NULL);
	TMPL_free_varlist(vl);
}

/*
 * /prefs/
 *
 * HTML is in templates/prefs.tmpl
 */
static void prefs(void)
{
	TMPL_varlist *vl = NULL;

	ADD_HDR(vl);
	send_template("templates/prefs.tmpl", vl, NULL);
	TMPL_free_varlist(vl);
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
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist;

	if (IS_POST() && valid_csrf_token()) {
		update_fmap();
		fcgx_p("Location: /prefs/fmap/?updated=yes\r\n\r\n");
		return;
	} else if (IS_GET() && IS_SET(get_var(qvars, "updated"))) {
		vl = add_html_var(vl, "fields_updated", "yes");
	}

	ADD_HDR(vl);

	set_custom_field_names();
	vl = add_html_var(vl, "receipt_date", DFN_RECEIPT_DATE);
	vl = add_html_var(vl, "alt_receipt_date", !strcmp(DFN_RECEIPT_DATE,
			fields.receipt_date) ? "" : fields.receipt_date);

	vl = add_html_var(vl, "department", DFN_DEPARTMENT);
	vl = add_html_var(vl, "alt_department", !strcmp(DFN_DEPARTMENT,
			fields.department) ? "" : fields.department);

	vl = add_html_var(vl, "employee_number", DFN_EMPLOYEE_NUMBER);
	vl = add_html_var(vl, "alt_employee_number",
			!strcmp(DFN_EMPLOYEE_NUMBER, fields.employee_number) ?
			"" : fields.employee_number);

	vl = add_html_var(vl, "reason", DFN_REASON);
	vl = add_html_var(vl, "alt_reason", !strcmp(DFN_REASON,
			fields.reason) ? "" : fields.reason);

	vl = add_html_var(vl, "po_num", DFN_PO_NUM);
	vl = add_html_var(vl, "alt_po_num", !strcmp(DFN_PO_NUM,
			fields.po_num) ? "" : fields.po_num);

	vl = add_html_var(vl, "cost_codes", DFN_COST_CODES);
	vl = add_html_var(vl, "alt_cost_codes", !strcmp(DFN_COST_CODES,
			fields.cost_codes) ? "" : fields.cost_codes);

	vl = add_html_var(vl, "account_codes", DFN_ACCOUNT_CODES);
	vl = add_html_var(vl, "alt_account_codes", !strcmp(DFN_ACCOUNT_CODES,
			fields.account_codes) ? "" : fields.account_codes);

	vl = add_html_var(vl, "supplier_name", DFN_SUPPLIER_NAME);
	vl = add_html_var(vl, "alt_supplier_name", !strcmp(DFN_SUPPLIER_NAME,
			fields.supplier_name) ? "" : fields.supplier_name);

	vl = add_html_var(vl, "supplier_town", DFN_SUPPLIER_TOWN);
	vl = add_html_var(vl, "alt_supplier_town", !strcmp(DFN_SUPPLIER_TOWN,
			fields.supplier_town) ? "" : fields.supplier_town);

	vl = add_html_var(vl, "vat_number", DFN_VAT_NUMBER);
	vl = add_html_var(vl, "alt_vat_number", !strcmp(DFN_VAT_NUMBER,
			fields.vat_number) ? "" : fields.vat_number);

	vl = add_html_var(vl, "gross_amount", DFN_GROSS_AMOUNT);
	vl = add_html_var(vl, "alt_gross_amount", !strcmp(DFN_GROSS_AMOUNT,
			fields.gross_amount) ? "" : fields.gross_amount);

	vl = add_html_var(vl, "net_amount", DFN_NET_AMOUNT);
	vl = add_html_var(vl, "alt_net_amount", !strcmp(DFN_NET_AMOUNT,
			fields.net_amount) ? "" : fields.net_amount);

	vl = add_html_var(vl, "vat_amount", DFN_VAT_AMOUNT);
	vl = add_html_var(vl, "alt_vat_amount", !strcmp(DFN_VAT_AMOUNT,
			fields.vat_amount) ? "" : fields.vat_amount);

	vl = add_html_var(vl, "vat_rate", DFN_VAT_RATE);
	vl = add_html_var(vl, "alt_vat_rate", !strcmp(DFN_VAT_RATE,
			fields.vat_rate) ? "" : fields.vat_rate);

	vl = add_html_var(vl, "currency", DFN_CURRENCY);
	vl = add_html_var(vl, "alt_currency", !strcmp(DFN_CURRENCY,
			fields.currency) ? "" : fields.currency);

	vl = add_html_var(vl, "payment_method", DFN_PAYMENT_METHOD);
	vl = add_html_var(vl, "alt_payment_method",
			!strcmp(DFN_PAYMENT_METHOD, fields.payment_method) ?
			"" : fields.payment_method);
	free_fields();

	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/prefs_fmap.tmpl", vl, fmtlist);
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
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
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist;

	/*
	 * If we got POST data, update the users settings before
	 * showing them.
	 */
	if (IS_POST() && valid_csrf_token()) {
		if ((!IS_SET(get_var(qvars, "email1")) &&
		     !IS_SET(get_var(qvars, "email2"))) ||
		    (strcmp(get_var(qvars, "email1"),
			    get_var(qvars, "email2")) != 0)) {
			vl = add_html_var(vl, "email_error", "yes");
			form_err = true;
		} else if (strcmp(user_session.username,
					get_var(qvars, "email1")) != 0) {
			if (user_already_exists(get_var(qvars, "email1"))) {
				vl = add_html_var(vl, "user_exists", "yes");
				form_err = true;
			}
		}
		if (strlen(get_var(qvars, "pass1")) > 7 &&
		    strlen(get_var(qvars, "pass2")) > 7) {
			if (strcmp(get_var(qvars, "pass1"),
						get_var(qvars, "pass2")) != 0) {
				vl = add_html_var(vl, "pass_error",
						"mismatch");
				form_err = true;
			}
		/*
		 * If the password fields are > 0 in length, then we tried
		 * to update it.
		 */
		} else if (IS_SET(get_var(qvars, "pass1")) &&
			   IS_SET(get_var(qvars, "pass2"))) {
			vl = add_html_var(vl, "pass_error", "length");
			form_err = true;
		}

		if (!form_err) {
			do_edit_user();
			/* After the update we want to re-GET */
			fcgx_p("Location: /prefs/edit_user/?updated=yes"
								"\r\n\r\n");
			return;
		}
	} else {
		if (IS_SET(get_var(qvars, "updated")))
			vl = add_html_var(vl, "updated", "yes");
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

		vl = add_html_var(vl, "username", get_var(db_row, "username"));
		vl = add_html_var(vl, "email1", get_var(db_row, "username"));
		vl = add_html_var(vl, "email2", get_var(db_row, "username"));
		vl = add_html_var(vl, "name", get_var(db_row, "name"));

		free_vars(db_row);
		mysql_free_result(res);
	} else {
		vl = add_html_var(vl, "username", get_var(qvars, "email1"));
		vl = add_html_var(vl, "email1", get_var(qvars, "email1"));
		vl = add_html_var(vl, "email2", get_var(qvars, "email2"));
		vl = add_html_var(vl, "name", get_var(qvars, "name"));
	}

	ADD_HDR(vl);

	add_csrf_token(vl);
	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/prefs_edit_user.tmpl", vl, fmtlist);
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
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
	TMPL_varlist *vl = NULL;

	if (!IS_APPROVER())
		return;

	ADD_HDR(vl);

	send_template("templates/extract_data.tmpl", vl, NULL);
	TMPL_free_varlist(vl);
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
	if (!valid_csrf_token())
		return;

	if (!avars)
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
					image_id, user_session.uid,
					username, time(NULL), APPROVED,
					reason);
			sql_query("UPDATE images SET approved = %d WHERE id = "
					"'%s'", APPROVED, image_id);
		} else if (action[0] == 'r') { /* rejected */
			sql_query("INSERT INTO reviewed VALUES ("
					"'%s', %u, '%s', %ld, %d, "
					"'%s')",
					image_id, user_session.uid,
					username, time(NULL), REJECTED,
					reason);
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
	unsigned long i;
	unsigned long nr_rows;
	int from = 0;
	int page = 1;
	int nr_pages = 0;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;
	TMPL_fmtlist *fmtlist;

	if (!IS_APPROVER())
		return;

	ADD_HDR(ml);

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
		d_fprintf(error_log, "User %u seems to have an invalid "
					"capability setting in the passwd "
					"table.\n", user_session.uid);
		return;
	}

	if (qvars)
		get_page_pagination(get_var(qvars, "page_no"), APPROVER_ROWS,
							&page, &from);

	memset(assql, 0, sizeof(assql));
	/* If the user isn't APPROVER_SELF, don't show them their receipts */
	if (!(user_session.capabilities & APPROVER_SELF))
		sprintf(assql, "AND images.uid != %u", user_session.uid);
	else
		assql[0] = '\0';

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
			pmsql, assql, pmsql, assql, from, APPROVER_ROWS);
	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0) {
		ml = add_html_var(ml, "receipts", "no");
		goto out;
	}

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
		TMPL_varlist *vl = NULL;

		db_row = get_dbrow(res);

		nr_pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
							(float)APPROVER_ROWS);

		vl = add_html_var(vl, "image_path", get_var(db_row, "path"));
		vl = add_html_var(vl, "image_name", get_var(db_row, "name"));

		name = username_to_name(get_var(db_row, "username"));
		vl = add_html_var(vl, "name", name);
		free(name);

		secs = atol(get_var(db_row, "its"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = add_html_var(vl, "images_timestamp", tbuf);

		secs = atol(get_var(db_row, "tts"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = add_html_var(vl, "tags_timestamp", tbuf);
		vl = add_html_var(vl, "fields.department", fields.department);
		vl = add_html_var(vl, "department",
					get_var(db_row, "department"));
		vl = add_html_var(vl, "fields.employee_number",
					fields.employee_number);
		vl = add_html_var(vl, "employee_number",
					get_var(db_row, "employee_number"));
		vl = add_html_var(vl, "fields.cost_codes", fields.cost_codes);
		vl = add_html_var(vl, "cost_codes",
					get_var(db_row, "cost_codes"));
		vl = add_html_var(vl, "fields.account_codes",
					fields.account_codes);
		vl = add_html_var(vl, "account_codes",
					get_var(db_row, "account_codes"));
		vl = add_html_var(vl, "fields.po_num", fields.po_num);
		vl = add_html_var(vl, "po_num", get_var(db_row, "po_num"));
		vl = add_html_var(vl, "fields.supplier_name",
					fields.supplier_name);
		vl = add_html_var(vl, "supplier_name",
					get_var(db_row, "supplier_name"));
		vl = add_html_var(vl, "fields.supplier_town",
					fields.supplier_town);
		vl = add_html_var(vl, "supplier_town",
					get_var(db_row, "supplier_town"));
		vl = add_html_var(vl, "fields.currency", fields.currency);
		vl = add_html_var(vl, "currency", get_var(db_row, "currency"));
		vl = add_html_var(vl, "fields.gross_amount",
					fields.gross_amount);
		vl = add_html_var(vl, "gross_amount",
					get_var(db_row, "gross_amount"));
		vl = add_html_var(vl, "fields.vat_amount", fields.vat_amount);
		vl = add_html_var(vl, "vat_amount",
					get_var(db_row, "vat_amount"));
		vl = add_html_var(vl, "fields.net_amount", fields.net_amount);
		vl = add_html_var(vl, "net_amount",
					get_var(db_row, "net_amount"));
		vl = add_html_var(vl, "fields.vat_rate", fields.vat_rate);
		vl = add_html_var(vl, "vat_rate", get_var(db_row, "vat_rate"));

		/* Sanity check the amounts */
		gross = strtod(get_var(db_row, "gross_amount"), NULL);
		net = strtod(get_var(db_row, "net_amount"), NULL);
		vat = strtod(get_var(db_row, "vat_amount"), NULL);
		vr = strtod(get_var(db_row, "vat_rate"), NULL);
		ret = check_amounts(gross, net, vat, vr);
		if (ret < 0)
			vl = add_html_var(vl, "amnt_err", "yes");
		else
			vl = add_html_var(vl, "amnt_err", "no");

		vl = add_html_var(vl, "fields.vat_number", fields.vat_number);
		vl = add_html_var(vl, "vat_number",
					get_var(db_row, "vat_number"));
		vl = add_html_var(vl, "fields.receipt_date",
					fields.receipt_date);

		secs = atol(get_var(db_row, "receipt_date"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = add_html_var(vl, "receipt_date", tbuf);
		vl = add_html_var(vl, "fields.payment_method",
					fields.payment_method);
		vl = add_html_var(vl, "payment_method",
					get_var(db_row, "payment_method"));
		vl = add_html_var(vl, "fields.reason", fields.reason);
		vl = add_html_var(vl, "reason", get_var(db_row, "reason"));
		vl = add_html_var(vl, "id", get_var(db_row, "id"));

		snprintf(item, sizeof(item), "%lu", i);
		vl = add_html_var(vl, "item", item);

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	free_fields();
	ml = TMPL_add_loop(ml, "table", loop);
	do_pagination(ml, page, nr_pages);
	/* Only use csrf if there is receipts to process */
	add_csrf_token(ml);

out:
	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/approve_receipts.tmpl", ml, fmtlist);
	TMPL_free_varlist(ml);
	TMPL_free_fmtlist(fmtlist);
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
	int from = 0;
	int page = 1;
	int nr_pages = 0;
	MYSQL_RES *res;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;
	TMPL_fmtlist *fmtlist;

	if (!IS_APPROVER())
		return;

	ADD_HDR(ml);

	if (qvars)
		get_page_pagination(get_var(qvars, "page_no"), GRID_SIZE,
							&page, &from);

	res = sql_query("SELECT (SELECT COUNT(*) FROM reviewed INNER JOIN "
			"images ON (reviewed.id = images.id)) AS nrows, "
			"reviewed.timestamp AS ats, images.id, images.path, "
			"images.name, images.timestamp AS its, "
			"reviewed.status, passwd.name AS user, passwd.uid "
			"FROM reviewed INNER JOIN images ON "
			"(reviewed.id = images.id) INNER JOIN passwd ON "
			"(images.uid = passwd.uid) ORDER BY "
			"reviewed.timestamp DESC LIMIT %d, %d",
			from, GRID_SIZE);
	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0) {
		ml = add_html_var(ml, "receipts", "no");
		goto out;
	}

	set_custom_field_names();
	ml = add_html_var(ml, "receipts", "yes");
	/* Draw gallery grid */
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		time_t secs;
		GHashTable *db_row = NULL;
		TMPL_varlist *vl = NULL;

		db_row = get_dbrow(res);

		nr_pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
							(float)GRID_SIZE);

		vl = add_html_var(vl, "id", get_var(db_row, "id"));
		vl = add_html_var(vl, "image_path", get_var(db_row, "path"));
		vl = add_html_var(vl, "image_name", get_var(db_row, "name"));
		vl = add_html_var(vl, "user", get_var(db_row, "user"));
		vl = add_html_var(vl, "uid", get_var(db_row, "uid"));

		secs = atol(get_var(db_row, "ats"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = add_html_var(vl, "review_date", "Review Date");
		vl = add_html_var(vl, "apdate", tbuf);

		secs = atol(get_var(db_row, "its"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = add_html_var(vl, "receipt_date", fields.receipt_date);
		vl = add_html_var(vl, "rdate", tbuf);

		if (atoi(get_var(db_row, "status")) == REJECTED)
			vl = add_html_var(vl, "status", "rejected");
		else
			vl = add_html_var(vl, "status", "approved");

		if (c == COL_SIZE && i < nr_rows) { /* Start a new row */
			vl = add_html_var(vl, "new_row", "yes");
			c = 0;
		} else {
			vl = add_html_var(vl, "new_row", "no");
		}
		c++;

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "table", loop);
	free_fields();
	do_pagination(ml, page, nr_pages);

out:
	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/reviewed_receipts.tmpl", ml, fmtlist);
	TMPL_free_varlist(ml);
	TMPL_free_fmtlist(fmtlist);
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
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist;

	ADD_HDR(vl);

	if (!tag_info_allowed(get_var(qvars, "image_id"))) {
		vl = add_html_var(vl, "show_info", "no");
		goto out2;
	}

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
	if (mysql_num_rows(res) == 0) {
		vl = add_html_var(vl, "show_info", "no");
		goto out1;
	}
	db_row = get_dbrow(res);
	set_custom_field_names();

	/* image url */
	vl = add_html_var(vl, "image_path", get_var(db_row, "path"));
	vl = add_html_var(vl, "image_name", get_var(db_row, "name"));

	vl = add_html_var(vl, "r_user", get_var(db_row, "user"));
	vl = add_html_var(vl, "r_uid", get_var(db_row, "uid"));
	vl = add_html_var(vl, "id", image_id);

	/* image upload timestamp */
	secs = atol(get_var(db_row, "images_timestamp"));
	strftime(tbuf, sizeof(tbuf), "%a %b %e %H:%M %Y %z", localtime(&secs));
	vl = add_html_var(vl, "images_timestamp", tbuf);

	/* image tag timestamp */
	secs = atol(get_var(db_row, "tags_timestamp"));
	strftime(tbuf, sizeof(tbuf), "%a %b %e %H:%M %Y %z", localtime(&secs));
	vl = add_html_var(vl, "tags_timestamp", tbuf);

	vl = add_html_var(vl, "fields.department", fields.department);
	vl = add_html_var(vl, "department", get_var(db_row, "department"));
	vl = add_html_var(vl, "fields.employee_number",
					fields.employee_number);
	vl = add_html_var(vl, "employee_number",
					get_var(db_row, "employee_number"));
	vl = add_html_var(vl, "fields.cost_codes", fields.cost_codes);
	vl = add_html_var(vl, "cost_codes", get_var(db_row, "cost_codes"));
	vl = add_html_var(vl, "fields.account_codes", fields.account_codes);
	vl = add_html_var(vl, "account_codes",
					get_var(db_row, "account_codes"));
	vl = add_html_var(vl, "fields.po_num", fields.po_num);
	vl = add_html_var(vl, "po_num", get_var(db_row, "po_num"));
	vl = add_html_var(vl, "fields.supplier_name", fields.supplier_name);
	vl = add_html_var(vl, "supplier_name",
					get_var(db_row, "supplier_name"));
	vl = add_html_var(vl, "fields.supplier_town", fields.supplier_town);
	vl = add_html_var(vl, "supplier_town",
					get_var(db_row, "supplier_town"));
	vl = add_html_var(vl, "fields.currency", fields.currency);
	vl = add_html_var(vl, "currency", get_var(db_row, "currency"));
	vl = add_html_var(vl, "fields.gross_amount", fields.gross_amount);
	vl = add_html_var(vl, "gross_amount",
					get_var(db_row, "gross_amount"));
	vl = add_html_var(vl, "fields.vat_amount", fields.vat_amount);
	vl = add_html_var(vl, "vat_amount",
					get_var(db_row, "vat_amount"));
	vl = add_html_var(vl, "fields.net_amount", fields.net_amount);
	vl = add_html_var(vl, "net_amount", get_var(db_row, "net_amount"));
	vl = add_html_var(vl, "fields.vat_rate", fields.vat_rate);
	vl = add_html_var(vl, "vat_rate", get_var(db_row, "vat_rate"));
	vl = add_html_var(vl, "fields.vat_number", fields.vat_number);
	vl = add_html_var(vl, "vat_number", get_var(db_row, "vat_number"));
	vl = add_html_var(vl, "fields.reason", fields.reason);
	vl = add_html_var(vl, "reason", get_var(db_row, "reason"));
	vl = add_html_var(vl, "fields.receipt_date", fields.receipt_date);

	secs = atol(get_var(db_row, "receipt_date"));
	strftime(tbuf, sizeof(tbuf), "%a %b %d, %Y", localtime(&secs));
	vl = add_html_var(vl, "receipt_date", tbuf);

	vl = add_html_var(vl, "fields.payment_method", fields.payment_method);
	vl = add_html_var(vl, "payment_method",
					get_var(db_row, "payment_method"));

	if (atoi(get_var(db_row, "approved")) == REJECTED)
		vl = add_html_var(vl, "approved", "rejected");
	else if (atoi(get_var(db_row, "approved")) == PENDING)
		vl = add_html_var(vl, "approved", "pending");
	else
		vl = add_html_var(vl, "approved", "yes");

	/* Only PENDING receipts of the user are editable */
	if (atoi(get_var(db_row, "approved")) == PENDING &&
	    atoi(get_var(db_row, "uid")) == user_session.uid) {
		vl = add_html_var(vl, "showedit", "true");
		if (strcmp(get_var(qvars, "edit"), "true") == 0) {
			/* Don't show the Edit button when editing */
			vl = add_html_var(vl, "showedit", "false");
			vl = add_html_var(vl, "edit", "true");
			/*
			 * Put the date into the same format that it should be
			 * entered by the user (YYYY-MM-DD).
			 */
			strftime(tbuf, sizeof(tbuf), "%Y-%m-%d",
							localtime(&secs));
			vl = add_html_var(vl, "receipt_date", tbuf);
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
		vl = add_html_var(vl, "a_time", tbuf);
		vl = add_html_var(vl, "reject_reason",
					get_var(db_row, "r_reason"));
		/* Only approvers can see who approved/rejected receipts */
		if (IS_APPROVER()) {
			vl = add_html_var(vl, "reviewed_by_n",
					get_var(db_row, "reviewed_by_n"));
			vl = add_html_var(vl, "reviewed_by_u",
					get_var(db_row, "reviewed_by_u"));
		}
	}
	/* Only need to add the token if the receipt info is editable */
	add_csrf_token(vl);

	free_vars(db_row);
	free_fields();

out1:
	mysql_free_result(res);
	free(image_id);

out2:
	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/receipt_info.tmpl", vl, fmtlist);
	TMPL_free_varlist(vl);
	TMPL_free_fmtlist(fmtlist);
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
	int from = 0;
	int page = 1;
	int nr_pages = 0;
	MYSQL_RES *res;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;
	TMPL_fmtlist *fmtlist;

	if (qvars)
		get_page_pagination(get_var(qvars, "page_no"), GRID_SIZE,
							&page, &from);

	ADD_HDR(ml);

	res = sql_query("SELECT (SELECT COUNT(*) FROM tags INNER JOIN images "
			"ON (tags.id = images.id) WHERE images.tagged = 1 AND "
			"images.uid = %u) AS nrows, tags.receipt_date, "
			"images.id, images.path, images.name, "
			"images.approved, reviewed.timestamp FROM tags "
			"INNER JOIN images ON (tags.id = images.id) "
			"LEFT JOIN reviewed ON (tags.id = reviewed.id) WHERE "
			"images.tagged = 1 AND images.uid = %u ORDER BY "
			"tags.timestamp DESC LIMIT %d, %d",
			user_session.uid, user_session.uid, from, GRID_SIZE);
	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0) {
		ml = add_html_var(ml, "receipts", "no");
		goto out;
	}

	set_custom_field_names();
	ml = add_html_var(ml, "receipts", "yes");
	/* Draw gallery grid */
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		time_t secs;
		GHashTable *db_row = NULL;
		TMPL_varlist *vl = NULL;

		db_row = get_dbrow(res);

		nr_pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
							(float)GRID_SIZE);

		vl = add_html_var(vl, "id", get_var(db_row, "id"));
		vl = add_html_var(vl, "image_path", get_var(db_row, "path"));
		vl = add_html_var(vl, "image_name", get_var(db_row, "name"));
		secs = atol(get_var(db_row, "receipt_date"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = add_html_var(vl, "fields.receipt_date",
							fields.receipt_date);
		vl = add_html_var(vl, "receipt_date", tbuf);
		/* If the receipt been reviewed, display its reviewed date */
		if (IS_SET(get_var(db_row, "timestamp"))) {
			secs = atol(get_var(db_row, "timestamp"));
			strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y",
							localtime(&secs));
			vl = add_html_var(vl, "reviewed_date", tbuf);
		}

		if (atoi(get_var(db_row, "approved")) == REJECTED)
			vl = add_html_var(vl, "approved", "rejected");
		else if (atoi(get_var(db_row, "approved")) == PENDING)
			vl = add_html_var(vl, "approved", "pending");
		else
			vl = add_html_var(vl, "approved", "yes");

		/* We want a 3 x 3 grid */
		if (c == COL_SIZE) /* Close off row */
			vl = add_html_var(vl, "close_row", "yes");
		else
			vl = add_html_var(vl, "close_row", "no");

		if (c == COL_SIZE && i < nr_rows) { /* Start a new row */
			vl = add_html_var(vl, "new_row", "yes");
			c = 0;
		} else {
			vl = add_html_var(vl, "new_row", "no");
		}
		c++;

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "table", loop);
	free_fields();
	do_pagination(ml, page, nr_pages);

out:
	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/tagged_receipts.tmpl", ml, fmtlist);
	TMPL_free_varlist(ml);
	TMPL_free_fmtlist(fmtlist);
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
	TMPL_varlist *vl = NULL;
	TMPL_fmtlist *fmtlist;
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

	vl = add_html_var(vl, "image_id", get_var(qvars, "image_id"));
	vl = add_html_var(vl, "image_path", get_var(qvars, "image_path"));
	vl = add_html_var(vl, "image_name", get_var(qvars, "image_name"));
	set_custom_field_names();

	if (!IS_SET(get_var(qvars, "department"))) {
		tag_error = true;
		vl = add_html_var(vl, "error.department", "1");
	}
	vl = add_html_var(vl, "fields.department", fields.department);
	vl = add_html_var(vl, "department", get_var(qvars, "department"));

	if (!IS_SET(get_var(qvars, "employee_number"))) {
		tag_error = true;
		vl = add_html_var(vl, "error.employee_number", "1");
	}
	vl = add_html_var(vl, "fields.employee_number",
					fields.employee_number);
	vl = add_html_var(vl, "employee_number",
					get_var(qvars, "employee_number"));

	if (!IS_SET(get_var(qvars, "cost_codes"))) {
		tag_error = true;
		vl = add_html_var(vl, "error.cost_codes", "1");
	}
	vl = add_html_var(vl, "fields.cost_codes", fields.cost_codes);
	vl = add_html_var(vl, "cost_codes", get_var(qvars, "cost_codes"));

	if (!IS_SET(get_var(qvars, "account_codes"))) {
		tag_error = true;
		vl = add_html_var(vl, "error.account_codes", "1");
	}
	vl = add_html_var(vl, "fields.account_codes", fields.account_codes);
	vl = add_html_var(vl, "account_codes",
					get_var(qvars, "account_codes"));

	if (!IS_SET(get_var(qvars, "po_num"))) {
		tag_error = true;
		vl = add_html_var(vl, "error.po_num", "1");
	}
	vl = add_html_var(vl, "fields.po_num", fields.po_num);
	vl = add_html_var(vl, "po_num", get_var(qvars, "po_num"));

	if (!IS_SET(get_var(qvars, "supplier_name"))) {
		tag_error = true;
		vl = add_html_var(vl, "error.supplier_name", "1");
	}
	vl = add_html_var(vl, "fields.supplier_name", fields.supplier_name);
	vl = add_html_var(vl, "supplier_name",
					get_var(qvars, "supplier_name"));

	if (!IS_SET(get_var(qvars, "supplier_town"))) {
		tag_error = true;
		vl = add_html_var(vl, "error.supplier_town", "1");
	}
	vl = add_html_var(vl, "fields.supplier_town", fields.supplier_town);
	vl = add_html_var(vl, "supplier_town",
					get_var(qvars, "supplier_town"));

	vl = add_html_var(vl, "fields.currency", fields.currency);
	vl = add_html_var(vl, "currency", get_var(qvars, "currency"));

	gross = strtod(get_var(qvars, "gross_amount"), NULL);
	net = strtod(get_var(qvars, "net_amount"), NULL);
	vat = strtod(get_var(qvars, "vat_amount"), NULL);
	vr = strtod(get_var(qvars, "vat_rate"), NULL);
	ret = check_amounts(gross, net, vat, vr);
	if (ret < 0) {
		tag_error = true;
		vl = add_html_var(vl, "error.amounts", "1");
	}
	vl = add_html_var(vl, "fields.gross_amount", fields.gross_amount);
	vl = add_html_var(vl, "gross_amount", get_var(qvars, "gross_amount"));
	vl = add_html_var(vl, "fields.net_amount", fields.net_amount);
	vl = add_html_var(vl, "net_amount", get_var(qvars, "net_amount"));
	vl = add_html_var(vl, "fields.vat_amount", fields.vat_amount);
	vl = add_html_var(vl, "vat_amount", get_var(qvars, "vat_amount"));
	vl = add_html_var(vl, "fields.vat_rate", fields.vat_rate);
	vl = add_html_var(vl, "vat_rate", get_var(qvars, "vat_rate"));

	if (!IS_SET(get_var(qvars, "vat_number"))) {
		tag_error = true;
		vl = add_html_var(vl, "error.vat_number", "1");
	}
	vl = add_html_var(vl, "fields.vat_number", fields.vat_number);
	vl = add_html_var(vl, "vat_number", get_var(qvars, "vat_number"));

	vl = add_html_var(vl, "fields.reason", fields.reason);
	vl = add_html_var(vl, "reason", get_var(qvars, "reason"));

	memset(&tm, 0, sizeof(tm));
	strptime(get_var(qvars, "receipt_date"), "%Y-%m-%d", &tm);
	strftime(secs, sizeof(secs), "%s", &tm);
	if (strtol(secs, NULL, 10) < time(NULL) - MAX_RECEIPT_AGE ||
	    strtol(secs, NULL, 10) > time(NULL)) {
		tag_error = true;
		vl = add_html_var(vl, "error.receipt_date", "1");
	}
	vl = add_html_var(vl, "fields.receipt_date", fields.receipt_date);
	vl = add_html_var(vl, "receipt_date", get_var(qvars, "receipt_date"));

	vl = add_html_var(vl, "fields.payment_method", fields.payment_method);
	vl = add_html_var(vl, "payment_method",
					get_var(qvars, "payment_method"));

	if (!tag_error) {
		tag_image();
		if (strstr(get_var(qvars, "from"), "receipt_info"))
			fcgx_p("Location: /receipt_info/?image_id=%s\r\n\r\n",
						get_var(qvars, "image_id"));
		else
			fcgx_p("Location: /receipts/\r\n\r\n");
	} else {
		if (strstr(get_var(qvars, "from"), "receipt_info"))
			vl = add_html_var(vl, "from", "receipt_info");
		add_csrf_token(vl);
		fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
		send_template("templates/process_receipt.tmpl", vl, fmtlist);
		TMPL_free_fmtlist(fmtlist);
	}
	TMPL_free_varlist(vl);
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
	TMPL_varlist *vl = NULL;

	ADD_HDR(vl);

	gather_receipt_stats_for_user(user_session.uid, vl);

	send_template("templates/stats.tmpl", vl, NULL);
	TMPL_free_varlist(vl);
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
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;
	TMPL_fmtlist *fmtlist;

	ADD_HDR(ml);
	/*
	 * Display the users last login time and location, we only show
	 * this on the /receipts/ page.
	 */
	display_last_login(ml);

	res = sql_query("SELECT id, timestamp, path, name FROM images WHERE "
			"tagged = 0 AND uid = %u", user_session.uid);
	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0) {
		ml = add_html_var(ml, "receipts", "no");
		goto out;
	}

	set_custom_field_names();
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		time_t secs;
		GHashTable *db_row = NULL;
		TMPL_varlist *vl = NULL;

		db_row = get_dbrow(res);

		vl = add_html_var(vl, "image_path", get_var(db_row, "path"));
		vl = add_html_var(vl, "image_name", get_var(db_row, "name"));
		secs = atol(get_var(db_row, "timestamp"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e %H:%M %Y %z",
						localtime(&secs));
		vl = add_html_var(vl, "timestamp", tbuf);
		vl = add_html_var(vl, "fields.department", fields.department);
		vl = add_html_var(vl, "fields.employee_number",
						fields.employee_number);
		vl = add_html_var(vl, "fields.cost_codes", fields.cost_codes);
		vl = add_html_var(vl, "fields.account_codes",
						fields.account_codes);
		vl = add_html_var(vl, "fields.po_num", fields.po_num);
		vl = add_html_var(vl, "fields.supplier_name",
						fields.supplier_name);
		vl = add_html_var(vl, "fields.supplier_town",
						fields.supplier_town);
		vl = add_html_var(vl, "fields.currency", fields.currency);
		vl = add_html_var(vl, "fields.gross_amount",
						fields.gross_amount);
		vl = add_html_var(vl, "fields.vat_amount", fields.vat_amount);
		vl = add_html_var(vl, "fields.net_amount", fields.net_amount);
		vl = add_html_var(vl, "fields.vat_rate", fields.vat_rate);
		vl = add_html_var(vl, "fields.vat_number", fields.vat_number);
		vl = add_html_var(vl, "fields.reason", fields.reason);
		vl = add_html_var(vl, "fields.receipt_date",
						fields.receipt_date);
		vl = add_html_var(vl, "fields.payment_method",
						fields.payment_method);
		/* image_id for hidden input field */
		vl = add_html_var(vl, "id", get_var(db_row, "id"));

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "table", loop);
	free_fields();
	/* Only use csrf if there are receipts to process */
	add_csrf_token(ml);

out:
	fmtlist = TMPL_add_fmt(NULL, "de_xss", de_xss);
	send_template("templates/receipts.tmpl", ml, fmtlist);
	TMPL_free_varlist(ml);
	TMPL_free_fmtlist(fmtlist);
	mysql_free_result(res);
}

/*
 * /env/
 *
 * Displays the environment list.
 */
static void env(void)
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

/*
 * Main application. This is where the requests come in and routed.
 */
void handle_request(void)
{
	bool logged_in = false;
	char *request_uri;
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

	/*
	 * Some routes need to come before the login / session stuff as
	 * they can't be logged in and have no session.
	 */
	if (match_uri(request_uri, "/activate_user/")) {
		activate_user();
		goto out2;
	}

	if (match_uri(request_uri, "/generate_new_key/")) {
		generate_new_key();
		goto out2;
	}

	if (match_uri(request_uri, "/forgotten_password/")) {
		forgotten_password();
		goto out2;
	}

	if (match_uri(request_uri, "/login/")) {
		login();
		goto out2;
	}

	logged_in = is_logged_in();
	if (!logged_in) {
		fcgx_p("Location: /login/\r\n\r\n");
		goto out2;
	}

	/* Logged in, set-up the user_session structure */
	set_user_session();

	/* Add new url handlers after here */

	if (match_uri(request_uri, "/receipts/")) {
		receipts();
		goto out;
	}

	if (match_uri(request_uri, "/process_receipt/")) {
		process_receipt();
		goto out;
	}

	if (match_uri(request_uri, "/tagged_receipts/")) {
		tagged_receipts();
		goto out;
	}

	if (match_uri(request_uri, "/receipt_info/")) {
		receipt_info();
		goto out;
	}

	if (match_uri(request_uri, "/approve_receipts/")) {
		approve_receipts();
		goto out;
	}

	if (match_uri(request_uri, "/process_receipt_approval/")) {
		process_receipt_approval();
		goto out;
	}

	if (match_uri(request_uri, "/reviewed_receipts/")) {
		reviewed_receipts();
		goto out;
	}

	if (match_uri(request_uri, "/extract_data/")) {
		extract_data();
		goto out;
	}

	if (match_uri(request_uri, "/do_extract_data/")) {
		do_extract_data();
		goto out;
	}

	if (match_uri(request_uri, "/get_image/")) {
		get_image();
		goto out;
	}

	if (match_uri(request_uri, "/delete_image/")) {
		delete_image();
		goto out;
	}

	if (match_uri(request_uri, "/env/")) {
		env();
		goto out;
	}

	if (match_uri(request_uri, "/prefs/fmap/")) {
		prefs_fmap();
		goto out;
	}

	if (match_uri(request_uri, "/prefs/edit_user/")) {
		prefs_edit_user();
		goto out;
	}

	if (match_uri(request_uri, "/prefs/")) {
		prefs();
		goto out;
	}

	if (match_uri(request_uri, "/admin/list_users/")) {
		admin_list_users();
		goto out;
	}

	if (match_uri(request_uri, "/admin/add_user/")) {
		admin_add_user();
		goto out;
	}

	if (match_uri(request_uri, "/admin/edit_user/")) {
		admin_edit_user();
		goto out;
	}

	if (match_uri(request_uri, "/admin/user_stats/")) {
		admin_user_stats();
		goto out;
	}

	if (match_uri(request_uri, "/admin/stats/")) {
		admin_stats();
		goto out;
	}

	if (match_uri(request_uri, "/admin/pending_activations/")) {
		admin_pending_activations();
		goto out;
	}

	if (match_uri(request_uri, "/admin/")) {
		admin();
		goto out;
	}

	if (match_uri(request_uri, "/stats/")) {
		stats();
		goto out;
	}

	if (match_uri(request_uri, "/logout/")) {
		logout();
		goto out;
	}

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
				env_vars.remote_addr,
				request_uri,
				env_vars.request_method,
				(unsigned int)((etp.tv_sec * 1000 +
				etp.tv_nsec / NS_MSEC) -
				(stp.tv_sec * 1000 + stp.tv_nsec / NS_MSEC)));
	free_env_vars();
	mysql_close(conn);
}
