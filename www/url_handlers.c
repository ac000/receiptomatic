/*
 * url_handlers.c
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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <alloca.h>
#include <netdb.h>

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
static void login(char *http_user_agent, char *http_x_forwarded_for,
							GHashTable *qvars)
{
	int ret = 1;
	int sid;
	TMPL_varlist *vl = NULL;

	if (qvars) {
		ret = check_auth(qvars);
		if (ret == 0) {
			sid = log_login(qvars, http_x_forwarded_for);
			create_session(qvars, http_user_agent,
						http_x_forwarded_for, sid);
			printf("Location: /receipts/\r\n\r\n");
			return; /* Successful login */
		}
	}

	if (ret == -1)
		vl = TMPL_add_var(0, "logged_in", "no", NULL);
	if (ret == -2)
		vl = TMPL_add_var(0, "enabled", "no", NULL);

	send_template("templates/login.tmpl", vl);
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
static void logout(struct session *current_session)
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
					current_session->session_id);
	res = tctdbqrysearch(qry);
	rbuf = tclistval(res, 0, &rsize);
	tctdbout(tdb, rbuf, strlen(rbuf));

	tclistdel(res);
	tctdbqrydel(qry);

	tctdbclose(tdb);
	tctdbdel(tdb);

	/* Immediately expire the session cookies */
	printf("Set-Cookie: session_id=deleted; "
				"expires=Thu, 01-Jan-1970 00:00:01 GMT; "
				"path=/; httponly\r\n");
	send_template("templates/logout.tmpl", NULL);
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
static void delete_image(struct session *current_session, GHashTable *qvars)
{
	char sql[SQL_MAX];
	char path[PATH_MAX];
	char image_path[PATH_MAX];
	char uidir[PATH_MAX];
	char *image_id;
	int headers_sent = 0;
	MYSQL *conn;
	MYSQL_RES *res;
	GHashTable *db_row = NULL;
	TMPL_varlist *vl = NULL;

	if (!qvars)
		goto out2;

	conn = db_conn();

	image_id = alloca(strlen(get_var(qvars, "image_id")) * 2 + 1);
	mysql_real_escape_string(conn, image_id, get_var(qvars, "image_id"),
					strlen(get_var(qvars, "image_id")));

	/* Only allow to delete images that are un-tagged */
	snprintf(sql, SQL_MAX, "SELECT path, name FROM images WHERE id = '%s' "
						"AND processed = 0", image_id);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) == 0)
		goto out1;

	db_row = get_dbrow(res);

	snprintf(path, PATH_MAX, "%s/%s/%s", IMAGE_PATH,
						get_var(db_row, "path"),
						get_var(db_row, "name"));
	realpath(path, image_path);

	vl = TMPL_add_var(vl, "image_path", get_var(db_row, "path"), NULL);
	vl = TMPL_add_var(vl, "image_name", get_var(db_row, "name"), NULL);
	vl = TMPL_add_var(vl, "image_id", get_var(qvars, "image_id"), NULL);

	memset(uidir, 0, sizeof(uidir));
	snprintf(uidir, sizeof(uidir), "/%d/", current_session->uid);
	/* Is it one of the users images? */
	if (strncmp(image_path + strlen(IMAGE_PATH), uidir, strlen(uidir))
									!= 0)
		goto out1;

	if (strcmp(get_var(qvars, "confirm"), "yes") == 0) {
		/* remove the full image */
		unlink(image_path);

		/* remove the small image */
		snprintf(path, PATH_MAX, "%s/%s/small/%s", IMAGE_PATH,
						get_var(db_row, "path"),
						get_var(db_row, "name"));
		realpath(path, image_path);
		unlink(image_path);

		/* remove the medium image */
		snprintf(path, PATH_MAX, "%s/%s/medium/%s", IMAGE_PATH,
						get_var(db_row, "path"),
						get_var(db_row, "name"));
		realpath(path, image_path);
		unlink(image_path);

		snprintf(sql, SQL_MAX, "DELETE FROM images WHERE id = '%s'",
								image_id);
		d_fprintf(sql_log, "%s\n", sql);
		mysql_real_query(conn, sql, strlen(sql));

		/* We don't want to display the delete_image page again */
		goto out1;
	}

	send_template("templates/delete_image.tmpl", vl);
	headers_sent = 1;

out1:
	mysql_close(conn);
	mysql_free_result(res);
	free_vars(db_row);
	TMPL_free_varlist(vl);
out2:
	if (!headers_sent)
		printf("Location: /receipts/\r\n\r\n");
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
	if (!realpath(path, image_path))
		return;

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
	printf("Content-Length: %ld\r\n\r\n", sb.st_size);
	d_fprintf(debug_log, "Sending image: %s\n", image);

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
	if (!realpath(path, image_path))
		return;

	/* Don't let users access other users images */
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
	printf("Content-Disposition: filename = %s\r\n\r\n",
							basename(image_path));

	while (bytes_read > 0) {
		bytes_read = read(fd, &buf, BUF_SIZE);
		fwrite(buf, bytes_read, 1, stdout);
	}
	close(fd);
}

/*
 * /admin/
 *
 * HTML is in templates/admin.tmpl
 *
 * Admin index page.
 */
static void admin(struct session *current_session)
{
	TMPL_varlist *vl = NULL;

	if (!(current_session->capabilities & ADMIN))
		return;

	vl = TMPL_add_var(vl, "admin", "yes", NULL);

	if (current_session->capabilities & APPROVER)
		vl = TMPL_add_var(vl, "approver", "yes", NULL);

	vl = TMPL_add_var(vl, "user_hdr", current_session->user_hdr, NULL);

	send_template("templates/admin.tmpl", vl);
	TMPL_free_varlist(vl);
}

/*
 * /admin/list_users/
 *
 * HTML is in templates/admin_list_users.tmpl
 *
 * List users in the system.
 */
static void admin_list_users(struct session *current_session, GHashTable *qvars)
{
	char sql[SQL_MAX];
	char page[10];
	int rpp = 15;	/* Rows Per Page to display */
	int nr_rows;
	int i;
	int pages;
	int page_no = 1;
	int from = 0;
	MYSQL *conn;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;

	if (!(current_session->capabilities & ADMIN))
		return;

	ml = TMPL_add_var(ml, "admin", "yes", NULL);

	if (current_session->capabilities & APPROVER)
		ml = TMPL_add_var(ml, "approver", "yes", NULL);

	ml = TMPL_add_var(ml, "user_hdr", current_session->user_hdr, NULL);

	if (qvars)
		get_page_pagination(get_var(qvars, "page_no"), rpp, &page_no,
									&from);

	conn = db_conn();
	snprintf(sql, SQL_MAX, "SELECT uid, username, name, capabilities, "
					"enabled, activated FROM passwd LIMIT "
					"%d, %d", from, rpp);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_query(conn, sql);
	res = mysql_store_result(conn);

	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		char caps[33] = "\0";
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		pages = ceilf((float)nr_rows / (float)rpp);

		if (!(i % 2))
			vl = TMPL_add_var(NULL, "zebra", "yes", NULL);
		else
			vl = TMPL_add_var(NULL, "zebra", "no", NULL);

		vl = TMPL_add_var(vl, "uid", get_var(db_row, "uid"), NULL);
		vl = TMPL_add_var(vl, "username", get_var(db_row,
							"username"), NULL);
		vl = TMPL_add_var(vl, "name", get_var(db_row, "name"), NULL);

		/* Pretty print the set of capabilities */
		if (atoi(get_var(db_row, "capabilities")) & APPROVER)
			strcat(caps, "Approver -");
		if (atoi(get_var(db_row, "capabilities")) & APPROVER_CARD)
			strcat(caps, " Card");
		if (atoi(get_var(db_row, "capabilities")) & APPROVER_CASH)
			strcat(caps, " Cash");
		if (atoi(get_var(db_row, "capabilities")) & APPROVER_CHEQUE)
			strcat(caps, " Cheque");
		if (atoi(get_var(db_row, "capabilities")) & APPROVER_SELF)
			strcat(caps, " Self");
		vl = TMPL_add_var(vl, "capabilities", caps, NULL);

		if (atoi(get_var(db_row, "capabilities")) & ADMIN)
			vl = TMPL_add_var(vl, "admin", "yes", NULL);
		else
			vl = TMPL_add_var(vl, "admin", "no", NULL);

		if (atoi(get_var(db_row, "enabled")) == 1)
			vl = TMPL_add_var(vl, "enabled", "yes", NULL);
		else
			vl = TMPL_add_var(vl, "enabled", "no", NULL);

		if (atoi(get_var(db_row, "activated")) == 1)
			vl = TMPL_add_var(vl, "activated", "yes", NULL);
		else
			vl = TMPL_add_var(vl, "activated", "no", NULL);

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}

	if (pages > 1) {
		if (page_no - 1 > 0) {
			snprintf(page, 10, "%d", page_no - 1);
			ml = TMPL_add_var(ml, "prev_page", page, NULL);
		}
		if (page_no + 1 <= pages) {
			snprintf(page, 10, "%d", page_no + 1);
			ml = TMPL_add_var(ml, "next_page", page, NULL);
		}
	} else {
		ml = TMPL_add_var(ml, "no_pages", "true", NULL);
	}
	ml = TMPL_add_loop(ml, "table", loop);

	send_template("templates/admin_list_users.tmpl", ml);
	TMPL_free_varlist(ml);
	mysql_free_result(res);
	mysql_close(conn);
}

/*
 * /admin/add_user/
 *
 * HTML is in templates/admin_add_user.tmpl
 *
 * Add a user to the system.
 */
static void admin_add_user(struct session *current_session, GHashTable *qvars)
{
	unsigned char capabilities = 0;
	int form_err = 0;
	TMPL_varlist *vl = NULL;

	if (!(current_session->capabilities & ADMIN))
		return;

	vl = TMPL_add_var(vl, "admin", "yes", NULL);

	if (current_session->capabilities & APPROVER)
		vl = TMPL_add_var(vl, "approver", "yes", NULL);

	vl = TMPL_add_var(vl, "user_hdr", current_session->user_hdr, NULL);

	if (!qvars)
		goto out;

	if (strlen(get_var(qvars, "name")) == 0) {
		form_err = 1;
		vl = TMPL_add_var(vl, "name_error", "yes", NULL);
	}
	vl = TMPL_add_var(vl, "name", get_var(qvars, "name"), NULL);

	if ((strlen(get_var(qvars, "email1")) == 0 &&
				strlen(get_var(qvars, "email2")) == 0) ||
				(strcmp(get_var(qvars, "email1"),
				get_var(qvars, "email2")) != 0)) {
		form_err = 1;
		vl = TMPL_add_var(vl, "email_error", "yes", NULL);
	}
	vl = TMPL_add_var(vl, "email1", get_var(qvars, "email1"),  NULL);
	vl = TMPL_add_var(vl, "email2", get_var(qvars, "email2"), NULL);

	if (strlen(get_var(qvars, "ap_card")) > 0 ||
				strlen(get_var(qvars, "ap_cash")) > 0 ||
				strlen(get_var(qvars, "ap_cheque")) > 0 ||
				strlen(get_var(qvars, "ap_self")) > 0) {
		capabilities |= APPROVER;
		if (strlen(get_var(qvars, "ap_card")) > 0) {
			capabilities |= APPROVER_CARD;
			vl = TMPL_add_var(vl, "ap_card", "yes", NULL);
		}
		if (strlen(get_var(qvars, "ap_cash")) > 0) {
			capabilities |= APPROVER_CASH;
			vl = TMPL_add_var(vl, "ap_cash", "yes", NULL);
		}
		if (strlen(get_var(qvars, "ap_cheque")) > 0) {
			capabilities |= APPROVER_CHEQUE;
			vl = TMPL_add_var(vl, "ap_cheque", "yes", NULL);
		}
		if (strlen(get_var(qvars, "ap_self")) > 0) {
			capabilities |= APPROVER_SELF;
			vl = TMPL_add_var(vl, "ap_self", "yes", NULL);
		}
	}
	if (strlen(get_var(qvars, "is_admin")) > 0) {
		capabilities |= ADMIN;
		vl = TMPL_add_var(vl, "is_admin", "yes", NULL);
	}

	if (!form_err) {
		int ret;

		ret = do_add_user(qvars, capabilities);
		if (ret == -10) {
			/*
			 * Tried to add an already existing user.
			 * Tell the admin.
			 */
			vl = TMPL_add_var(vl, "dup_user", "yes", NULL);
		} else {
			printf("Location: /admin/add_user/\r\n\r\n");
			goto out2;
		}
	}

out:
	send_template("templates/admin_add_user.tmpl", vl);

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
static void admin_edit_user(char *request_method,
					struct session *current_session,
					GHashTable *qvars)
{
	char sql[SQL_MAX];
	unsigned int uid;
	int form_err = 0;
	MYSQL *conn;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;

	if (!(current_session->capabilities & ADMIN))
		return;

	if (!qvars)
		return;

	vl = TMPL_add_var(vl, "admin", "yes", NULL);

	if (current_session->capabilities & APPROVER)
		vl = TMPL_add_var(vl, "approver", "yes", NULL);

	vl = TMPL_add_var(vl, "user_hdr", current_session->user_hdr, NULL);

	/* If we got a POST, update user settings before showing them. */
	if (strcmp(request_method, "POST") == 0) {
		if ((strlen(get_var(qvars, "email1")) == 0 &&
				strlen(get_var(qvars, "email2")) == 0) ||
				(strcmp(get_var(qvars, "email1"),
					get_var(qvars, "email2")) != 0)) {
			vl = TMPL_add_var(vl, "email_error", "yes", NULL);
			form_err = 1;
		}
		if (strlen(get_var(qvars, "pass1")) > 7 &&
					strlen(get_var(qvars, "pass2")) > 7) {
			if (strcmp(get_var(qvars, "pass1"),
					get_var(qvars, "pass2")) != 0) {
				vl = TMPL_add_var(vl, "pass_error",
							"mismatch", NULL);
				form_err = 1;
			}
		/*
		 * If the password fields are > 0 in length, then we tried
		 * to update it.
		 */
		} else if (strlen(get_var(qvars, "pass1")) != 0 &&
					strlen(get_var(qvars, "pass2")) != 0) {
			vl = TMPL_add_var(vl, "pass_error", "length", NULL);
			form_err = 1;
		}

		if (!form_err) {
			do_update_user(qvars);
			vl = TMPL_add_var(vl, "updated", "yes", NULL);
		}
	}

	vl = TMPL_add_var(vl, "uid", get_var(qvars, "uid"), NULL);
	uid = atoi(get_var(qvars, "uid"));

	/*
	 * If form_err is still 0, then either we got a GET and just want
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

		conn = db_conn();
		snprintf(sql, SQL_MAX, "SELECT username, name, capabilities, "
						"enabled, activated, d_reason "
						"FROM passwd WHERE uid = %u",
						uid);
		d_fprintf(sql_log, "%s\n", sql);
		mysql_query(conn, sql);
		res = mysql_store_result(conn);
		if (mysql_num_rows(res) == 0)
			goto mysql_cleanup;

		db_row = get_dbrow(res);

		vl = TMPL_add_var(vl, "username", get_var(db_row, "username"),
							NULL);
		vl = TMPL_add_var(vl, "email1", get_var(db_row, "username"),
							NULL);
		vl = TMPL_add_var(vl, "email2", get_var(db_row, "username"),
							NULL);
		vl = TMPL_add_var(vl, "name", get_var(db_row, "name"), NULL);
		if (atoi(get_var(db_row, "enabled")) == 1)
			vl = TMPL_add_var(vl, "is_enabled", "yes", NULL);
		if (atoi(get_var(db_row, "activated")) == 1)
			vl = TMPL_add_var(vl, "is_activated", "yes", NULL);
		vl = TMPL_add_var(vl, "d_reason", get_var(db_row,
							"d_reason"), NULL);

		capabilities = atoi(get_var(db_row, "capabilities"));
		if (capabilities & APPROVER_CARD)
			vl = TMPL_add_var(vl, "ap_card", "yes", NULL);
		if (capabilities & APPROVER_CASH)
			vl = TMPL_add_var(vl, "ap_cash", "yes", NULL);
		if (capabilities & APPROVER_CHEQUE)
			vl = TMPL_add_var(vl, "ap_cheque", "yes", NULL);
		if (capabilities & APPROVER_SELF)
			vl = TMPL_add_var(vl, "ap_self", "yes", NULL);

		if (capabilities & ADMIN)
			vl = TMPL_add_var(vl, "is_admin", "yes", NULL);

		free_vars(db_row);
	} else {
		vl = TMPL_add_var(vl, "username", get_var(qvars, "email1"),
								NULL);
		vl = TMPL_add_var(vl, "email1", get_var(qvars, "email1"),
								NULL);
		vl = TMPL_add_var(vl, "email2", get_var(qvars, "email2"),
								NULL);
		vl = TMPL_add_var(vl, "name", get_var(qvars, "name"), NULL);
		if (atoi(get_var(qvars, "enabled")) == 1)
			vl = TMPL_add_var(vl, "is_enabled", "yes", NULL);
		if (atoi(get_var(qvars, "activated")) == 1)
			vl = TMPL_add_var(vl, "is_activated", "yes", NULL);

		if (atoi(get_var(qvars, "ap_card")) == 1)
			vl = TMPL_add_var(vl, "ap_card", "yes", NULL);
		if (atoi(get_var(qvars, "ap_cash")) == 1)
			vl = TMPL_add_var(vl, "ap_cash", "yes", NULL);
		if (atoi(get_var(qvars, "ap_cheque")) == 1)
			vl = TMPL_add_var(vl, "ap_cheque", "yes", NULL);
		if (atoi(get_var(qvars, "ap_self")) == 1)
			vl = TMPL_add_var(vl, "ap_self", "yes", NULL);

		if (atoi(get_var(qvars, "is_admin")) == 1)
			vl = TMPL_add_var(vl, "is_admin", "yes", NULL);

		goto out;
	}

mysql_cleanup:
	mysql_free_result(res);
	mysql_close(conn);

out:
	send_template("templates/admin_edit_user.tmpl", vl);
	TMPL_free_varlist(vl);
}

/*
 * /admin/pending_activations/
 *
 * HTML is in templates/admin_pending_activations.tmpl
 *
 * List currently pending user account activations.
 */
static void admin_pending_activations(struct session *current_session,
							GHashTable *qvars)
{
	char sql[SQL_MAX];
	char page[10];
	int rpp = 15;	/* Rows Per Page to display */
	int nr_rows;
	int i;
	int pages;
	int page_no = 1;
	int from = 0;
	MYSQL *conn;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;

	if (!(current_session->capabilities & ADMIN))
		return;

	ml = TMPL_add_var(ml, "admin", "yes", NULL);

	if (current_session->capabilities & APPROVER)
		ml = TMPL_add_var(ml, "approver", "yes", NULL);

	ml = TMPL_add_var(ml, "user_hdr", current_session->user_hdr, NULL);

	if (qvars)
		get_page_pagination(get_var(qvars, "page_no"), rpp, &page_no,
									&from);

	conn = db_conn();
	snprintf(sql, SQL_MAX, "SELECT name, user, expires FROM activations "
					"INNER JOIN passwd ON "
					"(activations.user = passwd.username) "
					"LIMIT %d, %d", from, rpp);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_query(conn, sql);
	res = mysql_store_result(conn);

	nr_rows = mysql_num_rows(res);
	for (i = 0; i < nr_rows; i++) {
		char tbuf[64];
		time_t secs;
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		pages = ceilf((float)nr_rows / (float)rpp);

		if (!(i % 2))
			vl = TMPL_add_var(NULL, "zebra", "yes", NULL);
		else
			vl = TMPL_add_var(NULL, "zebra", "no", NULL);

		vl = TMPL_add_var(vl, "name", get_var(db_row, "name"), NULL);
		vl = TMPL_add_var(vl, "username", get_var(db_row,
							"user"), NULL);
		secs = atol(get_var(db_row, "expires"));
		if (time(NULL) > secs)
			vl = TMPL_add_var(vl, "expired", "yes", NULL);
		strftime(tbuf, sizeof(tbuf), "%F %H:%M:%S", localtime(&secs));
		vl = TMPL_add_var(vl, "expires", tbuf, NULL);

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}

	if (pages > 1) {
		if (page_no - 1 > 0) {
			snprintf(page, 10, "%d", page_no - 1);
			ml = TMPL_add_var(ml, "prev_page", page, NULL);
		}
		if (page_no + 1 <= pages) {
			snprintf(page, 10, "%d", page_no + 1);
			ml = TMPL_add_var(ml, "next_page", page, NULL);
		}
	} else {
		ml = TMPL_add_var(ml, "no_pages", "true", NULL);
	}
	ml = TMPL_add_loop(ml, "table", loop);

	send_template("templates/admin_pending_activations.tmpl", ml);
	TMPL_free_varlist(ml);
	mysql_free_result(res);
	mysql_close(conn);
}

/*
 * /activate_user/
 *
 * HTML is in templates/activate_user.tmpl
 *
 * Activate a users account.
 */
static void activate_user(char *request_method, GHashTable *qvars)
{
	char sql[SQL_MAX];
	char *key;
	int post = 0;
	MYSQL *conn;
	MYSQL_RES *res;
	GHashTable *db_row = NULL;
	TMPL_varlist *vl = NULL;

	if (!qvars) {
		vl = TMPL_add_var(vl, "key_error", "yes", NULL);
		goto out2;
	}

	/*
	 * If we got a POST request, that means the user has attempted
	 * to set a password.
	 *
	 * Otherwise we should have an activation key to proceed with
	 * the account activation.
	 */
	if (strcmp(request_method, "POST") == 0)
		post = 1;

	conn = db_conn();

	key = alloca(strlen(get_var(qvars, "key")) * 2 + 1);
	mysql_real_escape_string(conn, key, get_var(qvars, "key"),
					strlen(get_var(qvars, "key")));

	snprintf(sql, SQL_MAX, "SELECT uid, name, user, expires FROM passwd "
					"INNER JOIN activations ON "
					"(passwd.username = "
					"activations.user) WHERE "
					"activations.akey = '%s'", key);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) == 0) {
		vl = TMPL_add_var(vl, "key_error", "yes", NULL);
		goto out;
	}

	db_row = get_dbrow(res);
	vl = TMPL_add_var(vl, "name", get_var(db_row, "name"), NULL);

	/* Check if the activation key has expired. */
	if (time(NULL) > atol(get_var(db_row, "expires"))) {
		vl = TMPL_add_var(vl, "expired", "yes", NULL);
		vl = TMPL_add_var(vl, "email", get_var(db_row, "user"), NULL);
		goto out;
	}
	vl = TMPL_add_var(vl, "key", get_var(qvars, "key"), NULL);

	/*
	 * The user is trying to set a password, do some sanity
	 * checking on it,
	 *
	 * The user needs to enter the password twice, make sure they match.
	 * Also make sure that the password is at least 8 characters long.
	 */
	if (post) {
		if (strlen(get_var(qvars, "pass1")) > 7 &&
					strlen(get_var(qvars, "pass2")) > 7) {
			if (strcmp(get_var(qvars, "pass1"),
					get_var(qvars, "pass2")) == 0) {
				do_activate_user(get_var(db_row, "uid"), key,
						get_var(qvars, "pass1"));
				vl = TMPL_add_var(vl, "activated", "yes",
									NULL);
			} else {
				vl = TMPL_add_var(vl, "password_error",
							"mismatch", NULL);
			}
		} else {
			vl = TMPL_add_var(vl, "password_error", "length",
									NULL);
		}
	}

out:
	free_vars(db_row);
	mysql_free_result(res);
	mysql_close(conn);

out2:
	send_template("templates/activate_user.tmpl", vl);
	TMPL_free_varlist(vl);
}

/*
 * /generate_new_key/
 *
 * HTML is in templates/generate_new_key.tmpl
 *
 * Generate a new activation key and send it to the user.
 */
static void generate_new_key(GHashTable *qvars)
{
	char sql[SQL_MAX];
	char *email_addr;
	char *key;
	time_t tm;
	MYSQL *conn;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;

	if (!qvars)
		return;

	conn = db_conn();

	email_addr = alloca(strlen(get_var(qvars, "email")) * 2 + 1);
	mysql_real_escape_string(conn, email_addr, get_var(qvars, "email"),
					strlen(get_var(qvars, "email")));

	snprintf(sql, SQL_MAX, "SELECT user FROM activations WHERE user = "
							"'%s'", email_addr);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));

	res = mysql_store_result(conn);
	if (mysql_num_rows(res) == 0)
		goto out;

	key = generate_activation_key(email_addr);

	tm = time(NULL);
	snprintf(sql, SQL_MAX, "REPLACE INTO activations VALUES ('%s', '%s', "
							"%ld)", email_addr,
							key, tm + 86400);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));

	send_activation_mail(get_var(qvars, "name"), email_addr, key);
	free(key);

	vl = TMPL_add_var(vl, "email", email_addr, NULL);

out:
	send_template("templates/generate_new_key.tmpl", vl);
	TMPL_free_varlist(vl);

	mysql_free_result(res);
	mysql_close(conn);
}

/*
 * /forgotten_password/
 *
 * HTML is in templates/forgotten_password.tmpl
 *
 * Allow a user to set a new password, if they have forgotten it.
 */
static void forgotten_password(GHashTable *qvars)
{
	char sql[SQL_MAX];
	char *email_addr;
	char *key;
	time_t tm;
	MYSQL *conn;
	MYSQL_RES *res;
	TMPL_varlist *vl = NULL;

	if (!qvars)
		goto out;

	conn = db_conn();

	vl = TMPL_add_var(vl, "email", get_var(qvars, "email"), NULL);

	email_addr = alloca(strlen(get_var(qvars, "email")) * 2 + 1);
	mysql_real_escape_string(conn, email_addr, get_var(qvars, "email"),
					strlen(get_var(qvars, "email")));

	snprintf(sql, SQL_MAX, "SELECT username FROM passwd WHERE username = "
							"'%s'", email_addr);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) == 0) {
		vl = TMPL_add_var(vl, "user_error", "yes", NULL);
		goto mysql_cleanup;
	}

	key = generate_activation_key(email_addr);

	tm = time(NULL);
	snprintf(sql, SQL_MAX, "INSERT INTO activations VALUES ('%s', '%s', "
							"%ld)", email_addr,
							key, tm + 86400);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));

	send_activation_mail(get_var(qvars, "name"), email_addr, key);
	free(key);
	vl = TMPL_add_var(vl, "sent", "yes", NULL);

mysql_cleanup:
	mysql_free_result(res);
	mysql_close(conn);

out:
	send_template("templates/forgotten_password.tmpl", vl);
	TMPL_free_varlist(vl);
}

/*
 * /prefs/
 *
 * HTML is in templates/prefs.tmpl
 */
static void prefs(struct session *current_session)
{
	TMPL_varlist *vl = NULL;

	if (current_session->capabilities & ADMIN)
		vl = TMPL_add_var(vl, "admin", "yes", NULL);
	if (current_session->capabilities & APPROVER)
		vl = TMPL_add_var(vl, "approver", "yes", NULL);

	vl = TMPL_add_var(vl, "user_hdr", current_session->user_hdr, NULL);

	send_template("templates/prefs.tmpl", vl);
	TMPL_free_varlist(vl);
}

/*
 * /prefs/fmap/
 *
 * HTML is in templates/prefs_fmap.tmpl
 *
 * Change the image tag field names.
 */
static void prefs_fmap(struct session *current_session, GHashTable *qvars)
{
	struct field_names fields;
	int updated = 0;
	TMPL_varlist *vl = NULL;

	if (qvars) {
		update_fmap(current_session, qvars);
		updated = 1;
	}

	if (current_session->capabilities & APPROVER)
		vl = TMPL_add_var(vl, "approver", "yes", NULL);
	if (current_session->capabilities & ADMIN)
		vl = TMPL_add_var(vl, "admin", "yes", NULL);

	vl = TMPL_add_var(vl, "user_hdr", current_session->user_hdr, NULL);

	fields = field_names;
	set_custom_field_names(current_session, &fields);

	if (updated)
		vl = TMPL_add_var(vl, "fields_updated", "yes", NULL);

	vl = TMPL_add_var(vl, "receipt_date", DFN_RECEIPT_DATE,NULL);
	vl = TMPL_add_var(vl, "alt_receipt_date", !strcmp(DFN_RECEIPT_DATE,
					fields.receipt_date) ? "":
					fields.receipt_date, NULL);

	vl = TMPL_add_var(vl, "department", DFN_DEPARTMENT, NULL);
	vl = TMPL_add_var(vl, "alt_department",!strcmp(DFN_DEPARTMENT,
					fields.department) ? "" :
					fields.department, NULL);

	vl = TMPL_add_var(vl, "employee_number", DFN_EMPLOYEE_NUMBER, NULL);
	vl = TMPL_add_var(vl, "alt_employee_number",
					!strcmp(DFN_EMPLOYEE_NUMBER,
					fields.employee_number) ? "" :
					fields.employee_number, NULL);

	vl = TMPL_add_var(vl, "reason", DFN_REASON, NULL);
	vl = TMPL_add_var(vl, "alt_reason",!strcmp(DFN_REASON,
					fields.reason) ? "" :
					fields.reason, NULL);

	vl = TMPL_add_var(vl, "po_num", DFN_PO_NUM, NULL);
	vl = TMPL_add_var(vl, "alt_po_num", !strcmp(DFN_PO_NUM,
					fields.po_num) ? "" :
					fields.po_num, NULL);

	vl = TMPL_add_var(vl, "cost_codes", DFN_COST_CODES, NULL);
	vl = TMPL_add_var(vl, "alt_cost_codes", !strcmp(DFN_COST_CODES,
					fields.cost_codes) ? "" :
					fields.cost_codes, NULL);

	vl = TMPL_add_var(vl, "account_codes", DFN_ACCOUNT_CODES, NULL);
	vl = TMPL_add_var(vl, "alt_account_codes", !strcmp(DFN_ACCOUNT_CODES,
					fields.account_codes) ? "" :
					fields.account_codes, NULL);

	vl = TMPL_add_var(vl, "supplier_name", DFN_SUPPLIER_NAME, NULL);
	vl = TMPL_add_var(vl, "alt_supplier_name", !strcmp(DFN_SUPPLIER_NAME,
					fields.supplier_name) ? "" :
					fields.supplier_name, NULL);

	vl = TMPL_add_var(vl, "supplier_town", DFN_SUPPLIER_TOWN, NULL);
	vl = TMPL_add_var(vl, "alt_supplier_town", !strcmp(DFN_SUPPLIER_TOWN,
					fields.supplier_town) ? "" :
					fields.supplier_town, NULL);

	vl = TMPL_add_var(vl, "vat_number", DFN_VAT_NUMBER, NULL);
	vl = TMPL_add_var(vl, "alt_vat_number", !strcmp(DFN_VAT_NUMBER,
					fields.vat_number) ? "" :
					fields.vat_number, NULL);

	vl = TMPL_add_var(vl, "gross_amount", DFN_GROSS_AMOUNT, NULL);
	vl = TMPL_add_var(vl, "alt_gross_amount", !strcmp(DFN_GROSS_AMOUNT,
					fields.gross_amount) ? "" :
					fields.gross_amount, NULL);

	vl = TMPL_add_var(vl, "net_amount", DFN_NET_AMOUNT, NULL);
	vl = TMPL_add_var(vl, "alt_net_amount", !strcmp(DFN_NET_AMOUNT,
					fields.net_amount) ? "" :
					fields.net_amount, NULL);

	vl = TMPL_add_var(vl, "vat_amount", DFN_VAT_AMOUNT, NULL);
	vl = TMPL_add_var(vl, "alt_vat_amount", !strcmp(DFN_VAT_AMOUNT,
					fields.vat_amount) ? "" :
					fields.vat_amount, NULL);

	vl = TMPL_add_var(vl, "vat_rate", DFN_VAT_RATE, NULL);
	vl = TMPL_add_var(vl, "alt_vat_rate", !strcmp(DFN_VAT_RATE,
					fields.vat_rate) ? "" :
					fields.vat_rate, NULL);

	vl = TMPL_add_var(vl, "currency", DFN_CURRENCY, NULL);
	vl = TMPL_add_var(vl, "alt_currency", !strcmp(DFN_CURRENCY,
					fields.currency) ? "" :
					fields.currency, NULL);

	vl = TMPL_add_var(vl, "payment_method", DFN_PAYMENT_METHOD, NULL);
	vl = TMPL_add_var(vl, "alt_payment_method", !strcmp(DFN_PAYMENT_METHOD,
					fields.payment_method) ? "" :
					fields.payment_method, NULL);

	send_template("templates/prefs_fmap.tmpl", vl);
	TMPL_free_varlist(vl);
	free_fields(&fields);
}

/*
 * /prefs/edit_user/
 *
 * HTML is in templates/prefs_edit_user.tmpl
 *
 * Allow users to change their details.
 */
static void prefs_edit_user(char *request_method,
					struct session *current_session,
					GHashTable *qvars)
{
	int form_err = 0;
	TMPL_varlist *vl = NULL;

	/*
	 * If we got POST data, update the users settings before
	 * showing them.
	 */
	if (strcmp(request_method, "POST") == 0) {
		if ((strlen(get_var(qvars, "email1")) == 0 &&
				strlen(get_var(qvars, "email2")) == 0) ||
				(strcmp(get_var(qvars, "email1"),
				get_var(qvars, "email2")) != 0)) {
			vl = TMPL_add_var(vl, "email_error", "yes", NULL);
			form_err = 1;
		} else if (strcmp(current_session->username,
					get_var(qvars,"email1")) != 0) {
			if (user_already_exists(get_var(qvars,"email1"))) {
				vl = TMPL_add_var(vl, "user_exists", "yes",
									NULL);
				form_err = 1;
			}
		}
		if (strlen(get_var(qvars, "pass1")) > 7 &&
					strlen(get_var(qvars, "pass2")) > 7) {
			if (strcmp(get_var(qvars, "pass1"),
					get_var(qvars, "pass2")) != 0) {
				vl = TMPL_add_var(vl, "pass_error",
							"mismatch", NULL);
				form_err = 1;
			}
		/*
		 * If the password fields are > 0 in length, then we tried
		 * to update it.
		 */
		} else if (strlen(get_var(qvars, "pass1")) != 0 &&
					strlen(get_var(qvars, "pass2")) != 0) {
			vl = TMPL_add_var(vl, "pass_error", "length", NULL);
			form_err = 1;
		}

		if (!form_err) {
			do_edit_user(current_session, qvars);
			/* After the update we want to re-GET */
			printf("Location: /prefs/edit_user/?updated=yes"
								"\r\n\r\n");
			return;
		}
	} else {
		if (strlen(get_var(qvars, "updated")) > 0)
			vl = TMPL_add_var(vl, "updated", "yes", NULL);
	}

	/*
	 * If form_err is still 0, then either we got a GET and just want
	 * to show the users settings from the database. Or we got a POST
	 * and successfully updated the users settings and want to show them.
	 *
	 * Else we tried to update the users settings but made some mistake
	 * and need to re-edit them in which case we need show the values
	 * from the POST'd form.
	 */
	if (!form_err) {
		char sql[SQL_MAX];
		MYSQL *conn;
		MYSQL_RES *res;
		GHashTable *db_row = NULL;

		conn = db_conn();
		snprintf(sql, SQL_MAX, "SELECT username, name FROM passwd "
							"WHERE uid = %u",
							current_session->uid);
		d_fprintf(sql_log, "%s\n", sql);
		mysql_query(conn, sql);
		res = mysql_store_result(conn);
		db_row = get_dbrow(res);

		vl = TMPL_add_var(vl, "username", get_var(db_row, "username"),
									NULL);
		vl = TMPL_add_var(vl, "email1", get_var(db_row, "username"),
									NULL);
		vl = TMPL_add_var(vl, "email2", get_var(db_row, "username"),
									NULL);
		vl = TMPL_add_var(vl, "name", get_var(db_row, "name"), NULL);

		free_vars(db_row);
		mysql_free_result(res);
		mysql_close(conn);
	} else {
		vl = TMPL_add_var(vl, "username", get_var(qvars, "email1"),
									NULL);
		vl = TMPL_add_var(vl, "email1", get_var(qvars, "email1"),
									NULL);
		vl = TMPL_add_var(vl, "email2", get_var(qvars, "email2"),
									NULL);
		vl = TMPL_add_var(vl, "name", get_var(qvars, "name"), NULL);
	}

	if (current_session->capabilities & ADMIN)
		vl = TMPL_add_var(vl, "admin", "yes", NULL);
	if (current_session->capabilities & APPROVER)
		vl = TMPL_add_var(vl, "approver", "yes", NULL);

	vl = TMPL_add_var(vl, "user_hdr", current_session->user_hdr, NULL);

	send_template("templates/prefs_edit_user.tmpl", vl);
	TMPL_free_varlist(vl);
}

/*
 * /do_extract_data/
 */
static void do_extract_data(struct session *current_session, GHashTable *qvars)
{
	int fd;
	char temp_name[30] = "/tmp/receiptomatic-www-XXXXXX";

	if (!(current_session->capabilities & APPROVER))
		return;

	fd = mkstemp(temp_name);

	if (strcmp(get_var(qvars, "whence"), "now") == 0)
		extract_data_now(current_session, fd);

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
static void extract_data(struct session *current_session)
{
	TMPL_varlist *vl = NULL;

	if (!(current_session->capabilities & APPROVER))
		return;
	if (current_session->capabilities & ADMIN)
		vl = TMPL_add_var(vl, "admin", "yes", NULL);

	vl = TMPL_add_var(vl, "user_hdr", current_session->user_hdr, NULL);
	vl = TMPL_add_var(vl, "approver", "yes", NULL);

	send_template("templates/extract_data.tmpl", vl);
	TMPL_free_varlist(vl);
}

/*
 * /process_receipt_approval/
 *
 * Processes the form data from /approve_receipts/
 */
static void process_receipt_approval(struct session *current_session)
{
	char sql[SQL_MAX];
	char buf[SQL_MAX];
	char *username;
	int list_size;
	int i;
	MYSQL *conn;
	MYSQL_RES *res;
	GList *post_vars = NULL;

	if (!(current_session->capabilities & APPROVER))
		return;

	memset(buf, 0, sizeof(buf));
	fread(buf, sizeof(buf) - 1, 1, stdin);
	if (!strstr(buf, "=") && !strstr(buf, "&"))
		return;

	post_vars = get_avars(buf);

	conn = db_conn();

	username = alloca(strlen(current_session->username) * 2 + 1);
	mysql_real_escape_string(conn, username, current_session->username,
					strlen(current_session->username));

	mysql_query(conn, "LOCK TABLES approved WRITE, images WRITE, "
								"tags READ");

	list_size = g_list_length(post_vars);
	for (i = 0; i < list_size; i++) {
		char *action = get_avar(post_vars, i, "approved_status");
		char *reason;
		char *image_id;

		image_id = alloca(strlen(get_avar(post_vars, i, "id")) *
									2 + 1);
		mysql_real_escape_string(conn, image_id, get_avar(post_vars,
							i, "id"),
							strlen(get_avar(
							post_vars, i, "id")));

		reason = alloca(strlen(get_avar(post_vars, i, "reason")) *
									2 + 1);
		mysql_real_escape_string(conn, reason, get_avar(post_vars,
							i, "reason"),
							strlen(get_avar(
							post_vars, i,
							"reason")));

		/* Can user approve their own receipts? */
		if (!(current_session->capabilities & APPROVER_SELF)) {
			snprintf(sql, SQL_MAX, "SELECT id FROM images WHERE "
						"id = '%s' AND uid = %u",
						image_id,
						current_session->uid);
			d_fprintf(sql_log, "%s\n", sql);
			mysql_real_query(conn, sql, strlen(sql));
			res = mysql_store_result(conn);
			if (mysql_num_rows(res) > 0)
				action[0] = 's';
		}
		/* Can user approve card transactions? */
		if (!(current_session->capabilities & APPROVER_CARD)) {
			snprintf(sql, SQL_MAX, "SELECT id FROM tags WHERE "
						"id = '%s' AND payment_method "
						"= 'card'", image_id);
			d_fprintf(sql_log, "%s\n", sql);
			mysql_real_query(conn, sql, strlen(sql));
			res = mysql_store_result(conn);
			if (mysql_num_rows(res) > 0)
				action[0] = 's';
		}
		/* Can user approve cash transactions? */
		if (!(current_session->capabilities & APPROVER_CASH)) {
			snprintf(sql, SQL_MAX, "SELECT id FROM tags WHERE "
						"id = '%s' AND payment_method "
						"= 'cash'", image_id);
			d_fprintf(sql_log, "%s\n", sql);
			mysql_real_query(conn, sql, strlen(sql));
			res = mysql_store_result(conn);
			if (mysql_num_rows(res) > 0)
				action[0] = 's';
		}
		/* Can user approve cheque transactions? */
		if (!(current_session->capabilities & APPROVER_CHEQUE)) {
			snprintf(sql, SQL_MAX, "SELECT id FROM tags WHERE "
						"id = '%s' AND payment_method "
						"= 'cheque'", image_id);
			d_fprintf(sql_log, "%s\n", sql);
			mysql_real_query(conn, sql, strlen(sql));
			res = mysql_store_result(conn);
			if (mysql_num_rows(res) > 0)
				action[0] = 's';
		}

		/* Make sure this reciept hasn't already been processed */
		snprintf(sql, SQL_MAX, "SELECT status from approved WHERE "
							"id = '%s'", image_id);
		d_fprintf(sql_log, "%s\n", sql);
		mysql_real_query(conn, sql, strlen(sql));
		res = mysql_store_result(conn);
		if (mysql_num_rows(res) > 0)
			action[0] = 's'; /* This receipt is already done */

		/* Make sure it is a valid tagged-receipt */
		snprintf(sql, SQL_MAX, "SELECT id FROM tags WHERE id = '%s'",
								image_id);
		d_fprintf(sql_log, "%s\n", sql);
		mysql_real_query(conn, sql, strlen(sql));
		res = mysql_store_result(conn);
		if (mysql_num_rows(res) == 0)
			action[0] = 's'; /* Not a valid receipt */

		if (action[0] == 'a') { /* approved */
			snprintf(sql, SQL_MAX, "INSERT INTO approved VALUES ("
						"'%s', %u, '%s', %ld, %d, "
						"'%s')",
						image_id, current_session->uid,
						username, time(NULL), APPROVED,
						reason);
			d_fprintf(sql_log, "%s\n", sql);
			mysql_real_query(conn, sql, strlen(sql));
			snprintf(sql, SQL_MAX, "UPDATE images SET approved = "
						"%d WHERE id = '%s'",
						APPROVED, image_id);
			d_fprintf(sql_log, "%s\n", sql);
			mysql_query(conn, sql);
		} else if (action[0] == 'r') { /* rejected */
			snprintf(sql, SQL_MAX, "INSERT INTO approved VALUES ("
						"'%s', %u, '%s', %ld, %d, "
						"'%s')",
						image_id, current_session->uid,
						username, time(NULL), REJECTED,
						reason);
			d_fprintf(sql_log, "%s\n", sql);
			mysql_real_query(conn, sql, strlen(sql));
			snprintf(sql, SQL_MAX, "UPDATE images SET approved = "
						"%d WHERE id = '%s'",
						REJECTED, image_id);
			d_fprintf(sql_log, "%s\n", sql);
			mysql_query(conn, sql);
		}
	}

	mysql_query(conn, "UNLOCK TABLES");
	mysql_free_result(res);
	mysql_close(conn);
	free_avars(post_vars);

	printf("Location: /approve_receipts/\r\n\r\n");
}

/*
 * /approve_receipts/
 *
 * HTML is in templates/approve_receipts.tmpl
 *
 * Allows an approver to approve or reject receipts.
 */
static void approve_receipts(struct session *current_session, GHashTable *qvars)
{
	char sql[SQL_MAX];
	char pmsql[128];
	char assql[512];
	char page[10];
	static const char *pm = "tags.payment_method = ";
	static const char *cash = "'cash'";
	static const char *card = "'card'";
	static const char *cheque = "'cheque'";
	char join[5];
	MYSQL *conn;
	MYSQL_RES *res;
	int i;
	int nr_rows;
	int from = 0;
	int page_no = 1;
	int pages;
	struct field_names fields;
	TMPL_varlist *ml = NULL;
	TMPL_varlist *vl = NULL;
	TMPL_loop *loop = NULL;

	if (!(current_session->capabilities & APPROVER))
		return;

	memset(pmsql, 0, sizeof(pmsql));
	/*
	 * Prepare the payment_method sql clause depending on the users
	 * approver capabilities.
	 */
	if (current_session->capabilities & APPROVER_CASH) {
		strcat(pmsql, pm);
		strcat(pmsql, cash);
	}
	if (current_session->capabilities & APPROVER_CARD) {
		if (strlen(pmsql) > 0)
			strcpy(join, " OR ");
		else
			strcpy(join, "\0");
		strcat(pmsql, join);
		strcat(pmsql, pm);
		strcat(pmsql, card);
	}
	if (current_session->capabilities & APPROVER_CHEQUE) {
		if (strlen(pmsql) > 0)
			strcpy(join, " OR ");
		else
			strcpy(join, "\0");
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
	if (strlen(pmsql) == 0) {
		d_fprintf(error_log, "User %u seems to have an invalid "
					"capability setting in the passwd "
					"table.\n", current_session->uid);
		return;
	}

	if (qvars)
		get_page_pagination(get_var(qvars, "page_no"), APPROVER_ROWS,
							&page_no, &from);

	conn = db_conn();

	memset(assql, 0, sizeof(assql));
	/* If the user isn't APPROVER_SELF, don't show them their receipts */
	if (!(current_session->capabilities & APPROVER_SELF))
		sprintf(assql, "AND images.uid != %u", current_session->uid);
	else
		assql[0] = '\0';

	snprintf(sql, SQL_MAX, "SELECT (SELECT COUNT(*) FROM images "
					"INNER JOIN tags ON "
					"(images.id = tags.id) WHERE "
					"images.approved = 1 AND (%s) %s) AS "
					"nrows, images.id, images.username, "
					"images.timestamp AS its, "
					"images.path, images.name, "
					"tags.username, "
					"tags.timestamp AS tts, "
					"tags.employee_number, "
					"tags.department, tags.po_num, "
					"tags.cost_codes, tags.account_codes, "
					"tags.supplier_town, "
					"tags.supplier_name, tags.currency, "
					"tags.gross_amount, tags.vat_amount, "
					"tags.net_amount, tags.vat_rate, "
					"tags.vat_number, tags.receipt_date, "
					"tags.reason, tags.payment_method "
					"FROM images INNER JOIN tags ON "
					"(images.id = tags.id) WHERE "
					"images.approved = 1 AND (%s) %s "
					"LIMIT %d, %d",
					pmsql, assql, pmsql, assql, from,
					APPROVER_ROWS);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_query(conn, sql);
	res = mysql_store_result(conn);

	if (current_session->capabilities & APPROVER)
		ml = TMPL_add_var(ml, "approver", "yes", NULL);
	if (current_session->capabilities & ADMIN)
		ml = TMPL_add_var(ml, "admin", "yes", NULL);

	ml = TMPL_add_var(ml, "user_hdr", current_session->user_hdr, NULL);

	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0) {
		ml = TMPL_add_var(ml, "receipts", "no", NULL);
		goto out;
	}

	fields = field_names;
	set_custom_field_names(current_session, &fields);

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

		pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
							(float)APPROVER_ROWS);

		vl = TMPL_add_var(NULL, "image_path", get_var(db_row, "path"),
									NULL);
		vl = TMPL_add_var(vl, "image_name", get_var(db_row, "name"),
									NULL);

		name = username_to_name(get_var(db_row, "username"));
		vl = TMPL_add_var(vl, "name", name, NULL);
		free(name);

		secs = atol(get_var(db_row, "its"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = TMPL_add_var(vl, "images_timestamp", tbuf, NULL);

		secs = atol(get_var(db_row, "tts"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = TMPL_add_var(vl, "tags_timestamp", tbuf, NULL);
		vl = TMPL_add_var(vl, "fields.department", fields.department,
									NULL);
		vl = TMPL_add_var(vl, "department", get_var(db_row,
							"department"), NULL);
		vl = TMPL_add_var(vl, "fields.employee_number",
						fields.employee_number, NULL);
		vl = TMPL_add_var(vl, "employee_number", get_var(db_row,
						"employee_number"), NULL);
		vl = TMPL_add_var(vl, "fields.cost_codes", fields.cost_codes,
									NULL);
		vl = TMPL_add_var(vl, "cost_codes", get_var(db_row,
							"cost_codes"), NULL);
		vl = TMPL_add_var(vl, "fields.account_codes",
						fields.account_codes, NULL);
		vl = TMPL_add_var(vl, "account_codes", get_var(db_row,
						"account_codes"), NULL);
		vl = TMPL_add_var(vl, "fields.po_num", fields.po_num, NULL);
		vl = TMPL_add_var(vl, "po_num", get_var(db_row, "po_num"),
									NULL);
		vl = TMPL_add_var(vl, "fields.supplier_name",
						fields.supplier_name, NULL);
		vl = TMPL_add_var(vl, "supplier_name", get_var(db_row,
						"supplier_name"), NULL);
		vl = TMPL_add_var(vl, "fields.supplier_town",
						fields.supplier_town, NULL);
		vl = TMPL_add_var(vl, "supplier_town", get_var(db_row,
						"supplier_town"), NULL);
		vl = TMPL_add_var(vl, "fields.currency", fields.currency,
									NULL);
		vl = TMPL_add_var(vl, "currency", get_var(db_row, "currency"),
									NULL);
		vl = TMPL_add_var(vl, "fields.gross_amount",
						fields.gross_amount, NULL);
		vl = TMPL_add_var(vl, "gross_amount", get_var(db_row,
							"gross_amount"), NULL);
		vl = TMPL_add_var(vl, "fields.vat_amount", fields.vat_amount,
									NULL);
		vl = TMPL_add_var(vl, "vat_amount", get_var(db_row,
							"vat_amount"), NULL);
		vl = TMPL_add_var(vl, "fields.net_amount", fields.net_amount,
									NULL);
		vl = TMPL_add_var(vl, "net_amount", get_var(db_row,
							"net_amount"), NULL);
		vl = TMPL_add_var(vl, "fields.vat_rate", fields.vat_rate,
									NULL);
		vl = TMPL_add_var(vl, "vat_rate", get_var(db_row, "vat_rate"),
									NULL);

		/* Sanity check the amounts */
		gross = strtod(get_var(db_row, "gross_amount"), NULL);
		net = strtod(get_var(db_row, "net_amount"), NULL);
		vat = strtod(get_var(db_row, "vat_amount"), NULL);
		vr = strtod(get_var(db_row, "vat_rate"), NULL);
		ret = check_amounts(gross, net, vat, vr);
		if (ret < 0)
			vl = TMPL_add_var(vl, "amnt_err", "yes", NULL);
		else
			vl = TMPL_add_var(vl, "amnt_err", "no", NULL);

		vl = TMPL_add_var(vl, "fields.vat_number", fields.vat_number,
									NULL);
		vl = TMPL_add_var(vl, "vat_number", get_var(db_row,
							"vat_number"), NULL);
		vl = TMPL_add_var(vl, "fields.receipt_date",
						fields.receipt_date, NULL);

		secs = atol(get_var(db_row, "receipt_date"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = TMPL_add_var(vl, "receipt_date", tbuf, NULL);
		vl = TMPL_add_var(vl, "fields.payment_method",
						fields.payment_method, NULL);
		vl = TMPL_add_var(vl, "payment_method", get_var(db_row,
						"payment_method"), NULL);
		vl = TMPL_add_var(vl, "fields.reason", fields.reason, NULL);
		vl = TMPL_add_var(vl, "reason", get_var(db_row, "reason"),
									NULL);
		vl = TMPL_add_var(vl, "id", get_var(db_row, "id"), NULL);

		snprintf(item, 3, "%d", i);
		vl = TMPL_add_var(vl, "item", item, NULL);

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	free_fields(&fields);

	if (pages > 1) {
		if (page_no - 1 > 0) {
			snprintf(page, 10, "%d", page_no - 1);
			ml = TMPL_add_var(ml, "prev_page", page, NULL);
		}
		if (page_no + 1 <= pages) {
			snprintf(page, 10, "%d", page_no + 1);
			ml = TMPL_add_var(ml, "next_page", page, NULL);
		}
	} else {
		ml = TMPL_add_var(ml, "no_pages", "true", NULL);
	}
	ml = TMPL_add_loop(ml, "table", loop);

out:
	send_template("templates/approve_receipts.tmpl", ml);
	TMPL_free_varlist(ml);
	mysql_free_result(res);
	mysql_close(conn);
}

/*
 * /reviewed_receipts/
 *
 * HTML is in templates/reviewed_receipts.tmpl
 *
 * Displays previously reviewed receipts.
 */
static void reviewed_receipts(struct session *current_session,
							GHashTable *qvars)
{
	int i;
	int c = 1;		/* column number */
	int from = 0;
	int page_no = 1;
	int nr_rows;
	int pages;
	char page[10];
	char sql[SQL_MAX];
	MYSQL *conn;
	MYSQL_RES *res;
	struct field_names fields;
	TMPL_varlist *vl = NULL;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;

	if (!(current_session->capabilities & APPROVER))
		return;

	if (qvars)
		get_page_pagination(get_var(qvars, "page_no"), GRID_SIZE,
							&page_no, &from);

	if (current_session->capabilities & APPROVER)
		ml = TMPL_add_var(ml, "approver", "yes", NULL);
	if (current_session->capabilities & ADMIN)
		ml = TMPL_add_var(ml, "admin", "yes", NULL);

	ml = TMPL_add_var(ml, "user_hdr", current_session->user_hdr, NULL);

	conn = db_conn();
	snprintf(sql, SQL_MAX, "SELECT (SELECT COUNT(*) FROM approved "
				"INNER JOIN images ON "
				"(approved.id = images.id)) AS nrows, "
				"approved.timestamp AS ats, images.id, "
				"images.path, images.name, images.timestamp "
				"AS its, approved.status, passwd.name AS "
				"user, passwd.uid FROM approved INNER JOIN "
				"images ON (approved.id = images.id) "
				"INNER JOIN passwd ON "
				"(images.uid = passwd.uid) ORDER BY "
				"approved.timestamp DESC LIMIT %d, %d",
				from, GRID_SIZE);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_query(conn, sql);
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

		pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
							(float)GRID_SIZE);

		vl = TMPL_add_var(NULL, "id", get_var(db_row, "id"), NULL);
		vl = TMPL_add_var(vl, "image_path", get_var(db_row, "path"),
									NULL);
		vl = TMPL_add_var(vl, "image_name", get_var(db_row, "name"),
									NULL);
		vl = TMPL_add_var(vl, "user", get_var(db_row, "user"), NULL);
		vl = TMPL_add_var(vl, "uid", get_var(db_row, "uid"), NULL);

		secs = atol(get_var(db_row, "ats"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = TMPL_add_var(vl, "review_date", "Review Date", NULL);
		vl = TMPL_add_var(vl, "apdate", tbuf, NULL);

		secs = atol(get_var(db_row, "its"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = TMPL_add_var(vl, "receipt_date", fields.receipt_date,
									NULL);
		loop = TMPL_add_varlist(loop, vl);
		vl = TMPL_add_var(vl, "rdate", tbuf, NULL);

		if (atoi(get_var(db_row, "status")) == REJECTED)
			vl = TMPL_add_var(vl, "status", "rejected", NULL);
		else
			vl = TMPL_add_var(vl, "status", "approved", NULL);

		if (c == COL_SIZE && i < nr_rows) { /* Start a new row */
			vl = TMPL_add_var(vl, "new_row", "yes", NULL);
			c = 0;
		} else {
			vl = TMPL_add_var(vl, "new_row", "no", NULL);
		}
		c++;

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	free_fields(&fields);

	if (pages > 1) {
		if (page_no - 1 > 0) {
			snprintf(page, 10, "%d", page_no - 1);
			ml = TMPL_add_var(ml, "prev_page", page, NULL);
		}
		if (page_no + 1 <= pages) {
			snprintf(page, 10, "%d", page_no + 1);
			ml = TMPL_add_var(ml, "next_page", page, NULL);
		}
	} else {
		ml = TMPL_add_var(ml, "no_pages", "true", NULL);
	}
	ml = TMPL_add_loop(ml, "table", loop);

out:
	send_template("templates/reviewed_receipts.tmpl", ml);
	TMPL_free_varlist(ml);
	mysql_free_result(res);
	mysql_close(conn);
}

/*
 * /receipt_info/
 *
 * HTML is in templates/receipt_info.tmpl
 *
 * Displays the logged information for a given receipt.
 */
static void receipt_info(struct session *current_session, GHashTable *qvars)
{
	char sql[SQL_MAX];
	char tbuf[60];
	char *image_id;
	struct field_names fields;
	time_t secs;
	MYSQL *conn;
	MYSQL_RES *res;
	GHashTable *db_row = NULL;
	TMPL_varlist *vl = NULL;

	if (current_session->capabilities & APPROVER)
		vl = TMPL_add_var(vl, "approver", "yes", NULL);
	if (current_session->capabilities & ADMIN)
		vl = TMPL_add_var(vl, "admin", "yes", NULL);

	vl = TMPL_add_var(vl, "user_hdr", current_session->user_hdr, NULL);

	if (!tag_info_allowed(current_session, get_var(qvars, "image_id"))) {
		vl = TMPL_add_var(vl, "show_info", "no", NULL);
		goto out;
	}

	conn = db_conn();

	image_id = alloca(strlen(get_var(qvars, "image_id")) * 2 + 1);
	mysql_real_escape_string(conn, image_id, get_var(qvars, "image_id"),
					strlen(get_var(qvars, "image_id")));
	snprintf(sql, SQL_MAX, "SELECT images.timestamp AS images_timestamp, "
				"images.path, images.name, images.approved,"
				"tags.timestamp AS tags_timestamp, "
				"tags.employee_number, tags.department, "
				"tags.po_num, tags.cost_codes, "
				"tags.account_codes, tags.supplier_name, "
				"tags.supplier_town, tags.currency, "
				"tags.gross_amount, tags.vat_amount, "
				"tags.net_amount, tags.vat_rate, "
				"tags.vat_number, tags.receipt_date, "
				"tags.reason, tags.payment_method, "
				"approved.reason AS r_reason, passwd.name AS "
				"user, passwd.uid FROM images INNER JOIN tags "
				"ON (images.id = tags.id) LEFT JOIN approved "
				"ON (approved.id = tags.id) INNER JOIN passwd "
				"ON (images.uid = passwd.uid) WHERE "
				"images.id = '%s' LIMIT 1", image_id);
	d_fprintf(sql_log, "%s\n", sql);
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

	vl = TMPL_add_var(vl, "r_user", get_var(db_row, "user"), NULL);
	vl = TMPL_add_var(vl, "r_uid", get_var(db_row, "uid"), NULL);
	vl = TMPL_add_var(vl, "id", image_id, NULL);

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
	strftime(tbuf, sizeof(tbuf), "%a %b %d, %Y", localtime(&secs));
	vl = TMPL_add_var(vl, "receipt_date", tbuf, NULL);

	vl = TMPL_add_var(vl, "fields.payment_method", fields.payment_method,
									NULL);
	vl = TMPL_add_var(vl, "payment_method", get_var(db_row,
						"payment_method"), NULL);

	if (atoi(get_var(db_row, "approved")) == REJECTED)
		vl = TMPL_add_var(vl, "approved", "rejected", NULL);
	else if (atoi(get_var(db_row, "approved")) == PENDING)
		vl = TMPL_add_var(vl, "approved", "pending", NULL);
	else
		vl = TMPL_add_var(vl, "approved", "yes", NULL);

	vl = TMPL_add_var(vl, "reject_reason", get_var(db_row, "r_reason"),
									NULL);

	/* Only PENDING receipts of the user are editable */
	if (atoi(get_var(db_row, "approved")) == PENDING &&
				atoi(get_var(db_row, "uid")) ==
				current_session->uid) {
		vl = TMPL_add_var(vl, "showedit", "true", NULL);
		if (strcmp(get_var(qvars, "edit"), "true") == 0) {
			/* Don't show the Edit button when editing */
			vl = TMPL_add_var(vl, "showedit", "false", NULL);
			vl = TMPL_add_var(vl, "edit", "true", NULL);
			/*
			 * Put the date into the same format that it should be
			 * entered by the user (YYYY-MM-DD).
			 */
			strftime(tbuf, sizeof(tbuf), "%Y-%m-%d",
							localtime(&secs));
			vl = TMPL_add_var(vl, "receipt_date", tbuf, NULL);
		}
	}
	free_vars(db_row);
	free_fields(&fields);
	mysql_free_result(res);
	mysql_close(conn);

out:
	send_template("templates/receipt_info.tmpl", vl);
	TMPL_free_varlist(vl);
}

/*
 * /tagged_receipts/
 *
 * Displays a gallery of previously tagged receipts.
 */
static void tagged_receipts(struct session *current_session, GHashTable *qvars)
{
	int i;
	int c = 1;		/* column number */
	int from = 0;
	int page_no = 1;
	int nr_rows;
	int pages;
	char page[10];
	char sql[SQL_MAX];
	MYSQL *conn;
	MYSQL_RES *res;
	struct field_names fields;
	TMPL_varlist *vl = NULL;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;

	if (qvars) {
		page_no = atoi(get_var(qvars, "page_no"));
		if (page_no < 1)
			page_no = 1;
		/* Determine the LIMIT offset to start from in the SQL */
		from = page_no * GRID_SIZE - GRID_SIZE;
	}

	if (current_session->capabilities & APPROVER)
		ml = TMPL_add_var(ml, "approver", "yes", NULL);
	if (current_session->capabilities & ADMIN)
		ml = TMPL_add_var(ml, "admin", "yes", NULL);

	ml = TMPL_add_var(ml, "user_hdr", current_session->user_hdr, NULL);

	conn = db_conn();
	snprintf(sql, SQL_MAX, "SELECT (SELECT COUNT(*) FROM tags "
				"INNER JOIN images ON "
				"(tags.id = images.id) WHERE "
				"images.processed = 1 AND images.uid = "
				"%u) AS nrows, tags.receipt_date, "
				"images.id, images.path, images.name, "
				"images.approved, approved.timestamp FROM "
				"tags INNER JOIN images ON "
				"(tags.id = images.id) LEFT JOIN approved ON "
				"(tags.id = approved.id) WHERE "
				"images.processed = 1 AND images.uid = "
				"%u ORDER BY tags.timestamp DESC LIMIT "
				"%d, %d",
				current_session->uid, current_session->uid,
				from, GRID_SIZE);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_query(conn, sql);
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

		pages = ceilf((float)atoi(get_var(db_row, "nrows")) /
							(float)GRID_SIZE);

		vl = TMPL_add_var(NULL, "id", get_var(db_row, "id"), NULL);
		vl = TMPL_add_var(vl, "image_path", get_var(db_row, "path"),
									NULL);
		vl = TMPL_add_var(vl, "image_name", get_var(db_row, "name"),
									NULL);
		secs = atol(get_var(db_row, "receipt_date"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y", localtime(&secs));
		vl = TMPL_add_var(vl, "fields.receipt_date",
						fields.receipt_date, NULL);
		vl = TMPL_add_var(vl, "receipt_date", tbuf, NULL);
		/* If the receipt been reviewed, display its reviewed date */
		if (strlen(get_var(db_row, "timestamp")) > 0) {
			secs = atol(get_var(db_row, "timestamp"));
			strftime(tbuf, sizeof(tbuf), "%a %b %e, %Y",
							localtime(&secs));
			vl = TMPL_add_var(vl, "reviewed_date", tbuf, NULL);
		}

		if (atoi(get_var(db_row, "approved")) == REJECTED)
			vl = TMPL_add_var(vl, "approved", "rejected", NULL);
		else if (atoi(get_var(db_row, "approved")) == PENDING)
			vl = TMPL_add_var(vl, "approved", "pending", NULL);
		else
			vl = TMPL_add_var(vl, "approved", "yes", NULL);

		/* We want a 3 x 3 grid */
		if (c == COL_SIZE) /* Close off row */
			vl = TMPL_add_var(vl, "close_row", "yes", NULL);
		else
			vl = TMPL_add_var(vl, "close_row", "no", NULL);

		if (c == COL_SIZE && i < nr_rows) { /* Start a new row */
			vl = TMPL_add_var(vl, "new_row", "yes", NULL);
			c = 0;
		} else {
			vl = TMPL_add_var(vl, "new_row", "no", NULL);
		}
		c++;

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	free_fields(&fields);

	if (pages > 1) {
		if (page_no - 1 > 0) {
			snprintf(page, 10, "%d", page_no - 1);
			ml = TMPL_add_var(ml, "prev_page", page, NULL);
		}
		if (page_no + 1 <= pages) {
			snprintf(page, 10, "%d", page_no + 1);
			ml = TMPL_add_var(ml, "next_page", page, NULL);
		}
	} else {
		ml = TMPL_add_var(ml, "no_pages", "true", NULL);
	}
	ml = TMPL_add_loop(ml, "table", loop);

out:
	send_template("templates/tagged_receipts.tmpl", ml);
	TMPL_free_varlist(ml);
	mysql_free_result(res);
	mysql_close(conn);
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
static void process_receipt(struct session *current_session, GHashTable *qvars)
{
	char sql[SQL_MAX];
	char secs[11];
	char *image_id;
	struct tm tm;
	int tag_error = 0;
	int ret;
	double gross;
	double net;
	double vat;
	double vr;
	struct field_names fields;
	TMPL_varlist *vl = NULL;
	MYSQL *conn;
	MYSQL_RES *res;

	if (!qvars)
		return;

	/* Prevent users from tagging other users receipts */
	if (!is_users_receipt(current_session, get_var(qvars, "image_id")))
		goto out;

	conn = db_conn();

	/* Receipt must be in PENDING status */
	image_id = alloca(strlen(get_var(qvars, "image_id")) * 2 + 1);
	mysql_real_escape_string(conn, image_id, get_var(qvars, "image_id"),
					strlen(get_var(qvars, "image_id")));
	snprintf(sql, SQL_MAX, "SELECT id FROM images WHERE id = '%s' AND "
						"approved = %d",
						get_var(qvars, "image_id"),
						PENDING);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) == 0)
		goto out;

	vl = TMPL_add_var(vl, "image_id", get_var(qvars, "image_id"), NULL);
	vl = TMPL_add_var(vl, "image_path", get_var(qvars, "image_path"),
									NULL);
	vl = TMPL_add_var(vl, "image_name", get_var(qvars, "image_name"),
									NULL);
	fields = field_names;
	set_custom_field_names(current_session, &fields);

	if (strlen(get_var(qvars, "department")) == 0) {
		tag_error = 1;
		vl = TMPL_add_var(vl, "error.department", "1", NULL);
	}
	vl = TMPL_add_var(vl, "fields.department", fields.department, NULL);
	vl = TMPL_add_var(vl, "department", get_var(qvars, "department"),
									NULL);

	if (strlen(get_var(qvars, "employee_number")) == 0) {
		tag_error = 1;
		vl = TMPL_add_var(vl, "error.employee_number", "1", NULL);
	}
	vl = TMPL_add_var(vl, "fields.employee_number", fields.employee_number,
									NULL);
	vl = TMPL_add_var(vl, "employee_number", get_var(qvars,
						"employee_number"), NULL);

	if (strlen(get_var(qvars, "cost_codes")) == 0) {
		tag_error = 1;
		vl = TMPL_add_var(vl, "error.cost_codes", "1", NULL);
	}
	vl = TMPL_add_var(vl, "fields.cost_codes", fields.cost_codes, NULL);
	vl = TMPL_add_var(vl, "cost_codes", get_var(qvars, "cost_codes"),
									NULL);

	if (strlen(get_var(qvars, "account_codes")) == 0) {
		tag_error = 1;
		vl = TMPL_add_var(vl, "error.account_codes", "1", NULL);
	}
	vl = TMPL_add_var(vl, "fields.account_codes", fields.account_codes,
									NULL);
	vl = TMPL_add_var(vl, "account_codes", get_var(qvars, "account_codes"),
									NULL);

	if (strlen(get_var(qvars, "po_num")) == 0) {
		tag_error = 1;
		vl = TMPL_add_var(vl, "error.po_num", "1", NULL);
	}
	vl = TMPL_add_var(vl, "fields.po_num", fields.po_num, NULL);
	vl = TMPL_add_var(vl, "po_num", get_var(qvars, "po_num"), NULL);

	if (strlen(get_var(qvars, "supplier_name")) == 0) {
		tag_error = 1;
		vl = TMPL_add_var(vl, "error.supplier_name", "1", NULL);
	}
	vl = TMPL_add_var(vl, "fields.supplier_name", fields.supplier_name,
									NULL);
	vl = TMPL_add_var(vl, "supplier_name", get_var(qvars, "supplier_name"),
									NULL);

	if (strlen(get_var(qvars, "supplier_town")) == 0) {
		tag_error = 1;
		vl = TMPL_add_var(vl, "error.supplier_town", "1", NULL);
	}
	vl = TMPL_add_var(vl, "fields.supplier_town", fields.supplier_town,
									NULL);
	vl = TMPL_add_var(vl, "supplier_town", get_var(qvars, "supplier_town"),
									NULL);

	vl = TMPL_add_var(vl, "fields.currency", fields.currency, NULL);
	vl = TMPL_add_var(vl, "currency", get_var(qvars, "currency"), NULL);

	gross = strtod(get_var(qvars, "gross_amount"), NULL);
	net = strtod(get_var(qvars, "net_amount"), NULL);
	vat = strtod(get_var(qvars, "vat_amount"), NULL);
	vr = strtod(get_var(qvars, "vat_rate"), NULL);
	ret = check_amounts(gross, net, vat, vr);
	if (ret < 0) {
		tag_error = 1;
		vl = TMPL_add_var(vl, "error.amounts", "1", NULL);
	}
	vl = TMPL_add_var(vl, "fields.gross_amount", fields.gross_amount,
									NULL);
	vl = TMPL_add_var(vl, "gross_amount", get_var(qvars, "gross_amount"),
									NULL);
	vl = TMPL_add_var(vl, "fields.net_amount", fields.net_amount, NULL);
	vl = TMPL_add_var(vl, "net_amount", get_var(qvars, "net_amount"),
									NULL);
	vl = TMPL_add_var(vl, "fields.vat_amount", fields.vat_amount, NULL);
	vl = TMPL_add_var(vl, "vat_amount", get_var(qvars, "vat_amount"),
									NULL);
	vl = TMPL_add_var(vl, "fields.vat_rate", fields.vat_rate, NULL);
	vl = TMPL_add_var(vl, "vat_rate", get_var(qvars, "vat_rate"), NULL);

	if (strlen(get_var(qvars, "vat_number")) == 0) {
		tag_error = 1;
		vl = TMPL_add_var(vl, "error.vat_number", "1", NULL);
	}
	vl = TMPL_add_var(vl, "fields.vat_number", fields.vat_number, NULL);
	vl = TMPL_add_var(vl, "vat_number", get_var(qvars, "vat_number"),
									NULL);

	vl = TMPL_add_var(vl, "fields.reason", fields.reason, NULL);
	vl = TMPL_add_var(vl, "reason", get_var(qvars, "reason"), NULL);

	memset(&tm, 0, sizeof(tm));
	strptime(get_var(qvars, "receipt_date"), "%Y-%m-%d", &tm);
	strftime(secs, sizeof(secs), "%s", &tm);
	if (strtol(secs, NULL, 10) < time(NULL) - MAX_RECEIPT_AGE ||
					strtol(secs, NULL, 10) > time(NULL)) {
		tag_error = 1;
		vl = TMPL_add_var(vl, "error.receipt_date", "1", NULL);
	}
	vl = TMPL_add_var(vl, "fields.receipt_date", fields.receipt_date,
									NULL);
	vl = TMPL_add_var(vl, "receipt_date", get_var(qvars, "receipt_date"),
									NULL);

	vl = TMPL_add_var(vl, "fields.payment_method", fields.payment_method,
									NULL);
	vl = TMPL_add_var(vl, "payment_method", get_var(qvars,
						"payment_method"), NULL);

	if (!tag_error) {
		tag_image(current_session, qvars);
		if (strstr(get_var(qvars, "from"), "receipt_info"))
			printf("Location: /receipt_info/?image_id=%s\r\n\r\n",
						get_var(qvars, "image_id"));
		else
			printf("Location: /receipts/\r\n\r\n");
	} else {
		if (strstr(get_var(qvars, "from"), "receipt_info"))
			vl = TMPL_add_var(vl, "from", "receipt_info");
		send_template("templates/process_receipt.tmpl", vl);
		TMPL_free_varlist(vl);
	}
	free_fields(&fields);

out:
	mysql_free_result(res);
	mysql_close(conn);
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
	MYSQL *conn;
	MYSQL_RES *res;
	struct field_names fields;
	TMPL_varlist *vl = NULL;
	TMPL_varlist *ml = NULL;
	TMPL_loop *loop = NULL;
	time_t llogin;
	char llogin_from[NI_MAXHOST];

	if (current_session->capabilities & APPROVER)
		ml = TMPL_add_var(ml, "approver", "yes", NULL);
	if (current_session->capabilities & ADMIN)
		ml = TMPL_add_var(ml, "admin", "yes", NULL);

	/* Display the user's name and UID at the top of the page */
	ml = TMPL_add_var(ml, "user_hdr", current_session->user_hdr, NULL);

	/*
	 * Display the users last login time and location, we only show
	 * this on the /receipts/ page.
	 */
	llogin = get_last_login(current_session->uid, llogin_from);
	if (llogin > 0) {
		char tbuf[32];

		strftime(tbuf, 32, "%a %b %e %H:%M %Y", localtime(&llogin));
		ml = TMPL_add_var(ml, "last_login", tbuf, NULL);
		ml = TMPL_add_var(ml, "last_login_from", llogin_from, NULL);
	} else {
		ml = TMPL_add_var(ml, "last_login", "First login", NULL);
	}

	conn = db_conn();
	snprintf(sql, SQL_MAX, "SELECT id, timestamp, path, name FROM images "
						"WHERE processed = 0 AND "
						"uid = %u",
						current_session->uid);
	d_fprintf(sql_log, "%s\n", sql);

	mysql_query(conn, sql);
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
		vl = TMPL_add_var(vl, "image_name", get_var(db_row, "name"),
									NULL);
		secs = atol(get_var(db_row, "timestamp"));
		strftime(tbuf, sizeof(tbuf), "%a %b %e %H:%M %Y %z",
							localtime(&secs));
		vl = TMPL_add_var(vl, "timestamp", tbuf, NULL);
		vl = TMPL_add_var(vl, "fields.department", fields.department,
									NULL);
		vl = TMPL_add_var(vl, "fields.employee_number",
						fields.employee_number, NULL);
		vl = TMPL_add_var(vl, "fields.cost_codes", fields.cost_codes,
									NULL);
		vl = TMPL_add_var(vl, "fields.account_codes",
						fields.account_codes, NULL);
		vl = TMPL_add_var(vl, "fields.po_num", fields.po_num, NULL);
		vl = TMPL_add_var(vl, "fields.supplier_name",
						fields.supplier_name, NULL);
		vl = TMPL_add_var(vl, "fields.supplier_town",
						fields.supplier_town, NULL);
		vl = TMPL_add_var(vl, "fields.currency", fields.currency,
									NULL);
		vl = TMPL_add_var(vl, "fields.gross_amount",
						fields.gross_amount, NULL);
		vl = TMPL_add_var(vl, "fields.vat_amount", fields.vat_amount,
									NULL);
		vl = TMPL_add_var(vl, "fields.net_amount", fields.net_amount,
									NULL);
		vl = TMPL_add_var(vl, "fields.vat_rate", fields.vat_rate,
									NULL);
		vl = TMPL_add_var(vl, "fields.vat_number", fields.vat_number,
									NULL);
		vl = TMPL_add_var(vl, "fields.reason", fields.reason, NULL);
		vl = TMPL_add_var(vl, "fields.receipt_date",
						fields.receipt_date, NULL);
		vl = TMPL_add_var(vl, "fields.payment_method",
						fields.payment_method, NULL);
		/* image_id for hidden input field */
		vl = TMPL_add_var(vl, "id", get_var(db_row, "id"), NULL);

		loop = TMPL_add_varlist(loop, vl);
		free_vars(db_row);
	}
	ml = TMPL_add_loop(ml, "table", loop);
	free_fields(&fields);

out:
	send_template("templates/receipts.tmpl", ml);
	TMPL_free_varlist(ml);
	mysql_free_result(res);
	mysql_close(conn);
}

/*
 * /env/
 *
 * Displays the environment list.
 */
static void env(void)
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
void handle_request(void)
{
	struct session current_session;
	int logged_in = 0;
	char *request_uri;
	char *request_method;
	char *http_cookie = "\0";	/* we might not get any cookies */
	char *http_user_agent;
	char *http_x_forwarded_for;
	char *query_string;
	struct timeval stv;
	struct timeval etv;
	GHashTable *qvars = NULL;

	gettimeofday(&stv, NULL);

	/*
	 * The below variables are the least that we require. If we don't
	 * get any of them (except for cookies as the client might not have
	 * one yet), just return out.
	 */
	if (getenv("REQUEST_URI"))
		request_uri = strdupa(getenv("REQUEST_URI"));
	else
		goto out2;
	if (getenv("REQUEST_METHOD"))
		request_method = strdupa(getenv("REQUEST_METHOD"));
	else
		goto out2;
	if (getenv("HTTP_COOKIE"))
		http_cookie = strdupa(getenv("HTTP_COOKIE"));
	if (getenv("HTTP_USER_AGENT"))
		http_user_agent = strdupa(getenv("HTTP_USER_AGENT"));
	else
		goto out2;
	if (getenv("HTTP_X_FORWARDED_FOR"))
		http_x_forwarded_for = strdupa(getenv("HTTP_X_FORWARDED_FOR"));
	else
		goto out2;
	if (getenv("QUERY_STRING"))
		query_string = strdupa(getenv("QUERY_STRING"));
	else
		goto out2;

	d_fprintf(debug_log, "Cookies: %s\n", http_cookie);

	/*
	 * Get the query values from a GET or POST and put them in
	 * a GHashTable.
	 *
	 * However, don't do this for /process_receipt_approval/ due to
	 * that currently needing the data in a different form, a GList
	 * of GHashTables.
	 */
	if (strncmp(request_uri, "/process_receipt_approval/", 26) != 0)
		qvars = set_vars(request_method, query_string);

	/*
	 * Some routes need to come before the login / session stuff as
	 * they can't be logged in and have no session.
	 */
	if (strncmp(request_uri, "/activate_user/", 15) == 0) {
		activate_user(request_method, qvars);
		goto out2;
	}

	if (strncmp(request_uri, "/generate_new_key/", 18) == 0) {
		generate_new_key(qvars);
		goto out2;
	}

	if (strncmp(request_uri, "/forgotten_password/", 20) == 0) {
		forgotten_password(qvars);
		goto out2;
	}

	memset(&current_session, 0, sizeof(current_session));
	if (strncmp(request_uri, "/login/", 7) == 0) {
		login(http_user_agent, http_x_forwarded_for, qvars);
		goto out;
	}

	logged_in = is_logged_in(http_cookie, http_user_agent,
							http_x_forwarded_for,
							request_uri);
	if (!logged_in) {
		printf("Location: /login/\r\n\r\n");
		goto out;
	}
	set_current_session(&current_session, http_cookie, request_uri);

	/* Add new url handlers after here */

	if (strncmp(request_uri, "/receipts/", 10) == 0) {
		receipts(&current_session);
		goto out;
	}

	if (strncmp(request_uri, "/process_receipt/", 17) == 0) {
		process_receipt(&current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/tagged_receipts/", 16) == 0) {
		tagged_receipts(&current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/receipt_info/", 14) == 0) {
		receipt_info(&current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/approve_receipts/", 18) == 0) {
		approve_receipts(&current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/process_receipt_approval/", 26) == 0) {
		process_receipt_approval(&current_session);
		goto out;
	}

	if (strncmp(request_uri, "/reviewed_receipts/", 19) == 0) {
		reviewed_receipts(&current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/extract_data/", 14) == 0) {
		extract_data(&current_session);
		goto out;
	}

	if (strncmp(request_uri, "/do_extract_data/", 17) == 0) {
		do_extract_data(&current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/get_image/", 11) == 0) {
		get_image(&current_session, request_uri);
		goto out;
	}

	if (strncmp(request_uri, "/full_image/", 12) == 0) {
		full_image(&current_session, request_uri);
		goto out;
	}

	if (strncmp(request_uri, "/delete_image/", 14) == 0) {
		delete_image(&current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/env/", 5) == 0) {
		env();
		goto out;
	}

	if (strncmp(request_uri, "/prefs/fmap/", 11) == 0) {
		prefs_fmap(&current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/prefs/edit_user/", 17) == 0) {
		prefs_edit_user(request_method, &current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/prefs/", 7) == 0) {
		prefs(&current_session);
		goto out;
	}

	if (strncmp(request_uri, "/admin/list_users/", 18) == 0) {
		admin_list_users(&current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/admin/add_user/", 16) == 0) {
		admin_add_user(&current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/admin/edit_user/", 17) == 0) {
		admin_edit_user(request_method, &current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/admin/pending_activations/", 27) == 0) {
		admin_pending_activations(&current_session, qvars);
		goto out;
	}

	if (strncmp(request_uri, "/admin/", 7) == 0) {
		admin(&current_session);
		goto out;
	}

	if (strncmp(request_uri, "/logout/", 8) == 0) {
		logout(&current_session);
		goto out;
	}

	/* Default location */
	printf("Location: /login/\r\n\r\n");

out:
	free(current_session.username);
	free(current_session.name);
	free(current_session.origin_ip);
	free(current_session.client_id);
	free(current_session.session_id);
	free(current_session.user_hdr);

out2:
	free_vars(qvars);
	gettimeofday(&etv, NULL);
	d_fprintf(access_log, "Got request from %s for %s (%s), %f secs\n",
				http_x_forwarded_for,
				request_uri,
				request_method,
				((double)etv.tv_sec +
				(double)etv.tv_usec / 1000000.0) -
				((double)stv.tv_sec + (double)stv.tv_usec
				/ 1000000.0));

	return;
}
