/*
 * audit.c - Auditing subsystem
 *
 * Copyright (C) 2011-2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 * 		 2016		Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <ctemplate.h>

#include <glib.h>

#include "common.h"
#include "utils.h"

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
 * Add a login entry to the utmp table.
 *
 * We log the time (seconds.microseconds), uid, username, ip address,
 * hostname and the session id that was assigned to this session.
 */
unsigned long long log_login(void)
{
	char *username;
	char *hostname;
	char *ip_addr;
	char host[NI_MAXHOST] = "\0";
	struct addrinfo hints;
	struct addrinfo *ares;
	struct timespec login_at;
	unsigned long long sid;
	unsigned int uid;
	MYSQL_RES *res;
	MYSQL_ROW row;

	clock_gettime(CLOCK_REALTIME, &login_at);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	getaddrinfo(env_vars.remote_addr, NULL, &hints, &ares);
	getnameinfo(ares->ai_addr, ares->ai_addrlen, host, NI_MAXHOST, NULL, 0,
			0);

	username = make_mysql_safe_string(get_var(qvars, "username"));
	hostname = make_mysql_safe_string(host);
	ip_addr = make_mysql_safe_string(env_vars.remote_addr);
	res = sql_query("SELECT uid FROM passwd WHERE username = '%s'",
			username);
	row = mysql_fetch_row(res);
	uid = atoi(row[0]);
	mysql_free_result(res);

	/* We need to be sure a new sid isn't inserted here */
	sql_query("LOCK TABLES utmp WRITE");
	res = sql_query("SELECT IFNULL(MAX(sid), 0) FROM utmp");
	row = mysql_fetch_row(res);

	sid = strtoull(row[0], NULL, 10) + 1;

	/* Divide tv_nsec by 1000 to get a rough microseconds value */
	sql_query("INSERT INTO utmp VALUES (%ld.%06ld, %u, '%s', '%s', %d, "
			"'%s', %llu)",
			login_at.tv_sec, login_at.tv_nsec / NS_USEC,
			uid, username, ip_addr, env_vars.remote_port,
			hostname, sid);
	sql_query("UNLOCK TABLES");

	mysql_free_result(res);
	free(username);
	free(hostname);
	free(ip_addr);
	freeaddrinfo(ares);

	return sid;
}

/*
 * Retrieves the last login time and the host the login came from
 * for a given user.
 *
 * If the user has never logged in before, 0 is returned.
 */
static time_t get_last_login(char *from_host)
{
	MYSQL_RES *res;
	MYSQL_ROW row;
	time_t login;

	/*
	 * We need to; ORDER BY login_at DESC LIMIT 1, 1
	 * due to the login being logged before we get the last login.
	 * This ensures we actually get the last login and not the
	 * current login.
	 *
	 * If the user has never logged in before, we will get an empty row.
	 */
	res = sql_query("SELECT login_at, hostname FROM utmp WHERE uid = %u "
			"ORDER BY login_at DESC LIMIT 1, 1", user_session.uid);
	if (mysql_num_rows(res) > 0) {
		row = mysql_fetch_row(res);
		login = atol(row[0]);
		snprintf(from_host, NI_MAXHOST, "%s", row[1]);
	} else {
		login = 0;
	}
	mysql_free_result(res);

	return login;
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

	fcgx_p("Set-Cookie: session_id=%s; path=/; httponly\r\n", session_id);

	mysql_free_result(res);
	free_vars(db_row);
	free(username);
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
