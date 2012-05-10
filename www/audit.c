/*
 * audit.c - Auditing subsystem
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
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include <glib.h>

#include "common.h"
#include "utils.h"

/*
 * Add a login entry to the utmp table.
 *
 * We log the time (seconds.microseconds), uid, username, ip address,
 * hostname and the session id that was assigned to this session.
 */
unsigned long long log_login(void)
{
	char sql[SQL_MAX];
	char *username;
	char *hostname;
	char *ip_addr;
	char host[NI_MAXHOST] = "\0";
	struct timespec login_at;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct sockaddr *addr = (struct sockaddr *)&addr4;
	unsigned long long sid;
	unsigned int uid;
	socklen_t addr_len = sizeof(addr4);
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;

	clock_gettime(CLOCK_REALTIME, &login_at);

	if (!strchr(env_vars.http_x_forwarded_for, ':')) {
		/* IPv4 */
		inet_pton(AF_INET, env_vars.http_x_forwarded_for,
							&addr4.sin_addr);
		addr4.sin_family = AF_INET;
	} else {
		/* IPv6 */
		inet_pton(AF_INET6, env_vars.http_x_forwarded_for,
							&addr6.sin6_addr);
		addr6.sin6_family = AF_INET6;

		addr = (struct sockaddr *)&addr6;
		addr_len = sizeof(addr6);
	}
	getnameinfo(addr, addr_len, host, NI_MAXHOST, NULL, 0, 0);

	conn = db_conn();

	username = alloca(strlen(get_var(qvars, "username")) * 2 + 1);
	mysql_real_escape_string(conn, username, get_var(qvars, "username"),
						strlen(get_var(qvars,
						"username")));
	hostname = alloca(strlen(host) * 2 + 1);
	mysql_real_escape_string(conn, hostname, host, strlen(host));

	ip_addr = alloca(strlen(env_vars.http_x_forwarded_for) * 2 + 1);
	mysql_real_escape_string(conn, ip_addr, env_vars.http_x_forwarded_for,
					strlen(env_vars.http_x_forwarded_for));

	snprintf(sql, SQL_MAX, "SELECT uid FROM passwd WHERE username = '%s'",
								username);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);
	uid = atoi(row[0]);
	mysql_free_result(res);

	/* We need to be sure a new sid isn't inserted here */
	mysql_query(conn, "LOCK TABLES utmp WRITE");
	mysql_query(conn, "SELECT IFNULL(MAX(sid), 0) FROM utmp");
	res = mysql_store_result(conn);
	row = mysql_fetch_row(res);

	sid = strtoull(row[0], NULL, 10) + 1;

	/* Divide tv_nsec by 1000 to get a rough microseconds value */
	snprintf(sql, SQL_MAX, "INSERT INTO utmp VALUES (%ld.%ld, %u, '%s', "
					"'%s', '%s', %llu)",
					login_at.tv_sec,
					login_at.tv_nsec / NS_USEC,
					uid, username, ip_addr, hostname, sid);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_real_query(conn, sql, strlen(sql));

	mysql_query(conn, "UNLOCK TABLES");

	mysql_free_result(res);
	mysql_close(conn);

	return sid;
}

/*
 * Retrieves the last login time and the host the login came from
 * for a given user.
 *
 * If the user has never logged in before, 0 is returned.
 */
time_t get_last_login(char *from_host)
{
	char sql[SQL_MAX];
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;
	time_t login;

	conn = db_conn();

	/*
	 * We need to; ORDER BY login_at DESC LIMIT 1, 1
	 * due to the login being logged before we get the last login.
	 * This ensures we actually get the last login and not the
	 * current login.
	 *
	 * If the user has never logged in before, we will get an empty row.
	 */
	snprintf(sql, SQL_MAX, "SELECT login_at, hostname FROM utmp WHERE "
					"uid = %u ORDER BY login_at DESC "
					"LIMIT 1, 1", user_session.uid);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_query(conn, sql);
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) > 0) {
		row = mysql_fetch_row(res);
		login = atol(row[0]);
		snprintf(from_host, NI_MAXHOST, "%s", row[1]);
	} else {
		login = 0;
	}

	mysql_free_result(res);
	mysql_close(conn);

	return login;
}
