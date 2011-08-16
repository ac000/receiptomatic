/*
 * audit.c - Auditing subsystem
 *
 * Copyright (C) 2011		OpenTech Labs
 * 				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#define _XOPEN_SOURCE

/* FastCGI stdio wrappers */
#include <fcgi_stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
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
unsigned int log_login(GHashTable *credentials, char *ip_addr)
{
	char sql[SQL_MAX];
	char *username;
	char *hostname;
	char host[NI_MAXHOST] = "\0";
	struct timeval login_at;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct sockaddr *addr = (struct sockaddr *)&addr4;
	unsigned int sid;
	unsigned int uid;
	socklen_t addr_len = sizeof(addr4);
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;

	gettimeofday(&login_at, NULL);

	if (!strchr(ip_addr, ':')) {
		/* IPv4 */
		inet_pton(AF_INET, ip_addr, &addr4.sin_addr);
		addr4.sin_family = AF_INET;
	} else {
		/* IPv6 */
		inet_pton(AF_INET6, ip_addr, &addr6.sin6_addr);
		addr6.sin6_family = AF_INET6;

		addr = (struct sockaddr *)&addr6;
		addr_len = sizeof(addr6);
	}
	getnameinfo(addr, addr_len, host, sizeof(host), NULL, 0, 0);
	
	conn = db_conn();

	username = alloca(strlen(get_var(credentials, "username")) * 2 + 1);
	mysql_real_escape_string(conn, username, get_var(credentials,
						"username"), strlen(get_var(
						credentials, "username")));
	hostname = alloca(strlen(host) * 2 + 1);
	mysql_real_escape_string(conn, hostname, host, strlen(host));

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

	sid = atoi(row[0]) + 1;

	snprintf(sql, SQL_MAX, "INSERT INTO utmp VALUES (%ld.%ld, %u, '%s', "
					"'%s', '%s', %u)",
					login_at.tv_sec, login_at.tv_usec,
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
time_t get_last_login(unsigned int uid, char *from_host)
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
					"LIMIT 1, 1", uid);
	d_fprintf(sql_log, "%s\n", sql);
	mysql_query(conn, sql);
	res = mysql_store_result(conn);
	if (mysql_num_rows(res) > 0) {
		row = mysql_fetch_row(res);
		login = atol(row[0]);
		strncpy(from_host, row[1], NI_MAXHOST);
	} else {
		login = 0;
	}

	mysql_free_result(res);
	mysql_close(conn);

	return login;
}