/*
 * db.c
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2016		Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#include "common.h"
#include "receiptomatic_config.h"
#include "url_helpers.h"
#include "utils.h"
#include "db.h"

/* Global MySQL connection handle */
MYSQL *conn;

enum { DB_CONN_GLOBAL, DB_CONN_LOCAL };

char *db_host = "localhost";
char *db_socket_name = NULL;
unsigned int db_port_num = 3306;
unsigned int db_flags = 0;

/*
 * Opens up a MySQL connection and returns the connection handle.
 */
static MYSQL *__db_conn(int db_conn_type)
{
	MYSQL *dbc;
	MYSQL *ret;

	if (MULTI_TENANT) {
		char tenant[TENANT_MAX + 1];
		char db[sizeof(tenant) + 3] = "rm_";

		get_tenant(env_vars.host, tenant);
		strncat(db, tenant, TENANT_MAX);
		free(db_name);
		db_name = strdup(db);
	}

	dbc = mysql_init(NULL);
	ret = mysql_real_connect(dbc, DB_HOST, DB_USER, DB_PASS, DB_NAME,
			DB_PORT_NUM, DB_SOCKET_NAME, DB_FLAGS);

	if (!ret) {
		d_fprintf(error_log, "Failed to connect to database. Error: "
				"%s\n", mysql_error(dbc));
		switch (mysql_errno(dbc)) {
		case ER_BAD_DB_ERROR:	/* unknown database */
			send_page("templates/invalid.tmpl");
			break;
		}
		dbc = NULL;
	}

	if (db_conn_type == DB_CONN_GLOBAL)
		conn = dbc;

	return dbc;
}

/*
 * Wrapper around __db_conn() to open a new global db connection.
 */
MYSQL *db_conn(void)
{
	return __db_conn(DB_CONN_GLOBAL);
}

/*
 * Wrapper around __db_conn() to open a new local db connection.
 */
MYSQL *db_conn_local(void)
{
	return __db_conn(DB_CONN_LOCAL);
}

/*
 * This takes a sql query and returns the result set.
 * It also takes __func__ to get the name of the calling function. It also
 * logs the query into the sql log.
 *
 * This function should not be called directly and should instead be used via
 * the sql_query() macro.
 *
 * This function will either return a result set or NULL. Note that some
 * queries don't return result sets by design.
 */
MYSQL_RES *__sql_query(MYSQL *dbconn, const char *func, const char *fmt, ...)
{
	va_list args;
	char sql[SQL_MAX];
	int len;
	MYSQL *dbc = conn;

	va_start(args, fmt);
	len = vsnprintf(sql, sizeof(sql), fmt, args);
	va_end(args);

	if (DEBUG_LEVEL) {
		char tenant[TENANT_MAX + 1];
		char ts_buf[32];
		time_t secs = time(NULL);
		struct tm *tm = localtime(&secs);

		get_tenant(env_vars.host, tenant);
		strftime(ts_buf, sizeof(ts_buf), "%F %T %z", tm);
		fprintf(sql_log, "[%s] %d %s %s: %s\n", ts_buf,  getpid(),
				tenant, func, sql);
		fflush(sql_log);
	}

	if (dbconn)
		dbc = dbconn;

	mysql_real_query(dbc, sql, len);
	return mysql_store_result(dbc);
}
