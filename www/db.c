/*
 * db.c
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2016, 2020	Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#include "common.h"
#include "url_helpers.h"
#include "utils.h"
#include "db.h"

/* Global MySQL connection handle */
MYSQL *conn;

enum { DB_CONN_GLOBAL, DB_CONN_LOCAL };

/*
 * Opens up a MySQL connection and returns the connection handle.
 */
static MYSQL *__db_conn(int db_conn_type)
{
	MYSQL *dbc;
	MYSQL *ret;
	char *db_name;

	if (cfg->multi_tenant) {
		char tenant[TENANT_MAX + 1];
		int len;

		get_tenant(env_vars.host, tenant);
		len = asprintf(&db_name, "rm_%s", tenant);
		if (len == -1)
			return NULL;
	} else {
		db_name = strdup(cfg->db_name);
	}

	dbc = mysql_init(NULL);
	ret = mysql_real_connect(dbc, cfg->db_host, cfg->db_user, cfg->db_pass,
				 db_name, cfg->db_port_num,
				 cfg->db_socket_name, cfg->db_flags);
	if (!ret) {
		d_fprintf(error_log,
			  "Failed to connect to database. Error: %s\n",
			  mysql_error(dbc));
		switch (mysql_errno(dbc)) {
		case ER_BAD_DB_ERROR:	/* unknown database */
			send_page("templates/invalid.tmpl");
			break;
		}
		dbc = NULL;
	}
	free(db_name);

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

	if (cfg->debug_level > 0) {
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
