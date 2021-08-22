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

/*
 * Opens up a MySQL connection and returns the connection handle.
 */
MYSQL *db_conn(void)
{
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

	conn = mysql_init(NULL);
	ret = mysql_real_connect(conn, cfg->db_host, cfg->db_user, cfg->db_pass,
				 db_name, cfg->db_port_num,
				 cfg->db_socket_name, cfg->db_flags);
	if (!ret) {
		d_fprintf(error_log,
			  "Failed to connect to database. Error: %s\n",
			  mysql_error(conn));
		switch (mysql_errno(conn)) {
		case ER_BAD_DB_ERROR:	/* unknown database */
			send_page("templates/invalid.tmpl");
			break;
		}
		mysql_close(conn);
		conn = NULL;
	}
	free(db_name);

	return conn;
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
MYSQL_RES *__sql_query(const char *func, const char *fmt, ...)
{
	va_list args;
	char sql[SQL_MAX];
	int len;

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

	mysql_real_query(conn, sql, len);

	return mysql_store_result(conn);
}
