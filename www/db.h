/*
 * db.h
 *
 * Copyright (C) 2011-2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _DB_H_
#define _DB_H_

/* For Tokyocabinet (user sessions) */
#include <tcutil.h>
#include <tctdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <libgen.h>

/* MySQL */
#include <mysql.h>
#include <mysqld_error.h>

/*
 * Wrapper around mysql_real_query(), it uses __sql_query() to do the
 * actual work. It takes a query string and passes that to __sql_query()
 * along with the function name of the caller for the sql log.
 */
#define sql_query(fmt, ...) \
	__sql_query((const char *)__func__, fmt, ##__VA_ARGS__)

extern MYSQL *conn;

MYSQL *db_conn(void);
MYSQL_RES *__sql_query(const char *func, const char *fmt, ...);

#endif /* _DB_H_ */
