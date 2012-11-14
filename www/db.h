/*
 * db.h
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
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

/*
 * The FCGI printf function seemed to be causing a conflict here, under F16
 * with GCC 4.6.2
 *
 * Just undef printf for the my_global stuff and then define it back again,
 * but only when building receiptomatic-www. For the receiver part
 * 'receiptomatic' we need to keep printf as printf.
 */
#ifdef _RECEIPTOMATIC_WWW_
#undef printf
#include <my_global.h>
#define printf FCGI_printf
#else
#include <my_global.h>
#endif

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
MYSQL_RES *__sql_query(const char *func, char *fmt, ...);

#endif /* _DB_H_ */
