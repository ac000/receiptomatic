/*
 * db.h
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
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
 * Just undef printf for the my_global stuff and then define it back again.
 */
#undef printf
#include <my_global.h>
#define printf FCGI_printf

#include <mysql.h>

MYSQL *db_conn(void);

#endif /* _DB_H_ */
