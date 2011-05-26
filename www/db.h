/*
 * db.h
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#ifndef _DB_H_
#define _DB_H_

/* MySQL */
#include <my_global.h>
#include <mysql.h>

MYSQL *db_conn(void);

#endif /* _DB_H_ */
