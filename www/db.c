/*
 * db.c
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#include <stdlib.h>

#include "common.h"
#include "receiptomatic_config.h"
#include "db.h"

char *db_host = "localhost";
char *db_socket_name = NULL;
unsigned int db_port_num = 3306;
unsigned int db_flags = 0;

/*
 * Opens a up a MySQL connection and returns the connection handle.
 */
MYSQL *db_conn(void)
{
	MYSQL *conn;
	MYSQL *ret;

	conn = mysql_init(NULL);
	ret = mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME,
					DB_PORT_NUM, DB_SOCKET_NAME,
					DB_FLAGS);
#ifdef _RECEIPTOMATIC_WWW_
	if (!ret)
		d_fprintf(error_log, "Failed to connect to database. Error: "
						"%s\n", mysql_error(conn));
#endif
	return conn;
}
