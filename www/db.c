/*
 * db.c
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

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

	conn = mysql_init(NULL);
	mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME,
					DB_PORT_NUM, DB_SOCKET_NAME,
					DB_FLAGS);

	return conn;
}
