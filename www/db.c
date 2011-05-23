/*
 * db.c
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#include "db.h"
#include "../db/db_config.h"

/*
 * Opens a up a MySQL connection and returns the connection handle.
 */
extern MYSQL *db_conn()
{
	MYSQL *conn;

	conn = mysql_init(NULL);
	mysql_real_connect(conn, opt_hostname, opt_user_name, opt_password,
						opt_db_name, opt_port_num,
						opt_socket_name, opt_flags);

	return conn;
}
