/*
 * receiptomatic_config.h
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#ifndef _RECEIPTOMATIC_CONFIG_H_
#define _RECEIPTOMATIC_CONFIG_H_

char *rec_image_path;
char *rec_base_url;
char *rec_session_db;

char *db_user;
char *db_password;
char *db_name;
/* These have default values set in db.c */
extern char *db_host;
extern char *db_socket_name;
extern unsigned int db_port_num;
extern unsigned int db_flags;

#define IMAGE_PATH	rec_image_path
#define BASE_URL	rec_base_url
#define SESSION_DB	rec_session_db

#define DB_USER		db_user
#define DB_PASS		db_password
#define DB_NAME		db_name
#define DB_HOST		db_host
#define DB_SOCKET_NAME	db_socket_name
#define DB_PORT_NUM	db_port_num
#define DB_FLAGS	db_flags

#endif /* _RECEIPTOMATIC_CONFIG_H_ */
