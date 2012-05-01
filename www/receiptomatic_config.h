/*
 * receiptomatic_config.h
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _RECEIPTOMATIC_CONFIG_H_
#define _RECEIPTOMATIC_CONFIG_H_

char *rec_image_path;
char *rec_base_url;
char *rec_session_db;

/* Default log path set in www/receiptomatic-www.c */
extern char *log_dir;

char *mail_cmd;
char *mail_from;
char *mail_reply_to;
char *mail_subject;

char *db_user;
char *db_password;
char *db_name;
/* These have default values set in db.c */
extern char *db_host;
extern char *db_socket_name;
extern unsigned int db_port_num;
extern unsigned int db_flags;

int nr_procs;

#define IMAGE_PATH	rec_image_path
#define BASE_URL	rec_base_url
#define SESSION_DB	rec_session_db

#define LOG_DIR		log_dir
#define ACCESS_LOG	access_log_path
#define ERROR_LOG	error_log_path
#define SQL_LOG		sql_log_path
#define DEBUG_LOG	debug_log_path

#define MAIL_CMD	mail_cmd
#define MAIL_FROM	mail_from
#define MAIL_REPLY_TO	mail_reply_to
#define MAIL_SUBJECT	mail_subject

#define DB_USER		db_user
#define DB_PASS		db_password
#define DB_NAME		db_name
#define DB_HOST		db_host
#define DB_SOCKET_NAME	db_socket_name
#define DB_PORT_NUM	db_port_num
#define DB_FLAGS	db_flags

#define NR_PROCS	nr_procs

#endif /* _RECEIPTOMATIC_CONFIG_H_ */
