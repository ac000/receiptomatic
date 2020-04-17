/*
 * config.h
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2020		Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdbool.h>

struct cfg {
	const char *session_db;

	const char *log_dir;

	const char *image_path;

	const char *mail_cmd;
	const char *mail_from;
	const char *mail_reply_to;
	const char *mail_subject;

	const char *db_user;
	const char *db_pass;
	const char *db_name;
	const char *db_host;
	const char *db_socket_name;
	unsigned int db_port_num;
	unsigned int db_flags;

	int nr_procs;

	bool multi_tenant;

	int debug_level;
};

#define CFG_DEF_LOG_DIR		"/tmp"
#define CFG_DEF_DB_HOST		"localhost"
#define CFG_DEF_DB_PORT_NUM	3306

extern const struct cfg *get_config(const char *filename);

#endif /* _CONFIG_H_ */
