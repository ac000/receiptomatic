/*
 * get_config.c
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "receiptomatic_config.h"
#include "common.h"

int get_config(char *filename)
{
	FILE *fp;
	char buf[BUF_SIZE];
	char *option;
	char *value;
	char *token;
	int ret = 1;

	fp = fopen(filename, "r");
	if (!fp) {
		ret = 0;
		goto out;
	}

	while (fgets(buf, BUF_SIZE, fp)) {
		token = strtok(buf, "=");
		option = token;
		token = strtok(NULL, "=");
		value = token;
		/* Loose the trailing \n */
		value[strlen(value) - 1] = '\0';

		if (strcmp(option, "IMAGE_PATH") == 0)
			rec_image_path = strdup(value);
		else if (strcmp(option, "BASE_URL") == 0)
			rec_base_url = strdup(value);
		else if (strcmp(option, "SESSION_DB") == 0)
			rec_session_db = strdup(value);
		else if (strcmp(option, "DB_USER") == 0)
			db_user = strdup(value);
		else if (strcmp(option, "DB_PASS") == 0)
			db_password = strdup(value);
		else if (strcmp(option, "DB_NAME") == 0)
			db_name = strdup(value);
		else if (strcmp(option, "DB_HOST") == 0)
			db_host = strdup(value);
		else if (strcmp(option, "DB_SOCKET_NAME") == 0)
			db_socket_name = strdup(value);
		else if (strcmp(option, "DB_PORT_NUM") == 0)
			db_port_num = atoi(value);
		else if (strcmp(option, "DB_FLAGS") == 0)
			db_flags = atoi(value);
	}

	fclose(fp);

out:
	return ret;
}
