/*
 * common.h
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <sys/time.h>

#include "db.h"

#define BUF_SIZE	4096
#define SQL_MAX		8192

#define REJECTED	0
#define PENDING 	1
#define APPROVED	2

/*
 * Wrapper around fprintf(). It will prepend the text passed it with
 * seconds.microseconds pid function:
 *
 * e.g if you call it like: d_fprintf(debug, "This is a test\n");
 * You will get:
 *
 * 1304600723.663486 1843 main: This is a test
 */
#define d_fprintf(stream, fmt, ...) \
	do { \
		struct timeval tv; \
		gettimeofday(&tv, NULL); \
		fprintf(stream, "%ld.%ld %d %s: " fmt, tv.tv_sec, tv.tv_usec, \
				getpid(), __FUNCTION__, ##__VA_ARGS__); \
		fflush(stream); \
	} while (0)

/*
 * Structure that defines a users session. The session is stored
 * in a tokyocabinet database table inbetween requests.
 */
struct session {
	unsigned int uid;
	unsigned char type;
	char *username;
	char *name;
	char *u_email;
	time_t login_at;
	time_t last_seen;
	char *origin_ip;
	char *client_id;
	char *request_id;
	char *session_id;
	unsigned int restrict_ip;
};

extern FILE *access_log;
extern FILE *sql_log;
extern FILE *error_log;
extern FILE *debug_log;

#endif /* _COMMON_H_ */
