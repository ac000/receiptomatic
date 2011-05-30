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

#define IMAGE_PATH	"/data/www/opentechlabs.net/receiptomatic/receipt_images"
#define BASE_URL	"http://ri.opentechlabs.net"
#define SESSION_DB	"/dev/shm/receiptomatic-www-sessions.tct"

#define GRID_SIZE	9
#define ROW_SIZE	3
#define COL_SIZE	3

#define APPROVER_ROWS	3	/* No. of rows / page on /approve_receipts/ */

#define APPROVER		(1 << 0)	/*  1 */
#define APPROVER_SELF		(1 << 1)	/*  2 */
#define APPROVER_CASH		(1 << 2)	/*  4 */
#define APPROVER_CARD		(1 << 3)	/*  8 */
#define APPROVER_CHEQUE 	(1 << 4)	/* 16 */

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
	unsigned char capabilities;
	char *username;
	char *name;
	time_t login_at;
	time_t last_seen;
	char *origin_ip;
	char *client_id;
	char *session_id;
	unsigned int restrict_ip;
};

struct field_names {
	char *receipt_date;
	char *department;
	char *employee_number;
	char *reason;
	char *po_num;
	char *cost_codes;
	char *account_codes;
	char *supplier_name;
	char *supplier_town;
	char *vat_number;
	char *gross_amount;
	char *net_amount;
	char *vat_amount;
	char *vat_rate;
	char *currency;
	char *payment_method;
};

extern FILE *access_log;
extern FILE *sql_log;
extern FILE *error_log;
extern FILE *debug_log;

#endif /* _COMMON_H_ */
