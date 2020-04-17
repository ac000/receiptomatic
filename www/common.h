/*
 * common.h
 *
 * Copyright (C) 2011-2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2016, 2020	Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

/* FastCGI Application Interface */
#include <fcgiapp.h>

/* HTML template library */
#include <flate.h>

#include <glib.h>

#include "short_types.h"
#include "config.h"
#include "db.h"
#include "utils.h"

#define __unused		__attribute__((unused))
#define __maybe_unused		__attribute__((unused))

#define GRID_SIZE	9
#define ROW_SIZE	3
#define COL_SIZE	3

#define APPROVER_ROWS	3	/* No. of rows / page on /approve_receipts/ */

#define APPROVER		(1 << 0)	/*   1 */
#define APPROVER_SELF		(1 << 1)	/*   2 */
#define APPROVER_CASH		(1 << 2)	/*   4 */
#define APPROVER_CARD		(1 << 3)	/*   8 */
#define APPROVER_CHEQUE		(1 << 4)	/*  16 */
#define ADMIN			(1 << 7)	/* 128 */

#define BUF_SIZE	4096
#define SQL_MAX		8192
#define ENTROPY_SIZE	   8

#define TENANT_MAX	64
#define SID_LEN		64
#define CSRF_LEN	64
#define IP_MAX		39
#define SHA1_LEN	40
#define SHA256_LEN	64

enum { REJECTED = 0, PENDING, APPROVED };
enum { SHA1, SHA256, SHA512 };
enum { STATS_ALL, STATS_USER };

/*
 * These three define the number of nanoseconds in a second,
 * millisecond and microsecond.
 */
#define NS_SEC		1000000000
#define NS_MSEC		1000000
#define NS_USEC		1000

/* Length of time (seconds) an activation key is valid */
#define KEY_EXP		86400

/* Macro to check if the user is an approver */
#define IS_APPROVER()	(((user_session.capabilities) & (APPROVER)) ? 1 : 0)
/* Macro to check if the user is an admin */
#define IS_ADMIN()	(((user_session.capabilities) & (ADMIN)) ? 1 : 0)
/* Macro to check if a char *variable is set, i.e a len > 0 */
#define IS_SET(var)	((strlen(var) > 0) ? 1 : 0)
/* Macro to check if the request method is POST */
#define IS_POST()	(strstr(env_vars.request_method, "POST"))
/* Macro to check if the request method is GET */
#define IS_GET()	(strstr(env_vars.request_method, "GET"))

/* Macro to add the Approver/Admin/user_hdr parts to the web page */
#define ADD_HDR(f) \
	do { \
		if (IS_ADMIN()) \
			lf_set_var(f, "admin", "", NULL); \
		if (IS_APPROVER()) \
			lf_set_var(f, "approver", "", NULL); \
		lf_set_var(f, "user_hdr", user_session.user_hdr, NULL); \
	} while (0)

/* Unbreak __func__ by my_global.h */
#ifdef __func__
	#undef __func__
#endif

/*
 * Wrapper around fprintf(). It will prepend the text passed it with
 * [datestamp] pid function:
 *
 * e.g if you call it like: d_fprintf(debug, "This is a test\n");
 * You will get:
 *
 * [2016-01-16 17:31:40 +0000] 1843 main: This is a test
 */
#define d_fprintf(stream, fmt, ...) \
	do { \
		if (stream == debug_log && cfg->debug_level == 0) \
			break; \
		time_t secs = time(NULL); \
		struct tm *tm = localtime(&secs); \
		char ts_buf[32]; \
		char tenant[TENANT_MAX + 1]; \
		get_tenant(env_vars.host, tenant); \
		strftime(ts_buf, sizeof(ts_buf), "%F %T %z", tm); \
		fprintf(stream, "[%s] %d %s %s: " fmt, ts_buf, getpid(), \
			tenant, __func__, ##__VA_ARGS__); \
		fflush(stream); \
	} while (0)

/* Remap some FCGX_ functions for usability/readability */
#define fcgx_p(fmt, ...)	FCGX_FPrintF(fcgx_out, fmt, ##__VA_ARGS__)
#define fcgx_ps(buf, size)	FCGX_PutStr(buf, size, fcgx_out)
#define fcgx_param(name)	FCGX_GetParam(name, fcgx_envp)
#define fcgx_putc(c)		FCGX_PutChar(c, fcgx_out)
#define fcgx_puts(s)		FCGX_PutS(s, fcgx_out)
#define fcgx_gs(buf, size)	FCGX_GetStr(buf, size, fcgx_in)

/* Nicer names for the libflate stuff */
#define lf_set_tmpl		flateSetFile
#define lf_set_var		flateSetVar
#define lf_set_row		flateDumpTableLine
#define lf_send			flatePrint
#define lf_free			flateFreeMem

/*
 * Wrapper around mysql_real_escape_string()
 *
 * Given a string it will return a string, that must be free'd, that is safe
 * to pass to mysql.
 */
static inline char *__make_mysql_safe_string(MYSQL *dbconn, const char *string)
{
	char *safe = malloc(strlen(string)*2 + 1);

	mysql_real_escape_string(dbconn, safe, string, strlen(string));
	return safe;
}

/*
 * Warppaer around __make_mysql_safe_string() using the global db connection.
 */
static inline char *make_mysql_safe_string(const char *string)
{
	return __make_mysql_safe_string(conn, string);
}

/*
 * Warppaer around __make_mysql_safe_string() using the local db connection.
 */
static inline char *make_mysql_safe_stringl(MYSQL *dbconn, const char *string)
{
	return __make_mysql_safe_string(dbconn, string);
}

/*
 * Structure that defines a users session. The session is stored
 * in a tokyocabinet database table inbetween requests.
 */
struct user_session {
	char tenant[TENANT_MAX + 1];
	unsigned long long sid;
	unsigned int uid;
	u8 capabilities;
	char *username;
	char *name;
	time_t login_at;
	time_t last_seen;
	char origin_ip[IP_MAX + 1];
	char *client_id;
	char session_id[SID_LEN + 1];
	char csrf_token[CSRF_LEN + 1];
	bool restrict_ip;
	char *user_hdr;
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

/*
 * This structure maps to the environment variable list sent
 * by the application. We don't store every item.
 */
struct env_vars {
	char *request_uri;
	char *request_method;
	char *content_type;
	off_t content_length;
	char *http_cookie;
	char *http_user_agent;
	char *remote_addr;
	int remote_port;
	char *host;
	char *query_string;
};

extern const struct cfg *cfg;

extern struct user_session user_session;
extern struct env_vars env_vars;
extern struct field_names fields;

extern FCGX_Stream *fcgx_in;
extern FCGX_Stream *fcgx_out;
extern FCGX_Stream *fcgx_err;
extern FCGX_ParamArray fcgx_envp;

/* Default Field Names */
#define DFN_RECEIPT_DATE	"Receipt Date"
#define DFN_DEPARTMENT		"Department"
#define DFN_EMPLOYEE_NUMBER	"Employee Number"
#define DFN_REASON		"Reason"
#define DFN_PO_NUM		"PO Num"
#define DFN_COST_CODES		"Cost Code(s)"
#define DFN_ACCOUNT_CODES	"Account Code(s)"
#define DFN_SUPPLIER_NAME	"Supplier Name"
#define DFN_SUPPLIER_TOWN	"Supplier Town"
#define DFN_VAT_NUMBER		"VAT Number"
#define DFN_GROSS_AMOUNT	"Gross Amount"
#define DFN_NET_AMOUNT		"Net Amount"
#define DFN_VAT_AMOUNT		"VAT Amount"
#define DFN_VAT_RATE		"VAT Rate"
#define DFN_CURRENCY		"Currency"
#define DFN_PAYMENT_METHOD	"Payment Method"

extern FILE *access_log;
extern FILE *sql_log;
extern FILE *error_log;
extern FILE *debug_log;

extern GList *u_files;
extern GList *avars;
extern GHashTable *qvars;

#endif /* _COMMON_H_ */
