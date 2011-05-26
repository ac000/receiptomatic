/*
 * receiptomatic-www.h
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#ifndef _RECEIPTOMATIC_WWW_H_
#define _RECEIPTOMATIC_WWW_H_

#define NR_PROCS	5	/* Number of processes to fork at startup */

#define IMAGE_PATH	"/data/www/opentechlabs.net/receiptomatic/receipt_images"
#define BASE_URL	"http://ri.opentechlabs.net"

#define SESSION_DB	"/dev/shm/receiptomatic-www-sessions.tct"
#define SESSION_CHECK	60 * 60		/* Check for old sessions every hour */
#define SESSION_EXPIRY	60 * 60 * 4	/* 4 hours */

#define GRID_SIZE	9
#define ROW_SIZE	3
#define COL_SIZE	3

#define APPROVER_ROWS	3	/* No. of rows / page on /approve_receipts/ */

#define USER		0

#define APPROVER		(1 << 0)	/*  1 */
#define APPROVER_SELF		(1 << 1)	/*  2 */
#define APPROVER_CASH		(1 << 2)	/*  4 */
#define APPROVER_CARD		(1 << 3)	/*  8 */
#define APPROVER_CHEQUE 	(1 << 4)	/* 16 */

#define MAX_RECEIPT_AGE	60 * 60 * 24 * 180	/* 180 days */

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

static int check_amounts(double gross, double net, double vat, double vr);
static void update_fmap(struct session *current_session, char *query);
static void set_custom_field_names(struct session *current_session,
						struct field_names *fields);
static char *username_to_name(char *username);
static void set_current_session(struct session *current_session, char *cookies,
							char *request_uri);
static char *create_session_id(void);
static void create_session(GHashTable *credentials, char *http_user_agent,
						char *http_x_forwarded_for);
static int is_logged_in(char *cookies, char *client_id, char *remote_ip,
							char *request_uri);
static int check_auth(GHashTable *credentials);
static void tag_image(struct session *current_session, GHashTable *qvars);
static int is_users_receipt(struct session *current_session, char *id);
static int tag_info_allowed(struct session *current_session, char *image_id);
static int image_access_allowed(struct session *current_session, char *path);
static void login(char *http_user_agent, char *http_x_forwarded_for);
static void logout(struct session *current_session);
static void delete_image(struct session *current_session);
static void get_image(struct session *current_session, char *image);
static void full_image(struct session *current_session, char *image);
static void prefs_fmap(struct session *current_session);
static void do_extract_data(struct session *current_session, char *query);
static void extract_data(struct session *current_session);
static void process_receipt_approval(struct session *current_session);
static void approve_receipts(struct session *current_session, char *query);
static void reviewed_receipts(struct session *current_session, char *query);
static void receipt_info(struct session *current_session, char *query);
static void tagged_receipts(struct session *current_session, char *query);
static void receipts(struct session *current_session);
static void env(void);
static void handle_request(void);
static void accept_request(void);
static void set_proc_title(char *title);
static void create_server(int nr);
static void dump_session_state(void);
static void clear_old_sessions(void);
static void init_clear_session_timer(void);

#endif /* _RECEIPTOMATIC_WWW_H_ */
