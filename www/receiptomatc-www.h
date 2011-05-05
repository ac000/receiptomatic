/*
 * receiptomatic-www.h
 *
 * Copyright (C) 2011 OpenTech Labs, Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#ifndef _RECEIPTOMATIC_WWW_H_
#define _RECEIPTOMATIC_WWW_H_

/*
 * Structure that defines a users session. The session is stored
 * in a SQLite databsse inbetween requests.
 */
struct session {
	unsigned int uid;
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

static MYSQL *db_conn();
static void update_fmap(struct session *current_session, char *query);
static void set_custom_field_names(struct session *current_session,
						struct field_names *fields);
static GHashTable *get_dbrow(MYSQL_RES *res);
static GHashTable *get_vars(char *query);
static char *get_var(GHashTable *vars, char *key);
static void free_vars(GHashTable *vars);
static void set_current_session(struct session *current_session, char *cookies,
							char *request_uri);
static char *create_session_id();
static void create_session(GHashTable *credentials, char *http_user_agent,
						char *http_x_forwarded_for);
static int is_logged_in(char *cookies, char *client_id, char *remote_ip,
							char *request_uri);
static int check_auth(GHashTable *credentials);
static void tag_image(struct session *current_session, char *query);
static int tag_info_allowed(struct session *current_session, char *image_id);
static int image_access_allowed(struct session *current_session, char *path);
static void login(char *http_user_agent, char *http_x_forwarded_for);
static void logout(struct session *current_session);
static void get_image(struct session *current_session, char *image);
static void full_image(struct session *current_session, char *image);
static void prefs_fmap(struct session *current_session);
static void receipt_info(struct session *current_session, char *query);
static void tagged_receipts(struct session *current_session, char *query);
static void receipts(struct session *current_session);
static void env();
static void handle_request();
static void accept_request();
static void create_server(int nr);
static int __dump_session_state(void *arg, int argc, char **argv,
								char **column);
static void dump_session_state();
static void clear_old_sessions();
static void init_clear_session_timer();
static void initialise_session_db();

#endif /* _RECEIPTOMATIC_WWW_H_ */
