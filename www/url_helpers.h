/*
 * url_helpers.h
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _URL_HELPERS_H_
#define _URL_HELPERS_H_

char *username_to_name(const char *username);
bool is_logged_in(void);
int check_auth(void);
bool is_users_receipt(const char *id);
bool tag_info_allowed(const char *image_id);
bool image_access_allowed(const char *path);
void set_user_session(void);
void add_csrf_token(TMPL_varlist *varlist);
bool valid_csrf_token(void);
void display_last_login(TMPL_varlist *varlist);
void create_session(unsigned long long sid);
int check_amounts(double gross, double net, double vat, double vr);
void set_default_field_names(void);
void set_custom_field_names(void);
void process_activation_changes(void);
void update_fmap(void);
void tag_image(void);
int do_add_user(unsigned char capabilities);
void do_update_user(void);
void do_edit_user(void);
void do_activate_user(const char *uid, const char *key, const char *password);
void gather_receipt_stats_for_user(long long uid, TMPL_varlist *varlist);
void send_template(const char *template, TMPL_varlist *varlist,
		   TMPL_fmtlist *fmtlist);
bool match_uri(const char *request_uri, const char *match);

#endif /* _URL_HELPERS_H_ */
