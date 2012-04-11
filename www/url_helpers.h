/*
 * url_helpers.h
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _URLHELPERS_H_
#define _URLHELPERS_H_

char *username_to_name(char *username);
bool is_logged_in(void);
int check_auth(void);
int is_users_receipt(const char *id);
int tag_info_allowed(const char *image_id);
int image_access_allowed(const char *path);
void set_user_session(void);
char *create_session_id(void);
char *generate_csrf_token(void);
void create_session(unsigned int sid);
int check_amounts(double gross, double net, double vat, double vr);
void set_default_field_names(struct field_names *fields);
void set_custom_field_names(struct field_names *fields);
void update_fmap(void);
void tag_image(void);
int do_add_user(unsigned char capabilities);
void do_update_user(void);
void do_edit_user(void);
void do_activate_user(const char *uid, const char *key, const char *password);
void send_template(const char *template, TMPL_varlist *varlist,
							TMPL_fmtlist *fmtlist);

#endif /* _URLHELPERS_H_ */
