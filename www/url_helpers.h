/*
 * url_helpers.h
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#ifndef _URLHELPERS_H_
#define _URLHELPERS_H_

char *username_to_name(char *username);
int is_logged_in(void);
int check_auth(GHashTable *credentials);
int is_users_receipt(char *id);
int tag_info_allowed(char *image_id);
int image_access_allowed(char *path);
void set_user_session(void);
char *create_session_id(void);
void create_session(GHashTable *credentials, unsigned int sid);
int check_amounts(double gross, double net, double vat, double vr);
void set_default_field_names(struct field_names *fields);
void set_custom_field_names(struct field_names *fields);
void update_fmap(GHashTable *qvars);
void tag_image(GHashTable *qvars);
int do_add_user(GHashTable *qvars, unsigned char capabilities);
void do_update_user(GHashTable *qvars);
void do_edit_user(GHashTable *qvars);
void do_activate_user(char *uid, char *key, char *password);
void send_template(char *template, TMPL_varlist *varlist);

#endif /* _URLHELPERS_H_ */
