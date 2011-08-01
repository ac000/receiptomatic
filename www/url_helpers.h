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
int is_logged_in(char *cookies, char *client_id, char *remote_ip,
							char *request_uri);
int check_auth(GHashTable *credentials);
int is_users_receipt(struct session *current_session, char *id);
int tag_info_allowed(struct session *current_session, char *image_id);
int image_access_allowed(struct session *current_session, char *path);
void set_current_session(struct session *current_session, char *cookies,
							char *request_uri);
char *create_session_id(void);
void create_session(GHashTable *credentials, char *http_user_agent,
						char *http_x_forwarded_for);
int check_amounts(double gross, double net, double vat, double vr);
void set_custom_field_names(struct session *current_session,
						struct field_names *fields);
void update_fmap(struct session *current_session, char *query);
void tag_image(struct session *current_session, GHashTable *qvars);
int do_add_user(GHashTable *qvars, unsigned char capabilities);
void do_activate_user(char *uid, char *key, char *password);

#endif /* _URLHELPERS_H_ */
