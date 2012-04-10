/*
 * utils.h
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _UTILS_H_
#define _UTILS_H_

void free_avars(void);
void free_vars(GHashTable *vars);
void free_u_files(void);
void set_vars(void);
GHashTable *get_dbrow(MYSQL_RES *res);
char *get_avar(int index, const char *key);
char *get_var(GHashTable *vars, const char *key);
void free_fields(struct field_names *fields);
void set_env_vars(void);
char *generate_activation_key(const char *email_addr);
void send_activation_mail(const char *name, const char *address,
							const char *key);
char *generate_password_hash(int hash_type, const char *password);
void delete_user_session(unsigned int uid);
int user_already_exists(const char *username);
void get_page_pagination(const char *req_page_no, int rpp, int *page_no,
								int *from);
void de_xss(const char *value, FILE *out);
char *xss_safe_string(const char *string);

#endif /* _UTILS_H_ */
