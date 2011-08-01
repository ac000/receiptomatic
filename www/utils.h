/*
 * utils.h
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#ifndef _UTILS_H_
#define _UTILS_H_

GHashTable *get_dbrow(MYSQL_RES *res);
GList *get_avars(char *query);
char *get_avar(GList *avars, int index, char *key);
void free_avars(GList *avars);
GHashTable *get_vars(char *query);
char *get_var(GHashTable *vars, char *key);
void free_vars(GHashTable *vars);
char *generate_activation_key(char *email_addr);
void send_activation_mail(char *name, char *address, char *key);
char *generate_password_hash(int hash_type, char *password);

#endif /* _UTILS_H_ */
