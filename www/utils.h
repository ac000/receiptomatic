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

extern char from_hex(char ch);
extern char to_hex(char code);
extern char *url_decode(char *str);
extern GHashTable *get_dbrow(MYSQL_RES *res);
extern GList *get_avars(char *query);
extern char *get_avar(GList *avars, int index, char *key);
extern void free_avars(GList *avars);
extern GHashTable *get_vars(char *query);
extern char *get_var(GHashTable *vars, char *key);
extern void free_vars(GHashTable *vars);

#endif /* _UTILS_H_ */
