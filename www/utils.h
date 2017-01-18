/*
 * utils.h
 *
 * Copyright (C) 2011-2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2016		Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdbool.h>

#include <flate.h>

#include <glib.h>

struct pagination {
	int requested_page;	/* Page requested by client */
	int page_no;		/* Page being returned to client */
	int rows_per_page;	/* Rows to show on each page */
	int nr_pages;		/* Number of pages across result set */
	int from;		/* Index into the result set to start from */
};

/* Pagination macro's */
#define IS_MULTI_PAGE(nr_pages)		(((nr_pages) > 1) ? 1 : 0)
#define IS_FIRST_PAGE(page)		(((page) == 1) ? 1 : 0)
#define IS_LAST_PAGE(page, nr_pages)	(((page) == (nr_pages)) ? 1 : 0)

char *get_tenant(const char *host, char *tenant);
char *generate_hash(char *hash, int type);
void free_avars(void);
void free_vars(GHashTable *vars);
void free_u_files(void);
void set_vars(void);
GHashTable *get_dbrow(MYSQL_RES *res);
const char *get_avar(int index, const char *key);
const char *get_var(GHashTable *vars, const char *key);
void free_fields(void);
void free_env_vars(void);
void free_user_session(void);
void set_env_vars(void);
void send_activation_mail(const char *name, const char *address,
			  const char *key);
char *generate_password_hash(int hash_type, const char *password);
void delete_user_session(unsigned int uid);
bool user_already_exists(const char *username);
void get_page_pagination(struct pagination *pn);
void do_pagination(Flate *f, const struct pagination *pn);
void do_zebra(Flate *f, unsigned long row, const char *zebra);
char *de_xss(const char *string);

#endif /* _UTILS_H_ */
