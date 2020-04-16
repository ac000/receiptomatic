/*
 * utils.h
 *
 * Copyright (C) 2011-2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2016, 2020	Andrew Clayton <andrew@digital-domain.net>
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

extern char *get_tenant(const char *host, char *tenant);
extern char *generate_hash(char *hash, int type);
extern void free_avars(void);
extern void free_vars(GHashTable *vars);
extern void free_u_files(void);
extern void set_vars(void);
extern GHashTable *get_dbrow(MYSQL_RES *res);
extern const char *get_avar(int index, const char *key);
extern const char *get_var(GHashTable *vars, const char *key);
extern void free_fields(void);
extern void free_env_vars(void);
extern void free_user_session(void);
extern void set_env_vars(void);
extern void send_activation_mail(const char *name, const char *address,
				 const char *key);
extern char *generate_password_hash(int hash_type, const char *password);
extern void delete_user_session(unsigned int uid);
extern bool user_already_exists(const char *username);
extern void get_page_pagination(struct pagination *pn);
extern void do_pagination(Flate *f, const struct pagination *pn);
extern void do_zebra(Flate *f, unsigned long row, const char *zebra);
extern char *de_xss(const char *string);

#endif /* _UTILS_H_ */
