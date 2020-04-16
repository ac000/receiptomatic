/*
 * url_helpers.h
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2016, 2020	Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _URL_HELPERS_H_
#define _URL_HELPERS_H_

#include <stdbool.h>

#include <flate.h>

#include "short_types.h"

extern char *username_to_name(const char *username);
extern bool is_users_receipt(const char *id);
extern bool tag_info_allowed(const char *image_id);
extern bool image_access_allowed(const char *path);
extern int check_amounts(double gross, double net, double vat, double vr);
extern void set_default_field_names(void);
extern void set_custom_field_names(void);
extern void process_activation_changes(void);
extern void update_fmap(void);
extern void tag_image(void);
extern int do_add_user(u8 capabilities);
extern void do_update_user(void);
extern void do_edit_user(void);
extern void do_activate_user(const char *uid, const char *key,
			     const char *password);
extern void gather_receipt_stats_for_user(unsigned int uid, int whom,
					  Flate *f);
extern void send_template(Flate *f);
extern void send_page(char *file);

#endif /* _URL_HELPERS_H_ */
