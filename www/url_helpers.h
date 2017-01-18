/*
 * url_helpers.h
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2016		Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _URL_HELPERS_H_
#define _URL_HELPERS_H_

#include <stdint.h>
#include <stdbool.h>

#include <flate.h>

char *username_to_name(const char *username);
bool is_users_receipt(const char *id);
bool tag_info_allowed(const char *image_id);
bool image_access_allowed(const char *path);
int check_amounts(double gross, double net, double vat, double vr);
void set_default_field_names(void);
void set_custom_field_names(void);
void process_activation_changes(void);
void update_fmap(void);
void tag_image(void);
int do_add_user(uint8_t capabilities);
void do_update_user(void);
void do_edit_user(void);
void do_activate_user(const char *uid, const char *key, const char *password);
void gather_receipt_stats_for_user(long long uid, Flate *f);
void send_template(Flate *f);
void send_page(char *file);

#endif /* _URL_HELPERS_H_ */
