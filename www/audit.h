/*
 * audit.h - Auditing subsystem
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2016, 2020	Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _AUDIT_H_
#define _AUDIT_H_

#include <stdbool.h>

#include <flate.h>

extern int check_auth(void);
extern bool is_logged_in(void);
extern unsigned long long log_login(void);
extern void display_last_login(Flate *f);
extern void create_session(unsigned long long sid);
extern void set_user_session(void);

#endif /* _AUDIT_H_ */
