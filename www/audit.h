/*
 * audit.h - Auditing subsystem
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2016		Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _AUDIT_H_
#define _AUDIT_H_

#include <stdbool.h>

#include <ctemplate.h>

int check_auth(void);
bool is_logged_in(void);
unsigned long long log_login(void);
void display_last_login(TMPL_varlist *varlist);
void create_session(unsigned long long sid);
void set_user_session(void);

#endif /* _AUDIT_H_ */
