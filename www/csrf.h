/*
 * csrf.h - CSRF mitigation functions
 *
 * Copyright (C) 2016		Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _CSRF_H_
#define _CSRF_H_

#include <stdbool.h>

#include <flate.h>

void add_csrf_token(Flate *f);
bool valid_csrf_token(void);

#endif /* _CSRF_H_ */
