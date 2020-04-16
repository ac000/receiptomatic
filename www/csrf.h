/*
 * csrf.h - CSRF mitigation functions
 *
 * Copyright (C) 2016, 2020	Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _CSRF_H_
#define _CSRF_H_

#include <stdbool.h>

#include <flate.h>

extern void add_csrf_token(Flate *f);
extern bool valid_csrf_token(void);

#endif /* _CSRF_H_ */
