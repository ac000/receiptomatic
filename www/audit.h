/*
 * audit.h - Auditing subsystem
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _AUDIT_H_
#define _AUDIT_H_

unsigned int log_login(void);
time_t get_last_login(char *from_host);

#endif /* _AUDIT_H_ */
