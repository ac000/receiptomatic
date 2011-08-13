/*
 * audit.h - Auditing subsystem
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#ifndef _AUDIT_H_
#define _AUDIT_H_

unsigned int log_login(GHashTable *credentials, char *ip_addr);
time_t get_last_login(unsigned int uid, char *from_host);

#endif /* _AUDIT_H_ */
