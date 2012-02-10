/*
 * url_handlers.h
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#ifndef _URLHANDLERS_H_
#define _URLHANDLERS_H_

#define MAX_RECEIPT_AGE (60 * 60 * 24 * 180)      /* 180 days */

void handle_request(void);

#endif /* _URLHANDLERS_H_ */
