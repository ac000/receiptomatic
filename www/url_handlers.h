/*
 * url_handlers.h
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _URL_HANDLERS_H_
#define _URL_HANDLERS_H_

#define MAX_RECEIPT_AGE (60 * 60 * 24 * 180)      /* 180 days */

void handle_request(void);

#endif /* _URL_HANDLERS_H_ */
