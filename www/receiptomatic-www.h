/*
 * receiptomatic-www.h
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#ifndef _RECEIPTOMATIC_WWW_H_
#define _RECEIPTOMATIC_WWW_H_

#define NR_PROCS	5	/* Number of processes to fork at startup */

#define SESSION_CHECK	(60 * 60)	/* Check for old sessions every hour */
#define SESSION_EXPIRY	(60 * 60 * 4)	/* 4 hours */

#endif /* _RECEIPTOMATIC_WWW_H_ */
