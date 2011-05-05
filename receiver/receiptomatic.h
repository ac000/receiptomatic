/*
 * receiptomatic.h
 *
 * Copyright (C) 2011 OpenTech Labs, Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#ifndef _RECEIPTOMATIC_H_
#define _RECEIPTOMATIC_H_

static char *create_image_id(char *path, char *filename);
static int do_sql(char *sql);
static void convert_image(char *path, char *filename, int size);
static void save_image(GMimeObject *part, char *path, char *filename);
static void process_part(GMimeObject *part, gpointer user_data);
static void process_message(int dirfd, char *filename);

#endif /* _RECEIPTOMATIC_H_ */
