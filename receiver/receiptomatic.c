/*
 * receiptomatic.c
 *
 * Copyright (C) 2011 OpenTech Labs, Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>

#include <mysql.h>

#include <mhash.h>

#include <magick/api.h>

#include <gmime/gmime.h>

#include <glib.h>

#include "receiptomatic.h"
#include "../db/db_config.h"


#define BUF_SIZE	4096
#define SQL_MAX		8192
#define BASE_PATH	"/data/www/opentechlabs.net/receiptomatic/receipt_images"

#define IMG_MEDIUM	1
#define IMG_SMALL	0


/*
 * Generate a SHA-256 of a given image
 */
static char *create_image_id(char *path, char *filename)
{
	int fd;
	int dirfd;
	ssize_t bytes_read = 1;
	int i;
	int hbs;
	char buf[BUF_SIZE];
	unsigned char *hash;
	char ht[3];
	char shash[65];
	MHASH td;

	td = mhash_init(MHASH_SHA256);
	dirfd = open(path, O_RDONLY);
	fd = openat(dirfd, filename, O_RDONLY);
	while (bytes_read > 0) {
		bytes_read = read(fd, &buf, BUF_SIZE);
		mhash(td, &buf, bytes_read);
	}
	close(fd);
	close(dirfd);
	hash = mhash_end(td);

	printf("Hash: ");
	memset(shash, 0, sizeof(shash));
	hbs = mhash_get_block_size(MHASH_SHA256);
	for (i = 0; i < hbs; i++) {
		sprintf(ht, "%.2x", hash[i]);
		strncat(shash, ht, 2);
	}
	printf("%s\n", shash);

	free(hash);

	return strdup(shash);
}

/*
 * Execute a SQL query
 */
static int do_sql(char *sql)
{
	MYSQL *conn;
	int ret = 0;

	conn = mysql_init(NULL);
	mysql_real_connect(conn, opt_hostname, opt_user_name,
					opt_password, opt_db_name,
					opt_port_num, opt_socket_name,
					opt_flags);
	mysql_query(conn, sql);
	mysql_close(conn);

	return ret;
}

static void convert_image(char *path, char *filename, int size)
{
	ExceptionInfo exception;
	Image *image;
	Image *new_image;
	ImageInfo *image_info;
	char output_file[PATH_MAX];
	int x;
	int y;

	chdir(path);

	if (size == IMG_SMALL) {
		mkdir("small", 0777);
		snprintf(output_file, PATH_MAX, "small/%s", filename);
		x = 180;
		y = 180;
	} else if (size == IMG_MEDIUM) {
		mkdir("medium", 0777);
		snprintf(output_file, PATH_MAX, "medium/%s", filename);
		x = 300;
		y = 300;
	} else {
		goto out;
	}
	printf("Creating image: %s\n", output_file);

	InitializeMagick(NULL);
	GetExceptionInfo(&exception);
	image_info = CloneImageInfo((ImageInfo *)NULL);
	strcpy(image_info->filename, filename);
	image = ReadImage(image_info, &exception);
	new_image = ResizeImage(image, x, y, LanczosFilter, 1.0, &exception);
	DestroyImage(image);
	strcpy(new_image->filename, output_file);
	WriteImage(image_info, new_image);

	DestroyImageInfo(image_info);
	DestroyMagick();

out:
	chdir("/tmp");
	return;
}

/*
 * Save the attached image to the filesystem
 */
static void save_image(GMimeObject *part, char *path, char *filename)
{
	int fd;
	int dirfd;
	GMimeStream *stream;
	GMimeDataWrapper *content;

	dirfd = open(path, O_RDONLY);
	fd = openat(dirfd, filename, O_CREAT | O_WRONLY | O_TRUNC, 0666);

	stream = g_mime_stream_fs_new(fd);
	content = g_mime_part_get_content_object((GMimePart *)part);
	g_mime_data_wrapper_write_to_stream(content, stream);
	g_mime_stream_flush(stream);

	g_object_unref(content);
        g_object_unref(stream);

	close(dirfd);
}

/*
 * Process a MIME part of the mail message
 */
static void process_part(GMimeObject *part, gpointer user_data)
{
	const GMimeContentType *content_type;
	char ymd[11];	/* YYYY/MM/DD */
	char filename[NAME_MAX];
	char ext[5];
	char path[PATH_MAX];
	char sql[SQL_MAX];
	char *to;
	char *image_id;
	int bytes;
	time_t t;
	DIR *dir;

	printf("Part: %s\n", (char *)g_mime_part_get_filename(
							(GMimePart *)part));
	content_type = g_mime_object_get_content_type(part);
	printf("Content-Type: %s\n",
				g_mime_content_type_to_string(content_type));
	if (strcmp(g_mime_content_type_to_string(content_type),
							"image/jpeg") == 0)
		strcpy(ext, ".jpg");
	else if (strcmp(g_mime_content_type_to_string(content_type),
							"image/png") == 0)
		strcpy(ext, ".png");
	else
		return;

	/* Determine the path where to store the image */
	to = (char *)internet_address_get_addr(user_data);
	t = time(NULL);
	strftime(ymd, sizeof(ymd), "%Y/%m/%d", localtime(&t));
	bytes = snprintf(path, PATH_MAX, "%s/%s/%s", BASE_PATH, to, ymd);
	if (bytes >= PATH_MAX)
		return;
	printf("Path: %s\n", path);

	dir = opendir(path);
	if (!dir) {
		g_mkdir_with_parents(path, 0777);
		strcpy(filename, "000-receipt_image");
		strcat(filename, ext);
	} else {
		struct dirent *entry;
		int ne = 0;
		while ((entry = readdir(dir)) != NULL) {
			/* skip . .. medium & small entries */
			if (entry->d_name[0] == '.' ||
						entry->d_name[0] == 'm' ||
						entry->d_name[0] == 's')
				continue;
			ne++;
		}
		closedir(dir);

		sprintf(filename, "%03d-receipt_image%s", ne, ext);
	}

	printf("Creating file: %s/%s\n", path, filename);
	save_image(part, path, filename);
	convert_image(path, filename, IMG_SMALL);
	convert_image(path, filename, IMG_MEDIUM);

	image_id = create_image_id(path, filename);

	/* In the database we only store the path relative from BASE_PATH */
	sprintf(path, "%s/%s", to, ymd);
	snprintf(sql, SQL_MAX,
		"INSERT INTO images VALUES ('%s', '%s', %ld, '%s', '%s', 0)",
					image_id, to, t, path, filename);
	printf("SQL: %s\n", sql);
	do_sql(sql);

	free(image_id);
}

/*
 * Process a mail message, passed on by sendmail
 */
static void process_message(int dirfd, char *filename)
{
	GMimeMessage *message;
	GMimeStream *stream;
	GMimeParser *parser;
	const InternetAddressList *recips;
	InternetAddress *addr;
	int fd;

	g_mime_init(0);

	fd = openat(dirfd, filename, O_RDONLY);
	stream = g_mime_stream_fs_new(fd);
	parser = g_mime_parser_new_with_stream(stream);
	message = g_mime_parser_construct_message(parser);
	recips = g_mime_message_get_recipients(message,
						GMIME_RECIPIENT_TYPE_TO);
	addr = internet_address_list_get_address(recips);
	printf("From: %s\n", (char *)g_mime_message_get_sender(message));
	printf("To: %s\n", internet_address_to_string(addr, FALSE));
	printf("Subject: %s\n", (char *)g_mime_message_get_subject(message));

	g_mime_message_foreach_part(message, (GMimePartFunc)process_part,
								(void *)addr);

	g_object_unref(stream);
	g_object_unref(parser);
	g_object_unref(message);

	g_mime_shutdown();
}

int main(int argc, char **argv)
{
	int fd;
	int dirfd;
	ssize_t bytes_read = 1;
	char buf[BUF_SIZE];
	char temp_name[21] = "receiptomatic-XXXXXX";

	/* Be super restrictive for the tempfile creation */
	umask(0077);
	chdir("/tmp");

	/*
	 * This program gets the mail message pipe'd to it from sendmail.
	 *
	 * This means we need to copy the mail message to a temporary file
	 * or the gmime stuff will fail due to operating on a pipe
	 * (illegal seek).
	 */
	fd = mkstemp(temp_name);
	while (bytes_read > 0) {
		bytes_read = read(STDIN_FILENO, &buf, BUF_SIZE);
		write(fd, buf, bytes_read);
	}
	close(fd);

	umask(0007);
	dirfd = open("/tmp", O_RDONLY);
	process_message(dirfd, temp_name);

	unlinkat(dirfd, temp_name, 0);
	close(dirfd);

	exit(EXIT_SUCCESS);
}
