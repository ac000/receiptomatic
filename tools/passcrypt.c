/*
 * passcrypt.c
 *
 * Copyright (C) 2011		OpenTech Labs
 * 				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

int main(int argc, char **argv)
{
	static const char salt_chars[64] =
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	char salt[21];
	int i;

	if (argc < 4) {
		printf("Usage: passcrypt -l <256/512> <password>\n");
		exit(EXIT_FAILURE);
	}

	memset(salt, 0, sizeof(salt));

	if (strcmp(argv[2], "256") == 0) {
		strcpy(salt, "$5$");
	} else if (strcmp(argv[2], "512") == 0) {
		strcpy(salt, "$6$");
	} else {
		printf("Unknown SHA type.\n");
		exit(EXIT_FAILURE);
	}

	for (i = 3; i < 19; i++) {
		int r;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		srandom(tv.tv_sec * tv.tv_usec);
		r = random() % 64; /* 0 - 63 */
		salt[i] = salt_chars[r];
	}
	strcat(salt, "$");

	printf("%s\n", crypt(argv[3], salt));

	exit(EXIT_SUCCESS);
}
