/*
 * data_extraction.c
 *
 * Copyright (C) 2011-2013	OpenTech Labs
 *				Andrew Clayton <andrew@digital-domain.net>
 *
 *		 2016, 2020	Andrew Clayton <andrew@digital-domain.net>
 *
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <glib.h>

#include "common.h"
#include "utils.h"
#include "data_extraction.h"

void send_receipt_data(int fd)
{
	ssize_t bytes_read;
	char buf[BUF_SIZE];
	struct stat sb;

	fstat(fd, &sb);

	fcgx_p("Content-Type: application/download; text/csv\r\n");
	fcgx_p("Content-Length: %ld\r\n", sb.st_size);
	fcgx_p("Content-Disposition: attachment; filename=receipt_data.csv"
								"\r\n\r\n");

	lseek(fd, 0, SEEK_SET);
	do {
		bytes_read = read(fd, &buf, BUF_SIZE);
		fcgx_ps(buf, bytes_read);
	} while (bytes_read > 0);
}

void extract_data_now(int fd)
{
	char line[BUF_SIZE];
	MYSQL_RES *res;
	unsigned long nr_rows;
	unsigned long i;
	ssize_t bytes_wrote;

	res = sql_query("SELECT tags.employee_number, tags.department, "
			"tags.po_num, tags.cost_codes, tags.account_codes, "
			"tags.supplier_town, tags.supplier_name, "
			"tags.currency, tags.gross_amount, tags.vat_amount, "
			"tags.net_amount, tags.vat_rate, tags.vat_number, "
			"tags.receipt_date, tags.reason, tags.payment_method "
			"FROM tags INNER JOIN reviewed ON "						"(tags.id = reviewed.id) WHERE "
			"reviewed.r_uid = %u AND reviewed.timestamp > %ld AND "
			"reviewed.status = %d",
			user_session.uid,
			user_session.login_at, APPROVED);
	nr_rows = mysql_num_rows(res);
	if (nr_rows == 0)
		goto out;

	snprintf(line, BUF_SIZE, "Employee Number\tDepartment\tPO Num\t"
					"Cost Codes\tAccount Codes\t"
					"Supplier Town\tSupplier Name\t"
					"Currency\tGross Amount\t"
					"VAT Amount\tNet Amount\tVAT Rate\t"
					"VAT Number\tReceipt Date\tReason\t"
					"Payment Method\r\n");
	bytes_wrote = write(fd, line, strlen(line));
	if (bytes_wrote < (ssize_t)strlen(line))
		d_fprintf(error_log, "Failed to write data: %s\n", line);

	for (i = 0; i < nr_rows; i++) {
		GHashTable *db_row = NULL;

		db_row = get_dbrow(res);
		snprintf(line, BUF_SIZE, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t"
					"%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\r\n",
					get_var(db_row, "employee_number"),
					get_var(db_row, "department"),
					get_var(db_row, "po_num"),
					get_var(db_row, "cost_codes"),
					get_var(db_row, "account_codes"),
					get_var(db_row, "supplier_town"),
					get_var(db_row, "supplier_name"),
					get_var(db_row, "currency"),
					get_var(db_row, "gross_amount"),
					get_var(db_row, "vat_amount"),
					get_var(db_row, "net_amount"),
					get_var(db_row, "vat_rate"),
					get_var(db_row, "vat_number"),
					get_var(db_row, "receipt_date"),
					get_var(db_row, "reason"),
					get_var(db_row, "payment_method"));
		bytes_wrote = write(fd, line, strlen(line));
		if (bytes_wrote < (ssize_t)strlen(line))
			d_fprintf(error_log, "Failed to write data: %s\n",
									line);
		free_vars(db_row);
	}

out:
	mysql_free_result(res);
}
