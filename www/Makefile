receiptomatc-www: receiptomatc-www.c
	gcc -Wall -o receiptomatc-www receiptomatc-www.c -I../../libctemplate -L../../libctemplate `pkg-config --libs --cflags glib-2.0` `mysql_config --cflags --libs` -lcrypt -lfcgi -lmhash -lsqlite3 -lmagic -lctemplate

clean:
	rm receiptomatc-www
