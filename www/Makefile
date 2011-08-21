CC=gcc
CFLAGS=-Wall -std=c99 -O2
LIBS=-L../../libctemplate `pkg-config --libs glib-2.0` `mysql_config --libs` -lm -lrt -lcrypt -lfcgi -lmhash -ltokyocabinet -lmagic -lctemplate
INCS=-I../../libctemplate `pkg-config --cflags glib-2.0` `mysql_config --cflags`

receiptomatic-www: receiptomatic-www.o get_config.o url_handlers.o url_helpers.o data_extraction.o utils.o db.o audit.o
	$(CC) -o receiptomatic-www receiptomatic-www.o get_config.o url_handlers.o url_helpers.o data_extraction.o utils.o db.o audit.o ${LIBS}

receiptomatic-www.o: common.h receiptomatic-www.h receiptomatic-www.c
	$(CC) $(CFLAGS) -c receiptomatic-www.c -D_RECEIPTOMATIC_WWW_ ${INCS}

url_handlers.o: common.h url_handlers.h url_handlers.c
	$(CC) $(CFLAGS) -c url_handlers.c -D_RECEIPTOMATIC_WWW_ ${INCS}

url_helpers.o: common.h url_helpers.h url_helpers.c
	$(CC) $(CFLAGS) -c -c url_helpers.c -D_RECEIPTOMATIC_WWW_ ${INCS}

data_extraction.o: common.h data_extraction.h data_extraction.c
	$(CC) $(CFLAGS) -c data_extraction.c -D_RECEIPTOMATIC_WWW_ ${INCS}

utils.o: common.h utils.h utils.c
	$(CC) $(CFLAGS) -c utils.c -D_RECEIPTOMATIC_WWW_ ${INCS}

db.o: common.h db.h db.c
	$(CC) $(CFLAGS) -c db.c -D_RECEIPTOMATIC_WWW_ ${INCS}

get_config.o: common.h get_config.c
	$(CC) $(CFLAGS) -c get_config.c -D_RECEIPTOMATIC_WWW_ ${INCS}

audit.o: common.h audit.h audit.c
	$(CC) $(CFLAGS) -c audit.c -D_RECEIPTOMATIC_WWW_ ${INCS}

clean:
	rm receiptomatic-www *.o
