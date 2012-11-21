CC=gcc
CFLAGS=-Wall -std=c99 -O2 -g -Wp,-D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64 -D_RECEIPTOMATIC_WWW_ -fexceptions -fstack-protector --param=ssp-buffer-size=4 -fPIE
LDFLAGS=-Wl,-z,now -pie
LIBS=-L../../libctemplate `pkg-config --libs glib-2.0` `pkg-config --libs gmime-2.0` `mysql_config --libs` -lm -lrt -lcrypt -lfcgi -lmhash -ltokyocabinet -lmagic -lctemplate-fcgi
INCS=-I../../libctemplate `pkg-config --cflags glib-2.0` `pkg-config --cflags gmime-2.0` `mysql_config --cflags`

receiptomatic-www: receiptomatic-www.o get_config.o url_handlers.o url_helpers.o data_extraction.o utils.o db.o audit.o
	$(CC) $(LDFLAGS) -o receiptomatic-www receiptomatic-www.o get_config.o url_handlers.o url_helpers.o data_extraction.o utils.o db.o audit.o ${LIBS}

receiptomatic-www.o: common.h receiptomatic-www.h receiptomatic-www.c
	$(CC) $(CFLAGS) -c receiptomatic-www.c ${INCS}

url_handlers.o: common.h url_handlers.h url_handlers.c
	$(CC) $(CFLAGS) -c url_handlers.c ${INCS}

url_helpers.o: common.h url_helpers.h url_helpers.c
	$(CC) $(CFLAGS) -c -c url_helpers.c ${INCS}

data_extraction.o: common.h data_extraction.h data_extraction.c
	$(CC) $(CFLAGS) -c data_extraction.c ${INCS}

utils.o: common.h utils.h utils.c
	$(CC) $(CFLAGS) -c utils.c ${INCS}

db.o: common.h db.h db.c
	$(CC) $(CFLAGS) -c db.c ${INCS}

get_config.o: common.h get_config.c get_config.h
	$(CC) $(CFLAGS) -c get_config.c ${INCS}

audit.o: common.h audit.h audit.c
	$(CC) $(CFLAGS) -c audit.c ${INCS}

clean:
	rm -f receiptomatic-www *.o
