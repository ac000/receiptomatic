LIBS=-L../../libctemplate `pkg-config --libs glib-2.0` `mysql_config --libs` -lm -lrt -lcrypt -lfcgi -lmhash -ltokyocabinet -lmagic -lctemplate
INCS=-I../../libctemplate `pkg-config --cflags glib-2.0` `mysql_config --cflags `
receiptomatic-www: receiptomatic-www.o get_config.o url_handlers.o url_helpers.o data_extraction.o utils.o db.o
	gcc -Wall -o receiptomatic-www receiptomatic-www.o get_config.o url_handlers.o url_helpers.o data_extraction.o utils.o db.o -D_RECEIPTOMATIC_WWW_ ${LIBS}

receiptomatic-www.o: common.h receiptomatic-www.h receiptomatic-www.c
	gcc -Wall -c receiptomatic-www.c ${INCS}

url_handlers.o: common.h url_handlers.h url_handlers.c
	gcc -Wall -c url_handlers.c ${INCS}

url_helpers.o: common.h url_helpers.h url_helpers.c
	gcc -Wall -c url_helpers.c ${INCS}

data_extraction.o: common.h data_extraction.h data_extraction.c
	gcc -Wall -c data_extraction.c ${INCS}

utils.o: common.h utils.h utils.c
	gcc -Wall -c utils.c ${INCS}

db.o: common.h db.h db.c
	gcc -Wall -c db.c ${INCS}

get_config.o: common.h get_config.c
	gcc -Wall -c get_config.c ${INCS}

clean:
	rm receiptomatic-www *.o
