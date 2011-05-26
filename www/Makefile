LIBS=-L../../libctemplate `pkg-config --libs glib-2.0` `mysql_config --libs` -lm -lrt -lcrypt -lfcgi -lmhash -ltokyocabinet -lmagic -lctemplate
INCS=-I../../libctemplate `pkg-config --cflags glib-2.0` `mysql_config --cflags `
receiptomatic-www: receiptomatic-www.o url_handlers.o data_extraction.o utils.o db.o
	gcc -Wall -o receiptomatic-www receiptomatic-www.o url_handlers.o data_extraction.o utils.o db.o ${LIBS}

receiptomatic-www.o: common.h receiptomatic-www.h receiptomatic-www.c
	gcc -Wall -c receiptomatic-www.c ${INCS}

url_handlers.o: common.h url_handlers.c
	gcc -Wall -c url_handlers.c ${INCS}

data_extraction.o: common.h data_extraction.h data_extraction.c
	gcc -Wall -c data_extraction.c ${INCS}

utils.o: common.h utils.h utils.c
	gcc -Wall -c utils.c ${INCS}

db.o: db.h ../db/db_config.h db.c
	gcc -Wall -c db.c ${INCS}

clean:
	rm receiptomatic-www *.o
