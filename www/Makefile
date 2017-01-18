CC=gcc
CFLAGS=-Wall -std=c99 -O2 -g -Wp,-D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64 -D_HAVE_FCGX -fexceptions -fstack-protector --param=ssp-buffer-size=4 -fPIE
LDFLAGS=-Wl,-z,now -pie
LIBS=-L../../libflate `pkg-config --libs glib-2.0` `pkg-config --libs gmime-2.6` `mysql_config --libs` -lm -lrt -lcrypt -lfcgi -lmhash -ltokyocabinet -lmagic -lflate -pthread
INCS=-I../../libflate `pkg-config --cflags glib-2.0` `pkg-config --cflags gmime-2.6` `mysql_config --cflags`

objects =	audit.o \
		csrf.o \
		data_extraction.o \
		db.o \
		get_config.o \
		receiptomatic-www.o \
		url_handlers.o \
		url_helpers.o \
		utils.o

receiptomatic-www: $(objects)
	@echo -e "  LNK\t$@"
	@$(CC) $(LDFLAGS) -o receiptomatic-www $(objects) ${LIBS}

receiptomatic-www.o: common.h get_config.h receiptomatic_config.h url_handlers.h receiptomatic-www.h receiptomatic-www.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c receiptomatic-www.c ${INCS}

url_handlers.o: common.h utils.h data_extraction.h url_helpers.h url_handlers.h audit.h csrf.h url_handlers.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c url_handlers.c ${INCS}

url_helpers.o: common.h utils.h audit.h url_helpers.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c -c url_helpers.c ${INCS}

data_extraction.o: common.h utils.h data_extraction.h data_extraction.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c data_extraction.c ${INCS}

utils.o: common.h utils.h utils.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c utils.c ${INCS}

db.o: common.h db.h db.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c db.c ${INCS}

get_config.o: receiptomatic_config.h common.h get_config.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c get_config.c ${INCS}

audit.o: common.h utils.h audit.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c audit.c ${INCS}

csrf.o: common.h utils.h csrf.c
	@echo -e "  CC\t$@"
	@$(CC) $(CFLAGS) -c csrf.c ${INCS}

clean:
	rm -f receiptomatic-www *.o
