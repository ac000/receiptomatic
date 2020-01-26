CC=gcc
CFLAGS=-Wall -std=c99 -O2 -D_FILE_OFFSET_BITS=64 -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -fPIC
LDFLAGS=-Wl,-z,relro -Wl,-z,now -pie
LIBS=-L../../libflate `pkg-config --libs gmime-2.6` `mysql_config --libs` `GraphicsMagick-config --ldflags --libs` -lmhash
INCS=-I../../libflate `pkg-config --cflags gmime-2.6` `mysql_config --cflags` `GraphicsMagick-config --cppflags`

receiptomatic: receiptomatic.c
	$(CC) $(CFLAGS) -c ../www/get_config.c ${INCS}
	$(CC) $(CFLAGS) $(LDFLAGS) -o receiptomatic receiptomatic.c get_config.o ${LIBS} ${INCS}

clean:
	rm -f receiptomatic *.o
