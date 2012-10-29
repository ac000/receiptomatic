CC=gcc
CFLAGS=-Wall -std=c99 -O2 -D_FILE_OFFSET_BITS=64
LIBS=`pkg-config --libs gmime-2.0` `mysql_config --libs` `GraphicsMagick-config --ldflags --libs` -lmhash
INCS=`pkg-config --cflags gmime-2.0` `mysql_config --cflags` `GraphicsMagick-config --cppflags`

receiptomatic: receiptomatic.c
	$(CC) $(CFLAGS) -c ../www/get_config.c ${INCS}
	$(CC) $(CFLAGS) -o receiptomatic receiptomatic.c get_config.o ${LIBS} ${INCS}

clean:
	rm -f receiptomatic *.o
