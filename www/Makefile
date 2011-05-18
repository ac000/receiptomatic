receiptomatic-www: receiptomatic-www.c
	gcc -Wall -o receiptomatic-www receiptomatic-www.c -I../../libctemplate -L../../libctemplate `pkg-config --libs --cflags glib-2.0` `mysql_config --cflags --libs` -lm -lrt -lcrypt -lfcgi -lmhash -ltokyocabinet -lmagic -lctemplate

clean:
	rm receiptomatic-www
