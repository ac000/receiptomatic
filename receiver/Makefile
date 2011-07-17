receiptomatic: receiptomatic.c
	gcc -g -Wall -o receiptomatic receiptomatic.c ../www/get_config.o ../www/db.o `pkg-config --cflags --libs gmime-2.0` `mysql_config --cflags --libs` `GraphicsMagick-config --cppflags --ldflags --libs` -lmhash

clean:
	rm receiptomatic
