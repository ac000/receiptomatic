APPNAME  = receiptomatic-www

DEPDIR  := .d
$(shell mkdir -p $(DEPDIR) >/dev/null)
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td

CC      = gcc
CFLAGS  = -Wall -Wextra -Wdeclaration-after-statement -Wvla -std=c99 -O2 -g \
          -Wp,-D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64 -D_HAVE_FCGX \
          -fexceptions -fstack-protector --param=ssp-buffer-size=4 -fPIE \
          -I../../libflate $(shell pkg-config --cflags glib-2.0) \
          $(shell pkg-config --cflags gmime-2.6) \
          $(shell mysql_config --cflags)
LDFLAGS = -Wl,-z,now,-z,defs,-z,relro,--as-needed -pie
LIBS    = -L../../libflate $(shell pkg-config --libs glib-2.0) \
          $(shell pkg-config --libs gmime-2.6) \
          $(shell mysql_config --libs) \
          -lm -lrt -lcrypt -lfcgi -lmhash -ltokyocabinet -lmagic -lflate \
          -pthread
POSTCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

sources = $(wildcard *.c)
objects = $(sources:.c=.o)

v = @
ifeq ($V,1)
	v =
endif

.PHONY: all
all: $(APPNAME)

$(APPNAME): $(objects)
	@echo -e "  LNK\t$@"
	$(v)$(CC) $(LDFLAGS) -o $@ $(objects) $(LIBS)

%.o: %.c
%.o: %.c $(DEPDIR)/%.d
	@echo -e "  CC\t$@"
	$(v)$(CC) $(DEPFLAGS) $(CFLAGS) -c -o $@ $<
	$(POSTCOMPILE)

$(DEPDIR)/%.d: ;
.PRECIOUS: $(DEPDIR)/%.d

include $(wildcard $(patsubst %,$(DEPDIR)/%.d,$(basename $(sources))))

.PHONY: clean
clean:
	$(v)rm -f $(APPNAME) $(objects)
	$(v)rm -f $(DEPDIR)/*
	$(v)rmdir $(DEPDIR)
