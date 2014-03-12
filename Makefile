CC = gcc
STUFF = $(shell pkg-config --cflags glib-2.0 nice libmicrohttpd jansson libssl libcrypto sofia-sip-ua ini_config) -ldl -D_GNU_SOURCE $(HAVE_PORTRANGE)
LIBS = $(shell pkg-config --libs glib-2.0 nice libmicrohttpd jansson libssl libcrypto sofia-sip-ua ini_config) -ldl -lsrtp -D_GNU_SOURCE $(HAVE_PORTRANGE)
OPTS = -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wunused #-Werror #-O2
GDB = -g -ggdb #-gstabs
OBJS=janus.o cmdline.o config.o apierror.o rtcp.o dtls.o ice.o sdp.o utils.o

all: janus cmdline plugins

.PHONY: plugins docs

plugins:
	$(MAKE) -C plugins

docs:
	$(MAKE) -C docs

cmdline:
	rm -f cmdline.o
	gengetopt --set-package="janus" --set-version="0.0.1" < janus.ggo

%.o: %.c
	$(CC) $(STUFF) -fPIC $(GDB) -c $< -o $@ $(OPTS)

janus : $(OBJS)
	$(CC) $(GDB) -o janus $(OBJS) $(LIBS)

clean :
	rm -f janus *.o plugins/*.o plugins/*.so
	rm -rf docs/html
