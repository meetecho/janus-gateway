CC = gcc
STUFF = $(shell pkg-config --cflags glib-2.0 nice libmicrohttpd jansson libssl libcrypto sofia-sip-ua ini_config) -ldl -D_GNU_SOURCE $(HAVE_PORTRANGE)
LIBS = $(shell pkg-config --libs glib-2.0 nice libmicrohttpd jansson libssl libcrypto sofia-sip-ua ini_config) -ldl -lsrtp -lusrsctp -D_GNU_SOURCE $(HAVE_PORTRANGE)
OPTS = -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wunused -Wno-format-security #-Werror #-O2
GDB = -fstack-protector-all -g -ggdb -rdynamic #-gstabs
OBJS=janus.o cmdline.o config.o apierror.o rtcp.o dtls.o sctp.o ice.o sdp.o utils.o

all: cmdline janus plugins

.PHONY: plugins docs sctptest

plugins:
ifndef INSTALLSH
	$(error Please use the install.sh script to compile Janus)
endif
	$(MAKE) -C plugins

docs:
	$(MAKE) -C docs

cmdline:
	gengetopt --set-package="janus" --set-version="0.0.3" < janus.ggo

sctptest:
	$(MAKE) -C sctptest

%.o: %.c
	$(CC) $(STUFF) -fPIC $(GDB) -c $< -o $@ $(OPTS)

janus : $(OBJS)
ifndef INSTALLSH
	$(error Please use the install.sh script to compile Janus)
endif
	$(CC) $(GDB) -o janus $(OBJS) $(LIBS)

clean :
	rm -f janus *.o plugins/*.o plugins/*.so
	rm -rf docs/html
