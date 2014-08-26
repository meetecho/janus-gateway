STUFF = $(shell pkg-config --cflags glib-2.0 nice libmicrohttpd jansson libssl libcrypto sofia-sip-ua ini_config) -ldl -D_GNU_SOURCE $(HAVE_PORTRANGE) $(HAVE_SCTP) $(HAVE_WS)
LIBS = $(shell pkg-config --libs glib-2.0 nice libmicrohttpd jansson libssl libcrypto sofia-sip-ua ini_config) -ldl -lsrtp $(SCTP_LIB) $(WS_LIB) -D_GNU_SOURCE $(HAVE_PORTRANGE) $(HAVE_SCTP) $(HAVE_WS)
OBJS=janus.o cmdline.o config.o apierror.o rtcp.o dtls.o sctp.o ice.o sdp.o record.o utils.o
BINS=janus

all: cmdline janus plugins

.PHONY: plugins docs sctptest wstest

plugins:
ifndef INSTALLSH
	$(error Please use the install.sh script to compile Janus)
endif
	$(MAKE) -C plugins

docs:
	$(MAKE) -C docs

cmdline:
	gengetopt --set-package="janus" --set-version="0.0.4" < janus.ggo

sctptest:
	$(MAKE) -C sctptest

wstest:
	$(MAKE) -C wstest

clean :
	rm -f janus *.o plugins/*.o plugins/*.so
	rm -f sctptest/test sctptest/*.o
	rm -f wstest/test wstest/*.o
	rm -f postprocessing/janus-pp-rec postprocessing/*.o
	rm -rf docs/html

include common.make
