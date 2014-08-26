STUFF = $(shell pkg-config --cflags glib-2.0 jansson sofia-sip-ua opus ogg ini_config) -ldl -D_GNU_SOURCE
LIBS = $(shell pkg-config --libs glib-2.0 jansson sofia-sip-ua opus ogg ini_config) -ldl -D_GNU_SOURCE
OBJS = janus_echotest.so janus_streaming.so janus_sip.so janus_videocall.so janus_videoroom.so
UTILS = ../apierror.o ../config.o ../rtcp.o ../record.o ../utils.o
ifeq ($(HAVE_OPUS),1)
	OBJS += janus_audiobridge.so
endif
ifeq ($(HAVE_OGG),1)
	OBJS += janus_voicemail.so
endif
BINS =

all: $(OBJS)

%.so: %.o $(UTILS)
ifndef INSTALLSH
	$(error Please use the install.sh script to compile Janus)
endif
	$(CC) -shared -fPIC $(GDB) -o $@ $< $(UTILS) $(LIBS)

clean:
	rm -f *.so *.o

include ../common.make
