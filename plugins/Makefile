CC = gcc
STUFF = $(shell pkg-config --cflags glib-2.0 jansson sofia-sip-ua opus ogg ini_config) -ldl -D_GNU_SOURCE
LIBS = $(shell pkg-config --libs glib-2.0 jansson sofia-sip-ua opus ogg ini_config) -ldl -D_GNU_SOURCE
OPTS = -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wunused #-Werror #-O2
GDB = -g -ggdb #-gstabs
OBJS = janus_echotest.so janus_streaming.so janus_sip.so janus_videocall.so janus_videoroom.so
ifeq ($(HAVE_OPUS),1)
	OBJS += janus_audiobridge.so
endif
ifeq ($(HAVE_OGG),1)
	OBJS += janus_voicemail.so
endif

all: $(OBJS)

%.o: %.c
	$(CC) $(STUFF) -shared -fPIC $(GDB) -c $< -o $@ $(OPTS)

%.so: %.o ../config.o ../rtcp.o ../utils.o
ifndef INSTALLSH
	$(error Please use the install.sh script to compile Janus)
endif
	$(CC) -shared -fPIC $(GDB) -o $@ $< ../config.o ../rtcp.o ../utils.o $(LIBS)

clean:
	rm -f *.so *.o

