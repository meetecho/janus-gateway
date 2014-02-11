CC = gcc
STUFF = $(shell pkg-config --cflags glib-2.0 jansson sofia-sip-ua opus ogg ini_config) -ldl -D_GNU_SOURCE
LIBS = $(shell pkg-config --libs glib-2.0 jansson sofia-sip-ua opus ogg ini_config) -ldl -D_GNU_SOURCE
OPTS = -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wunused #-Werror #-O2
GDB = -g -ggdb #-gstabs

all: janus_echotest.so janus_streaming.so janus_sip.so janus_videocall.so janus_audiobridge.so janus_videoroom.so janus_voicemail.so

%.o: %.c
	$(CC) $(STUFF) -shared -fPIC $(GDB) -c $< -o $@ $(OPTS)

%.so: %.o ../rtcp.o
	$(CC) -shared -fPIC $(GDB) -o $@ $< ../config.o ../rtcp.o $(LIBS)

clean:
	rm -f *.so *.o

