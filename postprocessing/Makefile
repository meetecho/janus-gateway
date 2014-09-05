STUFF = $(shell pkg-config --cflags glib-2.0 libavutil libavcodec libavformat ogg) -ldl
LIBS = $(shell pkg-config --libs glib-2.0 libavutil libavcodec libavformat ogg) -ldl
OBJS=janus-pp-rec.o pp-webm.o pp-opus.o
BINS=janus-pp-rec

all: janus-pp-rec

clean :
	rm -f janus-pp-rec *.o

include ../common.make
