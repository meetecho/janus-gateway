STUFF = $(shell pkg-config --cflags libavutil libavcodec libavformat ogg) -ldl
LIBS = $(shell pkg-config --libs libavutil libavcodec libavformat ogg) -ldl
OBJS=janus-pp-rec.o pp-webm.o pp-opus.o
BINS=janus-pp-rec

all: janus-pp-rec

clean :
	rm -f janus-pp-rec *.o

include ../common.make
