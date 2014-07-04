CC = gcc
STUFF = $(shell pkg-config --cflags libavutil libavcodec libavformat ogg) -ldl
LIBS = $(shell pkg-config --libs libavutil libavcodec libavformat ogg) -ldl
OPTS = -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wunused -Wno-format-security #-Werror #-O2
GDB = -fstack-protector-all -g -ggdb -rdynamic #-gstabs
OBJS=janus-pp-rec.o pp-webm.o pp-opus.o

all: janus-pp-rec

%.o: %.c
	$(CC) $(STUFF) -fPIC $(GDB) -c $< -o $@ $(OPTS)

janus-pp-rec : $(OBJS)
ifndef INSTALLSH
	$(error Please use the install.sh script to compile the Janus post-processing utility)
endif
	$(CC) $(GDB) -o janus-pp-rec $(OBJS) $(LIBS)

clean :
	rm -f janus-pp-rec *.o
