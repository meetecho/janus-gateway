CC = gcc
LIBS = -lwebsock
OPTS = -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wunused -Wno-format-security #-Werror #-O2
GDB = -fstack-protector-all -g -ggdb -rdynamic #-gstabs
OBJS=test.o

all: test

%.o: %.c
	$(CC) $(STUFF) -fPIC $(GDB) -c $< -o $@ $(OPTS)

test : $(OBJS)
	$(CC) $(GDB) -o test $(OBJS) $(LIBS)

clean :
	rm -f test *.o
