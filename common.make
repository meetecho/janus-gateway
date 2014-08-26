CC = gcc
OPTS = -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wunused -Wno-format-security #-Werror #-O2
GDB = -fstack-protector-all -g -ggdb -rdynamic #-gstabs

%.o: %.c
	$(CC) $(STUFF) -fPIC $(GDB) -c $< -o $@ $(OPTS) $(CFLAGS)

$(BINS): $(OBJS)
ifndef INSTALLSH
	$(error Please use the install.sh script to compile $(BINS))
endif
	$(CC) $(GDB) -o $@ $(OBJS) $(LIBS) $(LDFLAGS)
