CC = gcc
OPTS = -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
       -Wunused -fstrict-aliasing -Wextra -Wformat=2 -Winit-self -Winline \
       -Wpacked -Wpointer-arith -Wmissing-format-attribute -Wmissing-noreturn \
       -Wnested-externs -Wstrict-prototypes -Wunsafe-loop-optimizations \
       -Wwrite-strings -Wno-missing-field-initializers -Wno-unused-parameter \
       -Wcast-align -Wformat-nonliteral -Wformat-security -Wswitch-default \
       -Wmissing-include-dirs -Waggregate-return -Wunused-but-set-variable \
       -Warray-bounds -Wold-style-definition
GDB = -fstack-protector-all -g -ggdb -rdynamic #-gstabs

%.o: %.c
	$(CC) $(STUFF) -fPIC $(GDB) -c $< -o $@ $(OPTS) $(CFLAGS)

$(BINS): $(OBJS)
ifndef INSTALLSH
	$(error Please use the install.sh script to compile $(BINS))
endif
	$(CC) $(GDB) -o $@ $(OBJS) $(LIBS) $(LDFLAGS)
