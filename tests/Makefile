CC=gcc

GOBJECT_CFLAGS=`pkg-config --cflags gobject-2.0`
GOBJECT_LIBS=`pkg-config --libs gobject-2.0`

CHECK_CFLAGS=`pkg-config --cflags check`
CHECK_LIBS=`pkg-config --libs check`

CFLAGS=-Wall -ggdb -I..

cmd_parser_test_objects=cmd_parser.o \
			../io/pecan_cmd_server.o \
			../io/pecan_node.o \
			../cmd/cmdproc.o \
			../cmd/command.o \
			../cmd/history.o \
			../cmd/transaction.o \
			../cmd/msg.o \
			../pecan_log.o

buffer_test_objects=buffer.o \
		   ../io/pecan_buffer.o

ab_test_objects=ab.o \
		../ab/pecan_contact.o \
		../ab/pecan_group.o \
		../ab/pecan_contactlist.o \
		../pecan_util.o

printf_test_objects=printf.o \
		    ../pecan_printf.o

# from Lauri Leukkunen's build system
ifdef V
Q = 
P = @printf "" # <- space before hash is important!!!
else
P = @printf "[%s] $@\n" # <- space before hash is important!!!
Q = @
endif

all: 

check_buffer: buffer.o ../io/pecan_buffer.o
check_buffer: CFLAGS := $(CFLAGS) $(GOBJECT_CFLAGS) $(CHECK_CFLAGS)
check_buffer: LIBS := $(GOBJECT_LIBS) $(CHECK_LIBS)

checks += check_buffer

all: $(checks)

check_%::
	$(P)LINK
	$(Q)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

cmd_parser_test: $(cmd_parser_test_objects)
	$(CC) $(GOBJECT_LIBS) $+ -o $@

ab_test: $(ab_test_objects)
	$(CC) $(GOBJECT_LIBS) $+ -o $@

printf_test: $(printf_test_objects)
	$(CC) $(GOBJECT_LIBS) $+ -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(GOBJECT_CFLAGS) $< -c -o $@

clean:
	rm -f printf_test $(printf_test_objects)
	rm -f ab_test $(ab_test_objects)
	rm -f cmd_parser_test $(cmd_parser_test_objects)
	rm -f $(checks)
	find . -name "*.o" | xargs rm -f
