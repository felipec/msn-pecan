CC := gcc

GOBJECT_CFLAGS := $(shell pkg-config --cflags gobject-2.0)
GOBJECT_LIBS := $(shell pkg-config --libs gobject-2.0)

CHECK_CFLAGS := $(shell pkg-config --cflags check)
CHECK_LIBS := $(shell pkg-config --libs check)

CFLAGS := -Wall -ggdb -I..

cmd_parser_test_objects := cmd_parser.o \
			   ../io/pn_cmd_server.o \
			   ../io/pn_node.o \
			   ../cmd/cmdproc.o \
			   ../cmd/command.o \
			   ../cmd/transaction.o \
			   ../cmd/msg.o \
			   ../pn_log.o

buffer_test_objects := buffer.o \
		       ../pn_buffer.o

ab_test_objects := ab.o \
		   ../ab/pn_contact.o \
		   ../ab/pn_group.o \
		   ../ab/pn_contactlist.o \
		   ../pn_util.o

printf_test_objects := printf.o \
		       ../pn_printf.o

# from Lauri Leukkunen's build system
ifdef V
Q = 
P = @printf "" # <- space before hash is important!!!
else
P = @printf "[%s] $@\n" # <- space before hash is important!!!
Q = @
endif

all: 

check_buffer: buffer.o ../pn_buffer.o
check_buffer: CFLAGS := $(CFLAGS) $(GOBJECT_CFLAGS) $(CHECK_CFLAGS)
check_buffer: LIBS := $(GOBJECT_LIBS) $(CHECK_LIBS)

checks += check_buffer

check_parser: parser.o ../io/pn_parser.o ../io/pn_node.o ../io/pn_stream.o ../pn_log.o ../pn_printf.o
check_parser: CFLAGS := $(CFLAGS) $(GOBJECT_CFLAGS) $(CHECK_CFLAGS)
check_parser: LIBS := $(GOBJECT_LIBS) $(CHECK_LIBS)

checks += check_parser

check_util: util.o ../pn_util.o
check_util: CFLAGS := $(CFLAGS) $(GOBJECT_CFLAGS) $(CHECK_CFLAGS)
check_util: LIBS := $(GOBJECT_LIBS) $(CHECK_LIBS)

checks += check_util

check_printf: printf.o ../pn_printf.o
check_printf: CFLAGS := $(CFLAGS) $(GOBJECT_CFLAGS) $(CHECK_CFLAGS)
check_printf: LIBS := $(GOBJECT_LIBS) $(CHECK_LIBS)

checks += check_printf

all: $(checks)

check_%::
	$(P)LINK
	$(Q)$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

cmd_parser_test: $(cmd_parser_test_objects)
	$(CC) $(GOBJECT_LIBS) $+ -o $@

ab_test: $(ab_test_objects)
	$(CC) $(GOBJECT_LIBS) $+ -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(GOBJECT_CFLAGS) $< -c -o $@

clean:
	rm -f printf_test $(printf_test_objects)
	rm -f ab_test $(ab_test_objects)
	rm -f cmd_parser_test $(cmd_parser_test_objects)
	rm -f $(checks)
	find . -name "*.o" | xargs rm -f
