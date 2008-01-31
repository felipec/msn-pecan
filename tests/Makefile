CC=gcc

GOBJECT_CFLAGS=`pkg-config --cflags gobject-2.0`
GOBJECT_LIBS=`pkg-config --libs gobject-2.0`

CFLAGS=-Wall -ggdb -I..

parse_test_objects=parse.o \
		   ../io/pecan_cmd_server.o \
		   ../io/pecan_node.o \
		   ../cmd/cmdproc.o \
		   ../cmd/command.o \
		   ../cmd/history.o \
		   ../cmd/transaction.o \
		   ../cmd/msg.o \
		   ../msn_io.o \
		   ../msn_log.o

buffer_test_objects=buffer.o \
		   ../io/pecan_buffer.o

all: parse_test buffer_test

parse_test: $(parse_test_objects)
	$(CC) $(GOBJECT_LIBS) $+ -o $@

buffer_test: $(buffer_test_objects)
	$(CC) $(GOBJECT_LIBS) $+ -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(GOBJECT_CFLAGS) $< -c -o $@

clean:
	rm -f parse_test $(parse_test_objects)
	rm -f buffer_test $(buffer_test_objects)
