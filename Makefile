CC=gcc

PURPLE_CFLAGS=`pkg-config --cflags purple`
PURPLE_LIBS=`pkg-config --libs purple`
PURPLE_PREFIX=`pkg-config --variable=prefix purple`

CFLAGS=-Wall -ggdb -I. -DMSN_DEBUG

purpledir=$(DESTDIR)/$(PURPLE_PREFIX)/lib/purple-2

objects = \
	directconn.o \
	error.o \
	msn.o \
	nexus.o \
	notification.o \
	object.o \
	page.o \
	session.o \
	state.o \
	switchboard.o \
	sync.o \
	msn_io.o \
	msn_log.o \
	msn_util.o \
	cmd/cmdproc.o \
	cmd/command.o \
	cmd/history.o \
	cmd/msg.o \
	cmd/table.o \
	cmd/transaction.o \
	ab/group.o \
	ab/user.o \
	ab/userlist.o \
	io/pecan_node.o \
	io/pecan_cmd_server.o \
	io/pecan_http_server.o \
	cvr/slp.o \
	cvr/slpcall.o \
	cvr/slplink.o \
	cvr/slpmsg.o \
	cvr/slpsession.o \
	fix-purple.o

sources = $(patsubst %.o,%.c,$(objects))

all: libmsn-pecan.so

libmsn-pecan.so: $(objects)
	$(CC) $(PURPLE_LIBS) $+ -shared -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(PURPLE_CFLAGS) $< -c -o $@

clean:
	rm -f libmsn-pecan.so $(objects)

depend:
	makedepend -Y -- $(CFLAGS) -- $(sources)

install: libmsn-pecan.so
	mkdir -p $(purpledir)
	install libmsn-pecan.so $(purpledir)
	# chcon -t textrel_shlib_t /usr/lib/purple-2/libmsn-pecan.so
