CC=gcc
XGETTEXT=xgettext
MSGFMT=msgfmt

PLATFORM=$(shell uname -s)

PURPLE_CFLAGS=`pkg-config --cflags purple`
PURPLE_LIBS=`pkg-config --libs purple`
PURPLE_PREFIX=`pkg-config --variable=prefix purple`

GOBJECT_CFLAGS=`pkg-config --cflags gobject-2.0`
GOBJECT_LIBS=`pkg-config --libs gobject-2.0`

CVR = y

ifdef DEBUG
CFLAGS+=-ggdb
else
CFLAGS+=-O2
endif

EXTRA_WARNINGS=-Wall -Wextra -Wformat-nonliteral -Wcast-align -Wpointer-arith \
	       -Wbad-function-cast -Wmissing-prototypes -Wstrict-prototypes \
	       -Wmissing-declarations -Winline -Wundef -Wnested-externs -Wcast-qual \
	       -Wshadow -Wwrite-strings -Wno-unused-parameter -Wfloat-equal -ansi -std=c99

SIMPLE_WARNINGS=-Wextra -ansi -std=c99 -Wno-unused-parameter

OTHER_WARNINGS=-D_FORTIFY_SOURCE=2 -fstack-protector -g3 -Wdisabled-optimization \
	       -Wendif-labels -Wformat=2 -Wstack-protector -Wswitch

CFLAGS+=-Wall # $(EXTRA_WARNINGS)

override CFLAGS+=-I. -D PACKAGE='"libmsn-pecan"' -DENABLE_NLS -DHAVE_LIBPURPLE -DPURPLE_DEBUG -D PLUGIN_NAME='msn-pecan'
ifdef CVR
override CFLAGS+=-DPECAN_CVR
endif

# For glib < 2.6 support (libpurple maniacs)
FALLBACK_CFLAGS+=-I./fix_purple

LDFLAGS:=-Wl,--no-undefined

prefix=$(DESTDIR)/$(PURPLE_PREFIX)
plugin_dir=$(prefix)/lib/purple-2
data_dir=$(prefix)/share

objects = \
	  msn.o \
	  nexus.o \
	  notification.o \
	  page.o \
	  session.o \
	  switchboard.o \
	  sync.o \
	  pecan_log.o \
	  pecan_printf.o \
	  pecan_util.o \
	  pecan_error.o \
	  pecan_status.o \
	  pecan_oim.o \
	  pecan_ud.o \
	  cmd/cmdproc.o \
	  cmd/command.o \
	  cmd/history.o \
	  cmd/msg.o \
	  cmd/table.o \
	  cmd/transaction.o \
	  io/pecan_buffer.o \
	  io/pecan_parser.o \
	  ab/pecan_group.o \
	  ab/pecan_contact.o \
	  ab/pecan_contactlist.o \
	  io/pecan_stream.o \
	  io/pecan_node.o \
	  io/pecan_cmd_server.o \
	  io/pecan_http_server.o \
	  io/pecan_ssl_conn.o \
	  io/pecan_socket.o \
	  fix_purple.o

ifdef CVR
objects += cvr/slp.o \
	   cvr/slpcall.o \
	   cvr/slplink.o \
	   cvr/slpmsg.o \
	   cvr/slpsession.o \
	   cvr/pecan_slp_object.o
endif

ifdef DIRECTCONN
objects += directconn.o
override CFLAGS += -DMSN_DIRECTCONN
endif

sources = $(patsubst %.o,%.c,$(objects))

PO_TEMPLATE = po/messages.pot
CATALOGS = nl fi fr it sr es sv

ifeq ($(PLATFORM),Darwin)
	SHLIBEXT=dylib
else
ifeq ($(PLATFORM),win32)
	SHLIBEXT=dll
	LDFLAGS:=-Wl,--enable-auto-image-base -Wl,--exclude-libs=libintl.a
else
	SHLIBEXT=so
endif
endif

ifdef STATIC
	plugin=libmsn-pecan.a
	override CFLAGS += -DPURPLE_STATIC_PRPL
else
	plugin=libmsn-pecan.$(SHLIBEXT)
	override CFLAGS += -fPIC
endif

.PHONY: all clean

all: $(plugin)

version := $(shell ./get-version.sh)

# from Lauri Leukkunen's build system
ifdef V
Q = 
P = @printf "" # <- space before hash is important!!!
else
P = @printf "[%s] $@\n" # <- space before hash is important!!!
Q = @
endif

$(plugin): $(objects)
$(plugin): CFLAGS := $(CFLAGS) $(PURPLE_CFLAGS) $(GOBJECT_CFLAGS) $(FALLBACK_CFLAGS) -D VERSION='"$(version)"'
$(plugin): LIBS := $(PURPLE_LIBS) $(GOBJECT_LIBS)

%.dylib::
	$(P)DYLIB
	$(Q)$(CC) $(LDFLAGS) -dynamiclib -o $@ $^ $(LIBS)

%.dll::
	$(P)SHLIB
	$(Q)$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)

%.so::
	$(P)SHLIB
	$(Q)$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)

%.a::
	$(P)ARCHIVE
	$(AR) rcs $@ $^

%.o:: %.c
	$(P)CC
	$(Q)$(CC) $(CFLAGS) -Wp,-MMD,$(dir $@).$(notdir $@).d -o $@ -c $<

clean:
	find -name '*.mo' -delete
	rm -f $(plugin) $(objects)

depend:
	makedepend -Y -- $(CFLAGS) -- $(sources)

po:
	mkdir -p $@

$(PO_TEMPLATE): $(sources) | po
	$(XGETTEXT) -kmc --keyword=_ --keyword=N_ -o $@ $(sources)

dist:
	git archive --format=tar --prefix=msn-pecan-$(version)/ HEAD > /tmp/msn-pecan-$(version).tar
	mkdir -p msn-pecan-$(version)
	git-changelog > msn-pecan-$(version)/ChangeLog
	chmod 664 msn-pecan-$(version)/ChangeLog
	tar --append -f /tmp/msn-pecan-$(version).tar --owner root --group root msn-pecan-$(version)/ChangeLog
	echo $(version) > msn-pecan-$(version)/version
	chmod 664 msn-pecan-$(version)/version
	tar --append -f /tmp/msn-pecan-$(version).tar --owner root --group root msn-pecan-$(version)/version
	rm -r msn-pecan-$(version)
	bzip2 /tmp/msn-pecan-$(version).tar

install: $(plugin)
	mkdir -p $(plugin_dir)
	install $(plugin) $(plugin_dir)
	# chcon -t textrel_shlib_t $(plugin_dir)/$(plugin)

%.mo:: %.po
	$(MSGFMT) -c -o $@ $<

install_locales: $(foreach e,$(CATALOGS),po/libmsn-pecan-$(e).mo)
	for x in $(CATALOGS); do \
	install -D po/libmsn-pecan-$$x.mo $(data_dir)/locale/$$x/LC_MESSAGES/libmsn-pecan.mo; \
	done
