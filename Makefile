CC := $(CROSS_COMPILE)gcc
WINDRES := $(CROSS_COMPILE)windres

XGETTEXT := xgettext
MSGFMT := msgfmt

PLATFORM := $(shell $(CC) -dumpmachine | cut -f 3 -d -)

PURPLE_CFLAGS := $(shell pkg-config --cflags purple)
PURPLE_LIBS := $(shell pkg-config --libs purple)
PURPLE_LIBDIR := $(shell pkg-config --variable=libdir purple)
PURPLE_DATADIR := $(shell pkg-config --variable=datadir purple)
PURPLE_PLUGINDIR := $(PURPLE_LIBDIR)/purple-2

GIO_CFLAGS := $(shell pkg-config --cflags gio-2.0)
GIO_LIBS := $(shell pkg-config --libs gio-2.0)

# default configuration options
CVR := y
LIBSIREN := y
LIBMSPACK := y
PLUS_SOUNDS := y
DEBUG := y
DIRECTCONN := y

CFLAGS := -O2

ifdef DEBUG
  CFLAGS += -ggdb
endif

ifdef DEVEL
  CFLAGS += -DPECAN_DEVEL
endif

EXTRA_WARNINGS := -Wall -Wextra -Wformat-nonliteral -Wcast-align -Wpointer-arith \
	-Wbad-function-cast -Wmissing-prototypes -Wstrict-prototypes \
	-Wmissing-declarations -Winline -Wundef -Wnested-externs -Wcast-qual \
	-Wshadow -Wwrite-strings -Wno-unused-parameter -Wfloat-equal -ansi -std=c99

SIMPLE_WARNINGS := -Wextra -ansi -std=c99 -Wno-unused-parameter

OTHER_WARNINGS := -D_FORTIFY_SOURCE=2 -fstack-protector -g3 -Wdisabled-optimization \
	-Wendif-labels -Wformat=2 -Wstack-protector -Wswitch

CFLAGS += -Wall # $(EXTRA_WARNINGS)

override CFLAGS += -D_XOPEN_SOURCE
override CFLAGS += -I. -DENABLE_NLS -DHAVE_LIBPURPLE -DPURPLE_DEBUG

ifdef CVR
  override CFLAGS += -DPECAN_CVR
endif

ifndef DO_NOT_USE_PSM
  override CFLAGS += -DPECAN_USE_PSM
endif

ifdef LIBSIREN
  override CFLAGS += -DPECAN_LIBSIREN
  LIBSIREN_LIBS := -lm
endif

ifdef LIBMSPACK
  override CFLAGS += -DPECAN_LIBMSPACK
  LIBMSPACK_LIBS := -lm
endif

ifdef PLUS_SOUNDS
  override CFLAGS += -DRECEIVE_PLUS_SOUNDS
endif

ifdef GIO
  override CFLAGS += -DUSE_GIO
endif

# extra debugging
override CFLAGS += -DPECAN_DEBUG_SLP

LDFLAGS := -Wl,--no-undefined

objects := msn.o \
	   nexus.o \
	   notification.o \
	   page.o \
	   session.o \
	   switchboard.o \
	   sync.o \
	   pn_log.o \
	   pn_printf.o \
	   pn_util.o \
	   pn_buffer.o \
	   pn_error.o \
	   pn_status.o \
	   pn_oim.o \
	   pn_dp_manager.o \
	   cmd/cmdproc.o \
	   cmd/command.o \
	   cmd/msg.o \
	   cmd/table.o \
	   cmd/transaction.o \
	   io/pn_parser.o \
	   ab/pn_group.o \
	   ab/pn_contact.o \
	   ab/pn_contactlist.o \
	   io/pn_stream.o \
	   io/pn_node.o \
	   io/pn_cmd_server.o \
	   io/pn_http_server.o \
	   io/pn_ssl_conn.o \
	   fix_purple.o

ifdef CVR
  objects += cvr/pn_peer_call.o \
	     cvr/pn_peer_link.o \
	     cvr/pn_peer_msg.o \
	     cvr/pn_msnobj.o
  objects += libpurple/xfer.o
endif

ifdef DIRECTCONN
  objects += cvr/pn_direct_conn.o
  override CFLAGS += -DMSN_DIRECTCONN
endif

ifdef LIBSIREN
  objects += ext/libsiren/common.o \
	     ext/libsiren/dct4.o \
	     ext/libsiren/decoder.o \
	     ext/libsiren/huffman.o \
	     ext/libsiren/rmlt.o \
	     pn_siren7.o
endif

ifdef LIBMSPACK
  objects += ext/libmspack/cabd.o \
	     ext/libmspack/mszipd.o \
	     ext/libmspack/lzxd.o \
	     ext/libmspack/qtmd.o \
	     ext/libmspack/system.o
endif

sources := $(objects:.o=.c)
deps := $(objects:.o=.d)

PO_TEMPLATE := po/messages.pot
CATALOGS := ar da de eo es fi fr tr hu it nb nl pt_BR pt sr sv tr zh_CN zh_TW

ifeq ($(PLATFORM),darwin)
  SHLIBEXT := dylib
else
ifeq ($(PLATFORM),mingw32)
  SHLIBEXT := dll
  LDFLAGS += -Wl,--enable-auto-image-base -L./win32
  objects += win32/resource.res
else
  SHLIBEXT := so
endif
endif

ifdef STATIC
  plugin := libmsn-pecan.a
  override CFLAGS += -DPURPLE_STATIC_PRPL
else
  plugin := libmsn-pecan.$(SHLIBEXT)
ifneq ($(PLATFORM),mingw32)
  override CFLAGS += -fPIC
endif
endif

.PHONY: clean

all: $(plugin)

version := $(shell ./get-version)

# pretty print
V = @
Q = $(V:y=)
QUIET_CC    = $(Q:@=@echo '   CC         '$@;)
QUIET_LINK  = $(Q:@=@echo '   LINK       '$@;)
QUIET_CLEAN = $(Q:@=@echo '   CLEAN      '$@;)
QUIET_MO    = $(Q:@=@echo '   MSGFMT     '$@;)
QUIET_WR    = $(Q:@=@echo '   WINDRES    '$@;)

D = $(DESTDIR)

plugin_libs := $(PURPLE_LIBS) $(GIO_LIBS)

ifdef LIBSIREN
  plugin_libs += $(LIBSIREN_LIBS)
endif

ifdef LIBMSPACK
  plugin_libs += $(LIBMSPACK_LIBS)
endif

$(plugin): $(objects)
$(plugin): CFLAGS := $(CFLAGS) $(PURPLE_CFLAGS) $(GIO_CFLAGS) $(FALLBACK_CFLAGS) -D VERSION='"$(version)"'
$(plugin): LIBS := $(plugin_libs)

messages.pot: $(sources)
	$(XGETTEXT) -kmc --keyword=_ --keyword=N_ -o $@ $(sources)

%.dylib::
	$(QUIET_LINK)$(CC) $(LDFLAGS) -dynamiclib -o $@ $^ $(LIBS)

%.so %.dll::
	$(QUIET_LINK)$(CC) $(LDFLAGS) -shared -o $@ $^ $(LIBS)

%.a::
	$(QUIET_LINK)$(AR) rcs $@ $^

%.o:: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) -MMD -o $@ -c $<

%.res:: %.rc
	$(QUIET_WR)$(WINDRES) $< -O coff -o $@

clean:
	$(QUIET_CLEAN)$(RM) $(plugin) $(objects) $(deps) `find -name '*.mo'`

%.mo:: %.po
	$(QUIET_MO)$(MSGFMT) -c -o $@ $<

dist: base := msn-pecan-$(version)
dist:
	git archive --format=tar --prefix=$(base)/ HEAD > /tmp/$(base).tar
	mkdir -p $(base)
	git-changelog > $(base)/ChangeLog
	chmod 664 $(base)/ChangeLog
	tar --append -f /tmp/$(base).tar --owner root --group root $(base)/ChangeLog
	echo $(version) > $(base)/.version
	chmod 664 $(base)/.version
	tar --append -f /tmp/$(base).tar --owner root --group root $(base)/.version
	rm -r $(base)
	bzip2 /tmp/$(base).tar

install: $(plugin)
	mkdir -p $(D)/$(PURPLE_PLUGINDIR)
	install $(plugin) $(D)/$(PURPLE_PLUGINDIR)
	# chcon -t textrel_shlib_t $(D)/$(PURPLE_PLUGINDIR)/$(plugin) # for selinux

uninstall:
	rm -f $(D)/$(PURPLE_PLUGINDIR)/$(plugin)
	for x in $(CATALOGS); do \
	rm -f $(D)/$(PURPLE_DATADIR)/locale/$$x/LC_MESSAGES/libmsn-pecan.mo; \
	done

install_locales: $(foreach e,$(CATALOGS),po/$(e).mo)
	for x in $(CATALOGS); do \
	install -D po/$$x.mo $(D)/$(PURPLE_DATADIR)/locale/$$x/LC_MESSAGES/libmsn-pecan.mo; \
	done

-include $(deps)
