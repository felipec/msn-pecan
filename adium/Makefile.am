EXTRA_DIST = directconn.c \
	     directconn.h

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

MSNSOURCES = msn.c \
	     nexus.c \
	     notification.c \
	     page.c \
	     session.c \
	     switchboard.c \
	     sync.c \
	     pn_log.c \
	     pn_printf.c \
	     pn_util.c \
	     pn_error.c \
	     pecan_status.c \
	     pn_oim.c \
	     pn_dp_manager.c \
	     pn_siren7.c \
	     cmd/cmdproc.c \
	     cmd/command.c \
	     cmd/history.c \
	     cmd/msg.c \
	     cmd/table.c \
	     cmd/transaction.c \
	     io/pn_buffer.c \
	     io/pn_parser.c \
	     ab/pn_group.c \
	     ab/pn_contact.c \
	     ab/pn_contactlist.c \
	     io/pn_stream.c \
	     io/pn_node.c \
	     io/pn_cmd_server.c \
	     io/pn_http_server.c \
	     io/pn_ssl_conn.c \
	     cvr/slp.c \
	     cvr/slpcall.c \
	     cvr/slplink.c \
	     cvr/slpmsg.c \
	     cvr/pn_msnobj.c \
	     cvr/xfer.c \
	     lib/libsiren/common.c \
	     lib/libsiren/dct4.c \
	     lib/libsiren/decoder.c \
	     lib/libsiren/huffman.c \
	     lib/libsiren/rmlt.c \
	     fix_purple.c

AM_CFLAGS = $(st)

version := $(shell $(srcdir)/get-version.sh)

libmsn_pecan_la_LDFLAGS = -module -avoid-version -lm

if STATIC_MSN

st = -DPURPLE_STATIC_PRPL
noinst_LTLIBRARIES = libmsn_pecan.la
libmsn_pecan_la_SOURCES = $(MSNSOURCES)
libmsn_pecan_la_CFLAGS = $(AM_CFLAGS)

else

st =
pkg_LTLIBRARIES   = libmsn_pecan.la
libmsn_pecan_la_SOURCES = $(MSNSOURCES)
libmsn_pecan_la_LIBADD = $(GLIB_LIBS)

endif

AM_CPPFLAGS = \
	      -I$(top_srcdir)/libpurple \
	      -I$(top_builddir)/libpurple \
	      $(GLIB_CFLAGS) \
	      $(DEBUG_CFLAGS) \
	      -DSTATIC_PECAN \
	      -DHAVE_LIBPURPLE \
	      -D_XOPEN_SOURCE \
	      -DADIUM \
	      -DPURPLE_DEBUG \
	      -DPECAN_DEBUG_SLP \
	      -DPECAN_CVR \
	      -DPECAN_USE_PSM \
	      -DPECAN_LIBSIREN \
	      -DRECEIVE_PLUS_SOUNDS \
	      -DGETTEXT_PACKAGE='"pidgin"' \
	      -DENABLE_NLS \
	      -DVERSION='"$(version)"'
