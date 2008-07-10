EXTRA_DIST = directconn.c \
	     directconn.h

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

MSNSOURCES = error.c \
	     msn.c \
	     nexus.c \
	     notification.c \
	     page.c \
	     session.c \
	     switchboard.c \
	     sync.c \
	     pecan_log.c \
	     pecan_printf.c \
	     pecan_util.c \
	     pecan_status.c \
	     cmd/cmdproc.c \
	     cmd/command.c \
	     cmd/history.c \
	     cmd/msg.c \
	     cmd/table.c \
	     cmd/transaction.c \
	     io/pecan_buffer.c \
	     ab/pecan_group.c \
	     ab/pecan_contact.c \
	     ab/pecan_contactlist.c \
	     io/pecan_stream.c \
	     io/pecan_node.c \
	     io/pecan_cmd_server.c \
	     io/pecan_http_server.c \
	     cvr/slp.c \
	     cvr/slpcall.c \
	     cvr/slplink.c \
	     cvr/slpmsg.c \
	     cvr/slpsession.c \
	     cvr/pecan_slp_object.c \
	     fix_purple.c

AM_CFLAGS = $(st)

version := $(shell $(srcdir)/get-version.sh)

libmsn_pecan_la_LDFLAGS = -module -avoid-version

if STATIC_MSN

st = -DPURPLE_STATIC_PRPL
noinst_LIBRARIES = libmsn_pecan.a
libmsn_pecan_a_SOURCES = $(MSNSOURCES)
libmsn_pecan_a_CFLAGS = $(AM_CFLAGS)

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
	      -D HAVE_LIBPURPLE \
	      -D PLUGIN_NAME='msn_pecan' \
	      -D VERSION='"$(version)"'
