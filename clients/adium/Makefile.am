pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

MSNSOURCES = \
	msn.c \
	nexus.c \
	notification.c \
	page.c \
	session.c \
	switchboard.c \
	sync.c \
	pn_log.c \
	pn_printf.c \
	pn_util.c \
	pn_buffer.c \
	pn_error.c \
	pn_status.c \
	pn_oim.c \
	pn_dp_manager.c \
	pn_siren7.c \
	cmd/cmdproc.c \
	cmd/command.c \
	cmd/msg.c \
	cmd/table.c \
	cmd/transaction.c \
	io/pn_parser.c \
	ab/pn_group.c \
	ab/pn_contact.c \
	ab/pn_contactlist.c \
	io/pn_stream.c \
	io/pn_node.c \
	io/pn_cmd_server.c \
	io/pn_http_server.c \
	io/pn_ssl_conn.c \
	io/pn_dc_conn.c \
	cvr/pn_peer_call.c \
	cvr/pn_peer_link.c \
	cvr/pn_peer_msg.c \
	cvr/pn_msnobj.c \
	cvr/pn_direct_conn.c \
	libpurple/xfer.c \
	ext/libsiren/common.c \
	ext/libsiren/dct4.c \
	ext/libsiren/decoder.c \
	ext/libsiren/huffman.c \
	ext/libsiren/rmlt.c \
	ext/libmspack/cabd.c \
	ext/libmspack/mszipd.c \
	ext/libmspack/lzxd.c \
	ext/libmspack/qtmd.c \
	ext/libmspack/system.c \
	fix_purple.c

AM_CFLAGS = $(st)

version := $(shell $(srcdir)/get-version)

libmsn_pecan_la_LDFLAGS = -module -avoid-version -lm

st = -DPURPLE_STATIC_PRPL
noinst_LTLIBRARIES = libmsn_pecan.la
libmsn_pecan_la_SOURCES = $(MSNSOURCES)
libmsn_pecan_la_CFLAGS = $(AM_CFLAGS)

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(GLIB_CFLAGS) \
	$(DEBUG_CFLAGS) \
	-DSTATIC_PECAN \
	-DHAVE_LIBPURPLE \
	-D_XOPEN_SOURCE \
	-DINTERNAL_MAINLOOP \
	-DADIUM \
	-DPURPLE_DEBUG \
	-DPECAN_DEBUG_SLP \
	-DPECAN_CVR \
	-DMSN_DIRECTCONN \
	-DPECAN_USE_PSM \
	-DPECAN_LIBSIREN \
	-DRECEIVE_PLUS_SOUNDS \
	-DGETTEXT_PACKAGE='"pidgin"' \
	-DENABLE_NLS \
	-DVERSION='"$(version)"'
