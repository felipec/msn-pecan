/**
 * Copyright (C) 2007-2009 Felipe Contreras
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef PN_STREAM_H
#define PN_STREAM_H

#include <glib.h>

typedef struct PnStream PnStream;

struct PnStream
{
    GIOChannel *channel;
#ifdef PECAN_DUMP_FILE
    gboolean dump;
#endif /* PECAN_DUMP_FILE */
};

PnStream *pn_stream_new (gint source);
void pn_stream_free (PnStream *stream);
GIOStatus pn_stream_read (PnStream *stream, gchar *buf, gsize count, gsize *bytes_read, GError **error);
GIOStatus pn_stream_write (PnStream *stream, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
GIOStatus pn_stream_read_full (PnStream *stream, gchar *buf, gsize count, gsize *bytes_read, GError **error);
GIOStatus pn_stream_write_full (PnStream *stream, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
GIOStatus pn_stream_flush (PnStream *stream, GError **error);
GIOStatus pn_stream_read_line (PnStream *stream, gchar **str_return, gsize *length, gsize *terminator_pos, GError **error);

#endif /* PN_STREAM_H */
