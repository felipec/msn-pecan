/**
 * Copyright (C) 2007-2008 Felipe Contreras
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#ifndef PECAN_STREAM_H
#define PECAN_STREAM_H

#include <glib.h>

typedef struct PecanStream PecanStream;

struct PecanStream
{
    GIOChannel *channel;
#ifdef PECAN_DUMP_FILE
    gboolean dump;
#endif /* PECAN_DUMP_FILE */
};

PecanStream *pecan_stream_new (gint source);
void pecan_stream_free (PecanStream *stream);
GIOStatus pecan_stream_read (PecanStream *stream, gchar *buf, gsize count, gsize *bytes_read, GError **error);
GIOStatus pecan_stream_write (PecanStream *stream, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
GIOStatus pecan_stream_read_full (PecanStream *stream, gchar *buf, gsize count, gsize *bytes_read, GError **error);
GIOStatus pecan_stream_write_full (PecanStream *stream, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
GIOStatus pecan_stream_flush (PecanStream *stream, GError **error);
GIOStatus pecan_stream_read_line (PecanStream *stream, gchar **str_return, gsize *length, gsize *terminator_pos, GError **error);

#endif /* PECAN_STREAM_H */
