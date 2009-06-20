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

#include "pn_stream.h"
#include "pn_log.h"

#include <string.h>

PnStream *
pn_stream_new (gint fd)
{
    PnStream *stream;
    stream = g_new (PnStream, 1);
    stream->channel = g_io_channel_unix_new (fd);
#ifdef PECAN_DUMP_FILE
    stream->dump = FALSE;
#endif /* PECAN_DUMP_FILE */
    return stream;
}

void
pn_stream_free (PnStream *stream)
{
    if (!stream)
        return;

    g_io_channel_shutdown (stream->channel, FALSE, NULL);
    g_io_channel_unref (stream->channel);

    g_free (stream);
}

GIOStatus
pn_stream_read (PnStream *stream,
                gchar *buf,
                gsize count,
                gsize *bytes_read,
                GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize tmp_bytes_read = 0;

    g_return_val_if_fail (stream, G_IO_STATUS_ERROR);

#if defined(PN_STREAM_RANDOM_ERRORS)
    if (g_random_int_range (0, 75) == 1)
    {
        tmp_error = g_error_new_literal (G_IO_CHANNEL_ERROR, G_IO_CHANNEL_ERROR_FAILED,
                                         "Randomly introduced error");
        goto skip;
    }
#endif /* defined(PN_STREAM_RANDOM_ERRORS) */

    status = g_io_channel_read_chars (stream->channel, buf, count,
                                      &tmp_bytes_read, &tmp_error);

#ifdef PECAN_DUMP_FILE
    if (stream->dump)
        pn_dump_file (buf, tmp_bytes_read);
#endif /* PECAN_DUMP_FILE */

#if defined(PN_STREAM_RANDOM_ERRORS)
skip:
#endif /* defined(PN_STREAM_RANDOM_ERRORS) */

    if (tmp_error)
    {
        pn_error ("error reading: %s", tmp_error->message);
        g_propagate_error (error, tmp_error);
    }

    if (bytes_read)
        *bytes_read = tmp_bytes_read;

    return status;
}

GIOStatus
pn_stream_write (PnStream *stream,
                 const gchar *buf,
                 gsize count,
                 gsize *bytes_written,
                 GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize tmp_bytes_written = 0;

    g_return_val_if_fail (stream, G_IO_STATUS_ERROR);

#if defined(PN_STREAM_RANDOM_ERRORS)
    if (g_random_int_range (0, 75) == 1)
    {
        tmp_error = g_error_new_literal (G_IO_CHANNEL_ERROR, G_IO_CHANNEL_ERROR_FAILED,
                                         "Randomly introduced error");
        goto skip;
    }
#endif /* defined(PN_STREAM_RANDOM_ERRORS) */

    status = g_io_channel_write_chars (stream->channel, buf, count,
                                       &tmp_bytes_written, &tmp_error);

#ifdef PECAN_DUMP_FILE
    if (stream->dump)
        pn_dump_file (buf, tmp_bytes_written);
#endif /* PECAN_DUMP_FILE */

#if defined(PN_STREAM_RANDOM_ERRORS)
skip:
#endif /* defined(PN_STREAM_RANDOM_ERRORS) */

    if (tmp_error)
    {
        pn_error ("error writing: %s", tmp_error->message);
        g_propagate_error (error, tmp_error);
    }

    if (bytes_written)
        *bytes_written = tmp_bytes_written;

    return status;
}

GIOStatus
pn_stream_read_full (PnStream *stream,
                     gchar *buf,
                     gsize count,
                     gsize *bytes_read,
                     GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    gsize tmp_bytes_read = 0;

    g_return_val_if_fail (stream, G_IO_STATUS_ERROR);

    while (TRUE)
    {
        GError *tmp_error = NULL;

        status = g_io_channel_read_chars (stream->channel, buf, count,
                                          &tmp_bytes_read, &tmp_error);

        if (status == G_IO_STATUS_AGAIN)
            continue;

#ifdef PECAN_DUMP_FILE
        if (stream->dump)
            pn_dump_file (buf, tmp_bytes_read);
#endif /* PECAN_DUMP_FILE */

        if (tmp_error)
        {
            pn_error ("error reading: %s", tmp_error->message);
            g_propagate_error (error, tmp_error);
        }

        break;
    }

    if (bytes_read)
        *bytes_read = tmp_bytes_read;

    return status;
}

GIOStatus
pn_stream_write_full (PnStream *stream,
                      const gchar *buf,
                      gsize count,
                      gsize *bytes_written,
                      GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    gsize tmp_bytes_written = 0;

    g_return_val_if_fail (stream, G_IO_STATUS_ERROR);

    while (TRUE)
    {
        GError *tmp_error = NULL;

        status = g_io_channel_write_chars (stream->channel, buf, count,
                                           &tmp_bytes_written, &tmp_error);

        if (status == G_IO_STATUS_AGAIN)
            continue;

#ifdef PECAN_DUMP_FILE
        if (stream->dump)
            pn_dump_file (buf, tmp_bytes_written);
#endif /* PECAN_DUMP_FILE */

        if (tmp_error)
        {
            pn_error ("error writing: %s", tmp_error->message);
            g_propagate_error (error, tmp_error);
        }

        break;
    }

    if (bytes_written)
        *bytes_written = tmp_bytes_written;

    return status;
}

GIOStatus
pn_stream_flush (PnStream *stream,
                 GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;

    g_return_val_if_fail (stream, G_IO_STATUS_ERROR);

    status = g_io_channel_flush (stream->channel, &tmp_error);

    if (tmp_error)
    {
        pn_error ("error flushing: %s", tmp_error->message);
        g_propagate_error (error, tmp_error);
    }

    return status;
}

GIOStatus
pn_stream_read_line (PnStream *stream,
                     gchar **str_return,
                     gsize *length,
                     gsize *terminator_pos,
                     GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;

    g_return_val_if_fail (stream, G_IO_STATUS_ERROR);

    status = g_io_channel_read_line (stream->channel, str_return, length, terminator_pos, &tmp_error);

#ifdef PECAN_DUMP_FILE
    if (stream->dump)
        pn_dump_file (*str_return, strlen (*str_return));
#endif /* PECAN_DUMP_FILE */

    if (tmp_error)
    {
        pn_error ("error flushing: %s", tmp_error->message);
        g_propagate_error (error, tmp_error);
    }

    return status;
}
