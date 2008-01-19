/**
 * Copyright (C) 2007 Felipe Contreras
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

#include "msn_io.h"

GIOStatus
msn_io_read (GIOChannel *channel,
             gchar *buf,
             gsize count,
             gsize *bytes_read)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *error = NULL;

    status = g_io_channel_read_chars (channel, buf, count, bytes_read, &error);

    if (status == G_IO_STATUS_AGAIN)
        return status;

    if (status != G_IO_STATUS_NORMAL)
    {
        purple_debug_error ("msn", "error reading: %s\n", error->message);
        return status;
    }

    return status;
}

GIOStatus
msn_io_write (GIOChannel *channel,
              const gchar *buf,
              gsize count,
              gsize *bytes_written)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *error = NULL;

    status = g_io_channel_write_chars (channel, buf, count, bytes_written, &error);

    if (status == G_IO_STATUS_AGAIN)
        return status;

    if (status != G_IO_STATUS_NORMAL)
    {
        purple_debug_error ("msn", "error writing: %s\n", error->message);
        return status;
    }

    return status;
}

GIOStatus
msn_io_read_full (GIOChannel *channel,
                  gchar *buf,
                  gsize count,
                  gsize *bytes_read)
{
    GIOStatus status = G_IO_STATUS_NORMAL;

    while (TRUE)
    {
        GError *error = NULL;

        status = g_io_channel_read_chars (channel, buf, count, bytes_read, &error);

        if (status == G_IO_STATUS_AGAIN)
            continue;

        if (status != G_IO_STATUS_NORMAL)
        {
            purple_debug_error ("msn", "error reading: %s\n", error->message);
            return status;
        }

        break;
    }

    return status;
}

GIOStatus
msn_io_write_full (GIOChannel *channel,
                   const gchar *buf,
                   gsize count,
                   gsize *bytes_written)
{
    GIOStatus status = G_IO_STATUS_NORMAL;

    while (TRUE)
    {
        GError *error = NULL;

        purple_debug_error ("msn", "write_chars\n");
        status = g_io_channel_write_chars (channel, buf, count, bytes_written, &error);

        if (status == G_IO_STATUS_AGAIN)
            continue;

        if (status != G_IO_STATUS_NORMAL)
        {
            purple_debug_error ("msn", "error writing: %s\n", error->message);
            return status;
        }

        break;
    }

    return status;
}

GIOStatus
msn_io_flush (GIOChannel *channel)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *error = NULL;

    status = g_io_channel_flush (channel, &error);

    if (status == G_IO_STATUS_ERROR)
    {
        purple_debug_error ("msn", "error flushing: %s\n", error->message);
        return status;
    }

    purple_debug_info ("msn", "flushed\n");

    return status;
}
