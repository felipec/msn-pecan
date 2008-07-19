/*
 * Copyright (C) 2008 Felipe Contreras.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <glib.h>

#include "io/pecan_parser_priv.h"

#include "pecan_config.h"
#include "pecan_log.h"

#include <string.h> /* for memcpy */

PecanParser *
pecan_parser_new (PecanNode *node)
{
    PecanParser *parser;
    parser = g_new0 (PecanParser, 1);
    parser->node = node;
    parser->need_more = TRUE;
    return parser;
}

void
pecan_parser_free (PecanParser *parser)
{
    if (!parser)
        return;
    g_free (parser->rx_buf);
    g_free (parser);
}

GIOStatus
pecan_parser_read_line (PecanParser *parser,
                        gchar **str_return,
                        gsize *length,
                        gsize *terminator_pos,
                        GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    gchar *cur;
    gchar *next;
    gint cur_len;

    pecan_log ("begin");

    if (parser->need_more)
    {
        gchar buf[MSN_BUF_LEN + 1];
        gsize bytes_read;

        status = pecan_node_read (parser->node, buf, MSN_BUF_LEN, &bytes_read, NULL);

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        /* append buf to rx_buf */
        parser->rx_buf = g_realloc (parser->rx_buf, bytes_read + parser->rx_len + 1);
        memcpy (parser->rx_buf + parser->rx_len, buf, bytes_read + 1);
        parser->rx_len += bytes_read;
    }

    cur = parser->rx_buf;

    next = strstr (cur, "\r\n");

    if (!next)
    {
        /* The line is incomplete. */
        parser->need_more = TRUE;
        status = G_IO_STATUS_AGAIN;
        goto leave;
    }

    next += 2;
    cur_len = next - cur;

    if (str_return)
        *str_return = g_strndup (cur, cur_len);

    if (length)
        *length = cur_len;

    if (terminator_pos)
        *terminator_pos = cur_len - 2;

    {
        gchar *tmp;

        parser->rx_len -= cur_len;

        tmp = parser->rx_buf;

        if (parser->rx_len > 0)
        {
            parser->rx_buf = g_memdup (next, parser->rx_len);
            parser->need_more = FALSE;
        }
        else
        {
            parser->rx_buf = NULL;
            parser->need_more = TRUE;
        }

        g_free (tmp);
    }

leave:
    if (status != G_IO_STATUS_NORMAL)
    {
        if (str_return)
            *str_return = NULL;

        if (length)
            *length = 0;

        if (terminator_pos)
            *terminator_pos = 0;
    }

    pecan_log ("end");

    return status;
}
