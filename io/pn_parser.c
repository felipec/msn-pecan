/*
 * Copyright (C) 2008-2009 Felipe Contreras.
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

#include <glib.h>

#include "io/pn_parser.h"
#include "io/pn_node.h"

#include "pn_log.h"

#include <string.h> /* for memcpy */

struct PnParser
{
    PnNode *node;
    gchar *rx_buf;
    gsize rx_len;
    gboolean need_more;
};

PnParser *
pn_parser_new (PnNode *node)
{
    PnParser *parser;
    parser = g_new0 (PnParser, 1);
    parser->node = node;
    parser->need_more = TRUE;
    return parser;
}

void
pn_parser_free (PnParser *parser)
{
    if (!parser)
        return;
    g_free (parser->rx_buf);
    g_free (parser);
}

void
pn_parser_reset (PnParser *parser)
{
    g_free (parser->rx_buf);
    parser->rx_buf = NULL;
    parser->need_more = TRUE;
}

GIOStatus
pn_parser_read_line (PnParser *parser,
                     gchar **str_return,
                     gsize *length,
                     gsize *terminator_pos,
                     GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    gchar *cur;
    gchar *next;
    gint cur_len;

    pn_log ("begin");

    if (parser->need_more)
    {
        gchar buf[0x2000 + 1];
        gsize bytes_read;

        status = pn_node_read (parser->node, buf, 0x2000, &bytes_read, NULL);

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        buf[bytes_read] = '\0';

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
            parser->rx_buf = g_memdup (next, parser->rx_len + 1);
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

    pn_log ("end");

    return status;
}

GIOStatus
pn_parser_read (PnParser *parser,
                gchar **buf_return,
                gsize length,
                GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;

    pn_log ("begin");

    if (parser->need_more)
    {
        gchar buf[0x2000 + 1];
        gsize bytes_read;

        status = pn_node_read (parser->node, buf, 0x2000, &bytes_read, NULL);

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        /* append buf to rx_buf */
        parser->rx_buf = g_realloc (parser->rx_buf, bytes_read + parser->rx_len + 1);
        memcpy (parser->rx_buf + parser->rx_len, buf, bytes_read + 1);
        parser->rx_len += bytes_read;
    }

    if (parser->rx_len < length)
    {
        /* The chunk is incomplete. */
        parser->need_more = TRUE;
        status = G_IO_STATUS_AGAIN;
        goto leave;
    }

    if (buf_return)
        *buf_return = g_strndup (parser->rx_buf, length);

    {
        gchar *tmp;

        parser->rx_len -= length;

        tmp = parser->rx_buf;

        if (parser->rx_len > 0)
        {
            parser->rx_buf = g_memdup (parser->rx_buf + length, parser->rx_len);
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
        if (buf_return)
            *buf_return = NULL;
    }

    pn_log ("end");

    return status;
}
