/*
 * Copyright (C) 2006-2009 Felipe Contreras.
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

#include "pn_dc_conn.h"
#include "pn_node_private.h"
#include "pn_log.h"

#include <string.h> /* for memcpy */
#include <stdint.h>

#include "cvr/pn_direct_conn.h" /* for pn_direct_conn_process_chunk */

struct PnDcConn {
    PnNode parent;

    gchar *rx_buf;
    gsize rx_len;
    gboolean need_more;
    guint32 body_len;
};

struct PnDcConnClass {
    PnNodeClass parent_class;
};

static GObjectClass *parent_class;

PnDcConn *
pn_dc_conn_new(gchar *name,
               PnNodeType type)
{
    PnDcConn *dc_conn;
    PnNode *conn;

    dc_conn = PN_DC_CONN(g_type_create_instance(PN_DC_CONN_TYPE));
    conn = PN_NODE(dc_conn);

    conn->name = g_strdup(name);
    conn->type = type;

    return dc_conn;
}

void
pn_dc_conn_free(PnDcConn *conn)
{
    g_object_unref(conn);
}

/* PnNode stuff. */

static void
parse_impl(PnNode *conn,
           gchar *buf,
           gsize bytes_read)
{
    pn_direct_conn_process_chunk(g_object_get_data(G_OBJECT(conn), "dc"),
                                 buf, bytes_read);
}

static void
channel_setup_impl (PnNode *conn,
                    GIOChannel *channel)
{
    g_io_channel_set_encoding(channel, NULL, NULL);
    g_io_channel_set_buffered(channel, TRUE);
}

static GIOStatus
write_impl(PnNode *conn,
           const gchar *buf,
           gsize count,
           gsize *ret_bytes_written,
           GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    PnDcConn *dc_conn;
    guint32 body_len;
    gsize bytes_written = 0;

    pn_debug("name=%s", conn->name);

    dc_conn = PN_DC_CONN(conn);

    body_len = GUINT32_TO_LE(count);

    /* write the length of the data */
    status = pn_stream_write(conn->stream,
                             (gchar *) &body_len, sizeof(body_len),
                             &bytes_written, NULL);

    if (status != G_IO_STATUS_NORMAL)
        goto leave;

    /* write the actual data */
    status = pn_stream_write(conn->stream, buf, count, &bytes_written, NULL);

    if (status != G_IO_STATUS_NORMAL)
        goto leave;

    status = pn_stream_flush(conn->stream, NULL);

leave:

    if (ret_bytes_written)
        *ret_bytes_written = bytes_written;

    return status;
}

static GIOStatus
read_impl(PnNode *conn,
          gchar *buf,
          gsize count,
          gsize *ret_bytes_read,
          GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    PnDcConn *dc_conn = PN_DC_CONN(conn);
    gsize length;

    pn_debug("name=%s", conn->name);

    if (dc_conn->need_more) {
        gsize bytes_read;

        status = pn_stream_read(conn->stream, buf, count, &bytes_read, NULL);

        if (status != G_IO_STATUS_NORMAL && status != G_IO_STATUS_AGAIN)
            goto leave;

        /* append buf to rx_buf */
        dc_conn->rx_buf = g_realloc(dc_conn->rx_buf, bytes_read + dc_conn->rx_len + 1);
        memcpy(dc_conn->rx_buf + dc_conn->rx_len, buf, bytes_read + 1);
        dc_conn->rx_len += bytes_read;

        if (status == G_IO_STATUS_AGAIN)
            goto leave;
    }

    if (!dc_conn->body_len) {
        if (dc_conn->rx_len < 4) {
            dc_conn->need_more = TRUE;
            status = G_IO_STATUS_AGAIN;
            goto leave;
        }

        dc_conn->body_len = GUINT32_FROM_LE(*(uint32_t *) dc_conn->rx_buf);
    }

    length = dc_conn->body_len + 4;

    if (dc_conn->rx_len < length) {
        dc_conn->need_more = TRUE;
        status = G_IO_STATUS_AGAIN;
        goto leave;
    }

    memcpy(buf, dc_conn->rx_buf + 4, dc_conn->body_len);
    if (ret_bytes_read)
        *ret_bytes_read = dc_conn->body_len;
    dc_conn->body_len = 0;

    {
        gchar *tmp;

        dc_conn->rx_len -= length;

        tmp = dc_conn->rx_buf;

        if (dc_conn->rx_len > 0) {
            dc_conn->rx_buf = g_memdup(dc_conn->rx_buf + length, dc_conn->rx_len);
            dc_conn->need_more = FALSE;
        } else {
            dc_conn->rx_buf = NULL;
            dc_conn->need_more = TRUE;
        }

        g_free(tmp);
    }

leave:
    return status;
}

/* GObject stuff. */

static void
finalize(GObject *obj)
{
    PnDcConn *dc_conn = PN_DC_CONN(obj);
    g_free(dc_conn->rx_buf);
    parent_class->finalize(obj);
}

static void
instance_init(GTypeInstance *instance,
              gpointer g_class)
{
    PnDcConn *dc_conn = PN_DC_CONN(instance);
    dc_conn->need_more = TRUE;
}

static void
class_init(gpointer g_class,
           gpointer class_data)
{
    PnNodeClass *conn_class = PN_NODE_CLASS(g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS(g_class);

    conn_class->write = &write_impl;
    conn_class->read = &read_impl;
    conn_class->parse = &parse_impl;
    conn_class->channel_setup = &channel_setup_impl;

    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent(g_class);
}

GType
pn_dc_conn_get_type(void)
{
    static gsize type;

    if (g_once_init_enter(&type)) {
        GType tmp_type;
        GTypeInfo type_info = {
            .class_size = sizeof(PnDcConnClass),
            .class_init = class_init,
            .instance_size = sizeof(PnDcConn),
            .instance_init = instance_init,
        };

        tmp_type = g_type_register_static(PN_NODE_TYPE, "PnDcConnType", &type_info, 0);

	g_once_init_leave(&type, tmp_type);
    }

    return type;
}
