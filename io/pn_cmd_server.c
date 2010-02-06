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

#include "pn_cmd_server.h"
#include "pn_node_private.h"
#include "cmd/cmdproc_private.h"
#include "cmd/command_private.h"

#include "pn_log.h"

#include <string.h>

struct PnCmdServer
{
    PnNode parent;

    gsize payload_len;
    gchar *rx_buf;
    gsize rx_len;

    struct MsnCmdProc *cmdproc;
};

struct PnCmdServerClass
{
    PnNodeClass parent_class;
};

static PnNodeClass *parent_class;

PnCmdServer *
pn_cmd_server_new (PnNodeType type)
{
    PnCmdServer *conn;

    pn_log ("begin");

    conn = PN_CMD_SERVER (g_type_create_instance (PN_CMD_SERVER_TYPE));

    {
        PnNode *tmp = PN_NODE (conn);
        tmp->type = type;
    }

    pn_log ("end");

    return conn;
}

void
pn_cmd_server_free (PnCmdServer *conn)
{
    pn_log ("begin");
    g_object_unref (conn);
    pn_log ("end");
}

void
pn_cmd_server_send (PnCmdServer *conn,
                    const gchar *command,
                    const gchar *format,
                    ...)
{
    va_list args;

    va_start (args, format);
    msn_cmdproc_send_valist (conn->cmdproc, command, format, args);
    va_end (args);
}

/** @todo reimplement this in a safer way (GIOChannel) */
/** @todo add extensive tests for this */
static void
parse_impl (PnNode *base_conn,
            gchar *buf,
            gsize bytes_read)
{
    PnCmdServer *cmd_conn;
    gchar *cur, *next, *old_rx_buf;
    gint cur_len;

    pn_log ("begin");

    pn_debug ("conn=%p,name=%s", base_conn, base_conn->name);

    cmd_conn = PN_CMD_SERVER (base_conn);

    buf[bytes_read] = '\0';

    /* append buf to rx_buf */
    cmd_conn->rx_buf = g_realloc (cmd_conn->rx_buf, bytes_read + cmd_conn->rx_len + 1);
    memcpy (cmd_conn->rx_buf + cmd_conn->rx_len, buf, bytes_read + 1);
    cmd_conn->rx_len += bytes_read;

    next = old_rx_buf = cmd_conn->rx_buf;
    cmd_conn->rx_buf = NULL;

    do
    {
        cur = next;

        if (cmd_conn->payload_len)
        {
            if (cmd_conn->payload_len > cmd_conn->rx_len)
                /* The payload is incomplete. */
                break;

            cur_len = cmd_conn->payload_len;
            next += cur_len;
        }
        else
        {
            next = strstr (cur, "\r\n");

            if (!next)
                /* The command is incomplete. */
                break;

            *next = '\0';
            next += 2;
            cur_len = next - cur;
        }

        cmd_conn->rx_len -= cur_len;

        if (cmd_conn->cmdproc)
        {
            if (cmd_conn->payload_len)
            {
                msn_cmdproc_process_payload (cmd_conn->cmdproc, cur, cur_len);
                cmd_conn->payload_len = 0;
            }
            else
            {
                msn_cmdproc_process_cmd_text (cmd_conn->cmdproc, cur);
                cmd_conn->payload_len = cmd_conn->cmdproc->last_cmd->payload_len;
            }
        }
    } while (cmd_conn->rx_len > 0);

    if (cmd_conn->rx_len > 0)
        cmd_conn->rx_buf = g_memdup (cur, cmd_conn->rx_len);

    g_free (old_rx_buf);

    pn_log ("end");
}

static void
close_impl (PnNode *conn)
{
    PnCmdServer *cmd_conn;

    if (conn->status == PN_NODE_STATUS_CLOSED) {
        pn_log ("already closed: %p", conn);
        return;
    }

    pn_log ("begin");

    cmd_conn = PN_CMD_SERVER (conn);

    g_free (cmd_conn->rx_buf);
    cmd_conn->rx_buf = NULL;
    cmd_conn->rx_len = 0;
    cmd_conn->payload_len = 0;

    if (cmd_conn->cmdproc)
        msn_cmdproc_flush (cmd_conn->cmdproc);

    parent_class->close (conn);

    pn_log ("end");
}

#if 0
static void
read_impl (PnNode *conn)
{
    MsnBuffer *read_buffer;
    int r;

    read_buffer = conn->read_buffer;

    read_buffer->size = MSN_BUF_SIZE;

    if (conn->payload)
    {
        msn_buffer_prepare (conn->buffer, conn->payload->size);
    }
    else
    {
        msn_buffer_prepare (conn->buffer, read_buffer->size);
    }

    read_buffer->data = conn->buffer->data + conn->buffer->filled;

    r = conn_end_object_read (conn->end, read_buffer->data, read_buffer->size, NULL, NULL);

    if (r == 0)
    {
        /* connection closed */
        pn_node_close (conn);
        return;
    }

    if (r < 0)
    {
        /* connection error */
        pn_node_close (conn);
        return;
    }

    read_buffer->filled = r;
    /* pecan_print ("read [%b]\n", read_buffer); */

    conn->buffer->filled += read_buffer->filled;

    while (conn->parse_pos < conn->buffer->filled)
    {
        if (conn->payload)
        {
            guint size;
            size = MIN (conn->payload->size - conn->payload->filled,
                        conn->buffer->filled - conn->parse_pos);

            conn->payload->filled += size;
            conn->parse_pos += size;

            if (conn->payload->filled == conn->payload->size)
            {
                if (conn->payload_cb)
                {
                    conn->payload->data = conn->buffer->data + conn->last_parse_pos;
                    conn->payload_cb (conn, conn->payload);
                }
                msn_buffer_free (conn->payload);
                conn->payload = NULL;
                conn->parsed = TRUE;
                conn->last_parse_pos = conn->parse_pos;
            }
        }
        else
        {
            /* PN_NODE_GET_CLASS (conn)->parse (conn); */
        }

        /** @todo only if parsed? yes indeed! */
        if (conn->parsed)
        {
            if (conn->parse_pos == conn->buffer->filled)
            {
                /* g_debug ("reset\n"); */
                conn->buffer->filled = 0;
                conn->parse_pos = 0;
                conn->last_parse_pos = 0;
            }

            conn->parsed = FALSE;
        }
    }
}
#endif

/* GObject stuff. */

static void
finalize (GObject *obj)
{
    PnCmdServer *cmd_conn = PN_CMD_SERVER (obj);
    msn_cmdproc_destroy (cmd_conn->cmdproc);
    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static void
class_init (gpointer g_class,
            gpointer class_data)
{
    PnNodeClass *conn_class = PN_NODE_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_class->parse = &parse_impl;
    conn_class->close = &close_impl;

    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

static void
instance_init (GTypeInstance *instance,
               gpointer g_class)
{
    PnCmdServer *conn = PN_CMD_SERVER (instance);

    conn->cmdproc = msn_cmdproc_new ();
    g_object_set_data(G_OBJECT(conn), "cmdproc", conn->cmdproc);
}

GType
pn_cmd_server_get_type (void)
{
    static GType type = 0;

    if (G_UNLIKELY (type == 0))
    {
        GTypeInfo *type_info;

        type_info = g_new0 (GTypeInfo, 1);
        type_info->class_size = sizeof (PnCmdServerClass);
        type_info->class_init = class_init;
        type_info->instance_size = sizeof (PnCmdServer);
        type_info->instance_init = instance_init;

        type = g_type_register_static (PN_NODE_TYPE, "PnCmdServerType", type_info, 0);

        g_free (type_info);
    }

    return type;
}
