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

#include "pecan_cmd_server_priv.h"
#include "cmd/cmdproc_private.h"
#include "cmd/command_private.h"

#include "pecan_log.h"

#include <string.h>

#ifdef HAVE_LIBPURPLE
#include "fix_purple_win32.h"
#endif /* HAVE_LIBPURPLE */

static PecanNodeClass *parent_class = NULL;

PecanCmdServer *
pecan_cmd_server_new (const gchar *name,
                      PecanNodeType type)
{
    PecanCmdServer *conn;

    pecan_log ("begin");

    conn = CMD_PECAN_NODE (g_type_create_instance (CMD_PECAN_NODE_TYPE));

    {
        PecanNode *tmp = PECAN_NODE (conn);
        tmp->name = g_strdup (name);
        tmp->type = type;
    }

    pecan_log ("end");

    return conn;
}

void
pecan_cmd_server_free (PecanCmdServer *conn)
{
    pecan_log ("begin");
    g_object_unref (G_OBJECT (conn));
    pecan_log ("end");
}

#if 0
void
pecan_cmd_server_send (PecanCmdServer *conn,
                      const gchar *command,
                      const gchar *format,
                      ...)
{
    va_list args;

    if (format != NULL)
    {
        va_start (args, format);
        msn_cmdproc_send_valist (conn->cmdproc, command, format, args);
        va_end (args);
    }
    else
    {
        msn_cmdproc_send_valist (conn->cmdproc, command, format, args);
    }
}
#endif

/** @todo reimplement this in a safer way (GIOChannel) */
/** @todo add extensive tests for this */
static void
parse_impl (PecanNode *base_conn,
            gchar *buf,
            gsize bytes_read)
{
    PecanCmdServer *cmd_conn;
    gchar *cur, *next, *old_rx_buf;
    gint cur_len;

    pecan_log ("begin");

    pecan_debug ("conn=%p,name=%s", base_conn, base_conn->name);

    cmd_conn = CMD_PECAN_NODE (base_conn);

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

    pecan_log ("end");
}

static void
close_impl (PecanNode *conn)
{
    PecanCmdServer *cmd_conn;

    pecan_log ("begin");

    cmd_conn = CMD_PECAN_NODE (conn);

    g_free (cmd_conn->rx_buf);
    cmd_conn->rx_buf = NULL;
    cmd_conn->rx_len = 0;
    cmd_conn->payload_len = 0;

    if (cmd_conn->cmdproc)
        msn_cmdproc_flush (cmd_conn->cmdproc);

    PECAN_NODE_CLASS (parent_class)->close (conn);

    pecan_log ("end");
}

#if 0
static void
read_impl (PecanNode *conn)
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
        pecan_node_close (conn);
        return;
    }

    if (r < 0)
    {
        /* connection error */
        pecan_node_close (conn);
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
            /* PECAN_NODE_GET_CLASS (conn)->parse (conn); */
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
dispose (GObject *obj)
{
    PecanCmdServer *cmd_conn = CMD_PECAN_NODE (obj);

    pecan_log ("begin");

    if (cmd_conn->cmdproc)
    {
        msn_cmdproc_destroy (cmd_conn->cmdproc);
        cmd_conn->cmdproc = NULL;
    }

    G_OBJECT_CLASS (parent_class)->dispose (obj);

    pecan_log ("end");
}

static void
finalize (GObject *obj)
{
    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static void
class_init (gpointer g_class,
            gpointer class_data)
{
    PecanNodeClass *conn_class = PECAN_NODE_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_class->parse = &parse_impl;
    conn_class->close = &close_impl;

    gobject_class->dispose = dispose;
    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

static void
instance_init (GTypeInstance *instance,
               gpointer g_class)
{
    PecanCmdServer *conn = CMD_PECAN_NODE (instance);

    conn->cmdproc = msn_cmdproc_new ();
}

GType
pecan_cmd_server_get_type (void)
{
    static GType type = 0;

    if (type == 0) 
    {
        GTypeInfo *type_info;

        type_info = g_new0 (GTypeInfo, 1);
        type_info->class_size = sizeof (PecanCmdServerClass);
        type_info->class_init = class_init;
        type_info->instance_size = sizeof (PecanCmdServer);
        type_info->instance_init = instance_init;

        type = g_type_register_static (PECAN_NODE_TYPE, "PecanCmdServerType", type_info, 0);
    }

    return type;
}
