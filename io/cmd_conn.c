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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "cmd_conn.h"
#include "msn_log.h"

static ConnObjectClass *parent_class = NULL;

CmdConnObject *
cmd_conn_object_new (gchar *name,
                     ConnObjectType type)
{
    CmdConnObject *conn;

    msn_log ("begin");

    conn = CMD_CONN_OBJECT (g_type_create_instance (CMD_CONN_OBJECT_TYPE));

    {
        ConnObject *tmp = CONN_OBJECT (conn);
        tmp->name = g_strdup (name);
        tmp->type = type;
    }

    msn_log ("end");

    return conn;
}

void
cmd_conn_object_free (CmdConnObject *conn)
{
    msn_log ("begin");
    g_object_unref (G_OBJECT (conn));
    msn_log ("end");
}

void
cmd_conn_object_send (CmdConnObject *conn,
                      const char *command,
                      const char *format,
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

static void
parse_impl (ConnObject *base_conn,
            gchar *buf,
            gsize bytes_read)
{
    CmdConnObject *cmd_conn;
    gchar *cur, *end, *old_rx_buf;
    gint cur_len;

    cmd_conn = CMD_CONN_OBJECT (base_conn);

    buf[bytes_read] = '\0';

    cmd_conn->rx_buf = g_realloc (cmd_conn->rx_buf, bytes_read + cmd_conn->rx_len + 1);
    memcpy (cmd_conn->rx_buf + cmd_conn->rx_len, buf, bytes_read + 1);
    cmd_conn->rx_len += bytes_read;

    end = old_rx_buf = cmd_conn->rx_buf;

    do
    {
        cur = end;

        if (cmd_conn->payload_len)
        {
            if (cmd_conn->payload_len > cmd_conn->rx_len)
                /* The payload is still not complete. */
                break;

            cur_len = cmd_conn->payload_len;
            end += cur_len;
        }
        else
        {
            end = strstr(cur, "\r\n");

            if (end == NULL)
                /* The command is still not complete. */
                break;

            *end = '\0';
            end += 2;
            cur_len = end - cur;
        }

        cmd_conn->rx_len -= cur_len;

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
    } while (base_conn->connected && !cmd_conn->wasted && cmd_conn->rx_len > 0);

    if (cmd_conn->rx_len > 0)
        cmd_conn->rx_buf = g_memdup (cur, cmd_conn->rx_len);
    else
        cmd_conn->rx_buf = NULL;

    if (cmd_conn->wasted)
        conn_object_free (base_conn);

    g_free (old_rx_buf);
}

#if 0
static void
read_impl (ConnObject *conn)
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
        conn_object_close (conn);
        return;
    }

    if (r < 0)
    {
        /* connection error */
        conn_object_close (conn);
        return;
    }

    read_buffer->filled = r;
    /* msn_print ("read [%b]\n", read_buffer); */

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
            /* CONN_OBJECT_GET_CLASS (conn)->parse (conn); */
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
    CmdConnObject *conn = CMD_CONN_OBJECT (obj);

    if (!conn->dispose_has_run)
    {
        conn->dispose_has_run = TRUE;
    }

    G_OBJECT_CLASS (parent_class)->dispose (obj);
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
    ConnObjectClass *conn_class = CONN_OBJECT_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_class->parse = &parse_impl;

    gobject_class->dispose = dispose;
    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

static void
instance_init (GTypeInstance *instance,
               gpointer g_class)
{
    CmdConnObject *conn = CMD_CONN_OBJECT (instance);

    conn->dispose_has_run = FALSE;
}

GType
cmd_conn_object_get_type (void)
{
    static GType type = 0;

    if (type == 0) 
    {
        static const GTypeInfo type_info =
        {
            sizeof (CmdConnObjectClass),
            NULL, /* base_init */
            NULL, /* base_finalize */
            class_init, /* class_init */
            NULL, /* class_finalize */
            NULL, /* class_data */
            sizeof (CmdConnObject),
            0, /* n_preallocs */
            instance_init /* instance_init */
        };

        type = g_type_register_static (CONN_OBJECT_TYPE, "CmdConnObjectType", &type_info, 0);
    }

    return type;
}
