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

static void
parse_impl (CmdConnObject *conn,
            gchar *buf,
            gsize bytes_read)
{
    ConnObject *base_conn;
    gchar *cur, *end, *old_rx_buf;
    gint cur_len;

    base_conn = CONN_OBJECT (conn);

    buf[bytes_read] = '\0';

    conn->rx_buf = g_realloc (conn->rx_buf, bytes_read + conn->rx_len + 1);
    memcpy (conn->rx_buf + conn->rx_len, buf, bytes_read + 1);
    conn->rx_len += bytes_read;

    end = old_rx_buf = conn->rx_buf;

    base_conn->processing = TRUE;

    do
    {
        cur = end;

        if (conn->payload_len)
        {
            if (conn->payload_len > conn->rx_len)
                /* The payload is still not complete. */
                break;

            cur_len = conn->payload_len;
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

        conn->rx_len -= cur_len;

        if (conn->payload_len)
        {
            msn_cmdproc_process_payload (conn->cmdproc, cur, cur_len);
            conn->payload_len = 0;
        }
        else
        {
            msn_cmdproc_process_cmd_text (conn->cmdproc, cur);
        }
    } while (base_conn->connected && !conn->wasted && conn->rx_len > 0);

    if (base_conn->connected && !conn->wasted)
    {
        if (conn->rx_len > 0)
            conn->rx_buf = g_memdup (cur, conn->rx_len);
        else
            conn->rx_buf = NULL;
    }

    base_conn->processing = FALSE;

    if (conn->wasted)
        conn_object_free (base_conn);

    g_free (old_rx_buf);
}

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
    CmdConnObject *conn = CMD_CONN_OBJECT (obj);

    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static void
class_init (gpointer g_class,
            gpointer class_data)
{
    ConnObjectClass *conn_class = CONN_OBJECT_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

#if 0
    conn_class->connect = &connect_impl;
    conn_class->error = &error_impl;
    conn_class->read = &read_impl;
#endif
    conn_class->parse = &parse_impl;

    gobject_class->dispose = dispose;
    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

void
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
