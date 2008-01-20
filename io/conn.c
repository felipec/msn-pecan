/*
 * Copyright (C) 2006-2008 Felipe Contreras.
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

#include "conn.h"

#include <netdb.h>
#include <string.h>

#include <sys/poll.h>

#include "msn_log.h"

/* For open. */
#include <fcntl.h>
#include <unistd.h>

static GObjectClass *parent_class = NULL;

ConnObject *
conn_object_new (gchar *name, ConnObjectType type)
{
    ConnObject *conn;

    msn_log ("begin");

    conn = CONN_OBJECT (g_type_create_instance (CONN_OBJECT_TYPE));

    conn->name = g_strdup (name);
    conn->type = type;

    msn_log ("end");

    return conn;
}

void
conn_object_free (ConnObject *conn)
{
    msn_log ("begin");

    conn_object_close (conn);
    g_object_unref (G_OBJECT (conn));

    msn_log ("end");
}

void
conn_object_send_cmd (ConnObject *conn, MsnCmd *cmd)
{
    gchar *buf;
    int r;

    buf = g_strdup_printf ("%s %d %s\r\n", cmd->id, cmd->trid, cmd->args);

    r = conn_end_object_write (conn->end, buf, strlen (buf), NULL, NULL);

    /* msn_print (">> %v\n", MSN_TYPE_STRING, buf, r); */

    g_free (buf);
}

gchar *
conn_object_to_string (ConnObject *conn)
{
    return g_strdup_printf ("%s (%s:%d)", conn->name, conn->hostname, conn->port);
}

void
conn_object_error (ConnObject *conn)
{
    msn_info ("foo");
    CONN_OBJECT_GET_CLASS (conn)->error (conn);
}

void
conn_object_write (ConnObject *conn,
                   const gchar *buf,
                   gsize len)
{
    gsize bytes_written = 0;

    g_return_if_fail (conn != NULL);

    msn_debug ("conn=%p", conn);

    {
        GIOStatus status = G_IO_STATUS_NORMAL;

        status = conn_end_object_write (conn->end, buf, len, &bytes_written, &conn->error);

        if (status != G_IO_STATUS_NORMAL)
        {
            conn_object_error (conn);
        }
    }
}

static void
parse_cmd (ConnObject *conn,
           gchar *buf,
           gsize bytes_read)
{
    gchar *cur, *end, *old_rx_buf;
    gint cur_len;

    buf[bytes_read] = '\0';

    conn->rx_buf = g_realloc (conn->rx_buf, bytes_read + conn->rx_len + 1);
    memcpy (conn->rx_buf + conn->rx_len, buf, bytes_read + 1);
    conn->rx_len += bytes_read;

    end = old_rx_buf = conn->rx_buf;

    conn->processing = TRUE;

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
    } while (conn->connected && !conn->wasted && conn->rx_len > 0);

    if (conn->connected && !conn->wasted)
    {
        if (conn->rx_len > 0)
            conn->rx_buf = g_memdup(cur, conn->rx_len);
        else
            conn->rx_buf = NULL;
    }

    conn->processing = FALSE;

    if (conn->wasted)
        conn_object_free (conn);

    g_free (old_rx_buf);
}

static gboolean
read_cb (GIOChannel *source,
         GIOCondition condition,
         gpointer data)
{
    ConnObject *conn;
    gchar buf[MSN_BUF_LEN];
    gsize bytes_read;

    conn = data;

    msn_debug ("source=%p", source);

    {
        GIOStatus status = G_IO_STATUS_NORMAL;

        status = conn_end_object_read (conn->end, buf, sizeof (buf), &bytes_read, &conn->error);

        if (status == G_IO_STATUS_AGAIN)
            return TRUE;

        if (status != G_IO_STATUS_NORMAL)
        {
            /* msn_servconn_got_error (servconn, MSN_SERVCONN_ERROR_READ); */
            return FALSE;
        }
    }

    parse_cmd (conn, buf, bytes_read);

    return TRUE;
}

static void
connect_cb (gpointer data,
            gint source,
            const gchar *error_message)
{
    ConnObject *conn;

    msn_log ("begin");

    conn = data;
    conn->connect_data = NULL;
    conn->processing = FALSE;

#if 0
    if (servconn->wasted)
    {
        if (source >= 0)
            close(source);
        msn_servconn_destroy(servconn);
        return;
    }
#endif

    if (source >= 0)
    {
        GIOChannel *channel = g_io_channel_unix_new (source);

        conn->end = conn_end_object_new (channel);
        conn->connected = TRUE;

        msn_info ("connected: %p", channel);
        conn->read_watch = g_io_add_watch (channel, G_IO_IN, read_cb, conn);

        conn_end_object_connect (conn->end);

        CONN_OBJECT_GET_CLASS (conn)->connect (conn);

        if (conn->connect_cb)
            conn->connect_cb (conn);
    }
    else
    {
        msn_error ("connection error: %p: %s", error_message);
        /* msn_servconn_got_error (conn, MSN_SERVCONN_ERROR_CONNECT); */
    }

    msn_log ("begin");
}

void
conn_object_connect (ConnObject *conn,
                     const gchar *hostname,
                     gint port)
{
    g_return_if_fail (conn != NULL);
    g_return_if_fail (hostname != NULL);
    g_return_if_fail (port > 0);

    msn_log ("begin");

    conn_object_close (conn);

    g_free (conn->hostname);
    conn->hostname = g_strdup (hostname);
    conn->port = port;

#if 0
    if (session->http_method)
    {
        /* HTTP Connection. */

        if (!servconn->httpconn->connected)
            if (!msn_httpconn_connect(servconn->httpconn, host, port))
                return FALSE;

        servconn->connected = TRUE;
        servconn->httpconn->virgin = TRUE;

        /* Someone wants to know we connected. */
        servconn->connect_cb(servconn);

        return TRUE;
    }
#endif

    conn->connect_data = purple_proxy_connect (NULL, conn->session->account, hostname, port, connect_cb, conn);

    if (conn->connect_data != NULL)
        conn->processing = TRUE;

    msn_log ("end");
}

void
conn_object_close (ConnObject *conn)
{
    msn_info ("conn=%p", conn);

    if (conn->connect_data)
    {
        purple_proxy_connect_cancel (conn->connect_data);
        conn->connect_data = NULL;
    }
}

/* ConnObject stuff. */

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
            CONN_OBJECT_GET_CLASS (conn)->parse (conn);
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

static void
connect_impl (ConnObject *conn)
{
}

static void
error_impl (ConnObject *conn)
{
}

/* GObject stuff. */

static void
conn_object_dispose (GObject *obj)
{
    ConnObject *conn = (ConnObject *) obj;

    if (!conn->dispose_has_run)
    {
        conn->dispose_has_run = TRUE;
    }

    G_OBJECT_CLASS (parent_class)->dispose (obj);
}

static void
conn_object_finalize (GObject *obj)
{
    ConnObject *conn = (ConnObject *) obj;

    conn_end_object_free (conn->end);

    msn_buffer_free (conn->read_buffer);
    msn_buffer_free (conn->buffer);

    g_free (conn->name);
    g_free (conn->hostname);

    /* Chain up to the parent class */
    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

void
conn_object_class_init (gpointer g_class, gpointer class_data)
{
    ConnObjectClass *conn_class = CONN_OBJECT_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_class->connect = &connect_impl;
    conn_class->error = &error_impl;
    conn_class->read = &read_impl;

    gobject_class->dispose = conn_object_dispose;
    gobject_class->finalize = conn_object_finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

void
conn_object_instance_init (GTypeInstance *instance,
                           gpointer g_class)
{
    ConnObject *conn = CONN_OBJECT (instance);

    conn->dispose_has_run = FALSE;
    conn->buffer = msn_buffer_new_and_alloc (0);
    conn->read_buffer = msn_buffer_new ();
}

GType
conn_object_get_type (void)
{
    static GType type = 0;

    if (type == 0) 
    {
        static const GTypeInfo type_info =
        {
            sizeof (ConnObjectClass),
            NULL, /* base_init */
            NULL, /* base_finalize */
            conn_object_class_init, /* class_init */
            NULL, /* class_finalize */
            NULL, /* class_data */
            sizeof (ConnObject),
            0, /* n_preallocs */
            conn_object_instance_init /* instance_init */
        };

        type = g_type_register_static (G_TYPE_OBJECT, "ConnObjectType", &type_info, 0);
    }

    return	type;
}
