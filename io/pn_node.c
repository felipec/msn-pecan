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

#include "pn_node_private.h"
#include "pn_stream.h"
#include "pn_log.h"
#include "pn_global.h"

#include "session.h" /* for libpurple account */

#ifdef HAVE_LIBPURPLE
#include <proxy.h>
#endif /* HAVE_LIBPURPLE */

void pn_node_error (PnNode *conn);

static GObjectClass *parent_class;

GQuark
pn_node_error_quark (void)
{
    return g_quark_from_static_string ("conn-object-error-quark");
}

static inline const gchar *
status_to_str (GIOStatus status)
{
    const gchar *id;

    switch (status)
    {
        case G_IO_STATUS_ERROR: id = "ERROR"; break;
        case G_IO_STATUS_NORMAL: id = "NORMAL"; break;
        case G_IO_STATUS_EOF: id = "EOF"; break;
        case G_IO_STATUS_AGAIN: id = "AGAIN"; break;
        default: id = NULL; break;
    }

    return id;
}

#if defined(USE_GIO)
static void
read_cb (GObject *source,
         GAsyncResult *result,
         gpointer user_data)
{
    PnNode *conn;
    gssize size;
    GError *error = NULL;

    conn = PN_NODE(user_data);
    size = g_input_stream_read_finish (G_INPUT_STREAM (source),
                                       result, &error);

    conn = PN_NODE(user_data);

    if (G_UNLIKELY (size == 0))
        error = g_error_new_literal(PN_NODE_ERROR, PN_NODE_ERROR_OPEN,
                                    "End of stream");

    if (error)
        goto nok;

    pn_node_parse (conn, (char *) conn->input_buffer, size);

    if (conn->status == PN_NODE_STATUS_OPEN)
        g_input_stream_read_async (G_INPUT_STREAM (source), conn->input_buffer, PN_BUF_LEN,
                                   G_PRIORITY_DEFAULT, NULL, read_cb, conn);
    else
        g_object_unref (conn);

    return;

nok:
    conn->error = error;
    pn_node_error (conn);
    g_object_unref (conn);
}
#else
static gboolean
read_cb (GIOChannel *source,
         GIOCondition condition,
         gpointer data)
{
    PnNode *conn;
    gchar buf[PN_BUF_LEN + 1];
    gsize bytes_read;

    pn_log ("begin");

    conn = PN_NODE (data);

    pn_debug ("conn=%p,name=%s", conn, conn->name);

    g_object_ref (conn);

    {
        GIOStatus status = G_IO_STATUS_NORMAL;

        status = pn_node_read (conn, buf, PN_BUF_LEN, &bytes_read, NULL);

        if (status == G_IO_STATUS_AGAIN)
        {
            g_object_unref (conn);
            return TRUE;
        }

        if (status == G_IO_STATUS_EOF)
        {
            conn->error = g_error_new (PN_NODE_ERROR, PN_NODE_ERROR_OPEN, "End of stream");
        }

        if (conn->error)
        {
            pn_node_error (conn);
            g_object_unref (conn);
            return FALSE;
        }
    }

    pn_node_parse (conn, buf, bytes_read);

    g_object_unref (conn);

    pn_log ("end");

    return TRUE;
}
#endif

static void
open_cb (PnNode *next,
         gpointer data)
{
    PnNode *conn;

    conn = PN_NODE (data);

    pn_log ("begin");

    conn->status = PN_NODE_STATUS_OPEN;

    {
        PnNodeClass *class;
        class = g_type_class_peek (PN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->open_sig, 0, conn);
    }

    g_signal_handler_disconnect (next, conn->open_sig_handler);
    conn->open_sig_handler = 0;

    pn_log ("end");
}

static void
close_cb (PnNode *next,
          gpointer data)
{
    PnNode *conn;

    conn = PN_NODE (data);

    pn_log ("begin");

    pn_node_close (conn);

    {
        PnNodeClass *class;
        class = g_type_class_peek (PN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->close_sig, 0, conn);
    }

    pn_log ("end");
}

static void
error_cb (PnNode *next,
          gpointer data)
{
    PnNode *conn;

    conn = PN_NODE (data);

    pn_log ("begin");

    if (next->error)
    {
        g_propagate_error (&conn->error, next->error);
        next->error = NULL;
    }

    {
        PnNodeClass *class;
        class = g_type_class_peek (PN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->error_sig, 0, conn);
    }

    pn_log ("end");
}

PnNode *
pn_node_new (gchar *name,
             PnNodeType type)
{
    PnNode *conn;

    pn_log ("begin");

    conn = PN_NODE (g_type_create_instance (PN_NODE_TYPE));

    conn->name = g_strdup (name);
    conn->type = type;

    pn_log ("end");

    return conn;
}

void
pn_node_free (PnNode *conn)
{
    g_return_if_fail (conn != NULL);
    pn_log ("begin");
    g_object_unref (conn);
    pn_log ("end");
}

void
pn_node_set_id (PnNode *conn,
                guint id,
                const gchar *name)
{
    conn->id = id;
    g_free(conn->name);
    conn->name = g_strdup (name);
}

void
pn_node_error (PnNode *conn)
{
    g_return_if_fail (conn != NULL);

    pn_debug ("conn=%p", conn);

    g_object_ref (conn);

    {
        PnNodeClass *class;
        class = g_type_class_peek (PN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->error_sig, 0, conn);
    }

    if (conn->error)
    {
        pn_warning ("unhandled error: %s", conn->error->message);
        g_clear_error (&conn->error);
    }

    g_object_unref (conn);
}

GIOStatus
pn_node_write (PnNode *conn,
               const gchar *buf,
               gsize count,
               gsize *ret_bytes_written,
               GError **error)
{
    return PN_NODE_GET_CLASS (conn)->write (conn, buf, count, ret_bytes_written, error);
}

GIOStatus
pn_node_read (PnNode *conn,
              gchar *buf,
              gsize count,
              gsize *ret_bytes_read,
              GError **error)
{
    return PN_NODE_GET_CLASS (conn)->read (conn, buf, count, ret_bytes_read, error);
}

/* If two nodes are linked the 'next' node is used for the real communication. */
void
pn_node_link (PnNode *conn,
              PnNode *next)
{
    conn->next = g_object_ref (next);
    next->prev = conn;

    conn->open_sig_handler = g_signal_connect (next, "open", G_CALLBACK (open_cb), conn);
    conn->close_sig_handler = g_signal_connect (next, "close", G_CALLBACK (close_cb), conn);
    conn->error_sig_handler = g_signal_connect (next, "error", G_CALLBACK (error_cb), conn);
}

void
pn_node_connect (PnNode *conn,
                 const gchar *hostname,
                 gint port)
{
    PN_NODE_GET_CLASS (conn)->connect (conn, hostname, port);
}

void
pn_node_close (PnNode *conn)
{
    PN_NODE_GET_CLASS (conn)->close (conn);
}

void
pn_node_parse (PnNode *conn,
               gchar *buf,
               gsize bytes_read)
{
    PN_NODE_GET_CLASS (conn)->parse (conn, buf, bytes_read);
}

/* PnNode stuff. */

#if defined(USE_GIO)
static void
connect_cb(GObject *source,
           GAsyncResult *res,
           gpointer user_data)
{
    GSocketConnection *socket_conn;
    PnNode *conn;

    conn = PN_NODE(user_data);
    socket_conn = g_socket_client_connect_to_host_finish(G_SOCKET_CLIENT(source), res, NULL);

    g_object_unref(source);

    g_object_ref(conn);

    if (socket_conn) {
        GSocket *socket;
        GInputStream *input;

        conn->socket_conn = socket_conn;
        socket = g_socket_connection_get_socket(socket_conn);

        conn->status = PN_NODE_STATUS_OPEN;

        input = g_io_stream_get_input_stream (G_IO_STREAM (conn->socket_conn));
        g_object_ref (conn);
        g_input_stream_read_async (input, conn->input_buffer, PN_BUF_LEN,
                                   G_PRIORITY_DEFAULT, NULL,
                                   read_cb, conn);
    }
    else {
        conn->error = g_error_new_literal(PN_NODE_ERROR, PN_NODE_ERROR_OPEN,
                                          "Unable to connect");

        pn_node_error(conn);
    }

    {
        PnNodeClass *class;
        class = g_type_class_peek(PN_NODE_TYPE);
        g_signal_emit(G_OBJECT(conn), class->open_sig, 0, conn);
    }

    g_object_unref(conn);
}
#elif defined(HAVE_LIBPURPLE)
static void
connect_cb (gpointer data,
            gint source,
            const gchar *error_message)
{
    PnNode *conn;

    pn_log ("begin");

    conn = PN_NODE (data);
    conn->connect_data = NULL;

    g_object_ref (conn);

    if (source >= 0)
    {
        GIOChannel *channel;

        conn->stream = pn_stream_new (source);
        channel = conn->stream->channel;

        PN_NODE_GET_CLASS (conn)->channel_setup (conn, channel);

        conn->status = PN_NODE_STATUS_OPEN;

        pn_info ("connected: conn=%p,channel=%p", conn, channel);
        conn->read_watch = g_io_add_watch (channel, G_IO_IN, read_cb, conn);
#if 0
        g_io_add_watch (channel, G_IO_ERR | G_IO_HUP | G_IO_NVAL, close_cb, conn);
#endif
    }
    else
    {
        /* pn_error ("connection error: conn=%p,msg=[%s]", conn, error_message); */
        conn->error = g_error_new_literal (PN_NODE_ERROR, PN_NODE_ERROR_OPEN,
                                           error_message ? error_message : "Unable to connect");

        pn_node_error (conn);
    }

    {
        PnNodeClass *class;
        class = g_type_class_peek (PN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->open_sig, 0, conn);
    }

    g_object_unref (conn);

    pn_log ("end");
}
#endif

static void
connect_impl (PnNode *conn,
              const gchar *hostname,
              gint port)
{
    g_return_if_fail (conn);

    pn_log ("begin");

    pn_debug ("conn=%p,name=%s", conn, conn->name);
    pn_debug ("hostname=%s,port=%d", hostname, port);
    pn_debug ("next=%p", conn->next);

    g_free (conn->hostname);
    conn->hostname = g_strdup (hostname);
    conn->port = port;

    if (conn->next)
    {
        conn->status = PN_NODE_STATUS_CONNECTING;

        pn_node_connect (conn->next, hostname, port);
    }
    else
    {
        pn_node_close (conn);

        conn->status = PN_NODE_STATUS_CONNECTING;

#if defined(USE_GIO)
        GSocketClient *client;
        client = g_socket_client_new();
        g_socket_client_connect_to_host_async(client, hostname, port,
                                              NULL, connect_cb, conn);
#elif defined(HAVE_LIBPURPLE)
        conn->connect_data = purple_proxy_connect (NULL, msn_session_get_user_data (conn->session),
                                                   hostname, port, connect_cb, conn);
#endif
    }

    pn_log ("end");
}

static void
close_impl (PnNode *conn)
{
    g_return_if_fail (conn);

    if (conn->status == PN_NODE_STATUS_CLOSED) {
        pn_log ("already closed: %p", conn);
        return;
    }

    pn_log ("begin");

    pn_info ("closing '%s'", conn->name);
    pn_debug ("conn=%p,name=%s", conn, conn->name);

    conn->status = PN_NODE_STATUS_CLOSED;

    g_free (conn->hostname);
    conn->hostname = NULL;

    if (conn->next) {
        pn_node_close (conn->next);
        goto leave;
    }

#if defined(USE_GIO)
    if (conn->socket_conn) {
        g_object_unref(conn->socket_conn);
        conn->socket_conn = NULL;
    }
#else
#if defined(HAVE_LIBPURPLE)
    if (conn->connect_data) {
        purple_proxy_connect_cancel (conn->connect_data);
        conn->connect_data = NULL;
    }
#endif
    if (conn->read_watch)
    {
        g_source_remove (conn->read_watch);
        conn->read_watch = 0;
    }
#endif

    if (conn->stream)
    {
        pn_info ("stream shutdown: %p", conn->stream);
        pn_stream_free (conn->stream);
        conn->stream = NULL;
    }
    else
        pn_error ("not connected: conn=%p", conn);

leave:
    conn->status = PN_NODE_STATUS_CLOSED;

    pn_log ("end");
}

static void
error_impl (PnNode *conn)
{
    pn_info ("foo");
}

static GIOStatus
write_impl (PnNode *conn,
            const gchar *buf,
            gsize count,
            gsize *ret_bytes_written,
            GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;

    pn_debug ("name=%s", conn->name);

    if (conn->next)
    {
        status = pn_node_write (conn->next, buf, count, ret_bytes_written, error);
    }
    else
    {
        GError *tmp_error = NULL;
        gsize bytes_written = 0;

#if defined(USE_GIO)
        GOutputStream *output = g_io_stream_get_output_stream (G_IO_STREAM (conn->socket_conn));

        g_output_stream_write_all (output, buf, count, &bytes_written, NULL, &tmp_error);
#else
        pn_debug ("stream=%p", conn->stream);

        status = pn_stream_write_full (conn->stream, buf, count, &bytes_written, &tmp_error);

        pn_log ("bytes_written=%zu", bytes_written);

        if (status == G_IO_STATUS_NORMAL)
        {
            if (bytes_written < count)
            {
                /* This shouldn't happen, right? */
                /* It doesn't seem to happen, but keep checking for now. */
                pn_error ("write check: %zu < %zu", bytes_written, count);
            }
        }
        else
        {
            pn_warning ("not normal: status=%d (%s)",
                        status, status_to_str (status));
        }
#endif

        if (ret_bytes_written)
            *ret_bytes_written = bytes_written;

        if (tmp_error)
        {
            conn->error = g_error_copy (tmp_error);
            g_propagate_error (error, tmp_error);
        }
    }

    return status;
}

static GIOStatus
read_impl (PnNode *conn,
           gchar *buf,
           gsize count,
           gsize *ret_bytes_read,
           GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;

    pn_debug ("name=%s", conn->name);

    if (conn->next)
    {
        pn_error ("whaaat");
        status = pn_node_read (conn->next, buf, count, ret_bytes_read, error);
    }
    else
    {
        GError *tmp_error = NULL;
        gsize bytes_read = 0;

        pn_debug ("stream=%p", conn->stream);

        status = pn_stream_read (conn->stream, buf, count, &bytes_read, &tmp_error);

        if (status != G_IO_STATUS_NORMAL)
        {
            pn_info ("not normal: status=%d (%s)",
                     status, status_to_str (status));
        }

        pn_log ("bytes_read=%zu", bytes_read);

        if (ret_bytes_read)
            *ret_bytes_read = bytes_read;

        if (tmp_error)
        {
            conn->error = g_error_copy (tmp_error);
            g_propagate_error (error, tmp_error);
        }
    }

    return status;
}

static void
parse_impl (PnNode *conn,
            gchar *buf,
            gsize bytes_read)
{
    pn_debug ("name=%s", conn->name);
}

static void
channel_setup_impl (PnNode *conn,
                    GIOChannel *channel)
{
    g_io_channel_set_encoding(channel, NULL, NULL);
    g_io_channel_set_buffered(channel, FALSE);
}

/* GObject stuff. */

static void
dispose (GObject *obj)
{
    PnNode *conn = PN_NODE (obj);

    pn_log ("begin");

    if (conn->next)
    {
        if (conn->open_sig_handler)
            g_signal_handler_disconnect (conn->next, conn->open_sig_handler);
        g_signal_handler_disconnect (conn->next, conn->close_sig_handler);
        g_signal_handler_disconnect (conn->next, conn->error_sig_handler);
        pn_node_free (conn->next);
        conn->next = NULL;
    }

    parent_class->dispose (obj);

    pn_log ("end");
}

static void
finalize (GObject *obj)
{
    PnNode *conn = PN_NODE (obj);

    pn_node_close (conn);

    g_free (conn->name);
    parent_class->finalize (obj);
}

static void
class_init (gpointer g_class,
            gpointer class_data)
{
    PnNodeClass *conn_class = PN_NODE_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_class->connect = &connect_impl;
    conn_class->close = &close_impl;
    conn_class->error = &error_impl;
    conn_class->write = &write_impl;
    conn_class->read = &read_impl;
    conn_class->parse = &parse_impl;
    conn_class->channel_setup = &channel_setup_impl;

    gobject_class->dispose = dispose;
    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent (g_class);

    conn_class->open_sig = g_signal_new ("open", G_TYPE_FROM_CLASS (gobject_class),
                                         G_SIGNAL_RUN_FIRST, 0, NULL, NULL,
                                         g_cclosure_marshal_VOID__VOID,
                                         G_TYPE_NONE, 0);

    conn_class->close_sig = g_signal_new ("close", G_TYPE_FROM_CLASS (gobject_class),
                                          G_SIGNAL_RUN_FIRST, 0, NULL, NULL,
                                          g_cclosure_marshal_VOID__VOID,
                                          G_TYPE_NONE, 0);

    conn_class->error_sig = g_signal_new ("error", G_TYPE_FROM_CLASS (gobject_class),
                                          G_SIGNAL_RUN_FIRST, 0, NULL, NULL,
                                          g_cclosure_marshal_VOID__VOID,
                                          G_TYPE_NONE, 0);
}

GType
pn_node_get_type (void)
{
    static GType type = 0;

    if (G_UNLIKELY (type == 0))
    {
        GTypeInfo *type_info;

        type_info = g_new0 (GTypeInfo, 1);
        type_info->class_size = sizeof (PnNodeClass);
        type_info->class_init = class_init;
        type_info->instance_size = sizeof (PnNode);

        type = g_type_register_static (G_TYPE_OBJECT, "PnNodeType", type_info, 0);

        g_free (type_info);
    }

    return type;
}
