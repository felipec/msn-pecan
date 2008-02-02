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

#include "pecan_node_priv.h"
#include "msn_io.h"
#include "msn_log.h"

#include "session.h" /* for libpurple account */

#ifdef HAVE_LIBPURPLE
/* libpurple stuff. */
#include <proxy.h>

#include "fix_purple_win32.h"
#endif /* HAVE_LIBPURPLE */

void pecan_node_error (PecanNode *conn);

static GObjectClass *parent_class = NULL;
static guint error_sig;

GQuark
pecan_node_error_quark (void)
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

static gboolean
read_cb (GIOChannel *source,
         GIOCondition condition,
         gpointer data)
{
    PecanNode *conn;
    gchar buf[MSN_BUF_LEN + 1];
    gsize bytes_read;

    msn_log ("begin");

    conn = PECAN_NODE (data);

    msn_debug ("conn=%p,name=%s", conn, conn->name);

    {
        GIOStatus status = G_IO_STATUS_NORMAL;

        status = pecan_node_read (conn, buf, MSN_BUF_LEN, &bytes_read, &conn->error);

        if (status == G_IO_STATUS_AGAIN)
            return TRUE;

        if (conn->error)
        {
            pecan_node_error (conn);
            return FALSE;
        }

        if (status == G_IO_STATUS_EOF)
        {
            conn->error = g_error_new (PECAN_NODE_ERROR, PECAN_NODE_ERROR_OPEN, "End of stream");
            pecan_node_error (conn);
            return FALSE;
        }
    }

    g_object_ref (conn);

    pecan_node_parse (conn, buf, bytes_read);

    g_object_unref (conn);

    msn_log ("end");

    return TRUE;
}

static void
open_cb (PecanNode *next,
         gpointer data)
{
    PecanNode *conn;

    conn = PECAN_NODE (data);

    msn_log ("begin");

    {
        PecanNodeClass *class;
        class = g_type_class_peek (PECAN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->open_sig, 0, conn);
    }

    g_signal_handler_disconnect (conn->next, conn->open_sig_handler);
    conn->open_sig_handler = 0;

    msn_log ("end");
}

static void
close_cb (PecanNode *next,
          gpointer data)
{
    PecanNode *conn;

    conn = PECAN_NODE (data);

    msn_log ("begin");

    pecan_node_close (conn);

    {
        PecanNodeClass *class;
        class = g_type_class_peek (PECAN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->close_sig, 0, conn);
    }

    msn_log ("begin");
}

static void
error_cb (PecanNode *next,
          gpointer data)
{
    PecanNode *conn;

    conn = PECAN_NODE (data);

    msn_log ("begin");

    if (next->error)
    {
        g_propagate_error (&conn->error, next->error);
        next->error = NULL;
    }

    g_signal_emit (G_OBJECT (conn), error_sig, 0, conn);

    msn_log ("begin");
}

PecanNode *
pecan_node_new (gchar *name, PecanNodeType type)
{
    PecanNode *conn;

    msn_log ("begin");

    conn = PECAN_NODE (g_type_create_instance (PECAN_NODE_TYPE));

    conn->name = g_strdup (name);
    conn->type = type;

    msn_log ("end");

    return conn;
}

void
pecan_node_free (PecanNode *conn)
{
    g_return_if_fail (conn != NULL);
    msn_log ("begin");
    g_object_unref (G_OBJECT (conn));
    msn_log ("end");
}

void
pecan_node_error (PecanNode *conn)
{
    g_return_if_fail (conn != NULL);

    msn_debug ("conn=%p", conn);

    g_signal_emit (G_OBJECT (conn), error_sig, 0, conn);

    if (conn->error)
    {
        msn_warning ("unhandled error: %s", conn->error->message);
        g_clear_error (&conn->error);
    }
}

GIOStatus
pecan_node_write (PecanNode *conn,
                   const gchar *buf,
                   gsize count,
                   gsize *ret_bytes_written,
                   GError **error)
{
    return PECAN_NODE_GET_CLASS (conn)->write (conn, buf, count, ret_bytes_written, error);
}

GIOStatus
pecan_node_read (PecanNode *conn,
                  gchar *buf,
                  gsize count,
                  gsize *ret_bytes_read,
                  GError **error)
{
    return PECAN_NODE_GET_CLASS (conn)->read (conn, buf, count, ret_bytes_read, error);
}

void
pecan_node_link (PecanNode *conn,
                  PecanNode *next)
{
    conn->next = g_object_ref (next);
    conn->open_sig_handler = g_signal_connect (next, "open", G_CALLBACK (open_cb), conn);
    conn->close_sig_handler = g_signal_connect (next, "close", G_CALLBACK (close_cb), conn);
    conn->error_sig_handler = g_signal_connect (next, "error", G_CALLBACK (error_cb), conn);
}

void
pecan_node_connect (PecanNode *conn,
                     const gchar *hostname,
                     gint port)
{
    PECAN_NODE_GET_CLASS (conn)->connect (conn, hostname, port);
}

void
pecan_node_close (PecanNode *conn)
{
    PECAN_NODE_GET_CLASS (conn)->close (conn);
}

void
pecan_node_parse (PecanNode *conn,
                   gchar *buf,
                   gsize bytes_read)
{
    PECAN_NODE_GET_CLASS (conn)->parse (conn, buf, bytes_read);
}

/* PecanNode stuff. */

static void
connect_cb (gpointer data,
            gint source,
            const gchar *error_message)
{
    PecanNode *conn;

    msn_log ("begin");

    conn = PECAN_NODE (data);
    conn->connect_data = NULL;

    if (source >= 0)
    {
        GIOChannel *channel;

        conn->channel = channel = g_io_channel_unix_new (source);

        g_io_channel_set_encoding (channel, NULL, NULL);
        g_io_channel_set_buffered (channel, FALSE);

        msn_info ("connected: conn=%p,channel=%p", conn, channel);
        conn->read_watch = g_io_add_watch (channel, G_IO_IN, read_cb, conn);
#if 0
        g_io_add_watch (channel, G_IO_ERR | G_IO_HUP | G_IO_NVAL, close_cb, conn);
#endif
    }
    else
    {
        /* msn_error ("connection error: conn=%p,msg=[%s]", conn, error_message); */
        conn->error = g_error_new_literal (PECAN_NODE_ERROR, PECAN_NODE_ERROR_OPEN,
                                           "Unable to connect");
        pecan_node_error (conn);
    }

    {
        PecanNodeClass *class;
        class = g_type_class_peek (PECAN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->open_sig, 0, conn);
    }

    msn_log ("end");
}

static void
connect_impl (PecanNode *conn,
              const gchar *hostname,
              gint port)
{
    g_return_if_fail (conn);

    msn_log ("begin");

    msn_debug ("conn=%p,name=%s", conn, conn->name);
    msn_debug ("hostname=%s,port=%d", hostname, port);
    msn_debug ("next=%p", conn->next);

    g_free (conn->hostname);
    conn->hostname = g_strdup (hostname);
    conn->port = port;

    if (conn->next)
    {
        conn->next->prev = conn;
        pecan_node_connect (conn->next, hostname, port);
        conn->next->prev = NULL;
    }
    else
    {
        pecan_node_close (conn);

#ifdef HAVE_LIBPURPLE
        conn->connect_data = purple_proxy_connect (NULL, msn_session_get_account (conn->session),
                                                   hostname, port, connect_cb, conn);
#endif /* HAVE_LIBPURPLE */
    }

    msn_log ("end");
}

static void
close_impl (PecanNode *conn)
{
    g_return_if_fail (conn);

    msn_log ("begin");

    msn_log ("conn=%p,name=%s", conn, conn->name);

    g_free (conn->hostname);
    conn->hostname = NULL;

    if (!conn->channel)
    {
        msn_warning ("not connected: conn=%p", conn);
    }

#ifdef HAVE_LIBPURPLE
    if (conn->connect_data)
    {
        purple_proxy_connect_cancel (conn->connect_data);
        conn->connect_data = NULL;
    }
#endif /* HAVE_LIBPURPLE */

    if (conn->read_watch)
    {
        g_source_remove (conn->read_watch);
        conn->read_watch = 0;
    }

    if (conn->channel)
    {
        msn_info ("channel shutdown: %p", conn->channel);
        g_io_channel_shutdown (conn->channel, FALSE, NULL);
        g_io_channel_unref (conn->channel);
        conn->channel = NULL;
    }

    msn_log ("end");
}

static void
error_impl (PecanNode *conn)
{
    msn_info ("foo");
}

static GIOStatus
write_impl (PecanNode *conn,
            const gchar *buf,
            gsize count,
            gsize *ret_bytes_written,
            GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;

    msn_debug ("name=%s", conn->name);

    if (conn->next)
    {
        conn->next->prev = conn;
        status = pecan_node_write (conn->next, buf, count, ret_bytes_written, error);
        conn->next->prev = NULL;
    }
    else
    {
        GError *tmp_error = NULL;
        gsize bytes_written = 0;

        msn_debug ("channel=%p", conn->channel);

        status = msn_io_write_full (conn->channel, buf, count, &bytes_written, &tmp_error);

        msn_log ("bytes_written=%d", bytes_written);

        if (status == G_IO_STATUS_NORMAL)
        {
            if (bytes_written < count)
            {
                /* This shouldn't happen, right? */
                msn_error ("write check: %d < %d", bytes_written, count);
            }
        }
        else
        {
            msn_warning ("not normal: status=%d (%s)",
                         status, status_to_str (status));
        }

        if (ret_bytes_written)
            *ret_bytes_written = bytes_written;

        if (tmp_error)
            g_propagate_error (error, tmp_error);
    }

    return status;
}

static GIOStatus
read_impl (PecanNode *conn,
           gchar *buf,
           gsize count,
           gsize *ret_bytes_read,
           GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;

    msn_debug ("name=%s", conn->name);

    if (conn->next)
    {
        msn_error ("whaaat");
        conn->next->prev = conn;
        status = pecan_node_read (conn->next, buf, count, ret_bytes_read, error);
        conn->next->prev = NULL;
    }
    else
    {
        GError *tmp_error = NULL;
        gsize bytes_read = 0;

        msn_debug ("channel=%p", conn->channel);

        status = msn_io_read (conn->channel, buf, count, &bytes_read, &tmp_error);

        if (status != G_IO_STATUS_NORMAL)
        {
            msn_info ("not normal: status=%d (%s)",
                      status, status_to_str (status));
        }

        msn_log ("bytes_read=%d", bytes_read);

        if (ret_bytes_read)
            *ret_bytes_read = bytes_read;

        if (tmp_error)
            g_propagate_error (error, tmp_error);
    }

    return status;
}

static void
parse_impl (PecanNode *conn,
            gchar *buf,
            gsize bytes_read)
{
    msn_debug ("name=%s", conn->name);
}

/* GObject stuff. */

static void
pecan_node_dispose (GObject *obj)
{
    PecanNode *conn = PECAN_NODE (obj);

    if (conn->next)
    {
        g_signal_handler_disconnect (conn->next, conn->open_sig_handler);
        g_signal_handler_disconnect (conn->next, conn->close_sig_handler);
        g_signal_handler_disconnect (conn->next, conn->error_sig_handler);
        pecan_node_free (conn->next);
        conn->next = NULL;
    }

    if (!conn->dispose_has_run)
    {
        conn->dispose_has_run = TRUE;

        pecan_node_close (conn);

        g_free (conn->name);
    }

    G_OBJECT_CLASS (parent_class)->dispose (obj);
}

static void
pecan_node_finalize (GObject *obj)
{
    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static void
class_init (gpointer g_class,
            gpointer class_data)
{
    PecanNodeClass *conn_class = PECAN_NODE_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_class->connect = &connect_impl;
    conn_class->close = &close_impl;
    conn_class->error = &error_impl;
    conn_class->write = &write_impl;
    conn_class->read = &read_impl;
    conn_class->parse = &parse_impl;

    gobject_class->dispose = pecan_node_dispose;
    gobject_class->finalize = pecan_node_finalize;

    parent_class = g_type_class_peek_parent (g_class);

    conn_class->open_sig = g_signal_new ("open", G_TYPE_FROM_CLASS (gobject_class),
                                         G_SIGNAL_RUN_FIRST, 0, NULL, NULL,
                                         g_cclosure_marshal_VOID__VOID,
                                         G_TYPE_NONE, 0);

    conn_class->close_sig = g_signal_new ("close", G_TYPE_FROM_CLASS (gobject_class),
                                          G_SIGNAL_RUN_FIRST, 0, NULL, NULL,
                                          g_cclosure_marshal_VOID__VOID,
                                          G_TYPE_NONE, 0);

    error_sig = g_signal_new ("error", G_TYPE_FROM_CLASS (gobject_class),
                              G_SIGNAL_RUN_FIRST, 0, NULL, NULL,
                              g_cclosure_marshal_VOID__VOID,
                              G_TYPE_NONE, 0);
}

static void
instance_init (GTypeInstance *instance,
               gpointer g_class)
{
}

GType
pecan_node_get_type (void)
{
    static GType type = 0;

    if (type == 0)
    {
        GTypeInfo *type_info;

        type_info = g_new0 (GTypeInfo, 1);
        type_info->class_size = sizeof (PecanNodeClass);
        type_info->class_init = class_init;
        type_info->instance_size = sizeof (PecanNode);
        type_info->instance_init = instance_init;

        type = g_type_register_static (G_TYPE_OBJECT, "PecanNodeType", type_info, 0);

        g_free (type_info);
    }

    return type;
}
