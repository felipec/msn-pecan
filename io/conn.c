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
#include "msn_io.h"
#include "msn_log.h"

#include "session.h" /* for libpurple account */

void conn_object_error (ConnObject *conn);

static GObjectClass *parent_class = NULL;
static guint error_sig;

GQuark
conn_object_error_quark (void)
{
    return g_quark_from_static_string ("conn-object-error-quark");
}

inline const gchar *
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
    ConnObject *conn;
    gchar buf[MSN_BUF_LEN];
    gsize bytes_read;

    conn = CONN_OBJECT (data);

    msn_debug ("name=%s", conn->name);
    msn_debug ("source=%p", source);

    {
        GIOStatus status = G_IO_STATUS_NORMAL;

        status = conn_object_read (conn, buf, sizeof (buf), &bytes_read, &conn->error);

        if (status == G_IO_STATUS_AGAIN)
            return TRUE;

        if (status != G_IO_STATUS_NORMAL || conn->error)
        {
            conn_object_error (conn);
            return FALSE;
        }
    }

    conn_object_parse (conn->prev ? conn->prev : conn,
                       buf, bytes_read);

    return TRUE;
}

static void
close_cb (ConnObject *next,
          gpointer data)
{
    ConnObject *conn;

    conn = CONN_OBJECT (data);

    msn_log ("begin");

    conn_object_close (conn);

    {
        ConnObjectClass *class;
        class = g_type_class_peek (CONN_OBJECT_TYPE);
        g_signal_emit (G_OBJECT (conn), class->close_sig, 0, conn);
    }

    msn_log ("begin");
}

static void
open_cb (ConnObject *next,
         gpointer data)
{
    ConnObject *conn;

    conn = CONN_OBJECT (data);

    msn_log ("begin");

    {
        ConnObjectClass *class;
        class = g_type_class_peek (CONN_OBJECT_TYPE);
        g_signal_emit (G_OBJECT (conn), class->open_sig, 0, conn);
    }

    msn_log ("end");
}

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
    g_return_if_fail (conn != NULL);
    msn_log ("begin");
    g_object_unref (G_OBJECT (conn));
    msn_log ("end");
}

void
conn_object_error (ConnObject *conn)
{
    g_return_if_fail (conn != NULL);

    msn_debug ("foo");

    g_signal_emit (G_OBJECT (conn), error_sig, 0, conn);

    if (conn->error)
    {
        msn_warning ("unhandled error: %s", conn->error->message);
        g_clear_error (&conn->error);
    }
}

GIOStatus
conn_object_write (ConnObject *conn,
                   const gchar *buf,
                   gsize count,
                   gsize *ret_bytes_written,
                   GError **error)
{
    return CONN_OBJECT_GET_CLASS (conn)->write (conn, buf, count, ret_bytes_written, error);
}

GIOStatus
conn_object_read (ConnObject *conn,
                  gchar *buf,
                  gsize count,
                  gsize *ret_bytes_read,
                  GError **error)
{
    return CONN_OBJECT_GET_CLASS (conn)->read (conn, buf, count, ret_bytes_read, error);
}

void
conn_object_link (ConnObject *conn,
                  ConnObject *next)
{
    conn->next = next;
    g_signal_connect (next, "open", G_CALLBACK (open_cb), conn);
    g_signal_connect (next, "close", G_CALLBACK (close_cb), conn);
}

void
conn_object_connect (ConnObject *conn,
                     const gchar *hostname,
                     gint port)
{
    CONN_OBJECT_GET_CLASS (conn)->connect (conn, hostname, port);
}

void
conn_object_close (ConnObject *conn)
{
    CONN_OBJECT_GET_CLASS (conn)->close (conn);
}

void
conn_object_parse (ConnObject *conn,
                   gchar *buf,
                   gsize bytes_read)
{
    CONN_OBJECT_GET_CLASS (conn)->parse (conn, buf, bytes_read);
}

/* ConnObject stuff. */

static void
connect_cb (gpointer data,
            gint source,
            const gchar *error_message)
{
    ConnObject *conn;

    msn_log ("begin");

    conn = CONN_OBJECT (data);
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
        conn->error = g_error_new_literal (CONN_OBJECT_ERROR, CONN_OBJECT_ERROR_OPEN,
                                           "Unable to connect");
        conn_object_error (conn);
    }

    {
        ConnObjectClass *class;
        class = g_type_class_peek (CONN_OBJECT_TYPE);
        g_signal_emit (G_OBJECT (conn), class->open_sig, 0, conn);
    }

    msn_log ("end");
}

static void
connect_impl (ConnObject *conn,
              const gchar *hostname,
              gint port)
{
    g_return_if_fail (conn);

    msn_log ("begin");

    msn_debug ("conn=%p", conn);

    if (conn->next)
    {
        conn->next->prev = conn;
        conn_object_connect (conn->next, hostname, port);
    }
    else
    {
        conn_object_close (conn);

        conn->connect_data = purple_proxy_connect (NULL, conn->session->account,
                                                   hostname, port, connect_cb, conn);
    }

    msn_log ("end");
}

static void
close_impl (ConnObject *conn)
{
    g_return_if_fail (conn != NULL);

    msn_log ("begin");

    if (!conn->channel)
    {
        msn_warning ("not connected: conn=%p", conn);
        return;
    }

    if (conn->connect_data)
    {
        purple_proxy_connect_cancel (conn->connect_data);
        conn->connect_data = NULL;
    }

    msn_info ("channel shutdown: %p", conn->channel);
    g_io_channel_shutdown (conn->channel, FALSE, NULL);
    g_io_channel_unref (conn->channel);
    conn->channel = NULL;

    g_free (conn->hostname);
    conn->hostname = NULL;

    msn_log ("end");
}

static void
error_impl (ConnObject *conn)
{
    msn_info ("foo");
}

static GIOStatus
write_impl (ConnObject *conn,
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
        status = conn_object_write (conn->next, buf, count, ret_bytes_written, error);
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
read_impl (ConnObject *conn,
           gchar *buf,
           gsize count,
           gsize *ret_bytes_read,
           GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;

    msn_debug ("name=%s", conn->name);

    if (conn->next)
    {
        conn->next->prev = conn;
        status = conn_object_read (conn->next, buf, count, ret_bytes_read, error);
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
parse_impl (ConnObject *conn,
            gchar *buf,
            gsize bytes_read)
{
    msn_debug ("name=%s", conn->name);
}

/* GObject stuff. */

static void
conn_object_dispose (GObject *obj)
{
    ConnObject *conn = (ConnObject *) obj;

    if (!conn->dispose_has_run)
    {
        conn->dispose_has_run = TRUE;

        conn_object_close (conn);

        g_free (conn->name);
    }

    if (conn->next)
    {
        conn_object_free (conn->next);
        conn->next = NULL;
    }

    G_OBJECT_CLASS (parent_class)->dispose (obj);
}

static void
conn_object_finalize (GObject *obj)
{
    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static void
class_init (gpointer g_class,
            gpointer class_data)
{
    ConnObjectClass *conn_class = CONN_OBJECT_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_class->connect = &connect_impl;
    conn_class->close = &close_impl;
    conn_class->error = &error_impl;
    conn_class->write = &write_impl;
    conn_class->read = &read_impl;
    conn_class->parse = &parse_impl;

    gobject_class->dispose = conn_object_dispose;
    gobject_class->finalize = conn_object_finalize;

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
            class_init, /* class_init */
            NULL, /* class_finalize */
            NULL, /* class_data */
            sizeof (ConnObject),
            0, /* n_preallocs */
            instance_init, /* instance_init */
        };

        type = g_type_register_static (G_TYPE_OBJECT, "ConnObjectType", &type_info, 0);
    }

    return type;
}
