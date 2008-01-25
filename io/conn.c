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
#include "session.h"

/* For open. */
#include <fcntl.h>
#include <unistd.h>

void conn_object_error (ConnObject *conn);

static GObjectClass *parent_class = NULL;
static guint error_sig;

GQuark
conn_object_error_quark (void)
{
    return g_quark_from_static_string ("conn-object-error-quark");
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

        if (conn->end)
        {
            status = conn_end_object_read (conn->end, buf, sizeof (buf), &bytes_read, &conn->error);
        }
        else
        {
            conn_object_read (conn, buf, sizeof (buf), &bytes_read, &conn->error);
        }

        if (status == G_IO_STATUS_AGAIN)
            return TRUE;

        if (status != G_IO_STATUS_NORMAL || conn->error)
        {
            conn_object_error (conn);
            return FALSE;
        }
    }

    CONN_OBJECT_GET_CLASS (conn)->parse (conn, buf, bytes_read);

    return TRUE;
}

static void
close_cb (ConnEndObject *conn_end,
          gpointer data)
{
    ConnObject *conn;

    conn = CONN_OBJECT (data);

    conn_object_close (conn);

    {
        ConnObjectClass *class;
        class = g_type_class_peek (CONN_OBJECT_TYPE);
        g_signal_emit (G_OBJECT (conn), class->close_sig, 0, conn);
    }
}

static void
open_cb (ConnEndObject *conn_end,
         gpointer data)
{
    ConnObject *conn;
    GIOChannel *channel;

    conn = data;
    channel = conn_end->channel;

    msn_log ("begin");

    if (channel)
    {
        conn->connected = TRUE;

        msn_info ("connected: conn=%p,channel=%p", conn, channel);
        conn->read_watch = g_io_add_watch (channel, G_IO_IN, read_cb, conn);
    }
    else
    {
        /* msn_error ("connection error: conn=%p,msg=[%s]", conn, error_message); */
        conn->error = g_error_new_literal (CONN_OBJECT_ERROR, CONN_OBJECT_ERROR_OPEN,
                                           "Unable to connect");
        conn_object_error (conn);
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
conn_object_set_end (ConnObject *conn,
                     ConnEndObject *conn_end)
{
    conn->end = conn_end;
    conn->prev = conn_end;
    g_signal_connect (conn->end, "open", G_CALLBACK (open_cb), conn);
    g_signal_connect (conn->end, "close", G_CALLBACK (close_cb), conn);
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
connect_impl (ConnObject *conn,
              const gchar *hostname,
              gint port)
{
    g_return_if_fail (conn != NULL);
    g_return_if_fail (hostname != NULL);
    g_return_if_fail (port > 0);

    msn_log ("begin");

    msn_debug ("conn=%p", conn);

    conn_object_close (conn);

    conn->end->prev = conn;
    conn_end_object_connect (conn->end, hostname, port);

    msn_log ("end");
}

static void
close_impl (ConnObject *conn)
{
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
    GIOStatus status = G_IO_STATUS_ERROR;
    gsize bytes_written = 0;

    g_return_val_if_fail (conn, status);

    msn_debug ("conn=%p", conn);

    status = conn_end_object_write (conn->end, buf, count, &bytes_written, &conn->error);

    if (status != G_IO_STATUS_NORMAL || conn->error)
    {
        conn_object_error (conn);
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
    return status;
}

static void
parse_impl (ConnObject *conn,
            gchar *buf,
            gsize bytes_read)
{
    msn_info ("foo");
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
        conn_end_object_free (conn->end);
        conn->end = NULL;

        g_free (conn->name);
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
    ConnObject *conn = CONN_OBJECT (instance);

    conn->dispose_has_run = FALSE;
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
