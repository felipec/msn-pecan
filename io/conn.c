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
static guint open_sig;
static guint close_sig;
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

        status = conn_end_object_read (conn->end, buf, sizeof (buf), &bytes_read, &conn->error);

        if (status == G_IO_STATUS_AGAIN)
            return TRUE;

        if (status != G_IO_STATUS_NORMAL)
        {
            conn_object_error (conn);
            return FALSE;
        }
    }

    CONN_OBJECT_GET_CLASS (conn)->parse (conn, buf, bytes_read);

    return TRUE;
}

static gboolean
close_cb (GIOChannel *source,
          GIOCondition condition,
          gpointer data)
{
    msn_warning ("source=%p", source);

    conn_object_close (data);

    g_signal_emit (G_OBJECT (data), close_sig, 0, data);

    return FALSE;
}

static void
open_cb (ConnEndObject *conn_end,
         gpointer data)
{
    ConnObject *conn;
    GIOChannel *channel;

    conn = data;
    channel = conn->end->channel;

    if (channel)
    {
        conn->connected = TRUE;

        msn_info ("connected: conn=%p,channel=%p", conn, channel);
        conn->read_watch = g_io_add_watch (channel, G_IO_IN, read_cb, conn);
        conn->close_watch = g_io_add_watch (channel, G_IO_ERR | G_IO_HUP | G_IO_NVAL, close_cb, conn);

        CONN_OBJECT_GET_CLASS (conn)->connect (conn);

        if (conn->connect_cb)
            conn->connect_cb (conn);
    }
    else
    {
        /* msn_error ("connection error: conn=%p,msg=[%s]", conn, error_message); */
        conn->error = g_error_new_literal (CONN_OBJECT_ERROR, CONN_OBJECT_ERROR_OPEN,
                                           "Unable to connect");
        conn_object_error (conn);
    }
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

        msn_log ("%d [%s]", len, buf);
        status = conn_end_object_write (conn->end, buf, len, &bytes_written, &conn->error);

        if (status != G_IO_STATUS_NORMAL)
        {
            conn_object_error (conn);
        }
    }
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

    msn_debug ("conn=%p", conn);

    conn_object_close (conn);

    conn->end = conn_end_object_new (NULL);
    conn->end->foo_data = conn->foo_data;

    g_signal_connect (conn->end, "open", G_CALLBACK (open_cb), conn);
    conn_end_object_connect (conn->end, hostname, port);

    msn_log ("end");
}

void
conn_object_close (ConnObject *conn)
{
    msn_info ("conn=%p", conn);

    if (!conn->end)
    {
        msn_warning ("not connected (conn=%p)", conn);
        return;
    }

    if (conn->read_watch)
    {
        g_source_remove (conn->read_watch);
        conn->read_watch = 0;
    }

    if (conn->close_watch)
    {
        g_source_remove (conn->close_watch);
        conn->close_watch = 0;
    }

    conn_end_object_close (conn->end);
    conn->end = NULL;
}

/* ConnObject stuff. */

static void
connect_impl (ConnObject *conn)
{
    msn_info ("foo");
}

static void
error_impl (ConnObject *conn)
{
    msn_info ("foo");
}

static void
read_impl (ConnObject *conn)
{
    msn_info ("foo");
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

        msn_buffer_free (conn->read_buffer);
        msn_buffer_free (conn->buffer);

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
    conn_class->error = &error_impl;
    conn_class->read = &read_impl;
    conn_class->parse = &parse_impl;

    gobject_class->dispose = conn_object_dispose;
    gobject_class->finalize = conn_object_finalize;

    parent_class = g_type_class_peek_parent (g_class);

    open_sig = g_signal_new ("open", G_TYPE_FROM_CLASS (gobject_class),
                             G_SIGNAL_RUN_FIRST, 0, NULL, NULL,
                             g_cclosure_marshal_VOID__VOID,
                             G_TYPE_NONE, 0);

    close_sig = g_signal_new ("close", G_TYPE_FROM_CLASS (gobject_class),
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
