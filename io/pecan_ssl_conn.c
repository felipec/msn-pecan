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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "pecan_ssl_conn_priv.h"
#include "pecan_node_priv.h"
#include "pecan_log.h"

#include "session.h" /* for libpurple account */

#ifdef HAVE_LIBPURPLE
/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <proxy.h>
#undef connect
#undef write
#undef read
#undef close
#endif /* HAVE_LIBPURPLE */

#include <errno.h>

static GObjectClass *parent_class = NULL;

static void
read_cb (gpointer data,
         PurpleSslConnection *gsc,
         PurpleInputCondition cond)
{
    PecanNode *conn;
    gchar buf[MSN_BUF_LEN + 1];
    gsize bytes_read;

    pecan_log ("begin");

    conn = PECAN_NODE (data);

    pecan_debug ("conn=%p,name=%s", conn, conn->name);

    g_object_ref (conn);

    {
        GIOStatus status = G_IO_STATUS_NORMAL;

        status = pecan_node_read (conn, buf, MSN_BUF_LEN, &bytes_read, NULL);

        if (status == G_IO_STATUS_AGAIN)
        {
            g_object_unref (conn);
            return;
        }

        if (status == G_IO_STATUS_EOF)
        {
            conn->error = g_error_new (PECAN_NODE_ERROR, PECAN_NODE_ERROR_OPEN, "End of stream");
        }

        if (conn->error)
        {
            pecan_node_error (conn);
            g_object_unref (conn);
            purple_ssl_close (gsc);
            return;
        }
    }

    /* pecan_node_parse (conn, buf, bytes_read); */

    g_object_unref (conn);

    pecan_log ("end");
}

PecanSslConn *
pecan_ssl_conn_new (gchar *name,
                    PecanNodeType type)
{
    PecanSslConn *ssl_conn;
    PecanNode *conn;

    pecan_log ("begin");

    ssl_conn = PECAN_SSL_CONN (g_type_create_instance (PECAN_SSL_CONN_TYPE));
    conn = PECAN_NODE (ssl_conn);

    conn->name = g_strdup (name);
    conn->type = type;

    pecan_log ("end");

    return ssl_conn;
}

void
pecan_ssl_conn_free (PecanSslConn *conn)
{
    g_return_if_fail (conn);

    pecan_log ("begin");
    g_object_unref (G_OBJECT (conn));
    pecan_log ("end");
}

/* PecanNode stuff. */

static void
connect_cb (gpointer data,
            PurpleSslConnection *gsc,
            PurpleInputCondition cond)
{
    PecanNode *conn;
    PecanSslConn *ssl_conn;

    pecan_log ("begin");

    conn = PECAN_NODE (data);
    ssl_conn = PECAN_SSL_CONN (data);

    g_object_ref (conn);

    if (gsc->fd >= 0)
    {
        pecan_info ("connected: conn=%p,ssl_conn=%p", conn, ssl_conn);
        purple_ssl_input_add (gsc, read_cb, conn);
    }
    else
    {
        /* pecan_error ("connection error: conn=%p,msg=[%s]", conn, error_message); */
        conn->error = g_error_new_literal (PECAN_NODE_ERROR, PECAN_NODE_ERROR_OPEN,
                                           "Unable to connect");
        pecan_node_error (conn);
    }

    {
        PecanNodeClass *class;
        class = g_type_class_peek (PECAN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->open_sig, 0, conn);
    }

    g_object_unref (conn);

    pecan_log ("end");
}

static void
connect_impl (PecanNode *conn,
              const gchar *hostname,
              gint port)
{
    PecanSslConn *ssl_conn;
    g_return_if_fail (conn);

    pecan_log ("begin");

    ssl_conn = PECAN_SSL_CONN (conn);

    pecan_debug ("conn=%p,name=%s", conn, conn->name);
    pecan_debug ("hostname=%s,port=%d", hostname, port);

    g_free (conn->hostname);
    conn->hostname = g_strdup (hostname);
    conn->port = port;

    pecan_node_close (conn);

#ifdef HAVE_LIBPURPLE
    ssl_conn->ssl_data = purple_ssl_connect (msn_session_get_account (conn->session),
                                             hostname, port, connect_cb, NULL, ssl_conn);
#endif /* HAVE_LIBPURPLE */

    pecan_log ("end");
}

static void
close_impl (PecanNode *conn)
{
    PecanSslConn *ssl_conn;

    g_return_if_fail (conn);

    pecan_log ("begin");

    ssl_conn = PECAN_SSL_CONN (conn);

    pecan_log ("conn=%p,name=%s", conn, conn->name);

    g_free (conn->hostname);
    conn->hostname = NULL;

    if (!ssl_conn->ssl_data)
    {
        pecan_warning ("not connected: conn=%p", conn);
    }

#ifdef HAVE_LIBPURPLE
#if 0
    if (ssl_conn->read_watch)
    {
        purple_input_remove (ssl_conn->read_watch);
        ssl_conn->read_watch = 0;
    }
#endif

    if (ssl_conn->ssl_data)
    {
        pecan_info ("ssl shutdown: %p", ssl_conn->ssl_data);
        purple_ssl_close (ssl_conn->ssl_data);
        ssl_conn->ssl_data = NULL;
    }
#endif /* HAVE_LIBPURPLE */

    pecan_log ("end");
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

static GIOStatus
write_impl (PecanNode *conn,
            const gchar *buf,
            gsize count,
            gsize *ret_bytes_written,
            GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    PecanSslConn *ssl_conn;

    pecan_debug ("name=%s", conn->name);

    ssl_conn = PECAN_SSL_CONN (conn);

    {
        gint bytes_written = 0;

        pecan_debug ("stream=%p", conn->stream);

        /* write_full */
        do
        {
            bytes_written = purple_ssl_write (ssl_conn->ssl_data, buf, count);

            if (bytes_written == 0)
                status = G_IO_STATUS_EOF;
            else if (bytes_written < 0)
            {
                if (errno == EAGAIN)
                    status = G_IO_STATUS_AGAIN;
                else
                    status = G_IO_STATUS_ERROR;
            }
        } while (status == G_IO_STATUS_AGAIN);

        pecan_log ("bytes_written=%d", bytes_written);

        if (status == G_IO_STATUS_NORMAL)
        {
            if (bytes_written < count)
            {
                /* This shouldn't happen, right? */
                pecan_error ("write check: %d < %d", bytes_written, count);
            }
        }
        else
        {
            pecan_warning ("not normal: status=%d (%s)",
                           status, status_to_str (status));
        }

        if (ret_bytes_written)
            *ret_bytes_written = bytes_written;

        /** @todo report error. */
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
    PecanSslConn *ssl_conn;

    ssl_conn = PECAN_SSL_CONN (conn);

    pecan_debug ("name=%s", conn->name);

    {
        gint bytes_read = 0;

        pecan_debug ("ssl_data=%p", ssl_conn->ssl_data);

        bytes_read = purple_ssl_read (ssl_conn->ssl_data, buf, count);

        if (bytes_read == 0)
            status = G_IO_STATUS_EOF;
        else if (bytes_read < 0)
        {
            if (errno == EAGAIN)
                status = G_IO_STATUS_AGAIN;
            else
                status = G_IO_STATUS_ERROR;
        }

        if (status != G_IO_STATUS_NORMAL)
        {
            pecan_info ("not normal: status=%d (%s)",
                        status, status_to_str (status));
        }

        pecan_log ("bytes_read=%d", bytes_read);

        if (ret_bytes_read)
            *ret_bytes_read = bytes_read;

        /** @todo report error. */
    }

    return status;
}

/* GObject stuff. */

static void
dispose (GObject *obj)
{
    PecanNode *conn = PECAN_NODE (obj);

    pecan_log ("begin");

    if (!conn->dispose_has_run)
    {
        conn->dispose_has_run = TRUE;

        pecan_node_close (conn);

        g_free (conn->name);
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

    conn_class->connect = &connect_impl;
    conn_class->close = &close_impl;
    conn_class->write = &write_impl;
    conn_class->read = &read_impl;

    gobject_class->dispose = dispose;
    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

static void
instance_init (GTypeInstance *instance,
               gpointer g_class)
{
}

GType
pecan_ssl_conn_get_type (void)
{
    static GType type = 0;

    if (type == 0)
    {
        GTypeInfo *type_info;

        type_info = g_new0 (GTypeInfo, 1);
        type_info->class_size = sizeof (PecanSslConnClass);
        type_info->class_init = class_init;
        type_info->instance_size = sizeof (PecanSslConn);
        type_info->instance_init = instance_init;

        type = g_type_register_static (PECAN_NODE_TYPE, "PecanSslConnType", type_info, 0);

        g_free (type_info);
    }

    return type;
}
