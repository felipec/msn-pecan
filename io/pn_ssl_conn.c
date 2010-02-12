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

#include "pn_ssl_conn.h"
#include "pn_node_private.h"
#include "pn_log.h"

#include "session.h" /* for libpurple account */

#ifdef HAVE_LIBPURPLE
#include <sslconn.h>
#endif /* HAVE_LIBPURPLE */

#include <errno.h>

struct PnSslConn
{
    PnNode parent;

    struct _PurpleSslConnection *ssl_data;
    PnSslConnReadCb read_cb;
    gpointer read_cb_data;
};

struct PnSslConnClass
{
    PnNodeClass parent_class;
};

static GObjectClass *parent_class;

static void
read_cb (gpointer data,
         PurpleSslConnection *gsc,
         PurpleInputCondition cond)
{
    PnNode *conn;
    PnSslConn *ssl_conn;

    pn_log ("begin");

    conn = PN_NODE (data);
    ssl_conn = PN_SSL_CONN (data);

    pn_debug ("conn=%p,name=%s", conn, conn->name);

    if (ssl_conn->read_cb)
    {
        ssl_conn->read_cb (conn, ssl_conn->read_cb_data);
        goto leave;
    }

    /* not used right now */
#if 0
    {
        gchar buf[MSN_BUF_LEN + 1];
        gsize bytes_read;

        g_object_ref (conn);

        {
            GIOStatus status = G_IO_STATUS_NORMAL;

            status = pn_node_read (conn, buf, MSN_BUF_LEN, &bytes_read, NULL);

            if (status == G_IO_STATUS_AGAIN)
            {
                g_object_unref (conn);
                return;
            }

            if (status == G_IO_STATUS_EOF)
            {
                conn->error = g_error_new (PN_NODE_ERROR, PN_NODE_ERROR_OPEN, "End of stream");
            }

            if (conn->error)
            {
                pn_node_error (conn);
                g_object_unref (conn);
                purple_ssl_close (gsc);
                return;
            }
        }

        pn_node_parse (conn, buf, bytes_read);

        g_object_unref (conn);
    }
#endif

leave:
    pn_log ("end");
}

PnSslConn *
pn_ssl_conn_new (gchar *name,
                 PnNodeType type)
{
    PnSslConn *ssl_conn;
    PnNode *conn;

    pn_log ("begin");

    ssl_conn = PN_SSL_CONN (g_type_create_instance (PN_SSL_CONN_TYPE));
    conn = PN_NODE (ssl_conn);

    conn->name = g_strdup (name);
    conn->type = type;

    pn_log ("end");

    return ssl_conn;
}

void
pn_ssl_conn_free (PnSslConn *conn)
{
    g_return_if_fail (conn);

    pn_log ("begin");
    g_object_unref (conn);
    pn_log ("end");
}

void
pn_ssl_conn_set_read_cb (PnSslConn *ssl_conn,
                            PnSslConnReadCb cb,
                            gpointer data)
{
    ssl_conn->read_cb = cb;
    ssl_conn->read_cb_data = data;
}

/* PnNode stuff. */

static void
connect_cb (gpointer data,
            PurpleSslConnection *gsc,
            PurpleInputCondition cond)
{
    PnNode *conn;
    PnSslConn *ssl_conn;

    pn_log ("begin");

    conn = PN_NODE (data);
    ssl_conn = PN_SSL_CONN (data);

    g_object_ref (conn);

    if (gsc->fd >= 0)
    {
        conn->status = PN_NODE_STATUS_OPEN;

        pn_info ("connected: conn=%p", conn);
        purple_ssl_input_add (gsc, read_cb, conn);
    }
    else
    {
        /* pn_error ("connection error: conn=%p,msg=[%s]", conn, error_message); */
        conn->error = g_error_new_literal (PN_NODE_ERROR, PN_NODE_ERROR_OPEN,
                                           "Unable to connect");
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

static void
error_cb (PurpleSslConnection *gsc,
          PurpleSslErrorType error,
          gpointer data)
{
    PnNode *conn;

    pn_log ("begin");

    conn = PN_NODE (data);

    {
        PnNodeClass *class;
        class = g_type_class_peek (PN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->error_sig, 0, conn);
    }

    pn_log ("end");
}

static void
connect_impl (PnNode *conn,
              const gchar *hostname,
              gint port)
{
    PnSslConn *ssl_conn;
    g_return_if_fail (conn);

    pn_log ("begin");

    ssl_conn = PN_SSL_CONN (conn);

    pn_debug ("conn=%p,name=%s", conn, conn->name);
    pn_debug ("hostname=%s,port=%d", hostname, port);

    pn_node_close (conn);

    g_free (conn->hostname);
    conn->hostname = g_strdup (hostname);
    conn->port = port;

    conn->status = PN_NODE_STATUS_CONNECTING;

#ifdef HAVE_LIBPURPLE
    ssl_conn->ssl_data = purple_ssl_connect (msn_session_get_user_data (conn->session),
                                             hostname, port, connect_cb, error_cb, ssl_conn);
#endif /* HAVE_LIBPURPLE */

    pn_log ("end");
}

static void
close_impl (PnNode *conn)
{
    PnSslConn *ssl_conn;

    g_return_if_fail (conn);

    if (conn->status == PN_NODE_STATUS_CLOSED) {
        pn_log ("already closed: %p", conn);
        return;
    }

    pn_log ("begin");

    ssl_conn = PN_SSL_CONN (conn);

    pn_log ("conn=%p,name=%s", conn, conn->name);

    g_free (conn->hostname);
    conn->hostname = NULL;

#ifdef HAVE_LIBPURPLE
    if (ssl_conn->ssl_data)
    {
        pn_info ("ssl shutdown: %p", ssl_conn->ssl_data);
        purple_ssl_close (ssl_conn->ssl_data);
        ssl_conn->ssl_data = NULL;
    }
    else
        pn_error ("not connected: conn=%p", conn);
#endif /* HAVE_LIBPURPLE */

    conn->status = PN_NODE_STATUS_CLOSED;

    pn_log ("end");
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
write_impl (PnNode *conn,
            const gchar *buf,
            gsize count,
            gsize *ret_bytes_written,
            GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    PnSslConn *ssl_conn;

    pn_debug ("name=%s", conn->name);

    ssl_conn = PN_SSL_CONN (conn);

    {
        gint bytes_written = 0;

        pn_debug ("stream=%p", conn->stream);

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

        pn_log ("bytes_written=%d", bytes_written);

        if (status == G_IO_STATUS_NORMAL)
        {
            if (bytes_written < count)
            {
                /* This shouldn't happen, right? */
                pn_error ("write check: %d < %zu", bytes_written, count);
            }
        }
        else
        {
            pn_warning ("not normal: status=%d (%s)",
                        status, status_to_str (status));
        }

        if (ret_bytes_written)
            *ret_bytes_written = bytes_written;

        /** @todo report error. */
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
    PnSslConn *ssl_conn;

    ssl_conn = PN_SSL_CONN (conn);

    pn_debug ("name=%s", conn->name);

    {
        gint bytes_read = 0;

        pn_debug ("ssl_data=%p", ssl_conn->ssl_data);

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
            pn_info ("not normal: status=%d (%s)",
                     status, status_to_str (status));
        }

        pn_log ("bytes_read=%d", bytes_read);

        if (ret_bytes_read)
            *ret_bytes_read = bytes_read;

        /** @todo report error. */
    }

    return status;
}

/* GObject stuff. */

static void
class_init (gpointer g_class,
            gpointer class_data)
{
    PnNodeClass *conn_class = PN_NODE_CLASS (g_class);

    conn_class->connect = &connect_impl;
    conn_class->close = &close_impl;
    conn_class->write = &write_impl;
    conn_class->read = &read_impl;

    parent_class = g_type_class_peek_parent (g_class);
}

GType
pn_ssl_conn_get_type (void)
{
    static GType type = 0;

    if (G_UNLIKELY (type == 0))
    {
        GTypeInfo *type_info;

        type_info = g_new0 (GTypeInfo, 1);
        type_info->class_size = sizeof (PnSslConnClass);
        type_info->class_init = class_init;
        type_info->instance_size = sizeof (PnSslConn);

        type = g_type_register_static (PN_NODE_TYPE, "PnSslConnType", type_info, 0);

        g_free (type_info);
    }

    return type;
}
