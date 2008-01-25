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

#include "conn_end_http.h"
#include "msn_log.h"
#include "msn_io.h"

/*
 * Documentation for the HTTP connection method is available at:
 * http://www.hypothetic.org/docs/msn/general/http_connections.php
 *
 * Basically one http connection can be used to communicate with different
 * servers (NS, SB). Only one request can be sent at a time.
 */

static ConnEndObjectClass *parent_class = NULL;

/* ConnEndHttpObject. */

ConnEndHttpObject *
conn_end_http_object_new (void)
{
    ConnEndHttpObject *conn_end_http;
    conn_end_http = CONN_END_HTTP_OBJECT (g_type_create_instance (CONN_END_HTTP_OBJECT_TYPE));
    return conn_end_http;
}

void
conn_end_http_object_free (ConnEndHttpObject *conn_end_http)
{
    g_return_if_fail (conn_end_http != NULL);
    g_object_unref (G_OBJECT (conn_end_http));
}

/* ConnEndHttpObject implementation. */

static void
open_cb (ConnObject *conn,
         ConnEndObject *conn_end)
{
    msn_log ("begin");

    msn_log ("foo=%p", conn_end);
    {
        g_signal_emit_by_name (G_OBJECT (conn_end->prev),
                               "open", 0, conn_end);
    }

    msn_log ("end");
}

static void
connect_impl (ConnEndObject *conn_end)
{
    ConnEndHttpObject *conn_end_http;
    msn_log ("foo=%p", conn_end);
    conn_end_http = CONN_END_HTTP_OBJECT (conn_end);
    conn_end_http->http_conn->session = conn_end->foo_data;
    CONN_OBJECT (conn_end_http->http_conn)->prev = conn_end;

    msn_log ("htto_conn=%p,conn_end=%p", conn_end_http->http_conn, conn_end);
    g_signal_connect (conn_end_http->http_conn, "open", G_CALLBACK (open_cb), conn_end);
    conn_object_connect (conn_end_http->http_conn, "foo", 1);
}

static void
close_impl (ConnEndObject *conn_end)
{
    ConnEndHttpObject *conn_end_http;
    msn_log ("foo");
    conn_end_http = CONN_END_HTTP_OBJECT (conn_end);
    conn_object_close (conn_end_http->http_conn);
}

static GIOStatus
read_impl (ConnEndObject *conn_end,
           gchar *buf,
           gsize count,
           gsize *ret_bytes_read,
           GError **error)
{
    return conn_object_read (CONN_END_HTTP_OBJECT (conn_end)->http_conn,
                             buf, count, ret_bytes_read, error);
}

static GIOStatus
write_impl (ConnEndObject *conn_end,
            const gchar *buf,
            gsize count,
            gsize *ret_bytes_written,
            GError **error)
{
    return conn_object_write (CONN_END_HTTP_OBJECT (conn_end)->http_conn,
                              buf, count, ret_bytes_written, error);
}

/* GObject stuff. */

static void
dispose (GObject *obj)
{
    ConnEndHttpObject *conn_end_http = (ConnEndHttpObject *) obj;

    if (!conn_end_http->dispose_has_run)
    {
        conn_end_http->dispose_has_run = TRUE;
        conn_end_object_close (CONN_END_OBJECT (conn_end_http));
    }

    G_OBJECT_CLASS (parent_class)->dispose (obj);
}

static void
finalize (GObject *obj)
{
    /* Chain up to the parent class */
    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static void
class_init (gpointer g_class,
            gpointer class_data)
{
    ConnEndObjectClass *conn_end_class = CONN_END_OBJECT_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_end_class->connect = &connect_impl;
    conn_end_class->close = &close_impl;
    conn_end_class->read = &read_impl;
    conn_end_class->write = &write_impl;

    gobject_class->dispose = dispose;
    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

static void
instance_init (GTypeInstance *instance,
               gpointer g_class)
{
    ConnEndHttpObject *conn_end_http = CONN_END_HTTP_OBJECT (instance);

    conn_end_http->http_conn = http_conn_object_new ("foobar");
}

GType
conn_end_http_object_get_type (void)
{
    static GType type = 0;

    if (type == 0) 
    {
        static const GTypeInfo type_info =
        {
            sizeof (ConnEndHttpObjectClass),
            NULL, /* base_init */
            NULL, /* base_finalize */
            class_init, /* class_init */
            NULL, /* class_finalize */
            NULL, /* class_data */
            sizeof (ConnEndHttpObject),
            0, /* n_preallocs */
            instance_init /* instance_init */
        };

        type = g_type_register_static (CONN_END_OBJECT_TYPE, "ConnEndHttpObjectType", &type_info, 0);
    }

    return type;
}
