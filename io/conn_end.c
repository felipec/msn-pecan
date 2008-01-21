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

#include "conn_end.h"
#include "msn_log.h"
#include "msn_io.h"

/* For read/write. */
#include <unistd.h>

static GObjectClass *parent_class = NULL;

static gboolean
close_cb (GIOChannel *source,
          GIOCondition condition,
          gpointer data)
{
    const char *cond_id;

    switch (condition)
    {
        case G_IO_PRI: cond_id = "PRI"; break;
        case G_IO_ERR: cond_id = "ERR"; break;
        case G_IO_HUP: cond_id = "HUP"; break;
        case G_IO_NVAL: cond_id = "NVAL"; break;
        default: cond_id = NULL; break;
    }

    msn_warning ("source=%p,condition=%s", source, cond_id);

    return FALSE;
}

/* ConnEndObject. */

ConnEndObject *
conn_end_object_new (GIOChannel *channel)
{
    ConnEndObject *conn_end;

    msn_log ("begin");

    conn_end = CONN_END_OBJECT (g_type_create_instance (CONN_END_OBJECT_TYPE));

    conn_end->channel = channel;

    g_io_channel_set_encoding (channel, NULL, NULL);
    g_io_channel_set_buffered (channel, FALSE);

    g_io_add_watch (channel, G_IO_ERR | G_IO_HUP | G_IO_NVAL, close_cb, conn_end);

    msn_log ("end");

    return conn_end;
}

void
conn_end_object_free (ConnEndObject *conn_end)
{
    g_return_if_fail (conn_end != NULL);
    msn_log ("begin");
    g_object_unref (G_OBJECT (conn_end));
    msn_log ("end");
}

void
conn_end_object_connect (ConnEndObject *conn_end)
{
    g_return_if_fail (conn_end != NULL);
    CONN_END_OBJECT_GET_CLASS (conn_end)->connect (conn_end);
}

void
conn_end_object_close (ConnEndObject *conn_end)
{
    g_return_if_fail (conn_end != NULL);
    CONN_END_OBJECT_GET_CLASS (conn_end)->close (conn_end);
}

GIOStatus
conn_end_object_read (ConnEndObject *conn_end,
                      gchar *buf,
                      gsize count,
                      gsize *bytes_read,
                      GError **error)
{
    return CONN_END_OBJECT_GET_CLASS (conn_end)->read (conn_end, buf, count, bytes_read, error);
}

GIOStatus
conn_end_object_write (ConnEndObject *conn_end,
                       const gchar *buf,
                       gsize count,
                       gsize *bytes_written,
                       GError **error)
{
    return CONN_END_OBJECT_GET_CLASS (conn_end)->write (conn_end, buf, count, bytes_written, error);
}

/* ConnEndObject implementation. */

static void
connect_impl (ConnEndObject *conn_end)
{
}

static void
close_impl (ConnEndObject *conn_end)
{
    if (conn_end->channel)
    {
        msn_info ("channel shutdown: %p", conn_end->channel);
        g_io_channel_shutdown (conn_end->channel, FALSE, NULL);
        g_io_channel_unref (conn_end->channel);
        conn_end->channel = NULL;
    }
}

static GIOStatus
read_impl (ConnEndObject *conn_end,
           gchar *buf,
           gsize count,
           gsize *ret_bytes_read,
           GError **ret_error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *error = NULL;
    gsize bytes_read = 0;

    msn_debug ("read: %p", conn_end->channel);

    status = msn_io_read (conn_end->channel, buf, count, &bytes_read, &error);

    if (status != G_IO_STATUS_NORMAL)
    {
        msn_warning ("not normal");
    }

    msn_log ("bytes_read=%d", bytes_read);

    if (ret_bytes_read)
        *ret_bytes_read = bytes_read;

    if (ret_error)
        *ret_error = error;

    return status;
}

static GIOStatus
write_impl (ConnEndObject *conn_end,
            const gchar *buf,
            gsize count,
            gsize *ret_bytes_written,
            GError **ret_error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *error = NULL;
    gsize bytes_written = 0;

    msn_debug ("write: %p", conn_end->channel);

    status = msn_io_write_full (conn_end->channel, buf, count, &bytes_written, &error);

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
        msn_error ("not normal");
    }

    if (ret_bytes_written)
        *ret_bytes_written = bytes_written;

    if (ret_error)
        *ret_error = error;

    return status;
}

/* GObject stuff. */

static void
conn_end_object_dispose (GObject *obj)
{
    ConnEndObject *conn_end = (ConnEndObject *) obj;

    if (!conn_end->dispose_has_run)
    {
        conn_end->dispose_has_run = TRUE;
        conn_end_object_close (conn_end);
    }

    G_OBJECT_CLASS (parent_class)->dispose (obj);
}

static void
conn_end_object_finalize (GObject *obj)
{
    /* Chain up to the parent class */
    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

void
conn_end_object_class_init (gpointer g_class, gpointer class_data)
{
    ConnEndObjectClass *conn_end_class = CONN_END_OBJECT_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_end_class->connect = &connect_impl;
    conn_end_class->close = &close_impl;
    conn_end_class->read = &read_impl;
    conn_end_class->write = &write_impl;

    gobject_class->dispose = conn_end_object_dispose;
    gobject_class->finalize = conn_end_object_finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

void
conn_end_object_instance_init (GTypeInstance *instance, gpointer g_class)
{
    ConnEndObject *conn_end = CONN_END_OBJECT (instance);

    conn_end->dispose_has_run = FALSE;
}

GType
conn_end_object_get_type (void)
{
    static GType type = 0;

    if (type == 0) 
    {
        static const GTypeInfo type_info =
        {
            sizeof (ConnEndObjectClass),
            NULL, /* base_init */
            NULL, /* base_finalize */
            conn_end_object_class_init, /* class_init */
            NULL, /* class_finalize */
            NULL, /* class_data */
            sizeof (ConnEndObject),
            0, /* n_preallocs */
            conn_end_object_instance_init /* instance_init */
        };

        type = g_type_register_static (G_TYPE_OBJECT, "ConnEndObjectType", &type_info, 0);
    }

    return type;
}
