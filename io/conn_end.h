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

#ifndef MSN_CONN_END_H
#define MSN_CONN_END_H

#include <proxy.h> /* libpurple */

typedef struct ConnEndObject ConnEndObject;
typedef struct ConnEndObjectClass ConnEndObjectClass;

struct ConnObject;

struct ConnEndObject
{
    GObject parent;
    gboolean dispose_has_run;

    GIOChannel *channel; /**< The current IO channel .*/
    gboolean is_open;

    PurpleProxyConnectData *connect_data;
    gpointer foo_data;
    gpointer foo_data_2;
    gchar *hostname;
    guint port;
    struct ConnObject *prev;
};

struct ConnEndObjectClass
{
    GObjectClass parent_class;

    guint open_sig;
    guint close_sig;

    void (*connect) (ConnEndObject *end);
    void (*close) (ConnEndObject *end);
    void (*free) (ConnEndObject *end);
    GIOStatus (*read) (ConnEndObject *end, gchar *buf, gsize count, gsize *bytes_read, GError **error);
    GIOStatus (*write) (ConnEndObject *end, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
};

#define CONN_END_OBJECT_TYPE (conn_end_object_get_type ())
#define CONN_END_OBJECT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), CONN_END_OBJECT_TYPE, ConnEndObject))
#define CONN_END_OBJECT_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), CONN_END_OBJECT_TYPE, ConnEndObjectClass))
#define CONN_IS_END_OBJECT(obj) (G_TYPE_CHECK_TYPE ((obj), CONN_END_OBJECT_TYPE))
#define CONN_IS_END_OBJECT_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), CONN_END_OBJECT_TYPE))
#define CONN_END_OBJECT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), CONN_END_OBJECT_TYPE, ConnEndObjectClass))

GType conn_end_object_get_type ();
ConnEndObject *conn_end_object_new ();
void conn_end_object_connect (ConnEndObject *conn_end, const gchar *hostname, guint port);
void conn_end_object_free (ConnEndObject *conn_end);
void conn_end_object_close (ConnEndObject *conn_end);
GIOStatus conn_end_object_read (ConnEndObject *conn_end, gchar *buf, gsize count, gsize *bytes_read, GError **error);
GIOStatus conn_end_object_write (ConnEndObject *conn_end, const gchar *buf, gsize count, gsize *bytes_written, GError **error);

#endif /* MSN_CONN_END_H */
