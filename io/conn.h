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

#ifndef MSN_CONN_H
#define MSN_CONN_H

#include <glib-object.h>

typedef enum ConnObjectType ConnObjectType;
typedef struct ConnObject ConnObject;

#define CONN_OBJECT_ERROR conn_object_error_quark ()

enum
{
    CONN_OBJECT_ERROR_OPEN,
    CONN_OBJECT_ERROR_READ,
    CONN_OBJECT_ERROR_WRITE
};

enum ConnObjectType
{
    MSN_CONN_NS,
    MSN_CONN_PASSPORT,
    MSN_CONN_CS
};

#define CONN_OBJECT_TYPE (conn_object_get_type ())
#define CONN_OBJECT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), CONN_OBJECT_TYPE, ConnObject))
#define CONN_OBJECT_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), CONN_OBJECT_TYPE, ConnObjectClass))
#define CONN_IS_OBJECT(obj) (G_TYPE_CHECK_TYPE ((obj), CONN_OBJECT_TYPE))
#define CONN_IS_OBJECT_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), CONN_OBJECT_TYPE))
#define CONN_OBJECT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), CONN_OBJECT_TYPE, ConnObjectClass))

ConnObject *conn_object_new (gchar *name, ConnObjectType type);
void conn_object_free (ConnObject *conn);
void conn_object_connect (ConnObject *conn, const gchar *hostname, gint port);
void conn_object_close (ConnObject *conn);

GIOStatus conn_object_read (ConnObject *conn, gchar *buf, gsize count, gsize *bytes_read, GError **error);
GIOStatus conn_object_write (ConnObject *conn, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
void conn_object_parse (ConnObject *conn, gchar *buf, gsize bytes_read);
void conn_object_link (ConnObject *conn, ConnObject *next);
void conn_object_error (ConnObject *conn);

#endif /* MSN_CONN_H */
