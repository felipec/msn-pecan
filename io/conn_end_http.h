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

#ifndef MSN_CONN_END_HTTP_H
#define MSN_CONN_END_HTTP_H

#include "conn_end.h"

#include "proxy.h"

typedef struct ConnEndHttpObject ConnEndHttpObject;
typedef struct ConnEndHttpObjectClass ConnEndHttpObjectClass;

struct ConnEndHttpObject
{
    ConnEndObject parent;
    gboolean dispose_has_run;

    gchar *hostname;
    guint parser_state;
    guint content_length;
    gchar *session_id;
    guint timeout_id;

    gboolean waiting_response;
    GQueue *write_queue;
};

struct ConnEndHttpObjectClass
{
    ConnEndObjectClass parent_class;
};

#define CONN_END_HTTP_OBJECT_TYPE (conn_end_http_object_get_type ())
#define CONN_END_HTTP_OBJECT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), CONN_END_HTTP_OBJECT_TYPE, ConnEndHttpObject))
#define CONN_END_HTTP_OBJECT_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), CONN_END_HTTP_OBJECT_TYPE, ConnEndHttpObjectClass))
#define CONN_END_HTTP_OBJECT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), CONN_END_HTTP_OBJECT_TYPE, ConnEndHttpObjectClass))

GType conn_end_http_object_get_type ();
ConnEndHttpObject *conn_end_http_object_new ();
void conn_end_http_object_free (ConnEndHttpObject *conn_end_http);

#endif /* MSN_CONN_END_HTTP_H */
