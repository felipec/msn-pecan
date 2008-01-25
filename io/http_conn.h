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

#ifndef MSN_HTTP_CONN_H
#define MSN_HTTP_CONN_H

#include <glib.h>
#include "glib-object.h"

typedef struct HttpConnObject HttpConnObject;
typedef struct HttpConnObjectClass HttpConnObjectClass;

#include "conn.h"

struct PurpleProxyConnectData;
struct MsnSession;

struct HttpConnObject
{
    ConnObject parent;
    gboolean dispose_has_run;

    GIOChannel *channel;
    gchar *hostname;
    guint parser_state;
    gboolean waiting_response;
    GQueue *write_queue;
    guint content_length;
    guint timeout_id;
    gchar *last_session_id;

    struct PurpleProxyConnectData *connect_data;
    struct MsnSession *session;
};

struct HttpConnObjectClass
{
    ConnObjectClass parent_class;
};

#define HTTP_CONN_OBJECT_TYPE (http_conn_object_get_type ())
#define HTTP_CONN_OBJECT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), HTTP_CONN_OBJECT_TYPE, HttpConnObject))
#define HTTP_CONN_OBJECT_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), HTTP_CONN_OBJECT_TYPE, HttpConnObjectClass))
#define CONN_IS_HTTP_OBJECT(obj) (G_TYPE_CHECK_TYPE ((obj), HTTP_CONN_OBJECT_TYPE))
#define CONN_IS_HTTP_OBJECT_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), HTTP_CONN_OBJECT_TYPE))
#define HTTP_CONN_OBJECT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), HTTP_CONN_OBJECT_TYPE, HttpConnObjectClass))

GType http_conn_object_get_type ();
HttpConnObject *http_conn_object_new (gchar *name);
void http_conn_object_free (HttpConnObject *http_conn);

#endif /* MSN_HTTP_CONN_H */
