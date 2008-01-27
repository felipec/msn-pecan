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

#ifndef MSN_HTTP_CONN_PRIVATE_H
#define MSN_HTTP_CONN_PRIVATE_H

#include <glib-object.h>

typedef struct HttpConnObjectClass HttpConnObjectClass;

#include "conn_private.h"
#include "http_conn.h"

struct HttpConnObject
{
    ConnObject parent;
    gboolean dispose_has_run;

    guint parser_state;
    gboolean waiting_response;
    GQueue *write_queue;
    guint content_length;
    guint timeout_id;
    gchar *last_session_id;
    gchar *session;
    gchar *gateway;

    GHashTable *childs;
    ConnObject *cur;
};

struct HttpConnObjectClass
{
    ConnObjectClass parent_class;
};

GType http_conn_object_get_type ();

#endif /* MSN_HTTP_CONN_PRIVATE_H */
