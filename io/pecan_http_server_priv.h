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

#ifndef PECAN_HTTP_SERVER_PRIVATE_H
#define PECAN_HTTP_SERVER_PRIVATE_H

#include <glib-object.h>

typedef struct PecanHttpServerClass PecanHttpServerClass;

#include "pecan_node_priv.h"
#include "pecan_http_server.h"

struct PecanHttpServer
{
    PecanNode parent;
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
    PecanNode *cur;
    gchar *old_buffer;
};

struct PecanHttpServerClass
{
    PecanNodeClass parent_class;
};

GType pecan_http_server_get_type (void);

#endif /* PECAN_HTTP_SERVER_PRIVATE_H */
