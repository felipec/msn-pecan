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

#ifndef PECAN_HTTP_SERVER_H
#define PECAN_HTTP_SERVER_H

#include <glib-object.h>

typedef struct PecanHttpServer PecanHttpServer;

#include "pecan_node.h"

#define PECAN_HTTP_SERVER_TYPE (pecan_http_server_get_type ())
#define PECAN_HTTP_SERVER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), PECAN_HTTP_SERVER_TYPE, PecanHttpServer))
#define PECAN_HTTP_SERVER_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), PECAN_HTTP_SERVER_TYPE, PecanHttpServerClass))
#define PECAN_IS_HTTP_SERVER(obj) (G_TYPE_CHECK_TYPE ((obj), PECAN_HTTP_SERVER_TYPE))
#define PECAN_IS_HTTP_SERVER_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), PECAN_HTTP_SERVER_TYPE))
#define PECAN_HTTP_SERVER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), PECAN_HTTP_SERVER_TYPE, PecanHttpServerClass))

PecanHttpServer *pecan_http_server_new (const gchar *name);
void pecan_http_server_free (PecanHttpServer *http_conn);

#endif /* PECAN_HTTP_SERVER_H */
