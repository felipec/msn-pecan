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

#ifndef PN_HTTP_SERVER_H
#define PN_HTTP_SERVER_H

#include <glib-object.h>

typedef struct PnHttpServer PnHttpServer;
typedef struct PnHttpServerClass PnHttpServerClass;

#include "pn_node.h"

#define PN_HTTP_SERVER_TYPE (pn_http_server_get_type ())
#define PN_HTTP_SERVER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), PN_HTTP_SERVER_TYPE, PnHttpServer))
#define PN_HTTP_SERVER_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), PN_HTTP_SERVER_TYPE, PnHttpServerClass))
#define PN_HTTP_SERVER_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), PN_HTTP_SERVER_TYPE, PnHttpServerClass))

PnHttpServer *pn_http_server_new (const gchar *name);
void pn_http_server_free (PnHttpServer *http_conn);

GType pn_http_server_get_type (void);

#endif /* PN_HTTP_SERVER_H */
