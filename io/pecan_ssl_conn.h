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

#ifndef PECAN_SSL_CONN_H
#define PECAN_SSL_CONN_H

#include <glib-object.h>

#include "io/pecan_node.h"

typedef struct PecanSslConn PecanSslConn;

#define PECAN_SSL_CONN_TYPE (pecan_ssl_conn_get_type ())
#define PECAN_SSL_CONN(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), PECAN_SSL_CONN_TYPE, PecanSslConn))
#define PECAN_SSL_CONN_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), PECAN_SSL_CONN_TYPE, PecanSslConnClass))
#define PECAN_IS_SSL_CONN(obj) (G_TYPE_CHECK_TYPE ((obj), PECAN_SSL_CONN_TYPE))
#define PECAN_IS_SSL_CONN_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), PECAN_SSL_CONN_TYPE))
#define PECAN_SSL_CONN_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), PECAN_SSL_CONN_TYPE, PecanSslConnClass))

PecanSslConn *pecan_ssl_conn_new (gchar *name, PecanNodeType type);
void pecan_ssl_conn_free (PecanSslConn *ssl_conn);

GType pecan_ssl_conn_get_type (void);

#endif /* PECAN_SSL_CONN_H */
