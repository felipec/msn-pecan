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

#ifndef PN_SSL_CONN_H
#define PN_SSL_CONN_H

#include <glib-object.h>

#include "io/pn_node.h"

typedef struct PnSslConn PnSslConn;
typedef struct PnSslConnClass PnSslConnClass;

typedef void (*PnSslConnReadCb) (PnNode *conn, gpointer data);

#define PN_SSL_CONN_TYPE (pn_ssl_conn_get_type ())
#define PN_SSL_CONN(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), PN_SSL_CONN_TYPE, PnSslConn))
#define PN_SSL_CONN_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), PN_SSL_CONN_TYPE, PnSslConnClass))
#define PN_SSL_CONN_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), PN_SSL_CONN_TYPE, PnSslConnClass))

PnSslConn *pn_ssl_conn_new (gchar *name, PnNodeType type);
void pn_ssl_conn_free (PnSslConn *ssl_conn);
/** @todo this thing should be on the main class */
void pn_ssl_conn_set_read_cb (PnSslConn *ssl_conn, PnSslConnReadCb read_cb, gpointer data);

GType pn_ssl_conn_get_type (void);

#endif /* PN_SSL_CONN_H */
