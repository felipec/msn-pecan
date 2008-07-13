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

#ifndef PECAN_SSL_CONN_PRIVATE_H
#define PECAN_SSL_CONN_PRIVATE_H

#include <glib-object.h>

#include "pecan_node_priv.h"
#include "pecan_ssl_conn.h"

typedef struct PecanSslConnClass PecanSslConnClass;

/* Forward declarations */

struct _PurpleSslConnection;

struct PecanSslConn
{
    PecanNode parent;

    struct _PurpleSslConnection *ssl_data;
    PecanSslConnReadCb read_cb;
    gpointer read_cb_data;
};

struct PecanSslConnClass
{
    PecanNodeClass parent_class;
};

#endif /* PECAN_SSL_CONN_PRIVATE_H */
