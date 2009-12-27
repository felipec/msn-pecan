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

#ifndef PN_DC_CONN_H
#define PN_DC_CONN_H

#include <glib-object.h>

#include "io/pn_node.h"

typedef struct PnDcConn PnDcConn;
typedef struct PnDcConnClass PnDcConnClass;

#define PN_DC_CONN_TYPE (pn_dc_conn_get_type())
#define PN_DC_CONN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), PN_DC_CONN_TYPE, PnDcConn))
#define PN_DC_CONN_CLASS(c) (G_TYPE_CHECK_CLASS_CAST((c), PN_DC_CONN_TYPE, PnDcConnClass))
#define PN_DC_CONN_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS((obj), PN_DC_CONN_TYPE, PnDcConnClass))

PnDcConn *pn_dc_conn_new(gchar *name, PnNodeType type);
void pn_dc_conn_free(PnDcConn *dc_conn);

GType pn_dc_conn_get_type(void);

#endif /* PN_DC_CONN_H */
