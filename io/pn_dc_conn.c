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

#include "pn_dc_conn.h"
#include "pn_node_private.h"
#include "pn_log.h"

struct PnDcConn {
    PnNode parent;
};

struct PnDcConnClass {
    PnNodeClass parent_class;
};

static GObjectClass *parent_class = NULL;

PnDcConn *
pn_dc_conn_new(gchar *name,
               PnNodeType type)
{
    PnDcConn *dc_conn;
    PnNode *conn;

    dc_conn = PN_DC_CONN(g_type_create_instance(PN_DC_CONN_TYPE));
    conn = PN_NODE(dc_conn);

    conn->name = g_strdup(name);
    conn->type = type;

    return dc_conn;
}

void
pn_dc_conn_free(PnDcConn *conn)
{
    g_object_unref(G_OBJECT(conn));
}

/* PnNode stuff. */

/* GObject stuff. */

static void
finalize(GObject *obj)
{
    G_OBJECT_CLASS(parent_class)->finalize(obj);
}

static void
class_init(gpointer g_class,
           gpointer class_data)
{
    PnNodeClass *conn_class = PN_NODE_CLASS(g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS(g_class);

    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent(g_class);
}

GType
pn_dc_conn_get_type(void)
{
    static volatile gsize type = 0;

    if (g_once_init_enter(&type)) {
        GType tmp_type;
        GTypeInfo type_info = {
            .class_size = sizeof(PnDcConnClass),
            .class_init = class_init,
            .instance_size = sizeof(PnDcConn),
        };

        tmp_type = g_type_register_static(PN_NODE_TYPE, "PnDcConnType", &type_info, 0);

	g_once_init_leave(&type, tmp_type);
    }

    return type;
}
