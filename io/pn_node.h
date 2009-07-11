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

#ifndef PN_NODE_H
#define PN_NODE_H

#include <glib-object.h>

typedef struct PnNode PnNode;

#define PN_NODE_ERROR pn_node_error_quark ()

enum
{
    PN_NODE_ERROR_OPEN,
    PN_NODE_ERROR_READ,
    PN_NODE_ERROR_WRITE
};

enum PnNodeType
{
    PN_NODE_NULL, /**< Not set */
    PN_NODE_NS, /**< Notification Server */
    PN_NODE_PASSPORT, /**< Passport Server (for login) */
    PN_NODE_CS, /**< Contact Server (addressbook stuff) */
    PN_NODE_SB, /**< Switcbhard Server (a conversation) */
    PN_NODE_HTTP, /**< HTTP gateway server */
};

typedef enum PnNodeType PnNodeType;

#define PN_NODE_TYPE (pn_node_get_type ())
#define PN_NODE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), PN_NODE_TYPE, PnNode))
#define PN_NODE_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), PN_NODE_TYPE, PnNodeClass))
#define PN_NODE_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), PN_NODE_TYPE, PnNodeClass))

PnNode *pn_node_new (gchar *name, PnNodeType type);
void pn_node_free (PnNode *conn);
void pn_node_connect (PnNode *conn, const gchar *hostname, gint port);
void pn_node_close (PnNode *conn);

GIOStatus pn_node_read (PnNode *conn, gchar *buf, gsize count, gsize *bytes_read, GError **error);
GIOStatus pn_node_write (PnNode *conn, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
/* Can destroy the node. For example: BYE command. */
void pn_node_parse (PnNode *conn, gchar *buf, gsize bytes_read);
void pn_node_link (PnNode *conn, PnNode *next);
/* Can destroy the node. */
void pn_node_error (PnNode *conn);

void pn_node_set_id (PnNode *conn, guint id, const gchar *name);

GType pn_node_get_type (void);

#endif /* PN_NODE_H */
