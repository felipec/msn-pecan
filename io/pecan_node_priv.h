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

#ifndef PECAN_NODE_PRIVATE_H
#define PECAN_NODE_PRIVATE_H

#include <glib-object.h>

#include "pecan_node.h"

typedef struct PecanNodeClass PecanNodeClass;

#define PECAN_NODE_ERROR pecan_node_error_quark ()

/* Forward declarations */

struct _PurpleProxyConnectData;
struct MsnSesion;

GQuark pecan_node_error_quark (void);

struct PecanNode
{
    GObject parent;
    gboolean dispose_has_run;

    GError *error; /**< The current IO error .*/
    guint read_watch; /** < The source id of the read watch. */

    PecanNodeType type;

    gchar *name;

    gpointer data; /**< Client data. */
    gpointer foo_data;
    PecanNode *prev;
    PecanNode *next;

    GIOChannel *channel; /**< The current IO channel .*/

    gchar *hostname;
    guint port;

    struct _PurpleProxyConnectData *connect_data;
    struct MsnSession *session;
    gulong open_sig_handler;
    gulong close_sig_handler;
    gulong error_sig_handler;
};

struct PecanNodeClass
{
    GObjectClass parent_class;

    guint open_sig;
    guint close_sig;

    GIOStatus (*read) (PecanNode *conn, gchar *buf, gsize count, gsize *bytes_read, GError **error);
    GIOStatus (*write) (PecanNode *conn, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
    void (*error) (PecanNode *conn);
    void (*connect) (PecanNode *conn, const gchar *hostname, gint port);
    void (*close) (PecanNode *conn);
    void (*parse) (PecanNode *conn, gchar *buf, gsize bytes_read);

};

#define PECAN_NODE_TYPE (pecan_node_get_type ())
#define PECAN_NODE(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), PECAN_NODE_TYPE, PecanNode))
#define PECAN_NODE_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), PECAN_NODE_TYPE, PecanNodeClass))
#define PECAN_IS_NODE(obj) (G_TYPE_CHECK_TYPE ((obj), PECAN_NODE_TYPE))
#define PECAN_IS_NODE_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), PECAN_NODE_TYPE))
#define PECAN_NODE_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), PECAN_NODE_TYPE, PecanNodeClass))

GType pecan_node_get_type ();

#endif /* PECAN_NODE_PRIVATE_H */
