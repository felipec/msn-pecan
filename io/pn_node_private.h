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

#ifndef PN_NODE_PRIVATE_H
#define PN_NODE_PRIVATE_H

#include <glib-object.h>

#include "pn_node.h"
#include "pn_stream.h"
#include "pn_global.h"

#if defined(USE_GIO)
#include <gio/gio.h>
#elif defined(HAVE_LIBPURPLE)
struct _PurpleProxyConnectData;
#endif

typedef struct PnNodeClass PnNodeClass;

#define PN_NODE_ERROR pn_node_error_quark ()

/* Forward declarations */

struct MsnSesion;

GQuark pn_node_error_quark (void);

enum pn_node_status {
    PN_NODE_STATUS_CLOSED,
    PN_NODE_STATUS_CONNECTING,
    PN_NODE_STATUS_OPEN,
};

struct PnNode
{
    GObject parent;
    enum pn_node_status status;

    GError *error; /**< The current IO error .*/
    guint read_watch; /** < The source id of the read watch. */

    PnNodeType type;

    guint id;
    gchar *name;

    gpointer data; /**< Client data. */
    PnNode *prev;
    PnNode *next;

    PnStream *stream; /**< The current IO stream .*/

    gchar *hostname;
    guint port;

    struct MsnSession *session;
    gulong open_sig_handler;
    gulong close_sig_handler;
    gulong error_sig_handler;

    gboolean dump_file;
#if defined(USE_GIO)
    GSocketConnection *socket_conn;
    guint8 input_buffer[PN_BUF_LEN + 1];
#elif defined(HAVE_LIBPURPLE)
    struct _PurpleProxyConnectData *connect_data;
#endif
};

struct PnNodeClass
{
    GObjectClass parent_class;

    guint open_sig;
    guint close_sig;
    guint error_sig;

    GIOStatus (*read) (PnNode *conn, gchar *buf, gsize count, gsize *bytes_read, GError **error);
    GIOStatus (*write) (PnNode *conn, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
    void (*error) (PnNode *conn);
    void (*connect) (PnNode *conn, const gchar *hostname, gint port);
    void (*close) (PnNode *conn);
    void (*parse) (PnNode *conn, gchar *buf, gsize bytes_read);
    void (*channel_setup) (PnNode *conn, GIOChannel *channel);
};

#endif /* PN_NODE_PRIVATE_H */
