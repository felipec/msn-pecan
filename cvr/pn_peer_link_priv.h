/**
 * Copyright (C) 2007-2009 Felipe Contreras
 * Copyright (C) 1998-2006 Pidgin (see pidgin-copyright)
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

#ifndef PN_PEERLINK_PRIV_H
#define PN_PEERLINK_PRIV_H

#include <glib.h>

struct MsnSession;
struct PnDirectConn;

struct PnPeerLink
{
    char *local_user;
    char *remote_user;

    int slp_seq_id;
    int slp_session_id;

    GList *slp_calls;
    GList *slp_msgs;

    GQueue *slp_msg_queue;
    struct MsnSession *session;
    struct PnDirectConn *direct_conn;

    unsigned int ref_count;
};

#endif /* PN_PEERLINK_PRIV_H */
