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

#ifndef MSN_DIRECTCONN_H
#define MSN_DIRECTCONN_H

typedef struct MsnDirectConn MsnDirectConn;

#include "cvr/pn_peer_link.h"

#include "cmd/msg.h"
#include "io/pn_stream.h"

struct PnNode;
struct _PurpleProxyConnectData;

struct MsnDirectConn
{
    PnPeerLink *link;
    PnPeerCall *initial_call;

    gboolean ack_sent;
    gboolean ack_recv;

    char *nonce;

    guint read_watch;
    gboolean connected;

    int port;

    int c;
    struct _PurpleProxyConnectData *connect_data;
    PecanStream *stream;
};

MsnDirectConn *msn_directconn_new(PnPeerLink *link);
gboolean msn_directconn_connect(MsnDirectConn *directconn,
                                const char *host, int port);
#if 0
void msn_directconn_listen(MsnDirectConn *directconn);
#endif
void msn_directconn_send_msg(MsnDirectConn *directconn, MsnMessage *msg);
void msn_directconn_parse_nonce(MsnDirectConn *directconn, const char *nonce);
void msn_directconn_destroy(MsnDirectConn *directconn);
void msn_directconn_send_handshake(MsnDirectConn *directconn);

#endif /* MSN_DIRECTCONN_H */
