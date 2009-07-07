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

#ifndef PN_DIRECT_CONN_H
#define PN_DIRECT_CONN_H

struct pn_peer_link;

#include "cmd/msg.h"
#include "io/pn_stream.h"

struct PnNode;
struct _PurpleProxyConnectData;

struct pn_direct_conn {
    struct pn_peer_link *link;
    struct pn_peer_call *initial_call;

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

struct pn_direct_conn *pn_direct_conn_new(struct pn_peer_link *link);
gboolean pn_direct_conn_connect(struct pn_direct_conn *direct_conn,
                                const char *host, int port);
#if 0
void pn_direct_conn_listen(struct pn_direct_conn *direct_conn);
#endif
void pn_direct_conn_send_msg(struct pn_direct_conn *direct_conn, MsnMessage *msg);
void pn_direct_conn_parse_nonce(struct pn_direct_conn *direct_conn, const char *nonce);
void pn_direct_conn_destroy(struct pn_direct_conn *direct_conn);
void pn_direct_conn_send_handshake(struct pn_direct_conn *direct_conn);

#endif /* PN_DIRECT_CONN_H */
