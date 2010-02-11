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
struct pn_direct_conn;

typedef void (*pn_io_cb_t) (struct pn_direct_conn *direct_conn, void *data);

enum pn_direct_conn_status {
    PN_DIRECT_CONN_STATUS_UNKNOWN,
    PN_DIRECT_CONN_STATUS_CONNECTING,
    PN_DIRECT_CONN_STATUS_OPEN,
};

struct pn_direct_conn {
    struct pn_peer_link *link;
    struct pn_peer_call *initial_call;

    gboolean ack_sent;
    gboolean ack_recv;

    char *nonce;

    gboolean connected;

    int port;

    struct PnNode *conn;
    gulong open_handler;

    guint write_watch;
    GIOStatus last_flush;
    pn_io_cb_t io_cb;
    void *io_cb_data;

    MsnMessage *last_msg;
    enum pn_direct_conn_status status;

    GQueue *addrs;
};

struct pn_direct_conn *pn_direct_conn_new(struct pn_peer_link *link);
gboolean pn_direct_conn_connect(struct pn_direct_conn *direct_conn,
                                const char *host, int port);
void pn_direct_conn_send_msg(struct pn_direct_conn *direct_conn, MsnMessage *msg);
void pn_direct_conn_destroy(struct pn_direct_conn *direct_conn);
void pn_direct_conn_send_handshake(struct pn_direct_conn *direct_conn);

void pn_direct_conn_process_chunk(struct pn_direct_conn *direct_conn, gchar *buf, gsize bytes_read);
void pn_direct_conn_add_addr(struct pn_direct_conn *direct_conn, const char *addr);
void pn_direct_conn_start(struct pn_direct_conn *direct_conn);

#endif /* PN_DIRECT_CONN_H */
