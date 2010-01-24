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

#include "pn_direct_conn.h"
#include "io/pn_stream.h"
#include "pn_log.h"

#include "session.h"
#include "pn_peer_msg.h"
#include "pn_peer_link.h"

#include "io/pn_node.h"

#include "pn_peer_msg_priv.h"

#include "io/pn_dc_conn.h"
#include "io/pn_node_private.h"

void
pn_direct_conn_send_handshake(struct pn_direct_conn *direct_conn)
{
    struct pn_peer_link *link;
    struct pn_peer_msg *peer_msg;

    link = direct_conn->link;

    peer_msg = pn_peer_msg_new();
    peer_msg->flags = 0x100;

    if (direct_conn->nonce) {
        guint32 t1;
        guint16 t2;
        guint16 t3;
        guint16 t4;
        guint64 t5;

        sscanf (direct_conn->nonce, "%08X-%04hX-%04hX-%04hX-%012" G_GINT64_MODIFIER "X", &t1, &t2, &t3, &t4, &t5);

        t1 = GUINT32_TO_LE(t1);
        t2 = GUINT16_TO_LE(t2);
        t3 = GUINT16_TO_LE(t3);
        t4 = GUINT16_TO_BE(t4);
        t5 = GUINT64_TO_BE(t5);

        peer_msg->ack_id     = t1;
        peer_msg->ack_sub_id = t2 | (t3 << 16);
        peer_msg->ack_size   = t4 | t5;
    }

    g_free(direct_conn->nonce);
    direct_conn->nonce = NULL;

    pn_peer_link_send_msg(link, peer_msg);

    direct_conn->ack_sent = TRUE;
}

void
pn_direct_conn_send_msg(struct pn_direct_conn *direct_conn, MsnMessage *msg)
{
    char *body;
    size_t body_len;

    body = msn_message_gen_slp_body(msg, &body_len);

    pn_node_write(direct_conn->conn, body, body_len, NULL, NULL);
}

void
pn_direct_conn_process_chunk(struct pn_direct_conn *direct_conn,
                             gchar *buf,
                             gsize bytes_read)
{
    MsnMessage *msg;
    msg = msn_message_new_msnslp();
    msn_message_parse_slp_body(msg, buf, bytes_read);
    pn_peer_link_process_msg(direct_conn->link, msg, 1, direct_conn);
}

static void
open_cb(PnNode *conn,
        gpointer data)
{
    struct pn_direct_conn *direct_conn = data;

    g_signal_handler_disconnect(conn, direct_conn->open_handler);
    direct_conn->open_handler = 0;

    if (!conn->open)
        return;

    /* send foo */
    pn_node_write(conn, "foo\0", 4, NULL, NULL);

    /* Send Handshake */
    pn_direct_conn_send_handshake(direct_conn);
}

gboolean
pn_direct_conn_connect(struct pn_direct_conn *direct_conn, const char *host, int port)
{
    pn_log ("begin");

    direct_conn->open_handler = g_signal_connect(direct_conn->conn, "open", G_CALLBACK(open_cb), direct_conn);

    pn_node_connect(direct_conn->conn, host, port);

    pn_log ("end");

    return TRUE;
}

struct pn_direct_conn*
pn_direct_conn_new(struct pn_peer_link *link)
{
    struct pn_direct_conn *direct_conn;

    pn_log ("begin");

    direct_conn = g_new0(struct pn_direct_conn, 1);

    direct_conn->link = link;
    direct_conn->conn = PN_NODE(pn_dc_conn_new("dc", PN_NODE_NULL));
    direct_conn->conn->session = pn_peer_link_get_session(link);

    g_object_set_data(G_OBJECT(direct_conn->conn), "dc", direct_conn);

    if (pn_peer_link_get_directconn(link))
        pn_warning ("got_transresp: LEAK");

    pn_peer_link_set_directconn(link, direct_conn);

    pn_log ("end");

    return direct_conn;
}

void
pn_direct_conn_destroy(struct pn_direct_conn *direct_conn)
{
    pn_log ("begin");

    if (direct_conn->open_handler)
        g_signal_handler_disconnect (direct_conn->conn, direct_conn->open_handler);

    pn_dc_conn_free(PN_DC_CONN(direct_conn->conn));

    g_free(direct_conn->nonce);

    pn_peer_link_set_directconn(direct_conn->link, NULL);

    g_free(direct_conn);

    pn_log ("end");
}
