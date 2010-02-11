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
#include "pn_peer_call.h"

#include "io/pn_node.h"

#include "pn_peer_msg_priv.h"

#include "io/pn_dc_conn.h"
#include "io/pn_node_private.h"

#include "cmd/msg_private.h"

#include "pn_util.h" /* for msn_parse_socket */

static void
foo_cb(struct pn_direct_conn *direct_conn,
       void *data)
{
    direct_conn->status = PN_DIRECT_CONN_STATUS_CONNECTING;
    pn_direct_conn_send_handshake(direct_conn);
}

static void
msg_cb(struct pn_direct_conn *direct_conn,
       void *data)
{
    MsnMessage *msg = data;

    g_return_if_fail(msg);

    direct_conn->last_msg = NULL;

    if (msg->ack_cb)
        msg->ack_cb(msg, msg->ack_data);
    msg->nak_cb = NULL;

    msn_message_unref(msg);
}

static gboolean
write_cb (GIOChannel *source,
          GIOCondition condition,
          gpointer data)
{
    struct pn_direct_conn *direct_conn = data;

    if (direct_conn->last_flush == G_IO_STATUS_AGAIN) {
        direct_conn->last_flush = pn_stream_flush(direct_conn->conn->stream, NULL);
        if (direct_conn->last_flush == G_IO_STATUS_AGAIN)
            return TRUE;
    }

    direct_conn->write_watch = 0;

    if (direct_conn->io_cb)
        direct_conn->io_cb(direct_conn, direct_conn->io_cb_data);

    return FALSE;
}

static void
async_write(struct pn_direct_conn *direct_conn,
            pn_io_cb_t done_cb,
            void *user_data,
            const gchar *buf,
            gsize count,
            gsize *ret_bytes_written,
            GError **error)
{
    direct_conn->last_flush = pn_node_write(direct_conn->conn,
                                            buf, count, ret_bytes_written, error);

    if (direct_conn->last_flush == G_IO_STATUS_AGAIN) {
        direct_conn->io_cb = done_cb;
        direct_conn->io_cb_data = user_data;
        direct_conn->write_watch = g_io_add_watch(direct_conn->conn->stream->channel,
                                                  G_IO_OUT, write_cb, direct_conn);
    }
    else if (done_cb)
        done_cb(direct_conn, user_data);
}

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

    pn_peer_link_send_msg(link, peer_msg);

    direct_conn->ack_sent = TRUE;
}

void
pn_direct_conn_send_msg(struct pn_direct_conn *direct_conn, MsnMessage *msg)
{
    char *body;
    size_t body_len;

    body = msn_message_gen_slp_body(msg, &body_len);

    if (direct_conn->status == PN_DIRECT_CONN_STATUS_CONNECTING) {
        async_write(direct_conn, NULL, NULL, body, body_len, NULL, NULL);
        goto leave;
    }

    direct_conn->last_msg = msn_message_ref(msg);
    async_write(direct_conn, msg_cb, msg, body, body_len, NULL, NULL);

leave:
    g_free(body);
}

static void
got_nonce(struct pn_direct_conn *direct_conn,
          MsnMessage *msg)
{
    direct_conn->ack_recv = TRUE;

    pn_peer_call_session_init(direct_conn->initial_call);
    direct_conn->initial_call = NULL;

    g_free(direct_conn->nonce);
    direct_conn->nonce = NULL;

    msn_message_unref(msg);
}

void
pn_direct_conn_process_chunk(struct pn_direct_conn *direct_conn,
                             gchar *buf,
                             gsize bytes_read)
{
    MsnMessage *msg;
    msg = msn_message_new_msnslp();
    msn_message_parse_slp_body(msg, buf, bytes_read);

    if (direct_conn->status == PN_DIRECT_CONN_STATUS_CONNECTING) {
        direct_conn->status = PN_DIRECT_CONN_STATUS_OPEN;
        got_nonce(direct_conn, msg);
        return;
    }

    pn_peer_link_process_msg(direct_conn->link, msg, 1, direct_conn);
}

static void
open_cb(PnNode *conn,
        gpointer data)
{
    struct pn_direct_conn *direct_conn = data;

    g_signal_handler_disconnect(conn, direct_conn->open_handler);
    direct_conn->open_handler = 0;

    if (!conn->status == PN_NODE_STATUS_OPEN) {
        if (g_queue_is_empty(direct_conn->addrs)) {
            pn_warning("no more addresses to try");
            pn_direct_conn_destroy(direct_conn);
            pn_peer_call_session_init(direct_conn->initial_call);
            return;
        }

        /* try next one */
        pn_direct_conn_start(direct_conn);
        return;
    }

    /* send foo */
    async_write(direct_conn, foo_cb, NULL,
                "foo\0", 4, NULL, NULL);
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

    direct_conn->addrs = g_queue_new();

    pn_log ("end");

    return direct_conn;
}

void
pn_direct_conn_destroy(struct pn_direct_conn *direct_conn)
{
    pn_log ("begin");

    {
        char *addr;
        while ((addr = g_queue_pop_head(direct_conn->addrs)))
            g_free(addr);
    }
    g_queue_free(direct_conn->addrs);

    if (direct_conn->last_msg)
        msn_message_unref(direct_conn->last_msg);

    if (direct_conn->open_handler)
        g_signal_handler_disconnect (direct_conn->conn, direct_conn->open_handler);

    if (direct_conn->write_watch)
        g_source_remove (direct_conn->write_watch);

    pn_dc_conn_free(PN_DC_CONN(direct_conn->conn));

    g_free(direct_conn->nonce);

    pn_peer_link_set_directconn(direct_conn->link, NULL);

    g_free(direct_conn);

    pn_log ("end");
}

void
pn_direct_conn_add_addr(struct pn_direct_conn *direct_conn,
                        const char *addr)
{
    g_queue_push_tail(direct_conn->addrs, g_strdup(addr));
}

void
pn_direct_conn_start(struct pn_direct_conn *direct_conn)
{
    char *addr;
    char *host;
    int port;

    addr = g_queue_pop_head(direct_conn->addrs);
    if (!addr)
        return;

    msn_parse_socket(addr, &host, &port);
    pn_direct_conn_connect(direct_conn, host, port);
    g_free(host);
    g_free(addr);
}
