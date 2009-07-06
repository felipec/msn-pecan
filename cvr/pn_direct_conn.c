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

#include "io/pn_node.h"

#ifndef _WIN32
#include <netinet/in.h>
#else
#include <win32dep.h>
#endif

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <proxy.h>

/**************************************************************************
 * Directconn Specific
 **************************************************************************/

void
pn_direct_conn_send_handshake(PnDirectConn *direct_conn)
{
    PnPeerLink *link;
    PnPeerMsg *peer_msg;

    g_return_if_fail(direct_conn != NULL);

    link = direct_conn->link;

    peer_msg = pn_peer_msg_new(link);
    peer_msg->flags = 0x100;

    if (direct_conn->nonce != NULL)
    {
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

/**************************************************************************
 * Connection Functions
 **************************************************************************/

#if 0
static int
create_listener(int port)
{
    int fd;
    int flags;
    const int on = 1;

#if 0
    struct addrinfo hints;
    struct addrinfo *c, *res;
    char port_str[5];

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));

    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(NULL, port_str, &hints, &res) != 0)
    {
        purple_debug_error("msn", "Could not get address info: %s.\n",
                           port_str);
        return -1;
    }

    for (c = res; c != NULL; c = c->ai_next)
    {
        fd = socket(c->ai_family, c->ai_socktype, c->ai_protocol);

        if (fd < 0)
            continue;

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

        if (bind(fd, c->ai_addr, c->ai_addrlen) == 0)
            break;

        close(fd);
    }

    if (c == NULL)
    {
        purple_debug_error("msn", "Could not find socket: %s.\n", port_str);
        return -1;
    }

    freeaddrinfo(res);
#else
    struct sockaddr_in sockin;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) != 0)
    {
        close(fd);
        return -1;
    }

    memset(&sockin, 0, sizeof(struct sockaddr_in));
    sockin.sin_family = AF_INET;
    sockin.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&sockin, sizeof(struct sockaddr_in)) != 0)
    {
        close(fd);
        return -1;
    }
#endif

    if (listen (fd, 4) != 0)
    {
        close (fd);
        return -1;
    }

    flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}
#endif

static GIOStatus
pn_direct_conn_write(PnDirectConn *direct_conn,
                     const char *data, size_t len)
{
    guint32 body_len;
    GIOStatus status = G_IO_STATUS_NORMAL;
    gsize tmp;

    g_return_val_if_fail(direct_conn != NULL, 0);

    pn_debug ("bytes_to_write=%d", len);

    body_len = GUINT32_TO_LE(len);

    /* Let's write the length of the data. */
    status = pn_stream_write (direct_conn->stream, (gchar *) &body_len, sizeof(body_len), &tmp, NULL);

    if (status == G_IO_STATUS_NORMAL)
    {
        /* Let's write the data. */
        status = pn_stream_write (direct_conn->stream, data, len, &tmp, NULL);
    }

    if (status == G_IO_STATUS_NORMAL)
    {
        pn_debug ("bytes_written=%d", tmp);

#ifdef PECAN_DEBUG_DC_FILES
        char *str;
        str = g_strdup_printf("%s/msntest/%s/w%.4d.bin", g_get_home_dir(), "dc", direct_conn->c);

        FILE *tf = g_fopen(str, "w");
        fwrite(&body_len, 1, sizeof(body_len), tf);
        fwrite(data, 1, len, tf);
        fclose(tf);

        g_free(str);

        direct_conn->c++;
#endif
    }
    else
    {
        /* pn_node_error(direct_conn->conn); */
        pn_direct_conn_destroy(direct_conn);
    }

    return status;
}

#if 0
void
pn_direct_conn_parse_nonce(PnDirectConn *direct_conn, const char *nonce)
{
    guint32 t1;
    guint16 t2;
    guint16 t3;
    guint16 t4;
    guint64 t5;

    g_return_if_fail(direct_conn != NULL);
    g_return_if_fail(nonce      != NULL);

    sscanf (nonce, "%08X-%04hX-%04hX-%04hX-%012llX", &t1, &t2, &t3, &t4, &t5);

    t1 = GUINT32_TO_LE(t1);
    t2 = GUINT16_TO_LE(t2);
    t3 = GUINT16_TO_LE(t3);
    t4 = GUINT16_TO_BE(t4);
    t5 = GUINT64_TO_BE(t5);

    direct_conn->slpheader = g_new0(MsnSlpHeader, 1);

    direct_conn->slpheader->ack_id     = t1;
    direct_conn->slpheader->ack_sub_id = t2 | (t3 << 16);
    direct_conn->slpheader->ack_size   = t4 | t5;
}
#endif

void
pn_direct_conn_send_msg(PnDirectConn *direct_conn, MsnMessage *msg)
{
    char *body;
    size_t body_len;

    body = msn_message_gen_slp_body(msg, &body_len);

    pn_direct_conn_write(direct_conn, body, body_len);
}

static void
pn_direct_conn_process_msg(PnDirectConn *direct_conn, MsnMessage *msg)
{
    pn_debug ("process_msg");

    pn_peer_link_process_msg(direct_conn->link, msg);
}

static gboolean
read_cb(GIOChannel *source, GIOCondition condition, gpointer data)
{
    PnDirectConn* direct_conn;
    gchar *body;
    guint32 body_len;
    gsize len;

    pn_debug ("source=%d", source);

    direct_conn = data;

    /* Let's read the length of the data. */
    if (pn_stream_read_full (direct_conn->stream, (gchar *) &body_len, sizeof(body_len), &len, NULL) != G_IO_STATUS_NORMAL)
    {
        pn_direct_conn_destroy(direct_conn);
        return FALSE;
    }

    body_len = GUINT32_FROM_LE(body_len);

    pn_debug ("body_len=%d", body_len);

    body = g_try_malloc(body_len);

    if (!body)
    {
        pn_error ("failed to allocate memory for read");

        return FALSE;
    }

    /* Let's read the data. */
    if (pn_stream_read_full (direct_conn->stream, body, body_len, &len, NULL) != G_IO_STATUS_NORMAL)
    {
        pn_direct_conn_destroy(direct_conn);
        return FALSE;
    }

    pn_debug ("bytes_read=%d", len);

    if (len > 0)
    {
        MsnMessage *msg;

#ifdef PECAN_DEBUG_DC_FILES
        {
            char *str;
            str = g_strdup_printf("%s/msntest/%s/r%04d.bin", g_get_home_dir(), "dc", direct_conn->c);

            FILE *tf = g_fopen(str, "w");
            fwrite(body, 1, len, tf);
            fclose(tf);

            g_free(str);
        }
#endif

        direct_conn->c++;

        msg = msn_message_new_msnslp();
        msn_message_parse_slp_body(msg, body, body_len);

        pn_direct_conn_process_msg(direct_conn, msg);
    }

    return TRUE;
}

static void
connect_cb(gpointer data, gint source, const gchar *error_message)
{
    PnDirectConn* direct_conn;
    int fd;

    pn_debug ("source=%d", source);

    direct_conn = data;
    direct_conn->connect_data = NULL;

    if (TRUE)
    {
        fd = source;
    }
    else
    {
        struct sockaddr_in client_addr;
        socklen_t client;
        fd = accept (source, (struct sockaddr *)&client_addr, &client);
    }

    if (fd > 0)
    {
        GIOChannel *channel;

        /* direct_conn->conn = pn_node_new (channel); */
        direct_conn->connected = TRUE;

        direct_conn->stream = pn_stream_new (fd);
        channel = direct_conn->stream->channel;

        pn_info ("connected: %p", channel);
        direct_conn->read_watch = g_io_add_watch (channel, G_IO_IN, read_cb, direct_conn);

        /* Send foo. */
        pn_direct_conn_write(direct_conn, "foo\0", 4);

        /* Send Handshake */
        pn_direct_conn_send_handshake(direct_conn);
    }
    else
    {
        pn_error ("bad input");
    }
}

static void
direct_conn_connect_cb(gpointer data, gint source, const gchar *error_message)
{
    if (error_message)
        pn_error ("error establishing direct connection: %s", error_message);

    connect_cb(data, source, error_message);
}

gboolean
pn_direct_conn_connect(PnDirectConn *direct_conn, const char *host, int port)
{
    MsnSession *session;

    g_return_val_if_fail(direct_conn != NULL, FALSE);
    g_return_val_if_fail(host       != NULL, TRUE);
    g_return_val_if_fail(port        > 0,    FALSE);

    pn_log ("begin");

    session = direct_conn->link->session;

#if 0
    if (session->http_method)
    {
        direct_conn->http_data->gateway_host = g_strdup(host);
    }
#endif

    direct_conn->connect_data = purple_proxy_connect(NULL, msn_session_get_account (session),
                                                    host, port, direct_conn_connect_cb, direct_conn);

    pn_log ("end");

    return (direct_conn->connect_data != NULL);
}

#if 0
void
pn_direct_conn_listen(PnDirectConn *direct_conn)
{
    int port;
    int fd;

    port = 7000;

    for (fd = -1; fd < 0;)
        fd = create_listener(++port);

    direct_conn->fd = fd;

    direct_conn->inpa = purple_input_add(fd, PURPLE_INPUT_READ, connect_cb,
                                         direct_conn);

    direct_conn->port = port;
    direct_conn->c = 0;
}
#endif

PnDirectConn*
pn_direct_conn_new(PnPeerLink *link)
{
    PnDirectConn *direct_conn;

    pn_log ("begin");

    direct_conn = g_new0(PnDirectConn, 1);

    direct_conn->link = link;

    if (link->direct_conn != NULL)
        pn_warning ("got_transresp: LEAK");

    link->direct_conn = direct_conn;

    pn_log ("end");

    return direct_conn;
}

void
pn_direct_conn_destroy(PnDirectConn *direct_conn)
{
    pn_log ("begin");

    if (direct_conn->stream)
    {
        pn_info ("stream shutdown: %p", direct_conn->stream);
        pn_stream_free (direct_conn->stream);
        direct_conn->stream = NULL;
    }

    if (direct_conn->connect_data != NULL)
        purple_proxy_connect_cancel(direct_conn->connect_data);

    if (direct_conn->read_watch)
    {
        g_source_remove (direct_conn->read_watch);
        direct_conn->read_watch = 0;
    }

    if (direct_conn->nonce != NULL)
        g_free(direct_conn->nonce);

    direct_conn->link->direct_conn = NULL;

    g_free(direct_conn);

    pn_log ("end");
}
