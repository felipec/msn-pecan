/**
 * Copyright (C) 2007-2008 Felipe Contreras
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "msn.h"
#include "servconn.h"
#include "error.h"

#include "msn_log.h"

static gboolean read_cb (GIOChannel *source, GIOCondition condition, gpointer data);

/**************************************************************************
 * Main
 **************************************************************************/

MsnServConn *
msn_servconn_new(MsnSession *session, MsnServConnType type)
{
    MsnServConn *servconn;

    g_return_val_if_fail(session != NULL, NULL);

    msn_log ("begin");
    servconn = g_new0(MsnServConn, 1);

    servconn->type = type;

    servconn->session = session;
    servconn->cmdproc = msn_cmdproc_new(session);
    servconn->cmdproc->servconn = servconn;

    servconn->httpconn = msn_httpconn_new(servconn);

    servconn->num = session->servconns_count++;

    servconn->tx_buf = purple_circ_buffer_new(MSN_BUF_LEN);

    msn_log ("end");

    return servconn;
}

void
msn_servconn_destroy(MsnServConn *servconn)
{
    g_return_if_fail(servconn != NULL);

    msn_log ("begin");

    if (servconn->processing)
    {
        servconn->wasted = TRUE;
        return;
    }

    conn_end_object_free (servconn->conn_end);

    if (servconn->destroy_cb)
        servconn->destroy_cb(servconn);

    if (servconn->httpconn != NULL)
        msn_httpconn_destroy(servconn->httpconn);

    g_free(servconn->host);

    purple_circ_buffer_destroy(servconn->tx_buf);

    if (servconn->cmdproc)
    {
        msn_cmdproc_destroy (servconn->cmdproc);
    }

    g_free(servconn);
    msn_log ("end");
}

void
msn_servconn_set_destroy_cb(MsnServConn *servconn,
                            void (*destroy_cb)(MsnServConn *))
{
    g_return_if_fail(servconn != NULL);

    servconn->destroy_cb = destroy_cb;
}

/**************************************************************************
 * Utility
 **************************************************************************/

void
msn_servconn_got_error(MsnServConn *servconn, MsnServConnError error)
{
    char *tmp;
    const char *when;

    const char *names[] = { "Notification", "Switchboard" };
    const char *name;

    name = names[servconn->type];

    switch (error)
    {
        case MSN_SERVCONN_ERROR_CONNECT:
            when = _("connecting to"); break;
        case MSN_SERVCONN_ERROR_WRITE:
            when = _("writting to"); break;
        case MSN_SERVCONN_ERROR_READ:
            when = _("reading from"); break;
        default:
            when = _("doing something on"); break;
    }

    {
        const char *reason;

        reason = servconn->error ? servconn->error->message : _("Unknown");

        msn_error ("connection error: %s (%s): %s", name, servconn->host, reason);
        tmp = g_strdup_printf(_("Error %s %s server:\n%s"), when, name, reason);
    }

    if (servconn->type == MSN_SERVCONN_NS)
    {
        msn_session_set_error(servconn->session, MSN_ERROR_SERVCONN, tmp);
    }
    else if (servconn->type == MSN_SERVCONN_SB)
    {
        MsnSwitchBoard *swboard;
        swboard = servconn->cmdproc->data;
        if (swboard != NULL)
            swboard->error = MSN_SB_ERROR_CONNECTION;
    }

    msn_servconn_disconnect(servconn);

    g_free(tmp);
}

/**************************************************************************
 * Connect
 **************************************************************************/

void
msn_servconn_disconnect(MsnServConn *servconn)
{
    g_return_if_fail(servconn != NULL);

    msn_log ("begin");

    if (servconn->connect_data != NULL)
    {
        purple_proxy_connect_cancel(servconn->connect_data);
        servconn->connect_data = NULL;
    }

    if (servconn->read_watch)
    {
        g_source_remove (servconn->read_watch);
        servconn->read_watch = 0;
    }

    conn_end_object_close (servconn->conn_end);

    servconn->rx_buf = NULL;
    servconn->rx_len = 0;
    servconn->payload_len = 0;

    servconn->connected = FALSE;

    msn_log ("end");
}

gssize
msn_servconn_write(MsnServConn *servconn, const char *buf, gsize len)
{
    gsize bytes_written = 0;

    g_return_val_if_fail(servconn != NULL, 0);

    msn_debug ("servconn=%p", servconn);

    if (!servconn->session->http_method)
    {
        GIOStatus status = G_IO_STATUS_NORMAL;

#if 0
        switch (servconn->type)
        {
            case MSN_SERVCONN_DC:
                status = conn_end_object_write (servconn->conn_end, &len, sizeof(len), &bytes_written, &servconn->error);
                status = conn_end_object_write (servconn->conn_end, buf, len, &bytes_written, &servconn->error);
                break;
            default:
                status = conn_end_object_write (servconn->conn_end, buf, len, &bytes_written, &servconn->error);
                break;
        }
#else
        status = conn_end_object_write (servconn->conn_end, buf, len, &bytes_written, &servconn->error);
#endif

        if (status != G_IO_STATUS_NORMAL)
        {
            msn_servconn_got_error(servconn, MSN_SERVCONN_ERROR_WRITE);
        }
    }
    else
    {
        int ret;
        ret = msn_httpconn_write(servconn->httpconn, buf, len);
        if (ret < 0)
        {
            msn_servconn_got_error(servconn, MSN_SERVCONN_ERROR_WRITE);
            return ret;
        }
    }

    return bytes_written;
}

static gboolean
read_cb (GIOChannel *source,
         GIOCondition condition,
         gpointer data)
{
    MsnServConn *servconn;
    MsnSession *session;
    char buf[MSN_BUF_LEN];
    char *cur, *end, *old_rx_buf;
    int cur_len;
    gsize bytes_read;

    servconn = data;
    session = servconn->session;

    msn_debug ("source=%p", source);

    {
        GIOStatus status = G_IO_STATUS_NORMAL;

        status = conn_end_object_read (servconn->conn_end, buf, sizeof(buf), &bytes_read, &servconn->error);

        if (status == G_IO_STATUS_AGAIN)
            return TRUE;

        if (status != G_IO_STATUS_NORMAL)
        {
            msn_servconn_got_error (servconn, MSN_SERVCONN_ERROR_READ);
            return FALSE;
        }
    }

    buf[bytes_read] = '\0';

    servconn->rx_buf = g_realloc(servconn->rx_buf, bytes_read + servconn->rx_len + 1);
    memcpy(servconn->rx_buf + servconn->rx_len, buf, bytes_read + 1);
    servconn->rx_len += bytes_read;

    end = old_rx_buf = servconn->rx_buf;

    servconn->processing = TRUE;

    do
    {
        cur = end;

        if (servconn->payload_len)
        {
            if (servconn->payload_len > servconn->rx_len)
                /* The payload is still not complete. */
                break;

            cur_len = servconn->payload_len;
            end += cur_len;
        }
        else
        {
            end = strstr(cur, "\r\n");

            if (end == NULL)
                /* The command is still not complete. */
                break;

            *end = '\0';
            end += 2;
            cur_len = end - cur;
        }

        servconn->rx_len -= cur_len;

        if (servconn->payload_len)
        {
            msn_cmdproc_process_payload(servconn->cmdproc, cur, cur_len);
            servconn->payload_len = 0;
        }
        else
        {
            msn_cmdproc_process_cmd_text(servconn->cmdproc, cur);
            servconn->payload_len = servconn->cmdproc->last_cmd->payload_len;
        }
    } while (servconn->connected && !servconn->wasted && servconn->rx_len > 0);

    if (servconn->connected && !servconn->wasted)
    {
        if (servconn->rx_len > 0)
            servconn->rx_buf = g_memdup(cur, servconn->rx_len);
        else
            servconn->rx_buf = NULL;
    }

    servconn->processing = FALSE;

    if (servconn->wasted)
        msn_servconn_destroy(servconn);

    g_free(old_rx_buf);

    return TRUE;
}

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
