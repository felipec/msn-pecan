/*
 * Copyright (C) 2008-2009 Felipe Contreras.
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

#include "pn_http_server.h"
#include "pn_node_private.h"
#include "pn_stream.h"
#include "pn_timer.h"
#include "pn_log.h"
#include "pn_global.h"

#include <glib.h>
#include <string.h>
#include <stdlib.h> /* for atoi */

#include "pn_util.h"
#include "session.h"

#ifdef HAVE_LIBPURPLE
#include <proxy.h> /* for purple_proxy_info_get_* */
#endif /* HAVE_LIBPURPLE */

struct PnHttpServer
{
    PnNode parent;

    guint parser_state;
    gboolean waiting_response;
    GQueue *write_queue;
    guint content_length;
    struct pn_timer *timer;
    gchar *last_session_id;
    gchar *session;
    gchar *gateway;

    gchar *old_buffer;

    guint write_watch;
    GIOStatus last_flush;
};

struct PnHttpServerClass
{
    PnNodeClass parent_class;
};

static PnNodeClass *parent_class;

typedef struct
{
    gchar *body;
    gsize body_len;
} HttpQueueData;

static GIOStatus
foo_write (PnNode *conn,
           const gchar *buf,
           gsize count,
           gsize *ret_bytes_written,
           GError **error);

static void
process_queue (PnHttpServer *http_conn,
               GError **error)
{
    HttpQueueData *queue_data;

    queue_data = g_queue_pop_head (http_conn->write_queue);

    if (queue_data)
    {
        foo_write (PN_NODE (http_conn),
                   queue_data->body,
                   queue_data->body_len,
                   NULL,
                   error);
        g_free (queue_data->body);
        g_free (queue_data);
    }
}

static gboolean
read_cb (GIOChannel *source,
         GIOCondition condition,
         gpointer data)
{
    PnNode *conn;
    gchar buf[PN_BUF_LEN + 1];
    gsize bytes_read;

    pn_log ("begin");

    conn = PN_NODE (data);

    pn_debug ("conn=%p,source=%p", conn, source);

    g_object_ref (conn);

    {
        GIOStatus status = G_IO_STATUS_NORMAL;

        status = pn_node_read (conn, buf, PN_BUF_LEN, &bytes_read, &conn->error);

        if (status == G_IO_STATUS_AGAIN)
        {
            g_object_unref (conn);
            return TRUE;
        }

        if (conn->error)
        {
            pn_node_error (conn);
            g_object_unref (conn);
            return FALSE;
        }

        if (status != G_IO_STATUS_NORMAL)
        {
            pn_warning ("not normal, status=%d", status);
            g_object_unref (conn);
            return TRUE;
        }
    }

    if (!conn->error)
    {
        PnHttpServer *http_conn;

        http_conn = PN_HTTP_SERVER (conn);

        /* make sure the server is not sending the same buffer again */
        /** @todo find out why this happens */
        if (!(http_conn->old_buffer &&
              strncmp (buf, http_conn->old_buffer, bytes_read) == 0))
        {
            g_object_ref (conn->prev);
            pn_node_parse (conn->prev, buf, bytes_read);
            g_object_unref (conn->prev);

            g_free (http_conn->old_buffer);
            http_conn->old_buffer = g_strndup (buf, bytes_read);
        }

        if (conn->error)
        {
            pn_node_error (conn);
            g_object_unref (conn);
            return FALSE;
        }
    }

    g_object_unref (conn);

    pn_log ("end");

    return TRUE;
}

PnHttpServer *
pn_http_server_new (const gchar *name)
{
    PnHttpServer *http_conn;

    pn_log ("begin");

    http_conn = PN_HTTP_SERVER (g_type_create_instance (PN_HTTP_SERVER_TYPE));

    {
        PnNode *tmp = PN_NODE (http_conn);
        tmp->name = g_strdup (name);
        tmp->type = PN_NODE_HTTP;
    }

    pn_log ("end");

    return http_conn;
}

void
pn_http_server_free (PnHttpServer *http_conn)
{
    pn_log ("begin");
    g_object_unref (http_conn);
    pn_log ("end");
}

#ifdef HAVE_LIBPURPLE
/* get proxy auth info and set up proxy auth header */
/* TODO find a way to do this without libpurple */
static inline char *
get_auth(PnNode *conn)
{
    const char *username, *password;
    PurpleProxyInfo *gpi;
    char *tmp, *auth;

    gpi = purple_proxy_get_setup(msn_session_get_user_data(conn->session));
    if (!gpi)
        return NULL;

    if (purple_proxy_info_get_type(gpi) != PURPLE_PROXY_HTTP &&
        purple_proxy_info_get_type(gpi) != PURPLE_PROXY_USE_ENVVAR)
        return NULL;

    username = purple_proxy_info_get_username(gpi);
    password = purple_proxy_info_get_password(gpi);
    if (!username && !password)
        return NULL;

    auth = g_strdup_printf("%s:%s", username ? username : "", password ? password : "");
    tmp = purple_base64_encode((const guchar *) auth, strlen(auth));
    g_free(auth);
    auth = g_strdup_printf("Proxy-Authorization: Basic %s\r\n", tmp);
    g_free(tmp);

    return auth;
}
#endif /* HAVE_LIBPURPLE */

static gboolean
write_cb (GIOChannel *source,
          GIOCondition condition,
          gpointer data)
{
    PnHttpServer *http_conn = data;

    if (http_conn->last_flush == G_IO_STATUS_AGAIN) {
        http_conn->last_flush = pn_stream_flush(PN_NODE(http_conn)->stream, NULL);
        if (http_conn->last_flush == G_IO_STATUS_AGAIN)
            return TRUE;
    }

    http_conn->write_watch = 0;

    return FALSE;
}

static GIOStatus
async_flush (PnHttpServer *http_conn, GError **error)
{
    PnNode *conn = PN_NODE(http_conn);

    http_conn->last_flush = pn_stream_flush (conn->stream, error);

    if (http_conn->last_flush == G_IO_STATUS_AGAIN)
        http_conn->write_watch = g_io_add_watch (conn->stream->channel,
                                                 G_IO_OUT, write_cb, http_conn);

    return http_conn->last_flush;
}

static GIOStatus
post (PnHttpServer *http_conn,
      gboolean poll,
      const gchar *buf,
      gsize count,
      gsize *ret_bytes_written,
      GError **error)
{
    PnNode *conn;
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize bytes_written = 0;

    gchar *header;
    gchar *params;
    gchar *auth = NULL;
    gchar *body = NULL;
    gsize body_len;
    gchar *session_id = http_conn->last_session_id;

    conn = PN_NODE (http_conn);

    if (poll)
        params = g_strdup_printf ("Action=poll&SessionID=%s",
                                  session_id);
    else if (session_id)
        params = g_strdup_printf ("SessionID=%s",
                                  session_id);
    else
        params = g_strdup_printf ("Action=open&Server=%s&IP=%s",
                                  conn->prev->type == PN_NODE_NS ? "NS" : "SB",
                                  conn->prev->hostname);

#ifdef HAVE_LIBPURPLE
    auth = get_auth(conn);
#endif /* HAVE_LIBPURPLE */

    /** @todo investigate why this returns NULL sometimes. */
    header = g_strdup_printf ("POST http://%s/gateway/gateway.dll?%s HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "User-Agent: MSMSGS\r\n"
                              "Host: %s\r\n"
                              "%s" /* Proxy auth */
                              "Proxy-Connection: Keep-Alive\r\n"
                              "Connection: Keep-Alive\r\n"
                              "Pragma: no-cache\r\n"
                              "Cache-Control: no-cache\r\n"
                              "Content-Type: application/x-msn-messenger\r\n"
                              "Content-Length: %zu\r\n\r\n",
                              http_conn->gateway,
                              params,
                              http_conn->gateway,
                              auth ? auth : "",
                              count);

    g_free (params);
    g_free (auth);

#ifdef PECAN_DEBUG_HTTP
    pn_debug ("header=[%s]", header);
#endif

    /** @todo this is inefficient */
    if (header)
    {
        if (buf && count) {
            gsize header_len;
            header_len = strlen (header);
            body_len = header_len + count;
            body = g_malloc (body_len);
            memcpy (body, header, header_len);
            memcpy (body + header_len, buf, count);
            g_free (header);
        }
        else
        {
            body = header;
            body_len = strlen (header);
        }
    }

    if (body)
    {
        status = pn_stream_write_full (conn->stream, body, body_len, &bytes_written, &tmp_error);
        g_free (body);
    }
    else
    {
        /** @todo this shouldn't happen. */
        pn_error ("body is null!");
        status = G_IO_STATUS_ERROR;
    }

    /** @todo investigate why multiple g_io_channel_write has memory leaks. */
#if 0
    if (status == G_IO_STATUS_NORMAL)
    {
        status = pn_stream_write_full (conn->stream, buf, count, &bytes_written, &tmp_error);
    }
#endif

    http_conn->waiting_response = TRUE;
    if (http_conn->timer)
        pn_timer_stop (http_conn->timer);

    if (status == G_IO_STATUS_NORMAL)
    {
        status = async_flush (http_conn, &tmp_error);

        /* fake status */
        if (status == G_IO_STATUS_AGAIN)
            status = G_IO_STATUS_NORMAL;
    }

    if (status == G_IO_STATUS_NORMAL)
        pn_log ("bytes_written=%zu", bytes_written);
    else
        pn_error ("not normal");

    if (ret_bytes_written)
        *ret_bytes_written = bytes_written;

    return status;
}

static gboolean
http_poll (gpointer data)
{
    PnNode *conn;
    PnHttpServer *http_conn;
    GIOStatus status = G_IO_STATUS_NORMAL;
    static guint count = 0;

    g_return_val_if_fail (data != NULL, FALSE);

    conn = PN_NODE (data);
    http_conn = PN_HTTP_SERVER (data);

    pn_debug ("stream=%p", conn->stream);

    count++;

    /* Don't poll if we already sent something, unless we have been waiting for
     * too long; a disconnection might have happened. */
    if (http_conn->waiting_response && count < 10)
    {
        /* There's no need to poll if we're already waiting for a response */
        pn_debug ("waiting for response");
        return TRUE;
    }

    status = post (http_conn, TRUE, NULL, 0, NULL, NULL);

    if (status != G_IO_STATUS_NORMAL)
    {
        PnNodeClass *class;
        pn_error ("not normal: status=%d", status);
        class = g_type_class_peek (PN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->error_sig, 0, conn);
        return FALSE;
    }

    return TRUE;
}

#if defined(USE_GIO)
static void
connect_cb(GObject *source,
           GAsyncResult *res,
           gpointer user_data)
{
    GSocketConnection *socket_conn;
    PnNode *conn;
    PnHttpServer *http_conn;

    conn = PN_NODE(user_data);
    http_conn = PN_HTTP_SERVER(user_data);
    socket_conn = g_socket_client_connect_to_host_finish(G_SOCKET_CLIENT(source), res, NULL);

    g_object_unref(source);

    g_object_ref(conn);

    if (socket_conn) {
        GIOChannel *channel;
        GSocket *socket;

        conn->socket_conn = socket_conn;
        socket = g_socket_connection_get_socket(socket_conn);
        conn->stream = pn_stream_new(g_socket_get_fd(socket));
        channel = conn->stream->channel;

        g_io_channel_set_encoding (channel, NULL, NULL);
        g_io_channel_set_line_term (channel, "\r\n", 2);

        conn->status = PN_NODE_STATUS_OPEN;

        http_conn->timer = pn_timer_new (http_poll, http_conn);
        pn_timer_start (http_conn->timer, 2);

        conn->read_watch = g_io_add_watch (channel, G_IO_IN, read_cb, conn);

        {
            PnNodeClass *class;
            class = g_type_class_peek (PN_NODE_TYPE);
            g_signal_emit (G_OBJECT (conn), class->open_sig, 0, conn);
        }
    }
    else {
        PnNodeClass *class;
        class = g_type_class_peek (PN_NODE_TYPE);

        conn->error = g_error_new_literal (PN_NODE_ERROR, PN_NODE_ERROR_OPEN,
                                           "Unable to connect");

        g_signal_emit (G_OBJECT (conn), class->error_sig, 0, conn);
    }

    g_object_unref(conn);
}
#elif defined(HAVE_LIBPURPLE)
static void
connect_cb (gpointer data,
            gint source,
            const gchar *error_message)
{
    PnNode *conn;
    PnHttpServer *http_conn;

    pn_log ("begin");

    conn = PN_NODE (data);
    http_conn = PN_HTTP_SERVER (data);

    conn->connect_data = NULL;

    if (source >= 0)
    {
        GIOChannel *channel;

        pn_stream_free (conn->stream);
        conn->stream = pn_stream_new (source);
        channel = conn->stream->channel;

        g_io_channel_set_encoding (channel, NULL, NULL);
        g_io_channel_set_line_term (channel, "\r\n", 2);

        conn->status = PN_NODE_STATUS_OPEN;

        http_conn->timer = pn_timer_new (http_poll, http_conn);
        pn_timer_start (http_conn->timer, 2);

        conn->read_watch = g_io_add_watch (channel, G_IO_IN, read_cb, conn);

        {
            PnNodeClass *class;
            class = g_type_class_peek (PN_NODE_TYPE);
            g_signal_emit (G_OBJECT (conn), class->open_sig, 0, conn);
        }
    }
    else
    {
        PnNodeClass *class;
        class = g_type_class_peek (PN_NODE_TYPE);

        conn->error = g_error_new_literal (PN_NODE_ERROR, PN_NODE_ERROR_OPEN,
                                           error_message ? error_message : "Unable to connect");

        g_signal_emit (G_OBJECT (conn), class->error_sig, 0, conn);
    }

    pn_log ("end");
}
#endif

static void
connect_impl (PnNode *conn,
              const gchar *hostname,
              gint port)
{
    PnHttpServer *http_conn;

    http_conn = PN_HTTP_SERVER (conn);

    g_return_if_fail (conn->prev);

    conn->status = PN_NODE_STATUS_CONNECTING;

    port = 80;
    pn_debug ("conn=%p,hostname=%s,port=%d", conn, hostname, port);
    if (conn->prev->type == PN_NODE_NS)
        hostname = http_conn->gateway;

#if defined(USE_GIO)
    GSocketClient *client;
    client = g_socket_client_new();
    g_socket_client_connect_to_host_async(client, hostname, port,
                                          NULL, connect_cb, conn);
#elif defined(HAVE_LIBPURPLE)
    /* close a pending connection */
    /* this can happen when reconecting before receiving the connection
     * callback. */
    if (conn->connect_data)
        purple_proxy_connect_cancel (conn->connect_data);

    conn->connect_data = purple_proxy_connect (NULL, msn_session_get_user_data (conn->session),
                                               hostname, port, connect_cb, conn);
#endif
}

static void
close_impl (PnNode *conn)
{
    PnHttpServer *http_conn;

    if (conn->status == PN_NODE_STATUS_CLOSED) {
        pn_log ("already closed: %p", conn);
        return;
    }

    pn_log ("begin");

    http_conn = PN_HTTP_SERVER (conn);

    pn_timer_free(http_conn->timer);
    http_conn->timer = NULL;

    if (http_conn->write_watch) {
        g_source_remove (http_conn->write_watch);
        http_conn->write_watch = 0;
    }

    g_free (http_conn->last_session_id);
    http_conn->last_session_id = NULL;

    g_free (http_conn->session);
    http_conn->session = NULL;

    http_conn->parser_state = 0;
    http_conn->waiting_response = FALSE;

    {
        HttpQueueData *queue_data;
        while ((queue_data = g_queue_pop_head (http_conn->write_queue)))
        {
            g_free (queue_data->body);
            g_free (queue_data);
        }
    }

    parent_class->close (conn);

    pn_log ("end");
}

static GIOStatus
read_impl (PnNode *conn,
           gchar *buf,
           gsize count,
           gsize *ret_bytes_read,
           GError **error)
{
    PnHttpServer *http_conn;
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize bytes_read = 0;

    pn_log ("begin");

    http_conn = PN_HTTP_SERVER (conn);

    pn_debug ("stream=%p", conn->stream);

    {
        gchar *str = NULL;
        gchar **tokens = NULL;

        if (http_conn->parser_state == 0)
        {
            gint code;

            {
                gsize terminator_pos;
                status = pn_stream_read_line (conn->stream,
                                              &str, NULL, &terminator_pos, &tmp_error);
                if (str)
                    str[terminator_pos] = '\0';
            }

            if (tmp_error)
            {
                pn_debug ("error reading: %s", tmp_error->message);
                goto leave;
            }

            if (status == G_IO_STATUS_AGAIN)
                return status;

            if (status != G_IO_STATUS_NORMAL) {
                tmp_error = g_error_new_literal (PN_NODE_ERROR, PN_NODE_ERROR_READ,
                                                 "Read error");
                goto leave;
            }

#ifdef PECAN_DEBUG_HTTP
            pn_debug ("str=[%s]", str);
#endif

            if (!str)
                return G_IO_STATUS_AGAIN;

            tokens = g_strsplit (str, " ", 3);

            if (!(tokens && tokens[0] &&
                  ((strcmp (tokens[0], "HTTP/1.1") == 0) ||
                   (strcmp (tokens[0], "HTTP/1.0") == 0))))
            {
                pn_debug ("error reading: parse error");
                tmp_error = g_error_new_literal (PN_NODE_ERROR, PN_NODE_ERROR_READ,
                                                 "Parse error");
                goto leave;
            }

            if (!(tokens[1]))
            {
                pn_debug ("error reading: parse error");
                tmp_error = g_error_new_literal (PN_NODE_ERROR, PN_NODE_ERROR_READ,
                                                 "Parse error");
                goto leave;
            }

            code = atoi (tokens[1]);

            if (code != 200 && code != 100)
            {
                pn_debug ("error reading: %d %s", code, tokens[2]);
                tmp_error = g_error_new (PN_NODE_ERROR, PN_NODE_ERROR_READ,
                                         "%s",  tokens[2]);
                goto leave;
            }

            g_strfreev (tokens);
            tokens = NULL;
            g_free (str);
            str = NULL;

            http_conn->parser_state++;
        }

        if (http_conn->parser_state == 1)
        {
            while (TRUE)
            {
                {
                    gsize terminator_pos;
                    status = pn_stream_read_line (conn->stream,
                                                  &str, NULL, &terminator_pos, &tmp_error);
                    if (str)
                        str[terminator_pos] = '\0';
                }

                if (tmp_error)
                {
                    pn_debug ("error reading: %s", tmp_error->message);
                    goto leave;
                }

                if (status == G_IO_STATUS_AGAIN)
                    return status;

                if (!str || str[0] == '\0')
                    break;

#ifdef PECAN_DEBUG_HTTP
                pn_debug ("str=[%s]", str);
#endif

                tokens = g_strsplit (str, ": ", 2);

                if (!(tokens[0] && tokens[1]))
                {
                    pn_debug ("error reading: parse error");
                    tmp_error = g_error_new_literal (PN_NODE_ERROR, PN_NODE_ERROR_READ,
                                                     "Parse error");
                    goto leave;
                }

                if (strcmp (tokens[0], "Content-Length") == 0)
                {
                    http_conn->content_length = atoi (tokens[1]);
                }
                else if (strcmp (tokens[0], "X-MSN-Messenger") == 0)
                {
                    gchar **tokens_b;
                    gint i;

                    tokens_b = g_strsplit (tokens[1], ";", -1);

                    for (i = 0; tokens_b[i]; i++)
                    {
                        gchar **tokens_c;
                        gchar *token;

                        tokens_c = g_strsplit (tokens_b[i], "=", 2);

                        token = tokens_c[0];

                        if (*token == ' ')
                            token++;

#ifdef PECAN_DEBUG_HTTP
                        pn_debug ("token=[%s]", token);
#endif

                        if (strcmp (token, "SessionID") == 0)
                        {
                            g_free (http_conn->last_session_id);
                            http_conn->last_session_id = g_strdup (tokens_c[1]);
                        }
                        else if (strcmp (token, "GW-IP") == 0)
                        {
                            g_free (http_conn->gateway);
                            http_conn->gateway = g_strdup (tokens_c[1]);
                        }
                        else if (strcmp (token, "Session") == 0)
                        {
                            g_free (http_conn->session);
                            http_conn->session = g_strdup (tokens_c[1]);
                        }

                        g_strfreev (tokens_c);
                    }

                    g_strfreev (tokens_b);
                }

                g_strfreev (tokens);
                tokens = NULL;
                g_free (str);
                str = NULL;
            }

            http_conn->parser_state++;
        }

        if (http_conn->parser_state == 2)
        {
            if (http_conn->session && (strcmp (http_conn->session, "close") == 0))
                pn_node_close (conn);
            else
                pn_debug ("session=%s", http_conn->session);

            status = pn_stream_read (conn->stream, buf, MIN (http_conn->content_length, count), &bytes_read, &tmp_error);

            if (status == G_IO_STATUS_AGAIN)
                return status;

            pn_log ("status=%d", status);
            pn_log ("bytes_read=%zu", bytes_read);

            if (ret_bytes_read)
                *ret_bytes_read = bytes_read;

            http_conn->content_length -= bytes_read;

            pn_log ("con_len=%d,read=%zu", http_conn->content_length, bytes_read);

            if (conn->status == PN_NODE_STATUS_CLOSED)
                goto leave;

            if (http_conn->content_length == 0) {
                http_conn->parser_state = 0;
                http_conn->waiting_response = FALSE;
                pn_timer_restart (http_conn->timer);
                process_queue (http_conn, &conn->error);
            }
        }

leave:
        g_strfreev (tokens);
        g_free (str);
    }

    if (tmp_error)
        g_propagate_error (error, tmp_error);

    pn_log ("end");

    return status;
}

static GIOStatus
foo_write (PnNode *conn,
           const gchar *buf,
           gsize count,
           gsize *ret_bytes_written,
           GError **error)
{
    PnHttpServer *http_conn = PN_HTTP_SERVER (conn);

    pn_debug ("stream=%p", conn->stream);

    return post (http_conn, FALSE, buf, count, ret_bytes_written, error);
}

static GIOStatus
write_impl (PnNode *conn,
            const gchar *buf,
            gsize count,
            gsize *ret_bytes_written,
            GError **error)
{
    PnHttpServer *http_conn;

    http_conn = PN_HTTP_SERVER (conn);

    pn_debug ("stream=%p", conn->stream);

    if (http_conn->waiting_response)
    {
        HttpQueueData *queue_data;

        queue_data = g_new0 (HttpQueueData, 1);

        queue_data->body = g_memdup (buf, count);
        queue_data->body_len = count;

        g_queue_push_tail (http_conn->write_queue, queue_data);

        /* fake success */
        if (ret_bytes_written)
            *ret_bytes_written = count;

        return G_IO_STATUS_NORMAL;
    }

    return foo_write (conn, buf, count, ret_bytes_written, error);
}

/* GObject stuff. */

static void
finalize (GObject *obj)
{
    PnHttpServer *http_conn = PN_HTTP_SERVER (obj);

    g_free (http_conn->old_buffer);
    g_free (http_conn->gateway);
    g_queue_free (http_conn->write_queue);

    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static void
class_init (gpointer g_class,
            gpointer class_data)
{
    PnNodeClass *conn_class = PN_NODE_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_class->connect = &connect_impl;
    conn_class->close = &close_impl;
    conn_class->write = &write_impl;
    conn_class->read = &read_impl;

    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

static void
instance_init (GTypeInstance *instance,
               gpointer g_class)
{
    PnHttpServer *http_conn = PN_HTTP_SERVER (instance);

    http_conn->gateway = g_strdup ("gateway.messenger.hotmail.com");
    http_conn->write_queue = g_queue_new ();
}

GType
pn_http_server_get_type (void)
{
    static GType type = 0;

    if (G_UNLIKELY (type == 0))
    {
        GTypeInfo *type_info;

        type_info = g_new0 (GTypeInfo, 1);
        type_info->class_size = sizeof (PnHttpServerClass);
        type_info->class_init = class_init;
        type_info->instance_size = sizeof (PnHttpServer);
        type_info->instance_init = instance_init;

        type = g_type_register_static (PN_NODE_TYPE, "PnHttpServerType", type_info, 0);

        g_free(type_info);
    }

    return type;
}
