/*
 * Copyright (C) 2008 Felipe Contreras.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Each command connection (NS,SB) can use the auxiliar HTTP connection method.
 * So commands are sent through a single HTTP gateway (ideally).
 *
 * The current implementation uses one HTTP connection per command connection.
 * For the NS the default gateway is used, but for SB's the SB IP is used.
 * That seems to work.
 */

#include "pecan_http_server_priv.h"
#include "pecan_stream.h"
#include "pecan_log.h"

#include <glib.h>
#include <string.h>

#include "pecan_util.h"
#include "session.h"

#ifdef HAVE_LIBPURPLE
#include "fix_purple.h"

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <proxy.h>
#undef connect
#undef write
#undef read
#undef close
#endif /* HAVE_LIBPURPLE */

static PecanNodeClass *parent_class = NULL;

typedef struct
{
    PecanNode *conn;
    gchar *body;
    gsize body_len;
} HttpQueueData;

static GIOStatus
foo_write (PecanNode *conn,
           PecanNode *prev,
           const gchar *buf,
           gsize count,
           gsize *ret_bytes_written,
           GError **error);

static void
process_queue (PecanHttpServer *http_conn,
               GError **error)
{
    HttpQueueData *queue_data;

    queue_data = g_queue_pop_head (http_conn->write_queue);

    if (queue_data)
    {
        foo_write (PECAN_NODE (http_conn),
                   queue_data->conn,
                   queue_data->body,
                   queue_data->body_len,
                   NULL,
                   error);
        g_object_unref (G_OBJECT (queue_data->conn));
        g_free (queue_data->body);
        g_free (queue_data);
    }
}

static gboolean
read_cb (GIOChannel *source,
         GIOCondition condition,
         gpointer data)
{
    PecanNode *conn;
    gchar buf[MSN_BUF_LEN + 1];
    gsize bytes_read;

    pecan_log ("begin");

    conn = PECAN_NODE (data);

    pecan_debug ("conn=%p,source=%p", conn, source);

    g_object_ref (conn);

    {
        GIOStatus status = G_IO_STATUS_NORMAL;

        status = pecan_node_read (conn, buf, MSN_BUF_LEN, &bytes_read, &conn->error);

        if (status == G_IO_STATUS_AGAIN)
        {
            g_object_unref (conn);
            return TRUE;
        }

        if (conn->error)
        {
            pecan_node_error (conn);
            g_object_unref (conn);
            return FALSE;
        }

        if (status != G_IO_STATUS_NORMAL)
        {
            pecan_warning ("not normal, status=%d", status);
            g_object_unref (conn);
            return TRUE;
        }
    }

    if (!conn->error)
    {
        PecanHttpServer *http_conn;

        http_conn = PECAN_HTTP_SERVER (conn);

        if (http_conn->cur)
        {
            /* make sure the server is not sending the same buffer again */
            /** @todo find out why this happens */
            if (!(http_conn->old_buffer &&
                  strncmp (buf, http_conn->old_buffer, bytes_read) == 0))
            {
                pecan_node_parse (http_conn->cur, buf, bytes_read);

                g_free (http_conn->old_buffer);
                http_conn->old_buffer = g_strndup (buf, bytes_read);
            }
        }

        http_conn->waiting_response = FALSE;

        process_queue (http_conn, &conn->error);

        if (conn->error)
        {
            pecan_node_error (conn);
            g_object_unref (conn);
            return FALSE;
        }
    }

    g_object_unref (conn);

    pecan_log ("end");

    return TRUE;
}

PecanHttpServer *
pecan_http_server_new (const gchar *name)
{
    PecanHttpServer *http_conn;

    pecan_log ("begin");

    http_conn = PECAN_HTTP_SERVER (g_type_create_instance (PECAN_HTTP_SERVER_TYPE));

    {
        PecanNode *tmp = PECAN_NODE (http_conn);
        tmp->name = g_strdup (name);
        tmp->type = PECAN_NODE_HTTP;
    }

    pecan_log ("end");

    return http_conn;
}

void
pecan_http_server_free (PecanHttpServer *http_conn)
{
    pecan_log ("begin");
    g_object_unref (G_OBJECT (http_conn));
    pecan_log ("end");
}

static gboolean
http_poll (gpointer data)
{
    PecanNode *conn;
    PecanHttpServer *http_conn;
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize bytes_written = 0;
    static guint count = 0;

    gchar *header;
    gchar *params;
    gchar *auth = NULL;

    g_return_val_if_fail (data != NULL, FALSE);

    conn = PECAN_NODE (data);
    http_conn = PECAN_HTTP_SERVER (data);

    pecan_debug ("stream=%p", conn->stream);

    if (!http_conn->cur)
        return TRUE;

    g_return_val_if_fail (http_conn->cur, FALSE);

    count++;

    /* Don't poll if we already sent something, unless we have been waiting for
     * too long; a disconnection might have happened. */
    if (http_conn->waiting_response && count < 10)
    {
        /* There's no need to poll if we're already waiting for a response */
        pecan_debug ("waiting for response");
        return TRUE;
    }

    params = pecan_strdup_printf ("Action=poll&SessionID=%s",
                                  (gchar *) http_conn->cur->foo_data);

    header = pecan_strdup_printf ("POST http://%s/gateway/gateway.dll?%s HTTP/1.1\r\n"
                                  "Accept: */*\r\n"
                                  "Accept-Language: en-us\r\n"
                                  "User-Agent: MSMSGS\r\n"
                                  "Host: %s\r\n"
                                  "Proxy-Connection: Keep-Alive\r\n"
                                  "%s" /* Proxy auth */
                                  "Connection: Keep-Alive\r\n"
                                  "Pragma: no-cache\r\n"
                                  "Content-Type: application/x-msn-messenger\r\n"
                                  "Content-Length: 0\r\n\r\n",
                                  http_conn->gateway,
                                  params,
                                  http_conn->gateway,
                                  auth ? auth : "");

#ifdef PECAN_DEBUG_HTTP
    pecan_debug ("header=[%s]", header);
#endif

    g_free (params);

    status = pecan_stream_write_full (conn->stream, header, strlen (header), &bytes_written, &tmp_error);

    if (status == G_IO_STATUS_NORMAL)
    {
        status = pecan_stream_flush (conn->stream, &tmp_error);

        g_free (header);

        if (status == G_IO_STATUS_NORMAL)
        {
            pecan_log ("bytes_written=%d", bytes_written);
            http_conn->waiting_response = TRUE;
        }
    }

    if (status != G_IO_STATUS_NORMAL)
    {
        PecanNodeClass *class;
        pecan_error ("not normal: status=%d", status);
        class = g_type_class_peek (PECAN_NODE_TYPE);
        g_signal_emit (G_OBJECT (conn), class->error_sig, 0, conn);
        return FALSE;
    }

    return TRUE;
}

static void
connect_cb (gpointer data,
            gint source,
            const gchar *error_message)
{
    PecanNode *conn;
    PecanHttpServer *http_conn;

    pecan_log ("begin");

    conn = PECAN_NODE (data);
    http_conn = PECAN_HTTP_SERVER (data);

    conn->connect_data = NULL;

    if (source >= 0)
    {
        GIOChannel *channel;

        pecan_stream_free (conn->stream);
        conn->stream = pecan_stream_new (source);
        channel = conn->stream->channel;

        g_io_channel_set_encoding (channel, NULL, NULL);
        g_io_channel_set_line_term (channel, "\r\n", 2);

        http_conn->timeout_id = g_timeout_add_seconds (2, http_poll, http_conn);
        conn->read_watch = g_io_add_watch (channel, G_IO_IN, read_cb, conn);

        {
            PecanNodeClass *class;
            class = g_type_class_peek (PECAN_NODE_TYPE);
            g_signal_emit (G_OBJECT (conn), class->open_sig, 0, conn);
        }
    }
    else
    {
        PecanNodeClass *class;
        class = g_type_class_peek (PECAN_NODE_TYPE);

        conn->error = g_error_new_literal (PECAN_NODE_ERROR, PECAN_NODE_ERROR_OPEN,
                                           error_message ? error_message : "Unable to connect");

        g_signal_emit (G_OBJECT (conn), class->error_sig, 0, conn);
    }

    pecan_log ("end");
}

static void
connect_impl (PecanNode *conn,
              const gchar *hostname,
              gint port)
{
    PecanHttpServer *http_conn;

    http_conn = PECAN_HTTP_SERVER (conn);

    g_return_if_fail (conn->session);

    if (!conn->stream)
    {
        /* close a pending connection */
        /* this can happen when reconecting before receiving the connection
         * callback. */
        if (conn->connect_data)
        {
            purple_proxy_connect_cancel (conn->connect_data);
        }

        if (conn->prev->type == PECAN_NODE_NS)
            hostname = http_conn->gateway;
        port = 80;
        pecan_debug ("conn=%p,hostname=%s,port=%d", conn, hostname, port);
        conn->connect_data = purple_proxy_connect (NULL, msn_session_get_account (conn->session),
                                                   hostname, port, connect_cb, conn);
        return;
    }
    else
    {
        if (conn->prev)
        {
            /* fake open */
            PecanNodeClass *class;
            class = g_type_class_peek (PECAN_NODE_TYPE);
            g_signal_emit (G_OBJECT (conn->prev), class->open_sig, 0, conn->prev);
        }
    }
}

static void
close_impl (PecanNode *conn)
{
    PecanHttpServer *http_conn;

    pecan_log ("begin");

    http_conn = PECAN_HTTP_SERVER (conn);

    if (http_conn->timeout_id)
    {
        g_source_remove (http_conn->timeout_id);
        http_conn->timeout_id = 0;
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
            g_object_unref (G_OBJECT (queue_data->conn));
            g_free (queue_data->body);
            g_free (queue_data);
        }
    }

    g_hash_table_remove_all (http_conn->childs);

    PECAN_NODE_CLASS (parent_class)->close (conn);

    pecan_log ("end");
}

static GIOStatus
read_impl (PecanNode *conn,
           gchar *buf,
           gsize count,
           gsize *ret_bytes_read,
           GError **error)
{
    PecanHttpServer *http_conn;
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize bytes_read = 0;

    pecan_log ("begin");

    http_conn = PECAN_HTTP_SERVER (conn);

    pecan_debug ("stream=%p", conn->stream);

    {
        gchar *str = NULL;
        gchar **tokens = NULL;

        if (http_conn->parser_state == 0)
        {
            gint code;

            {
                gsize terminator_pos;
                status = pecan_stream_read_line (conn->stream,
                                                 &str, NULL, &terminator_pos, &tmp_error);
                if (str)
                    str[terminator_pos] = '\0';
            }

            if (tmp_error)
            {
                pecan_debug ("error reading: %s", tmp_error->message);
                goto leave;
            }

            if (status == G_IO_STATUS_AGAIN)
                return status;

#ifdef PECAN_DEBUG_HTTP
            pecan_debug ("str=[%s]", str);
#endif

            tokens = g_strsplit (str, " ", 3);

            if (!(tokens[0] &&
                  ((strcmp (tokens[0], "HTTP/1.1") == 0) ||
                   (strcmp (tokens[0], "HTTP/1.0") == 0))))
            {
                pecan_debug ("error reading: parse error");
                tmp_error = g_error_new_literal (PECAN_NODE_ERROR, PECAN_NODE_ERROR_OPEN,
                                                 "Parse error");
                goto leave;
            }

            if (!(tokens[1]))
            {
                pecan_debug ("error reading: parse error");
                tmp_error = g_error_new_literal (PECAN_NODE_ERROR, PECAN_NODE_ERROR_OPEN,
                                                 "Parse error");
                goto leave;
            }

            code = atoi (tokens[1]);

            if (code != 200 && code != 100)
            {
                pecan_debug ("error reading: %d %s", code, tokens[2]);
                tmp_error = g_error_new (PECAN_NODE_ERROR, PECAN_NODE_ERROR_OPEN,
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
                    status = pecan_stream_read_line (conn->stream,
                                                     &str, NULL, &terminator_pos, &tmp_error);
                    if (str)
                        str[terminator_pos] = '\0';
                }

                if (tmp_error)
                {
                    pecan_debug ("error reading: %s", tmp_error->message);
                    goto leave;
                }

                if (status == G_IO_STATUS_AGAIN)
                    return status;

                if (str[0] == '\0')
                    break;

#ifdef PECAN_DEBUG_HTTP
                pecan_debug ("str=[%s]", str);
#endif

                tokens = g_strsplit (str, ": ", 2);

                if (!(tokens[0] && tokens[1]))
                {
                    pecan_debug ("error reading: parse error");
                    tmp_error = g_error_new_literal (PECAN_NODE_ERROR, PECAN_NODE_ERROR_OPEN,
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
                        pecan_debug ("token=[%s]", token);
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
            {
                PecanNode *child;
                gchar *session_id;
                gchar *t;

                t = strchr (http_conn->last_session_id, '.');
		session_id = g_strndup (http_conn->last_session_id, t - http_conn->last_session_id);

                child = g_hash_table_lookup (http_conn->childs, session_id);
                pecan_log ("child=%p", child);
                pecan_log ("sesison_id=[%s]", session_id);

                if (http_conn->session && (strcmp (http_conn->session, "close") == 0))
                {
                    if (child)
                    {
                        PecanNode *foo;

                        pecan_info ("removing child");
                        pecan_node_close (child);
                        g_hash_table_remove (http_conn->childs, session_id);

                        g_object_unref (G_OBJECT (http_conn->cur));
                        g_free (http_conn->gateway);
                        g_free (http_conn->last_session_id);
                        if ((foo = PECAN_NODE (g_hash_table_peek_first (http_conn->childs))))
                        {
                            http_conn->cur = foo;
                            http_conn->gateway = g_strdup (foo->hostname);
                            http_conn->last_session_id = g_strdup (foo->foo_data);
                        }
                        else
                        {
                            pecan_info ("no more childs");
                            http_conn->cur = NULL;
                            http_conn->gateway = NULL;
                            http_conn->last_session_id = NULL;
                        }
                    }
                }
                else
                {
                    if (!child)
                    {
                        child = http_conn->cur;
                        pecan_info ("adding child: %p", child);
                        g_hash_table_insert (http_conn->childs, g_strdup (session_id), g_object_ref (child));
                    }

                    if (child)
                    {
                        g_free (child->foo_data);
                        child->foo_data = g_strdup (http_conn->last_session_id);
                    }

                    pecan_debug ("session=%s", http_conn->session);
                }

                g_free (session_id);
            }

            status = pecan_stream_read (conn->stream, buf, MIN (http_conn->content_length, count), &bytes_read, &tmp_error);

            pecan_log ("status=%d", status);
            pecan_log ("bytes_read=%d", bytes_read);

            if (ret_bytes_read)
                *ret_bytes_read = bytes_read;

            http_conn->content_length -= bytes_read;

            pecan_log ("con_len=%d,read=%d", http_conn->content_length, bytes_read);

            if (http_conn->content_length == 0)
                http_conn->parser_state = 0;
        }

leave:
        g_strfreev (tokens);
        g_free (str);
    }

    if (tmp_error)
        g_propagate_error (error, tmp_error);

    pecan_log ("end");

    return status;
}

static inline void
reset_timer (PecanHttpServer *http_conn)
{
    if (http_conn->timeout_id)
        g_source_remove (http_conn->timeout_id);

    http_conn->timeout_id = g_timeout_add_seconds (2, http_poll, http_conn);
}

static GIOStatus
foo_write (PecanNode *conn,
           PecanNode *prev,
           const gchar *buf,
           gsize count,
           gsize *ret_bytes_written,
           GError **error)
{
    GIOStatus status = G_IO_STATUS_NORMAL;
    PecanHttpServer *http_conn;
    GError *tmp_error = NULL;
    gsize bytes_written = 0;

    http_conn = PECAN_HTTP_SERVER (conn);

    pecan_debug ("stream=%p", conn->stream);

    {
        gchar *params;
        gchar *header;
        gchar *body = NULL;
        gsize body_len;
        gchar *auth = NULL;
        gchar *session_id;

        session_id = prev->foo_data;

        if (session_id)
        {
            params = g_strdup_printf ("SessionID=%s",
                                      session_id);
        }
        else
        {
            params = g_strdup_printf ("Action=open&Server=%s&IP=%s",
                                      prev->type == PECAN_NODE_NS ? "NS" : "SB",
                                      prev->hostname);
        }

        /** @todo investigate why this returns NULL sometimes. */
        header = g_strdup_printf ("POST http://%s/gateway/gateway.dll?%s HTTP/1.1\r\n"
                                  "Accept: */*\r\n"
                                  "Accept-Language: en-us\r\n"
                                  "User-Agent: MSMSGS\r\n"
                                  "Host: %s\r\n"
                                  "Proxy-Connection: Keep-Alive\r\n"
                                  "%s" /* Proxy auth */
                                  "Connection: Keep-Alive\r\n"
                                  "Pragma: no-cache\r\n"
                                  "Content-Type: application/x-msn-messenger\r\n"
                                  "Content-Length: %d\r\n\r\n",
                                  http_conn->gateway,
                                  params,
                                  http_conn->gateway,
                                  auth ? auth : "",
                                  count);

        g_free (params);

#ifdef PECAN_DEBUG_HTTP
        pecan_debug ("header=[%s]", header);
#endif

        /** @todo this is inefficient */
        if (header)
        {
            gsize header_len;
            header_len = strlen (header);
            body_len = header_len + count;
            body = g_malloc (body_len);
            memcpy (body, header, header_len);
            memcpy (body + header_len, buf, count);
            g_free (header);
        }

        if (body)
        {
            status = pecan_stream_write_full (conn->stream, body, body_len, &bytes_written, &tmp_error);

            g_free (body);
        }
        else
        {
            /** @todo this shouldn't happen. */
            pecan_error ("body is null!");
            status = G_IO_STATUS_ERROR;
        }
    }

    /** @todo investigate why multiple g_io_channel_write has memory leaks. */
#if 0
    if (status == G_IO_STATUS_NORMAL)
    {
        status = pecan_stream_write_full (conn->stream, buf, count, &bytes_written, &tmp_error);
    }
#endif

    if (status == G_IO_STATUS_NORMAL)
        status = pecan_stream_flush (conn->stream, &tmp_error);

    if (status == G_IO_STATUS_NORMAL)
    {
        pecan_log ("bytes_written=%d", bytes_written);
        http_conn->waiting_response = TRUE;
        if (http_conn->cur)
            g_object_unref (http_conn->cur);
        http_conn->cur = prev;
        g_object_ref (G_OBJECT (http_conn->cur));

        reset_timer (http_conn);
    }
    else
    {
        pecan_error ("not normal");
    }

    if (ret_bytes_written)
        *ret_bytes_written = bytes_written;

    if (tmp_error)
        g_propagate_error (error, tmp_error);

    return status;
}

static GIOStatus
write_impl (PecanNode *conn,
            const gchar *buf,
            gsize count,
            gsize *ret_bytes_written,
            GError **error)
{
    PecanHttpServer *http_conn;
    PecanNode *prev;
    GIOStatus status = G_IO_STATUS_NORMAL;

    http_conn = PECAN_HTTP_SERVER (conn);
    prev = PECAN_NODE (conn->prev);

    pecan_debug ("stream=%p", conn->stream);
    pecan_debug ("conn=%p,prev=%p", conn, prev);

    g_return_val_if_fail (prev, G_IO_STATUS_ERROR);

    if (http_conn->waiting_response)
    {
        HttpQueueData *queue_data;

        queue_data = g_new0 (HttpQueueData, 1);

        g_object_ref (G_OBJECT (prev));
        queue_data->conn = prev;
        queue_data->body = g_memdup (buf, count);
        queue_data->body_len = count;

        g_queue_push_tail (http_conn->write_queue, queue_data);
        return status;
    }

    status = foo_write (conn, prev, buf, count, ret_bytes_written, error);

    return status;
}

/* GObject stuff. */

static void
dispose (GObject *obj)
{
    PecanHttpServer *http_conn = PECAN_HTTP_SERVER (obj);

    pecan_log ("begin");

    g_free (http_conn->old_buffer);
    http_conn->old_buffer = NULL;

    g_free (http_conn->gateway);
    http_conn->gateway = NULL;

    g_queue_free (http_conn->write_queue);
    http_conn->write_queue = NULL;

    g_hash_table_destroy (http_conn->childs);
    http_conn->childs = NULL;

    G_OBJECT_CLASS (parent_class)->dispose (obj);

    pecan_log ("end");
}

static void
finalize (GObject *obj)
{
    G_OBJECT_CLASS (parent_class)->finalize (obj);
}

static void
class_init (gpointer g_class,
            gpointer class_data)
{
    PecanNodeClass *conn_class = PECAN_NODE_CLASS (g_class);
    GObjectClass *gobject_class = G_OBJECT_CLASS (g_class);

    conn_class->connect = &connect_impl;
    conn_class->close = &close_impl;
    conn_class->write = &write_impl;
    conn_class->read = &read_impl;

    gobject_class->dispose = dispose;
    gobject_class->finalize = finalize;

    parent_class = g_type_class_peek_parent (g_class);
}

static void
instance_init (GTypeInstance *instance,
               gpointer g_class)
{
    PecanHttpServer *http_conn = PECAN_HTTP_SERVER (instance);

    http_conn->gateway = g_strdup ("gateway.messenger.hotmail.com");
    http_conn->write_queue = g_queue_new ();
    http_conn->childs = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
}

GType
pecan_http_server_get_type (void)
{
    static GType type = 0;

    if (type == 0) 
    {
        GTypeInfo *type_info;

        type_info = g_new0 (GTypeInfo, 1);
        type_info->class_size = sizeof (PecanHttpServerClass);
        type_info->class_init = class_init;
        type_info->instance_size = sizeof (PecanHttpServer);
        type_info->instance_init = instance_init;

        type = g_type_register_static (PECAN_NODE_TYPE, "PecanHttpServerType", type_info, 0);
    }

    return type;
}
