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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "http_conn.h"
#include "msn_io.h"
#include "msn_log.h"

static ConnObjectClass *parent_class = NULL;

#include <proxy.h> /* libpurple */
#include "session.h"

static gboolean
read_cb (GIOChannel *source,
         GIOCondition condition,
         gpointer data)
{
    ConnObject *conn;
    gchar *buf;
    gsize bytes_read;
    gboolean ret = TRUE;

    conn = data;

    msn_debug ("source=%p", source);

    buf = g_malloc (MSN_BUF_LEN);

    {
        GIOStatus status = G_IO_STATUS_NORMAL;

        conn_object_read (conn, buf, MSN_BUF_LEN, &bytes_read, &conn->error);

        if (status == G_IO_STATUS_AGAIN)
        {
            ret = TRUE;
            goto leave;
        }

        if (status != G_IO_STATUS_NORMAL || conn->error)
        {
            conn_object_error (conn);
            ret = FALSE;
            goto leave;
        }
    }

    conn_object_parse (conn->prev, buf, bytes_read);

leave:

    g_free (buf);

    return ret;
}

HttpConnObject *
http_conn_object_new (gchar *name)
{
    HttpConnObject *http_conn;

    msn_log ("begin");

    http_conn = HTTP_CONN_OBJECT (g_type_create_instance (HTTP_CONN_OBJECT_TYPE));

    {
        ConnObject *tmp = CONN_OBJECT (http_conn);
        tmp->name = g_strdup (name);
    }

    msn_log ("end");

    return http_conn;
}

void
http_conn_object_free (HttpConnObject *http_conn)
{
    msn_log ("begin");
    g_object_unref (G_OBJECT (http_conn));
    msn_log ("end");
}

typedef struct
{
    HttpConnObject *http_conn;
    gchar *body;
    gsize body_len;
} HttpQueueData;

static gboolean
http_poll (gpointer data)
{
    ConnObject *conn;
    HttpConnObject *http_conn;
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize bytes_written = 0;

    gchar *header;
    gchar *params;
    gchar *auth = NULL;

    g_return_val_if_fail (data != NULL, FALSE);

    conn = CONN_OBJECT (data);
    http_conn = HTTP_CONN_OBJECT (data);

    msn_debug ("channel=%p", conn->channel);

    if (http_conn->last_session_id == NULL)
        return TRUE;

    g_return_val_if_fail (http_conn->last_session_id != NULL, FALSE);

    if (http_conn->waiting_response)
    {
        /* There's no need to poll if we're already waiting for a response */
        msn_debug ("waiting for response");
        return TRUE;
    }

    params = g_strdup_printf ("Action=poll&SessionID=%s",
                              http_conn->last_session_id);

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
                              "Content-Length: 0\r\n\r\n",
                              http_conn->gateway,
                              params,
                              http_conn->gateway,
                              auth ? auth : "");

#ifdef MSN_DEBUG_HTTP
    msn_debug ("header=[%s]", header);
#endif

    g_free (params);

    status = msn_io_write_full (conn->channel, header, strlen (header), &bytes_written, &tmp_error);

    if (status == G_IO_STATUS_NORMAL);
    {
        status = g_io_channel_flush (conn->channel, &tmp_error);

        g_free (header);

        if (status == G_IO_STATUS_NORMAL);
        {
            msn_log ("bytes_written=%d", bytes_written);
            http_conn->waiting_response = TRUE;
        }
    }

    if (status != G_IO_STATUS_NORMAL);
    {
        msn_error ("error writing");
    }

    return TRUE;
}

static void
connect_cb (gpointer data,
            gint source,
            const gchar *error_message)
{
    ConnObject *conn;
    HttpConnObject *http_conn;

    msn_log ("begin");

    conn = CONN_OBJECT (data);
    http_conn = HTTP_CONN_OBJECT (data);

    conn->connect_data = NULL;

    if (source >= 0)
    {
        GIOChannel *channel;

        conn->channel = channel = g_io_channel_unix_new (source);

        g_io_channel_set_line_term (channel, "\r\n", 2);

        http_conn->timeout_id = g_timeout_add (2 * 1000, http_poll, http_conn);
        conn->read_watch = g_io_add_watch (channel, G_IO_IN, read_cb, conn);
    }

    {
        ConnObjectClass *class;
        class = g_type_class_peek (CONN_OBJECT_TYPE);
        g_signal_emit (G_OBJECT (conn), class->open_sig, 0, conn);
    }

    msn_log ("end");
}

static void
connect_impl (ConnObject *conn,
              const gchar *hostname,
              gint port)
{
    HttpConnObject *http_conn;

    http_conn = HTTP_CONN_OBJECT (conn);

    g_return_if_fail (conn->session != NULL);

    if (!conn->channel)
    {
        conn->connect_data = purple_proxy_connect (NULL, conn->session->account,
                                                   http_conn->gateway, 80, connect_cb, conn);
        return;
    }
}

static void
close_impl (ConnObject *conn)
{
    HttpConnObject *http_conn;

    http_conn = HTTP_CONN_OBJECT (conn);

    if (!conn->channel)
    {
        msn_warning ("not connected: conn=%p", conn);
        return;
    }

    if (conn->connect_data)
    {
        purple_proxy_connect_cancel (conn->connect_data);
        conn->connect_data = NULL;
    }

    if (http_conn->timeout_id)
    {
        g_source_remove (http_conn->timeout_id);
        http_conn->timeout_id = 0;
    }

    msn_info ("channel shutdown: %p", conn->channel);
    g_io_channel_shutdown (conn->channel, FALSE, NULL);
    g_io_channel_unref (conn->channel);
    conn->channel = NULL;

    g_free (conn->hostname);
    conn->hostname = NULL;

    g_free (http_conn->last_session_id);
    http_conn->last_session_id = NULL;

    http_conn->parser_state = 0;
    http_conn->waiting_response = FALSE;

    {
        HttpQueueData *http_data;
        while ((http_data = g_queue_pop_head (http_conn->write_queue)))
        {
            g_free (http_data->body);
            g_free (http_data);
        }
    }
}

static void
process_queue (HttpConnObject *http_conn,
               GError **error)
{
    http_conn->waiting_response = FALSE;

    {
        HttpQueueData *queue_data;

        queue_data = g_queue_pop_head (http_conn->write_queue);

        if (queue_data)
        {
            conn_object_write (CONN_OBJECT (queue_data->http_conn),
                               queue_data->body,
                               queue_data->body_len,
                               NULL,
                               error);

            g_free (queue_data->body);
            g_free (queue_data);
        }
    }
}

static GIOStatus
read_impl (ConnObject *conn,
           gchar *buf,
           gsize count,
           gsize *ret_bytes_read,
           GError **error)
{
    HttpConnObject *http_conn;
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize bytes_read = 0;

    http_conn = HTTP_CONN_OBJECT (conn);

    msn_debug ("channel=%p", conn->channel);

    {
        gchar *str = NULL;
        gchar **tokens = NULL;

        if (http_conn->parser_state == 0)
        {
            gint code;

            {
                gsize terminator_pos;
                status = g_io_channel_read_line (conn->channel,
                                                 &str, NULL, &terminator_pos, &tmp_error);
                if (str)
                    str[terminator_pos] = '\0';
            }

            if (tmp_error)
            {
                msn_debug ("error reading: %s", tmp_error->message);
                goto leave;
            }

            if (status == G_IO_STATUS_AGAIN)
                return status;

#ifdef MSN_DEBUG_HTTP
            msn_debug ("str=[%s]", str);
#endif

            tokens = g_strsplit (str, " ", 3);

            if (!(tokens[0] && (strcmp (tokens[0], "HTTP/1.1") == 0)))
            {
                msn_debug ("error reading: parse error");
                tmp_error = g_error_new_literal (CONN_OBJECT_ERROR, CONN_OBJECT_ERROR_OPEN,
                                                 "Parse error");
                goto leave;
            }

            if (!(tokens[1]))
            {
                msn_debug ("error reading: parse error");
                tmp_error = g_error_new_literal (CONN_OBJECT_ERROR, CONN_OBJECT_ERROR_OPEN,
                                                 "Parse error");
                goto leave;
            }

            code = atoi (tokens[1]);

            if (code != 200 && code != 100)
            {
                msn_debug ("error reading: %d %s", code, tokens[2]);
                tmp_error = g_error_new (CONN_OBJECT_ERROR, CONN_OBJECT_ERROR_OPEN,
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
                    status = g_io_channel_read_line (conn->channel,
                                                     &str, NULL, &terminator_pos, &tmp_error);
                    if (str)
                        str[terminator_pos] = '\0';
                }

                if (tmp_error)
                {
                    msn_debug ("error reading: %s", tmp_error->message);
                    goto leave;
                }

                if (status == G_IO_STATUS_AGAIN)
                    return status;

                if (str[0] == '\0')
                    break;

#ifdef MSN_DEBUG_HTTP
                msn_debug ("str=[%s]", str);
#endif

                tokens = g_strsplit (str, ": ", 2);

                if (!(tokens[0] && tokens[1]))
                {
                    msn_debug ("error reading: parse error");
                    tmp_error = g_error_new_literal (CONN_OBJECT_ERROR, CONN_OBJECT_ERROR_OPEN,
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

                    tokens_b = g_strsplit (tokens[1], "; ", -1);

                    for (i = 0; tokens_b[i]; i++)
                    {
                        char **tokens_c;

                        tokens_c = g_strsplit (tokens_b[i], "=", 2);

                        if (strcmp (tokens_c[0], "SessionID") == 0)
                        {
                            conn->prev->foo_data = g_strdup (tokens_c[1]);
                            http_conn->last_session_id = g_strdup (tokens_c[1]);
                        }
                        else if (strcmp (tokens_c[0], "GW-IP") == 0)
                        {
                            g_free (http_conn->gateway);
                            http_conn->gateway = g_strdup (tokens_c[1]);
                        }
                        else if (strcmp (tokens_c[0], "Session") == 0)
                        {
                            if (strcmp (tokens_c[1], "close") == 0)
                            {
                                conn_object_close (conn);
                            }
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
            status = msn_io_read (conn->channel, buf, MIN (http_conn->content_length, count), &bytes_read, &tmp_error);

            msn_log ("status=%d", status);
            msn_log ("bytes_read=%d", bytes_read);

            if (ret_bytes_read)
                *ret_bytes_read = bytes_read;

            http_conn->content_length -= bytes_read;

            msn_log ("con_len=%d,read=%d", http_conn->content_length, bytes_read);

            if (http_conn->content_length == 0)
                http_conn->parser_state = 0;
        }

leave:
        g_strfreev (tokens);
        g_free (str);
    }

    process_queue (http_conn, &tmp_error);

    if (tmp_error)
        g_propagate_error (error, tmp_error);

    return status;
}

static GIOStatus
write_impl (ConnObject *conn,
            const gchar *buf,
            gsize count,
            gsize *ret_bytes_written,
            GError **error)
{
    HttpConnObject *http_conn;
    ConnObject *prev;
    GIOStatus status = G_IO_STATUS_NORMAL;
    GError *tmp_error = NULL;
    gsize bytes_written = 0;

    http_conn = HTTP_CONN_OBJECT (conn);
    prev = CONN_OBJECT (conn->prev);

    msn_debug ("channel=%p", conn->channel);
    msn_debug ("conn=%p,prev=%p", conn, prev);

    g_return_val_if_fail (prev, G_IO_STATUS_ERROR);

    if (http_conn->waiting_response)
    {
        HttpQueueData *http_data;

        http_data = g_new0 (HttpQueueData, 1);

        http_data->http_conn = http_conn;
        http_data->body = g_memdup (buf, count);
        http_data->body_len = count;

        g_queue_push_tail (http_conn->write_queue, http_data);

        return status;
    }

    {
        gchar *params;
        gchar *header;
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
                                      prev->type == MSN_CONN_NS ? "NS" : "SB",
                                      prev->hostname);
        }

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
                                  conn->hostname,
                                  params,
                                  conn->hostname,
                                  auth ? auth : "",
                                  count);

#ifdef MSN_DEBUG_HTTP
        msn_debug ("header=[%s]", header);
#endif

        g_free (params);

        status = msn_io_write_full (conn->channel, header, strlen (header), &bytes_written, &tmp_error);
    }

    status = msn_io_write_full (conn->channel, buf, count, &bytes_written, &tmp_error);

    g_io_channel_flush (conn->channel, &tmp_error);

    if (status == G_IO_STATUS_NORMAL);
    {
        msn_log ("bytes_written=%d", bytes_written);
        http_conn->waiting_response = TRUE;
    }

    if (ret_bytes_written)
        *ret_bytes_written = bytes_written;

    if (tmp_error)
        g_propagate_error (error, tmp_error);

    return status;
}

/* GObject stuff. */

static void
dispose (GObject *obj)
{
    HttpConnObject *http_conn = HTTP_CONN_OBJECT (obj);

    g_free (http_conn->gateway);
    http_conn->gateway = NULL;

    g_queue_free (http_conn->write_queue);
    http_conn->write_queue = NULL;

    G_OBJECT_CLASS (parent_class)->dispose (obj);
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
    ConnObjectClass *conn_class = CONN_OBJECT_CLASS (g_class);
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
    HttpConnObject *http_conn = HTTP_CONN_OBJECT (instance);

    http_conn->gateway = g_strdup ("gateway.messenger.hotmail.com");
    http_conn->write_queue = g_queue_new ();
}

GType
http_conn_object_get_type (void)
{
    static GType type = 0;

    if (type == 0) 
    {
        static const GTypeInfo type_info =
        {
            sizeof (HttpConnObjectClass),
            NULL, /* base_init */
            NULL, /* base_finalize */
            class_init, /* class_init */
            NULL, /* class_finalize */
            NULL, /* class_data */
            sizeof (HttpConnObject),
            0, /* n_preallocs */
            instance_init /* instance_init */
        };

        type = g_type_register_static (CONN_OBJECT_TYPE, "HttpConnObjectType", &type_info, 0);
    }

    return type;
}
