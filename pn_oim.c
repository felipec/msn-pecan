/**
 * Copyright (C) 2008-2009 Felipe Contreras
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

#include <time.h> /* for strptime */

#include "pn_oim.h"
#include "io/pn_ssl_conn.h"
#include "io/pn_parser.h"

#include "io/pn_node_private.h"
#include "session_private.h"
#include <string.h> /* for strlen */
#include <stdlib.h> /* for atoi */

#include "pn_log.h"

#ifdef HAVE_LIBPURPLE
/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <util.h> /* for base64_dec */
#include <conversation.h> /* for conversation_new */
#endif /* HAVE_LIBPURPLE */

struct PecanOimSession
{
    MsnSession *session;
    GQueue *request_queue;
};

typedef struct OimRequest OimRequest;

struct OimRequest
{
    PecanOimSession *oim_session;
    gchar *passport;
    gchar *message_id;
    PnParser *parser;
    guint parser_state;
    guint32 date;
    gsize payload;

    gulong open_sig_handler;
    PnNode *conn;
};

static inline OimRequest *
oim_request_new (PecanOimSession *oim_session,
                 const gchar *passport,
                 const gchar *message_id)
{
    OimRequest *oim_request;

    oim_request = g_new0 (OimRequest, 1);
    oim_request->oim_session = oim_session;
    oim_request->passport = g_strdup (passport);
    oim_request->message_id = g_strdup (message_id);

    return oim_request;
}

static inline void
oim_request_free (OimRequest *oim_request)
{
    if (oim_request->open_sig_handler)
        g_signal_handler_disconnect (oim_request->conn, oim_request->open_sig_handler);

    pn_node_free (oim_request->conn);
    pn_parser_free (oim_request->parser);
    g_free (oim_request->passport);
    g_free (oim_request->message_id);
    g_free (oim_request);
}

PecanOimSession *
pn_oim_session_new (MsnSession *session)
{
    PecanOimSession *oim_session;

    oim_session = g_new0 (PecanOimSession, 1);
    oim_session->session = session;
    oim_session->request_queue = g_queue_new ();

    return oim_session;
}

void
pn_oim_session_free (PecanOimSession *oim_session)
{
    if (!oim_session)
        return;

    {
        OimRequest *oim_request;
        while ((oim_request = g_queue_pop_head (oim_session->request_queue)))
        {
            oim_request_free (oim_request);
        }
    }
    g_queue_free (oim_session->request_queue);

    g_free (oim_session);
}

static inline void
oim_send_request (PnNode *conn,
                  OimRequest *oim_request)
{
    gchar *body;
    gchar *header;
    gsize body_len;

    pn_log ("begin");

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                            "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                            "<soap:Header>"
                            "<PassportCookie xmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
                            "<t>%s</t>"
                            "<p>%s</p>"
                            "</PassportCookie>"
                            "</soap:Header>"
                            "<soap:Body>"
                            "<GetMessage xmlns=\"http://www.hotmail.msn.com/ws/2004/09/oim/rsi\">"
                            "<messageId>%s</messageId>"
                            "<alsoMarkAsRead>%s</alsoMarkAsRead>"
                            "</GetMessage>"
                            "</soap:Body>"
                            "</soap:Envelope>",
                            conn->session->passport_cookie.t,
                            conn->session->passport_cookie.p,
                            oim_request->message_id,
                            "true");

    body_len = strlen (body);

    header = g_strdup_printf ("POST /rsi/rsi.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://www.hotmail.msn.com/ws/2004/09/oim/rsi/GetMessage\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %" G_GSIZE_FORMAT "\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: %s\r\n"
                              "Connection: Keep-Alive\r\n"
                              "Cache-Control: no-cache\r\n"
                              /* "Cookie: MSPAuth=%s\r\n" */
                              "\r\n%s",
                              body_len,
                              "rsi.hotmail.com",
                              /* session->passport_info.mspauth, */
                              body);

    g_free (body);

    pn_debug ("header=[%s]", header);
    /* pn_debug ("body=[%s]", body); */

    {
        gsize len;
        pn_node_write (conn, header, strlen (header), &len, NULL);
        pn_debug ("write_len=%d", len);
    }

    g_free (header);

    pn_log ("end");
}

static void
open_cb (PnNode *conn,
         OimRequest *oim_request)
{
    g_return_if_fail (conn);

    pn_log ("begin");

    oim_send_request (conn, oim_request);

    g_signal_handler_disconnect (conn, oim_request->open_sig_handler);
    oim_request->open_sig_handler = 0;

    pn_log ("end");
}

static inline void oim_process_requests (PecanOimSession *oim_session);

static inline void
next_request (PecanOimSession *oim_session)
{
    OimRequest *oim_request;
    if ((oim_request = g_queue_pop_head (oim_session->request_queue)))
        oim_request_free (oim_request);
    oim_process_requests (oim_session);
}

static void
read_cb (PnNode *conn,
         gpointer data)
{
    OimRequest *oim_request;
    GIOStatus status = G_IO_STATUS_NORMAL;
    gchar *str = NULL, *message = NULL;

    oim_request = data;

    while (oim_request->parser_state < 2)
    {
        gsize terminator_pos;

        status = pn_parser_read_line (oim_request->parser, &str, NULL, &terminator_pos, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        if (str)
        {
            str[terminator_pos] = '\0';

            if (oim_request->parser_state == 1)
            {
#ifndef G_OS_WIN32
                if (strncmp (str, "Date: ", 6) == 0)
                {
                    struct tm time;
                    strptime (str + 6, "%d %b %Y %T %z", &time);
                    oim_request->date = mktime (&time);
                }
#else
                /** @todo find a way to parse the date in win32 */
                oim_request->date = time (NULL);
#endif
            }

            /* now comes the content */
            if (str[0] == '\0')
                oim_request->parser_state++;

            g_free (str);
        }
    }

    while (oim_request->parser_state == 2)
    {
        gsize terminator_pos;

        status = pn_parser_read_line (oim_request->parser, &str, NULL, &terminator_pos, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        if (str)
        {
            gchar *tmp, *incomplete_msg = message;

            str[terminator_pos] = '\0';

            tmp = (gchar *) purple_base64_decode (str, NULL);

            if (incomplete_msg)
            {
                message = g_strconcat (incomplete_msg, tmp, NULL);
                g_free (incomplete_msg);
                g_free (tmp);
            }
            else
                message = tmp;

            if (str[0] == '\0' || strchr (str, '<'))
                oim_request->parser_state++;

            g_free (str);
        }
    }

    if (message)
    {
        PurpleConversation *conv;
        pn_debug ("oim: passport=[%s],msg=[%s]", oim_request->passport, message);
        conv = purple_conversation_new (PURPLE_CONV_TYPE_IM,
                                        msn_session_get_user_data (oim_request->oim_session->session),
                                        oim_request->passport);

        purple_conversation_write (conv, NULL, message,
                                   PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_DELAYED, oim_request->date);

        g_free (message);
    }

leave:
    pn_node_close (conn);
    next_request (oim_request->oim_session);
}

static inline void
oim_process_requests (PecanOimSession *oim_session)
{
    OimRequest *oim_request;

    oim_request = g_queue_peek_head (oim_session->request_queue);

    if (!oim_request)
        return;

    {
        PnSslConn *ssl_conn;
        PnNode *conn;

        ssl_conn = pn_ssl_conn_new ("oim", PN_NODE_NULL);

        conn = PN_NODE (ssl_conn);
        conn->session = oim_session->session;

        oim_request->parser = pn_parser_new (conn);
        pn_ssl_conn_set_read_cb (ssl_conn, read_cb, oim_request);

        pn_node_connect (conn, "rsi.hotmail.com", 443);

        oim_request->conn = conn;
        oim_request->open_sig_handler = g_signal_connect (conn, "open", G_CALLBACK (open_cb), oim_request);
    }
}

void
pn_oim_session_request (PecanOimSession *oim_session,
                        const gchar *passport,
                        const gchar *message_id)
{
    gboolean initial;

    initial = g_queue_is_empty (oim_session->request_queue);

    g_queue_push_tail (oim_session->request_queue,
                       oim_request_new (oim_session, passport, message_id));

    if (initial)
        oim_process_requests (oim_session);
}
