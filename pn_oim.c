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

#include "pn_util.h"
#include "pn_locale.h"
#include "ab/pn_contact_priv.h"

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

    gchar lockkey[32];
    gboolean got_lockkey;
};

typedef struct OimRequest OimRequest;

struct OimRequest
{
    PecanOimSession *oim_session;
    gchar *passport;
    PnParser *parser;
    guint parser_state;
    gsize content_size;
    OimRequestType type;

    /* receiving stuff */
    gchar *message_id;

    /* sending stuff */
    gchar *oim_message;

    gulong open_sig_handler;
    PnNode *conn;
};

static inline OimRequest *
oim_request_new (PecanOimSession *oim_session,
                 const gchar *passport,
                 const gchar *message_id,
                 const gchar *oim_message,
                 OimRequestType type)
{
    OimRequest *oim_request;

    oim_request = g_new0 (OimRequest, 1);
    oim_request->oim_session = oim_session;
    oim_request->passport = g_strdup (passport);
    oim_request->message_id = g_strdup (message_id);
    oim_request->oim_message = g_strdup (oim_message);
    oim_request->type = type;

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
    g_free (oim_request->oim_message);
    g_free (oim_request);
}

PecanOimSession *
pn_oim_session_new (MsnSession *session)
{
    PecanOimSession *oim_session;

    oim_session = g_new0 (PecanOimSession, 1);
    oim_session->session = session;
    oim_session->request_queue = g_queue_new ();

    oim_session->got_lockkey = FALSE;

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
send_receive_request (PnNode *conn,
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

static inline void
send_send_request (PnNode *conn,
                   OimRequest *oim_request)
{
    GString *body_str;
    gchar *body;
    gchar *header;
    gsize body_len, msgtext_base64_len;
    struct pn_contact *contact;
    MsnSession *session;
    PurpleConnection *gc;
    const gchar *friendly_name;
    gchar *friendly_name_base64, *run_id, *msgtext_base64, *tmp;

    pn_log ("begin");

    session = oim_request->oim_session->session;

    gc = purple_account_get_connection (msn_session_get_user_data (session));
    friendly_name = purple_connection_get_display_name (gc);
    if (strlen (friendly_name) >= 48)
        friendly_name_base64 = purple_base64_encode ((const guchar*) friendly_name, 48);
    else
        friendly_name_base64 = purple_base64_encode ((const guchar*) friendly_name, strlen (friendly_name));

    contact = pn_contactlist_find_contact (session->contactlist, oim_request->passport);
    contact->sent_oims++;

    run_id = pn_rand_guid ();

    msgtext_base64 = tmp = purple_base64_encode ((const guchar*) oim_request->oim_message, strlen (oim_request->oim_message));
    msgtext_base64_len = strlen (msgtext_base64);

    body_str = g_string_new (NULL);

    g_string_printf (body_str,
                     "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                     "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                     "<soap:Header>"
                     "<From memberName=\"%s\" friendlyName=\"%s%s%s\" xml:lang=\"en-US\" proxy=\"MSNMSGR\" xmlns=\"http://messenger.msn.com/ws/2004/09/oim/\" msnpVer=\"MSNP13\" buildVer=\"8.0.0328\"/>"
                     "<To memberName=\"%s\" xmlns=\"http://messenger.msn.com/ws/2004/09/oim/\"/>"
                     "<Ticket passport=\"%s%s%s%s\" appid=\"%s\" lockkey=\"%s\" xmlns=\"http://messenger.msn.com/ws/2004/09/oim/\"/>"
                     "<Sequence xmlns=\"http://schemas.xmlsoap.org/ws/2003/03/rm\">"
                     "<Identifier xmlns=\"http://schemas.xmlsoap.org/ws/2002/07/utility\">http://messenger.msn.com</Identifier>"
                     "<MessageNumber>%d</MessageNumber>"
                     "</Sequence>"
                     "</soap:Header>"
                     "<soap:Body>"
                     "<MessageType xmlns=\"http://messenger.msn.com/ws/2004/09/oim/\">%s</MessageType>"
                     "<Content xmlns=\"http://messenger.msn.com/ws/2004/09/oim/\">MIME-Version: 1.0\r\n"
                     "Content-Type: text/plain; charset=UTF-8\r\n"
                     "Content-Transfer-Encoding: base64\r\n"
                     "X-OIM-Message-Type: OfflineMessage\r\n"
                     "X-OIM-Run-Id: {%s}\r\n"
                     "X-OIM-Sequence-Num: %d\r\n"
                     "\r\n",
                     session->username,
                     "=?utf-8?B?", friendly_name_base64, "?=",
                     oim_request->passport,
                     "t=", session->passport_cookie.t, "&amp;p=", session->passport_cookie.p,
                     "PROD01065C%ZFN6F",
                     oim_request->oim_session->lockkey ? oim_request->oim_session->lockkey : "",
                     contact->sent_oims,
                     "text",
                     run_id,
                     contact->sent_oims);

    g_free (friendly_name_base64);
    g_free (run_id);

    while (msgtext_base64_len > 76) {
        g_string_append_len (body_str, msgtext_base64, 76);
        g_string_append (body_str, "\r\n");
        msgtext_base64 += 76;
        msgtext_base64_len -= 76;
    }

    g_string_append (body_str, msgtext_base64);

    g_string_append (body_str,
                     "</Content>"
                     "</soap:Body>"
                     "</soap:Envelope>");

    g_free (tmp);

    body = g_string_free (body_str, FALSE);
    body_len = strlen (body);

    header = g_strdup_printf ("POST /OimWS/oim.asmx HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "SOAPAction: \"http://messenger.msn.com/ws/2004/09/oim/Store\"\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %" G_GSIZE_FORMAT "\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: %s\r\n"
                              "Connection: Keep-Alive\r\n"
                              "Cache-Control: no-cache\r\n"
                              "\r\n%s",
                              body_len,
                              "ows.messenger.msn.com",
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

    if (oim_request->type == PN_RECEIVE_OIM)
        send_receive_request (conn, oim_request);
    else
        send_send_request (conn, oim_request);

    g_signal_handler_disconnect (conn, oim_request->open_sig_handler);
    oim_request->open_sig_handler = 0;

    pn_log ("end");
}

static inline void oim_process_requests (PecanOimSession *oim_session);

static inline void
next_request (PecanOimSession *oim_session)
{
    OimRequest *oim_request;

    oim_request = g_queue_pop_head (oim_session->request_queue);

    if (oim_request) {
        if (oim_session->got_lockkey)
        {
            oim_session->got_lockkey = FALSE;

            g_queue_push_tail (oim_session->request_queue,
                               oim_request_new (oim_session, oim_request->passport, NULL,
                               oim_request->oim_message, PN_SEND_OIM));
        }

        oim_request_free (oim_request);
    }

    oim_process_requests (oim_session);
}

static void
process_body_receive (OimRequest *oim_request,
                      char *body,
                      gsize length)
{
    gchar *message = NULL;
    gchar *cur;
    guint32 date = 0;

    pn_debug("body=[%.*s]", length, body);

    /** @todo find a way to parse the date in win32 */
#ifndef G_OS_WIN32
    cur = strstr(body, "Date: ");
    if (cur) {
        struct tm time;
        cur += 6;
        date = mktime (&time);
        strptime (cur, "%d %b %Y %T %z", &time);
    }
#endif

    if (date == 0)
        date = time (NULL);

    cur = strstr (body, "\r\n\r\n");
    if (cur) {
        gchar *end;
        cur += 2;
        end = strstr (cur, "\r\n\r\n");
        *end = '\0';
        message = (gchar *) purple_base64_decode (cur, NULL);
    }

    if (message)
    {
        PurpleConversation *conv;
        pn_debug ("oim: passport=[%s],msg=[%s]", oim_request->passport, message);
        conv = purple_conversation_new (PURPLE_CONV_TYPE_IM,
                                        msn_session_get_user_data (oim_request->oim_session->session),
                                        oim_request->passport);

        purple_conversation_write (conv, NULL, message,
                                   PURPLE_MESSAGE_RECV | PURPLE_MESSAGE_DELAYED, date);

        g_free (message);
    }
}

static void
process_body_send (OimRequest *oim_request,
                   char *body,
                   gsize length)
{
    gchar *cur;

    pn_test("body=[%.*s]", length, body);

    cur = strstr (body, "<LockKeyChallenge ");
    if (cur)
    {
        gsize lockkey_len;
        gchar *lockkey;

        lockkey_len = strlen (cur) - 67 - strlen (strstr ((const char*) body, "</LockKeyChallenge>"));
        lockkey = malloc (lockkey_len);
        strncpy (lockkey, cur + 67, lockkey_len);

        pn_handle_challenge (lockkey, "PROD01065C%ZFN6F", "O4BG@C7BWLYQX?5G", oim_request->oim_session->lockkey);

        g_free (lockkey);

        oim_request->oim_session->got_lockkey = TRUE;

        return;
    }

    {
        PurpleConversation *conv;
        PurpleAccount *account;
        const gchar *error;

        if (strstr (body, "q0:SystemUnavailable"))
            error = _("The following message wasn't sent because the system is unavailable. This normally happens when the user is blocked or does not exist.");
        else if (strstr (body, "q0:SenderThrottleLimitExceeded"))
            error = _("The following message wasn't sent because you've sent messages too quickly.");
        else
            return;

        account = msn_session_get_user_data (oim_request->oim_session->session);
        conv = purple_find_conversation_with_account (PURPLE_CONV_TYPE_IM, oim_request->passport, account);

        if (!conv)
            conv = purple_conversation_new (PURPLE_CONV_TYPE_IM, account, oim_request->passport);

        purple_conversation_write (conv, NULL, error, PURPLE_MESSAGE_ERROR, time (NULL));
        purple_conversation_write (conv, NULL, oim_request->oim_message, PURPLE_MESSAGE_RAW, time (NULL));
    }
}

static void
read_cb (PnNode *conn,
         gpointer data)
{
    OimRequest *oim_request;
    GIOStatus status = G_IO_STATUS_NORMAL;
    gchar *str = NULL;

    oim_request = data;

    while (oim_request->parser_state == 0)
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

            if (strncmp (str, "Content-Length: ", 16) == 0)
                oim_request->content_size = atoi(str + 16);

            /* now comes the content */
            if (str[0] == '\0') {
                oim_request->parser_state++;
                break;
            }

            g_free (str);
        }
    }

    if (oim_request->parser_state == 1)
    {
        gchar *body;

        status = pn_parser_read (oim_request->parser, &body, oim_request->content_size, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        if (oim_request->type == PN_RECEIVE_OIM)
            process_body_receive (oim_request, body, oim_request->content_size);
        else
            process_body_send (oim_request, body, oim_request->content_size);

        g_free(body);
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

        if (oim_request->type == PN_RECEIVE_OIM)
            pn_node_connect (conn, "rsi.hotmail.com", 443);
        else
            pn_node_connect (conn, "ows.messenger.msn.com", 443);

        oim_request->conn = conn;
        oim_request->open_sig_handler = g_signal_connect (conn, "open", G_CALLBACK (open_cb), oim_request);
    }
}

void
pn_oim_session_request (PecanOimSession *oim_session,
                        const gchar *passport,
                        const gchar *message_id,
                        const gchar *oim_message,
                        OimRequestType type)
{
    gboolean initial;

    initial = g_queue_is_empty (oim_session->request_queue);

    g_queue_push_tail (oim_session->request_queue,
                       oim_request_new (oim_session, passport, message_id, oim_message, type));

    if (initial)
        oim_process_requests (oim_session);
}
