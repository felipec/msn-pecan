/**
 * Copyright (C) 2011 Felipe Contreras
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

#include "pn_auth.h"
#include "pn_auth_priv.h"

#include "io/pn_ssl_conn.h"
#include "io/pn_parser.h"

#include "io/pn_node_private.h"
#include "session_private.h"

#include "pn_log.h"

#include <string.h>
#include <stdlib.h> /* for atoi */
#include <stdio.h>

#ifdef __MINGW32__
__MINGW_IMPORT long timezone;
#endif

typedef struct AuthRequest AuthRequest;

struct AuthRequest
{
    PnAuth *auth;

    gulong open_sig_handler;
    PnNode *conn;

    PnParser *parser;
    guint parser_state;
    gsize content_size;

    gchar *redirect_url;
    gchar *ticket;
};

static void open_cb (PnNode *conn, AuthRequest *req);

static inline AuthRequest *
auth_request_new (PnAuth *auth)
{
    AuthRequest *req;

    req = g_new0 (AuthRequest, 1);
    req->auth = auth;

    return req;
}

static inline void
auth_request_free (AuthRequest *req)
{
    if (!req)
        return;

    if (req->open_sig_handler)
        g_signal_handler_disconnect (req->conn, req->open_sig_handler);

    pn_node_free (req->conn);
    pn_parser_free (req->parser);
    g_free (req->redirect_url);
    g_free (req->ticket);
    g_free (req);
}

PnAuth *
pn_auth_new (MsnSession *session)
{
    PnAuth *pn_auth;

    pn_auth = g_new0 (PnAuth, 1);
    pn_auth->session = session;

    return pn_auth;
}

void
pn_auth_free (PnAuth *auth)
{
    if (!auth)
        return;

    auth_request_free (auth->pending_req);

    g_free (auth->security_token.messenger_msn_com_t);
    g_free (auth->security_token.messenger_msn_com_p);

    g_free (auth->security_token.messengersecure_live_com);

    g_free (auth);
}

static time_t
parse_expiration_time (const char *str)
{
    int y, m, d, hour, min, sec;
    struct tm tm;

    sscanf (str, "%d-%d-%dT%d:%d:%dZ",
            &y, &m, &d, &hour, &min, &sec);

    memset(&tm, 0, sizeof(tm));
    tm.tm_sec = sec;
    tm.tm_min = min;
    tm.tm_hour = hour;
    tm.tm_mday = d;
    tm.tm_mon = m - 1;
    tm.tm_year = y - 1900;
    tm.tm_isdst = 0;

    return mktime (&tm) - timezone;
}

static void
process_body (AuthRequest *req,
              char *body,
              gsize length)
{
    gchar *cur;

    pn_test ("body=[%.*s]", (int) length, body);

    cur = strstr (body, "<psf:redirectUrl>");
    if (cur)
    {
        gchar *end;

        cur = strchr (cur, '>') + 1;
        end = strchr (cur, '<');

        req->redirect_url = g_strndup (cur, end - cur);

        return;
    }

    cur = strstr (body, "<wsse:BinarySecurityToken Id=\"PPToken1\">");
    if (!cur)
        cur = strstr (body, "<wsse:BinarySecurityToken Id=\"Compact1\">");
    if (cur)
    {
        gchar *login_params, *end, **tokens;

        cur = strchr (cur, '>') + 1;
        end = strchr (cur, '<');
        login_params = g_strndup (cur, end - cur);

        tokens = g_strsplit (login_params, "&amp;", 2);

        g_free (req->auth->security_token.messenger_msn_com_t);
        g_free (req->auth->security_token.messenger_msn_com_p);

        req->auth->security_token.messenger_msn_com_t = g_strdup (tokens[0] + 2);
        req->auth->security_token.messenger_msn_com_p = g_strdup (tokens[1] + 2);

        g_strfreev (tokens);
        g_free (login_params);
    }

    cur = strstr (body, "<wsa:Address>messenger.msn.com</wsa:Address>");
    if (cur)
    {
        gchar *end, *expires;
        time_t t;

        cur = strstr (cur, "<wsu:Expires>");
        if (cur) {
            cur += 13;
            end = strchr (cur, '<');
            if (end) {
                expires = g_strndup (cur, end - cur);

                t = parse_expiration_time (expires);
                req->auth->expiration_time.messenger_msn_com = t;

                g_free (expires);
            }
        }
    }

    cur = strstr (body, "<wsse:BinarySecurityToken Id=\"PPToken2\">");
    if (!cur)
        cur = strstr (body, "<wsse:BinarySecurityToken Id=\"Compact2\">");
    if (cur)
    {
        gchar *end;

        cur = strchr (cur, '>') + 1;
        end = strchr (cur, '<');

        g_free (req->auth->security_token.messengersecure_live_com);

        req->auth->security_token.messengersecure_live_com = g_strndup (cur, end - cur);
    }

    cur = strstr (body, "<wsa:Address>messengersecure.live.com</wsa:Address>");
    if (cur)
    {
        gchar *end, *expires;
        time_t t;

        cur = strstr (cur, "<wsu:Expires>");
        if (cur) {
            cur += 13;
            end = strchr (cur, '<');
            if (end) {
                expires = g_strndup (cur, end - cur);

                t = parse_expiration_time (expires);
                req->auth->expiration_time.messengersecure_live_com = t;

                g_free (expires);
            }
        }
    }

    req->auth->cb (req->auth, req->auth->cb_data);
}

static void
read_cb (PnNode *conn,
         gpointer data)
{
    PnAuth *auth;
    AuthRequest *req;
    GIOStatus status = G_IO_STATUS_NORMAL;
    gchar *str = NULL;

    req = data;
    auth = req->auth;

    while (req->parser_state == 0)
    {
        gsize terminator_pos;

        status = pn_parser_read_line (req->parser, &str, NULL, &terminator_pos, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        if (str)
        {
            str[terminator_pos] = '\0';

            if (strncmp (str, "Content-Length: ", 16) == 0)
                req->content_size = atoi(str + 16);

            /* now comes the content */
            if (str[0] == '\0') {
                req->parser_state++;
                g_free (str);
                break;
            }

            g_free (str);
        }
    }

    if (req->parser_state == 1)
    {
        gchar *body;

        status = pn_parser_read (req->parser, &body, req->content_size, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL)
            goto leave;

        process_body (req, body, req->content_size);

        g_free(body);
    }

leave:
    if (req->redirect_url)
    {
        req->parser_state = 0;
        g_free (req->redirect_url);
        req->redirect_url = NULL;
        pn_node_connect (req->conn, "msnia.login.live.com", 443);
        req->open_sig_handler = g_signal_connect (conn, "open", G_CALLBACK (open_cb), req);
    }
    else
    {
        pn_node_close (conn);
        auth_request_free (req);
        auth->pending_req = NULL;
    }
}

static void
open_cb (PnNode *conn,
         AuthRequest *req)
{
    MsnSession *session;
    gchar *body;
    gchar *header;
    gsize body_len;
    gchar *ticket = NULL;

    g_signal_handler_disconnect (conn, req->open_sig_handler);
    req->open_sig_handler = 0;

    pn_log ("begin");

    session = req->auth->session;
    if (req->ticket)
    {
        char *decoded, *joined , **split;

        decoded = g_uri_unescape_string (req->ticket, NULL);
        split = g_strsplit (decoded, ",", -1);
        g_free (decoded);
        joined = g_strjoinv ("&", split);
        g_strfreev (split);
        ticket = g_markup_escape_text (joined, -1);
        g_free (joined);
    }

    body = g_strdup_printf ("<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                            "<Envelope xmlns=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:wsse=\"http://schemas.xmlsoap.org/ws/2003/06/secext\" xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2002/12/policy\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/03/addressing\" xmlns:wssc=\"http://schemas.xmlsoap.org/ws/2004/04/sc\" xmlns:wst=\"http://schemas.xmlsoap.org/ws/2004/04/trust\">"
                            "<Header>"
                            "<ps:AuthInfo xmlns:ps=\"http://schemas.microsoft.com/Passport/SoapServices/PPCRL\" Id=\"PPAuthInfo\">"
                            "<ps:HostingApp>{7108E71A-9926-4FCB-BCC9-9A9D3F32E423}</ps:HostingApp>"
                            "<ps:BinaryVersion>4</ps:BinaryVersion>"
                            "<ps:UIVersion>1</ps:UIVersion>"
                            "<ps:Cookies/>"
                            "<ps:RequestParams>AQAAAAIAAABsYwQAAAAzMDg0</ps:RequestParams>"
                            "</ps:AuthInfo>"
                            "<wsse:Security xmlns:wsse=\"http://schemas.xmlsoap.org/ws/2003/06/secext\">"
                            "<wsse:UsernameToken Id=\"user\">"
                            "<wsse:Username>%s</wsse:Username>"
                            "<wsse:Password>%s</wsse:Password>"
                            "</wsse:UsernameToken>"
                            "</wsse:Security>"
                            "</Header>"
                            "<Body>"
                            "<ps:RequestMultipleSecurityTokens xmlns:ps=\"http://schemas.microsoft.com/Passport/SoapServices/PPCRL\" Id=\"RSTS\">"
                            "<wst:RequestSecurityToken Id=\"RST0\">"
                            "<wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>"
                            "<wsp:AppliesTo>"
                            "<wsa:EndpointReference xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/03/addressing\">"
                            "<wsa:Address>http://Passport.NET/tb</wsa:Address>"
                            "</wsa:EndpointReference>"
                            "</wsp:AppliesTo>"
                            "</wst:RequestSecurityToken>"
                            "<wst:RequestSecurityToken Id=\"RST1\">"
                            "<wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType>"
                            "<wsp:AppliesTo>"
                            "<wsa:EndpointReference xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/03/addressing\">"
                            "<wsa:Address>messenger.msn.com</wsa:Address>"
                            "</wsa:EndpointReference>"
                            "</wsp:AppliesTo>"
                            "<wsse:PolicyReference xmlns:wsse=\"http://schemas.xmlsoap.org/ws/2003/06/secext\" URI=\"?id=507\"/>"
                            "</wst:RequestSecurityToken>"
                            "</ps:RequestMultipleSecurityTokens>"
                            "</Body>"
                            "</Envelope>",
                            session->username,
                            session->password);

    g_free (ticket);

    body_len = strlen (body);

    header = g_strdup_printf ("POST %s HTTP/1.1\r\n"
                              "Accept: */*\r\n"
                              "Content-Type: text/xml; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
                              "Host: %s\r\n"
                              "Connection: Keep-Alive\r\n"
                              "Cache-Control: no-cache\r\n"
                              "\r\n%s",
                              req->redirect_url ? "/pp1100/RST.srf" : "/RST.srf",
                              body_len,
                              conn->hostname,
                              body);

    g_free (body);

    pn_test ("header=[%s]", header);
    /* pn_debug ("body=[%s]", body); */

    {
        gsize len;
        pn_node_write (conn, header, strlen (header), &len, NULL);
        pn_debug ("write_len=%zu", len);
    }

    g_free (header);

    pn_log ("end");
}

void
pn_auth_get_ticket (PnAuth *auth, int id, PnAuthCb cb, const char *ticket, void *cb_data)
{
    time_t ticket_time, current_time = time (NULL);

    g_print("ticket=%s\n", ticket);

    switch (id) {
    case 0: ticket_time = auth->expiration_time.messenger_msn_com; break;
    case 1: ticket_time = auth->expiration_time.messengersecure_live_com; break;
    default: return;
    }

    if (current_time >= ticket_time) {
        AuthRequest *req;
        PnSslConn *ssl_conn;
        PnNode *conn;

        req = auth_request_new (auth);
        ssl_conn = pn_ssl_conn_new ("auth", PN_NODE_NULL);

        conn = PN_NODE (ssl_conn);
        conn->session = auth->session;

        req->parser = pn_parser_new (conn);
        pn_ssl_conn_set_read_cb (ssl_conn, read_cb, req);

        pn_node_connect (conn, "loginnet.passport.com", 443);

        req->conn = conn;
        req->ticket = g_strdup (ticket);
        req->open_sig_handler = g_signal_connect (conn, "open", G_CALLBACK (open_cb), req);

        auth->pending_req = req;
        auth->cb = cb;
        auth->cb_data = cb_data;
    } else {
        cb (auth, cb_data);
    }
}
