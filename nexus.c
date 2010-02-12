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

#include "nexus.h"
#include "pn_log.h"
#include "pn_util.h"
#include "pn_locale.h"

#include "io/pn_ssl_conn.h"
#include "io/pn_node_private.h"

#include <stdlib.h> /* for strtoul */
#include <string.h> /* for strncpy, strlen, strchr */

#include "notification.h" /* for msn_got_login_params */

#include "session.h"
#include "session_private.h"

/* libpurple */
#include <util.h> /* for url_encode */

static void login_open_cb(PnNode *conn, gpointer data);

MsnNexus *
msn_nexus_new(MsnSession *session)
{
    MsnNexus *nexus;

    nexus = g_new0(MsnNexus, 1);
    nexus->session = session;
    nexus->challenge_data = g_hash_table_new_full(g_str_hash,
                                                  g_str_equal, g_free, g_free);

    return nexus;
}

void
msn_nexus_destroy(MsnNexus *nexus)
{
    if (nexus->error_handler)
        g_signal_handler_disconnect(nexus->conn, nexus->error_handler);
    if (nexus->open_handler)
        g_signal_handler_disconnect(nexus->conn, nexus->open_handler);
    g_object_unref(nexus->conn);
    pn_parser_free(nexus->parser);

    if (nexus->header)
        g_string_free(nexus->header, TRUE);

    g_free(nexus->login_host);
    g_free(nexus->login_path);

    if (nexus->challenge_data)
        g_hash_table_destroy(nexus->challenge_data);

    g_free(nexus);
}

static void
close_cb(PnNode *conn,
         MsnNexus *nexus)
{
    char *tmp;

    if (conn->error) {
        const char *reason;
        reason = conn->error->message;
        tmp = g_strdup_printf(_("error on nexus server: %s"), reason);
        g_clear_error(&conn->error);
    }
    else {
        tmp = g_strdup_printf(_("error on nexus server"));
    }

    msn_session_set_error(nexus->session, MSN_ERROR_AUTH, tmp);

    g_free(tmp);
}

/* login */

static void
got_header(MsnNexus *nexus,
           const gchar *header)
{
    MsnSession *session = nexus->session;

    if (strstr(header, "HTTP/1.1 200 OK")) {
        char *base, *c;
        char *login_params;

        base  = strstr(header, "Authentication-Info: ");

        if (!base)
            goto parse_error;

        base = strstr(base, "from-PP='");
        base += strlen("from-PP='");
        c = strchr(base, '\'');

        login_params = g_strndup(base, c - base);

        msn_got_login_params(session, login_params);

        g_free(login_params);

        msn_nexus_destroy(nexus);
        session->nexus = NULL;
        return;
    }
    else if (strstr(header, "HTTP/1.1 302")) {
        /* Redirect. */
        char *location, *c;

        location = strstr(header, "Location: ");
        if (!location)
            goto parse_error;
        location = strchr(location, ' ') + 1;

        if ((c = strchr(location, '\r')))
            *c = '\0';

        /* Skip the http:// */
        if ((c = strchr(location, '/')))
            location = c + 2;

        if ((c = strchr(location, '/'))) {
            g_free(nexus->login_path);
            nexus->login_path = g_strdup(c);

            *c = '\0';
        }

        g_free(nexus->login_host);
        nexus->login_host = g_strdup(location);

        pn_info("reconnecting to '%s'", nexus->login_host);
        pn_parser_reset(nexus->parser);
        nexus->parser_state = 0;

        nexus->open_handler = g_signal_connect(nexus->conn, "open", G_CALLBACK(login_open_cb), nexus);
        pn_node_connect(nexus->conn, nexus->login_host, 443);
        return;
    }
    else if (strstr(header, "HTTP/1.1 401 Unauthorized")) {
        const char *tmp;
        gchar *error = NULL;

        if ((tmp = strstr(header, "WWW-Authenticate"))) {
            if ((tmp = strstr(tmp, "cbtxt="))) {
                const char *c;
                char *tmp2;

                tmp += strlen("cbtxt=");

                c = strchr(tmp, '\n');
                if (!c)
                    c = tmp + strlen(tmp);

                tmp2 = g_strndup(tmp, c - tmp);
                error = pn_url_decode(tmp2);
                g_free(tmp2);
                if ((tmp2 = strstr(error, " Do one of the following or try again:")) != NULL)
                    *tmp2 = '\0';
            }
        }

        msn_session_set_error(session, MSN_ERROR_AUTH, error);
        g_free(error);
        return;
    }
    else if (strstr(header, "HTTP/1.1 503 Service Unavailable")) {
        msn_session_set_error(session, MSN_ERROR_SERV_UNAVAILABLE, NULL);
        return;
    }

parse_error:
    msn_session_set_error(session, MSN_ERROR_AUTH, _("nexus parse error"));
}

static void
login_read_cb(PnNode *conn,
              gpointer data)
{
    MsnNexus *nexus = data;
    GIOStatus status = G_IO_STATUS_NORMAL;
    gchar *str = NULL;

    if (!nexus->header)
        nexus->header = g_string_new(NULL);

    g_object_ref (conn);

    while (nexus->parser_state == 0) {
        gsize terminator_pos;

        status = pn_parser_read_line(nexus->parser, &str, NULL, &terminator_pos, NULL);

        if (status == G_IO_STATUS_AGAIN)
            goto leave;

        if (status != G_IO_STATUS_NORMAL) {
            msn_session_set_error(nexus->session, MSN_ERROR_AUTH,
                                  _("nexus stream error"));
            goto leave;
        }

        if (str) {
            str[terminator_pos] = '\0';

            nexus->header = g_string_append(nexus->header, str);

            if (str[0] == '\0') {
                gchar *tmp;
                nexus->parser_state++;
                tmp = g_string_free(nexus->header, FALSE);
                nexus->header = NULL;
                got_header(nexus, tmp);
                g_free(tmp);
                g_free(str);
                break;
            }

            g_free(str);
        }
    }

leave:
    g_object_unref(conn);
}

/* this guards against missing entries */
static inline const gchar *
get_key(GHashTable *challenge_data,
        const char *key)
{
    const gchar *entry;
    entry = g_hash_table_lookup(challenge_data, key);
    return entry ? entry : "(null)";
}

static void
login_open_cb(PnNode *conn,
              gpointer data)
{
    MsnNexus *nexus = data;
    MsnSession *session;
    const char *username, *password;
    char *req, *head, *tail;
    guint32 ctint;
    GIOStatus status = G_IO_STATUS_NORMAL;

    g_return_if_fail(conn);

    g_signal_handler_disconnect(conn, nexus->open_handler);
    nexus->open_handler = 0;

    session = nexus->session;

    username = msn_session_get_username(session);
    password = msn_session_get_password(session);

    ctint = strtoul((char *) g_hash_table_lookup(nexus->challenge_data, "ct"), NULL, 10) + 200;

    head = g_strdup_printf("GET %s HTTP/1.1\r\n"
                           "Authorization: Passport1.4 OrgVerb=GET,OrgURL=%s,sign-in=%s",
                           nexus->login_path,
                           (char *) g_hash_table_lookup(nexus->challenge_data, "ru"),
                           purple_url_encode(username));

    tail = g_strdup_printf("lc=%s,id=%s,tw=%s,fs=%s,ru=%s,ct=%" G_GUINT32_FORMAT ",kpp=%s,kv=%s,ver=%s,tpf=%s\r\n"
                           "User-Agent: MSMSGS\r\n"
                           "Host: %s\r\n"
                           "Connection: Keep-Alive\r\n"
                           "Cache-Control: no-cache\r\n",
                           get_key(nexus->challenge_data, "lc"),
                           get_key(nexus->challenge_data, "id"),
                           get_key(nexus->challenge_data, "tw"),
                           get_key(nexus->challenge_data, "fs"),
                           get_key(nexus->challenge_data, "ru"),
                           ctint,
                           get_key(nexus->challenge_data, "kpp"),
                           get_key(nexus->challenge_data, "kv"),
                           get_key(nexus->challenge_data, "ver"),
                           get_key(nexus->challenge_data, "tpf"),
                           nexus->login_host);

    req = g_strdup_printf("%s,pwd=%s,%s\r\n", head, purple_url_encode(password), tail);

    g_free(head);
    g_free(tail);

    status = pn_node_write(conn, req, strlen(req), NULL, NULL);

    if (status != G_IO_STATUS_NORMAL) {
        msn_session_set_error(nexus->session, MSN_ERROR_AUTH,
                              _("nexus stream error"));
    }

    g_free(req);
}

/* nexus */

static inline char *
get_field(char *s1, const char *s2)
{
    if (strncmp(s1, s2, strlen(s2)) == 0)
        return s1 += strlen(s2);
    return NULL;
}

static void
nexus_read_cb(PnNode *conn,
              gpointer data)
{
    MsnNexus *nexus = data;
    GIOStatus status = G_IO_STATUS_NORMAL;
    gchar *str = NULL;

    while (nexus->parser_state == 0) {
        gsize terminator_pos;

        status = pn_parser_read_line(nexus->parser, &str, NULL, &terminator_pos, NULL);

        if (status == G_IO_STATUS_AGAIN)
            return;

        if (status != G_IO_STATUS_NORMAL) {
            msn_session_set_error(nexus->session, MSN_ERROR_AUTH,
                                  _("nexus stream error"));
            return;
        }

        if (str) {
            char *field;
            str[terminator_pos] = '\0';

            if ((field = get_field(str, "PassportURLs: "))) {
                char *da_login;

                da_login = strstr(field, "DALogin=");
                if (da_login) {
                    char *c;

                    da_login += 8; /* skip over "DALogin=" */

                    c = strchr(da_login, ',');
                    if (c)
                        *c = '\0';

                    c = strchr(da_login, '/');
                    if (c) {
                        nexus->login_path = g_strdup(c);
                        *c = '\0';
                    }

                    nexus->login_host = g_strdup(da_login);

#if 0
                    /* test reconnection */
                    g_free(nexus->login_host);
                    nexus->login_host = g_strdup("msnia.login.live.com");
#endif
                }
            }

            g_free(str);

            if (nexus->login_host) {
                PnSslConn *ssl_conn;
                PnNode *conn;

                ssl_conn = pn_ssl_conn_new("login", PN_NODE_NULL);

                conn = PN_NODE(ssl_conn);
                conn->session = nexus->session;

                if (nexus->error_handler)
                    g_signal_handler_disconnect(nexus->conn, nexus->error_handler);
                if (nexus->open_handler)
                    g_signal_handler_disconnect(nexus->conn, nexus->open_handler);
                g_object_unref(nexus->conn);
                pn_parser_free(nexus->parser);
                nexus->parser_state = 0;

                nexus->parser = pn_parser_new(conn);
                pn_ssl_conn_set_read_cb(ssl_conn, login_read_cb, nexus);

                nexus->conn = conn;
                nexus->open_handler = g_signal_connect(conn, "open", G_CALLBACK(login_open_cb), nexus);
                nexus->error_handler = g_signal_connect(conn, "error", G_CALLBACK(close_cb), nexus);

                pn_node_connect(conn, nexus->login_host, 443);

                return;
            }
        }
    }
}

static void
nexus_open_cb(PnNode *conn,
              gpointer data)
{
    MsnNexus *nexus = data;
    const gchar *req = "GET /rdr/pprdr.asp\r\n\r\n";
    GIOStatus status = G_IO_STATUS_NORMAL;

    g_return_if_fail(conn);

    g_signal_handler_disconnect(conn, nexus->open_handler);
    nexus->open_handler = 0;
    g_signal_handler_disconnect(conn, nexus->error_handler);
    nexus->error_handler = 0;

    pn_node_write(conn, req, strlen(req), NULL, NULL);

    if (status != G_IO_STATUS_NORMAL) {
        msn_session_set_error(nexus->session, MSN_ERROR_AUTH,
                              _("nexus stream error"));
    }
}

void
msn_nexus_connect(MsnNexus *nexus)
{
    PnSslConn *ssl_conn;
    PnNode *conn;

    ssl_conn = pn_ssl_conn_new("nexus", PN_NODE_NULL);

    conn = PN_NODE(ssl_conn);
    conn->session = nexus->session;

    nexus->parser = pn_parser_new(conn);
    pn_ssl_conn_set_read_cb(ssl_conn, nexus_read_cb, nexus);

    nexus->conn = conn;
    nexus->open_handler = g_signal_connect(conn, "open", G_CALLBACK(nexus_open_cb), nexus);
    nexus->error_handler = g_signal_connect(conn, "error", G_CALLBACK(close_cb), nexus);

    pn_node_connect(conn, "nexus.passport.com", 443);
}
