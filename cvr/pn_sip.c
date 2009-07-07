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

#include "pn_sip.h"
#include "pn_peer_link.h"
#include "pn_peer_call.h"
#include "pn_peer_msg.h"
#include "pn_log.h"
#include "pn_buffer.h"

#include "cmd/cmdproc_private.h"
#include "cmd/msg_private.h"

#include "ab/pn_contact.h"
#include "ab/pn_contact_priv.h"
#include "ab/pn_contactlist_priv.h"

#include "cvr/pn_msnobj.h"
#include "switchboard.h"

#include "session_private.h"

#ifdef MSN_DIRECTCONN
#include "pn_direct_conn.h"
#endif /* MSN_DIRECTCONN */

#include "pn_util.h"

#include <string.h>

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <account.h>
#include <version.h>
#if PURPLE_VERSION_CHECK(2,5,0)
#include <smiley.h>
#endif /* PURPLE_VERSION_CHECK(2,5,0) */

static inline char *
get_token(const char *str,
          const char *start,
          const char *end)
{
    const char *c, *c2;

    if (!(c = strstr(str, start)))
        return NULL;

    c += strlen(start);

    if (end) {
        if (!(c2 = strstr(c, end)))
            return NULL;

        return g_strndup(c, c2 - c);
    }
    else {
        /** @todo this has to be changed */
        return g_strdup(c);
    }
}

#ifdef MSN_DIRECTCONN
static void
got_transresp(struct pn_peer_call *call,
              const char *nonce,
              const char *ips_str,
              int port)
{
    struct pn_direct_conn *direct_conn;
    char **ip_addrs, **c;

    direct_conn = pn_direct_conn_new(call->link);

    direct_conn->initial_call = call;

    /* pn_direct_conn_parse_nonce(direct_conn, nonce); */
    direct_conn->nonce = g_strdup(nonce);

    ip_addrs = g_strsplit(ips_str, " ", -1);

    for (c = ip_addrs; *c; c++) {
        pn_info("ip_addr = %s", *c);
        if (pn_direct_conn_connect(direct_conn, *c, port))
            break;
    }

    g_strfreev(ip_addrs);
}
#endif /* MSN_DIRECTCONN */

void
pn_sip_send_ok(struct pn_peer_call *call,
               const char *branch,
               const char *type,
               const char *content)
{
    struct pn_peer_link *link;
    struct pn_peer_msg *peer_msg;

    link = call->link;

    /* 200 OK */
    peer_msg = pn_peer_msg_sip_new(call, 1,
                                 "MSNSLP/1.0 200 OK",
                                 branch, type, content);

#ifdef PECAN_DEBUG_SLP
    peer_msg->info = "SLP 200 OK";
    peer_msg->text_body = TRUE;
#endif

    pn_peer_link_queue_msg(link, peer_msg);

    pn_peer_call_session_init(call);
}

void
pn_sip_send_decline(struct pn_peer_call *call,
                    const char *branch,
                    const char *type,
                    const char *content)
{
    struct pn_peer_link *link;
    struct pn_peer_msg *peer_msg;

    link = call->link;

    /* 603 Decline */
    peer_msg = pn_peer_msg_sip_new(call, 1,
                                 "MSNSLP/1.0 603 Decline",
                                 branch, type, content);

#ifdef PECAN_DEBUG_SLP
    peer_msg->info = "SLP 603 Decline";
    peer_msg->text_body = TRUE;
#endif

    pn_peer_link_queue_msg(link, peer_msg);
}

#define MAX_FILE_NAME_LEN 0x226

static void
got_sessionreq(struct pn_peer_call *call,
               const char *branch,
               const char *euf_guid,
               const char *context)
{
    pn_debug("euf_guid=[%s]", euf_guid);

    if (strcmp(euf_guid, "A4268EEC-FEC5-49E5-95C3-F126696BDBF6") == 0) {
        /* Emoticon or UserDisplay */
        char *content;
        gsize len;
        struct pn_peer_link *link;
        struct pn_peer_msg *peer_msg;
        struct pn_msnobj *obj;
        char *msnobj_data;
        struct pn_buffer *image;
        int type;

        /* Send Ok */
        content = g_strdup_printf("SessionID: %lu\r\n\r\n",
                                  call->session_id);

        pn_sip_send_ok(call, branch,
                       "application/x-msnmsgr-sessionreqbody",
                       content);

        g_free(content);

        link = call->link;

        msnobj_data = (char *) purple_base64_decode(context, &len);
        obj = pn_msnobj_new_from_string(msnobj_data);
        g_free(msnobj_data);

        if (!obj) {
            /** @todo reject invitation? */
            pn_warning("invalid object");
            return;
        }

        type = pn_msnobj_get_type(obj);

        if (type == PN_MSNOBJ_USERTILE) {
            /* image is owned by a local object, not obj */
            image = pn_msnobj_get_image(obj);
        }
#if PURPLE_VERSION_CHECK(2,5,0)
        else if (type == PN_MSNOBJ_EMOTICON) {
            PurpleStoredImage *img;
            char *path;
            path = g_build_filename(purple_smileys_get_storing_dir(), pn_msnobj_get_location(obj), NULL);
            img = purple_imgstore_new_from_file(path);
            image = pn_buffer_new_memdup((const gpointer) purple_imgstore_get_data(img),
                                         purple_imgstore_get_size(img));
            purple_imgstore_unref(img);
            g_free(path);
        }
#endif /* PURPLE_VERSION_CHECK(2,5,0) */
        else {
            pn_error("Wrong object?");
            pn_msnobj_free(obj);
            g_return_if_reached();
        }

        if (!image) {
            pn_error("Wrong object");
            pn_msnobj_free(obj);
            g_return_if_reached();
        }

        {
            gchar *tmp;
            tmp = pn_msnobj_to_string(obj);
            pn_info("object requested: %s", tmp);
            g_free(tmp);
        }

        pn_msnobj_free(obj);

        /* DATA PREP */
        peer_msg = pn_peer_msg_new(link);
        peer_msg->call = call;
        peer_msg->session_id = call->session_id;
        pn_peer_msg_set_body(peer_msg, NULL, 4);
#ifdef PECAN_DEBUG_SLP
        peer_msg->info = "SLP DATA PREP";
#endif
        pn_peer_link_queue_msg(link, peer_msg);

        /* DATA */
        peer_msg = pn_peer_msg_new(link);
        peer_msg->call = call;
        peer_msg->flags = 0x20;
#ifdef PECAN_DEBUG_SLP
        peer_msg->info = "SLP DATA";
#endif
        pn_peer_msg_set_image(peer_msg, image);
        pn_peer_link_queue_msg(link, peer_msg);
    }
    else if (strcmp(euf_guid, "5D3E02AB-6190-11D3-BBBB-00C04F795683") == 0) {
        MsnSession *session = pn_peer_link_get_session(call->link);
        session->xfer_invite_cb(call, branch, context);
    }
}

void
pn_sip_send_bye(struct pn_peer_call *call,
                const char *type)
{
    struct pn_peer_link *link;
    struct pn_peer_msg *peer_msg;
    char *header;
    MsnSession *session;

    link = call->link;
    session = pn_peer_link_get_session(link);

    header = g_strdup_printf("BYE MSNMSGR:%s MSNSLP/1.0",
                             msn_session_get_username(session));

    peer_msg = pn_peer_msg_sip_new(call, 0, header,
                                 "A0D624A6-6C0C-4283-A9E0-BC97B4B46D32",
                                 type,
                                 "\r\n");
    g_free(header);

#ifdef PECAN_DEBUG_SLP
    peer_msg->info = "SLP BYE";
    peer_msg->text_body = TRUE;
#endif

    pn_peer_link_queue_msg(link, peer_msg);
}

static void
got_invite(struct pn_peer_call *call,
           const char *branch,
           const char *type,
           const char *content)
{
    struct pn_peer_link *link;

    link = call->link;

    pn_log("type=%s", type);

    if (strcmp(type, "application/x-msnmsgr-sessionreqbody") == 0) {
        char *euf_guid, *context;
        char *temp;

        euf_guid = get_token(content, "EUF-GUID: {", "}\r\n");

        temp = get_token(content, "SessionID: ", "\r\n");
        if (temp)
            call->session_id = atoi(temp);
        g_free(temp);

        temp = get_token(content, "AppID: ", "\r\n");
        if (temp)
            call->app_id = atoi(temp);
        g_free(temp);

        context = get_token(content, "Context: ", "\r\n");

        if (context)
            got_sessionreq(call, branch, euf_guid, context);

        g_free(context);
        g_free(euf_guid);
    }
    else if (strcmp(type, "application/x-msnmsgr-transreqbody") == 0) {
        /* A direct connection? */

        const gchar *listening;
        gchar *new_content, *nonce;

        if (FALSE) {
#if 0
            struct pn_direct_conn *direct_conn;
            /* const char *ip_addr; */
            char *ip_port;
            int port;

            /* ip_addr = purple_prefs_get_string("/purple/ft/public_ip"); */
            ip_port = "5190";
            listening = "true";
            nonce = msn_rand_guid();

            direct_conn = pn_direct_conn_new(link);

            /* pn_direct_conn_parse_nonce(direct_conn, nonce); */
            direct_conn->nonce = g_strdup(nonce);

            pn_direct_conn_listen(direct_conn);

            port = direct_conn->port;

            new_content = g_strdup_printf("Bridge: TCPv1\r\n"
                                          "Listening: %s\r\n"
                                          "Nonce: {%s}\r\n"
                                          "Ipv4Internal-Addrs: 192.168.0.82\r\n"
                                          "Ipv4Internal-Port: %d\r\n"
                                          "\r\n",
                                          listening,
                                          nonce,
                                          port);
#endif
        }
        else {
            listening = "false";
            nonce = g_strdup("00000000-0000-0000-0000-000000000000");

            new_content = g_strdup_printf("Bridge: TCPv1\r\n"
                                          "Listening: %s\r\n"
                                          "Nonce: {%s}\r\n"
                                          "\r\n",
                                          listening,
                                          nonce);
        }

        pn_sip_send_ok(call, branch,
                       "application/x-msnmsgr-transrespbody",
                       new_content);

        g_free(new_content);
        g_free(nonce);
    }
#ifdef MSN_DIRECTCONN
    else if (!strcmp(type, "application/x-msnmsgr-transrespbody") == 0) {
        char *ip_addrs;
        char *temp;
        char *nonce;
        int port;

        nonce = get_token(content, "Nonce: {", "}\r\n");
        ip_addrs = get_token(content, "IPv4Internal-Addrs: ", "\r\n");

        temp = get_token(content, "IPv4Internal-Port: ", "\r\n");
        port = temp ? atoi(temp) : -1;
        g_free(temp);

        if (!ip_addrs)
            return;

        if (port > 0)
            got_transresp(call, nonce, ip_addrs, port);

        g_free(nonce);
        g_free(ip_addrs);
    }
#endif /* MSN_DIRECTCONN */
}

static void
got_ok(struct pn_peer_call *call,
       const char *type,
       const char *content)
{
    pn_log("type=%s", type);

    if (strcmp(type, "application/x-msnmsgr-sessionreqbody") == 0) {
#ifdef MSN_DIRECTCONN
        if (call->link->session->use_direct_conn &&
            call->type == PN_PEER_CALL_DC)
        {
            /* First let's try a DirectConnection. */

            struct pn_peer_link *link;
            struct pn_peer_msg *peer_msg;
            char *header;
            gchar *new_content;
            char *branch;

            link = call->link;

            branch = msn_rand_guid();

            new_content = g_strdup_printf("Bridges: TRUDPv1 TCPv1\r\n"
                                          "NetID: 0\r\n"
                                          "Conn-Type: Direct-Connect\r\n"
                                          "UPnPNat: false\r\n"
                                          "ICF: false\r\n");

            header = g_strdup_printf("INVITE MSNMSGR:%s MSNSLP/1.0",
                                     link->remote_user);

            peer_msg = pn_peer_msg_sip_new(call, 0, header, branch,
                                         "application/x-msnmsgr-transreqbody",
                                         new_content);

#ifdef PECAN_DEBUG_SLP
            peer_msg->info = "SLP INVITE";
            peer_msg->text_body = TRUE;
#endif
            pn_peer_link_send_msg(link, peer_msg);

            g_free(header);
            g_free(new_content);

            g_free(branch);
        }
        else
            pn_peer_call_session_init(call);
#else
        pn_peer_call_session_init(call);
#endif /* MSN_DIRECTCONN */
    }
    else if (strcmp(type, "application/x-msnmsgr-transreqbody") == 0) {
        /** @todo do we ever get this? */
        pn_info("OK with transreqbody");
    }
#ifdef MSN_DIRECTCONN
    else if (strcmp(type, "application/x-msnmsgr-transrespbody") == 0) {
        char *ip_addrs;
        char *temp;
        char *nonce;
        int port;

        {
            char *listening;
            listening = get_token(content, "Listening: ", "\r\n");
            if (strcmp(listening, "false") == 0) {
                /** @todo I'm not sure if this is OK. */
                pn_peer_call_session_init(call);
                g_free(listening);
                return;
            }
            g_free(listening);
        }

        nonce = get_token(content, "Nonce: {", "}\r\n");
        ip_addrs = get_token(content, "IPv4Internal-Addrs: ", "\r\n");

        temp = get_token(content, "IPv4Internal-Port: ", "\r\n");
        port = temp ? atoi(temp) : -1;
        g_free(temp);

        if (!ip_addrs)
            return;

        if (port > 0)
            got_transresp(call, nonce, ip_addrs, port);

        g_free(nonce);
        g_free(ip_addrs);
    }
#endif /* MSN_DIRECTCONN */
}

void
pn_sip_recv(struct pn_peer_link *link,
            const char *body)
{
    struct pn_peer_call *call;

    if (!body) {
        pn_warning("received bogus message");
        return;
    }

    if (strncmp(body, "INVITE", strlen("INVITE")) == 0) {
        char *branch;
        char *content;
        char *content_type;

        call = pn_peer_call_new(link);

        /* From: <msnmsgr:buddy@hotmail.com> */
#if 0
        call->remote_user = get_token(body, "From: <msnmsgr:", ">\r\n");
#endif

        branch = get_token(body, ";branch={", "}");

        call->id = get_token(body, "Call-ID: {", "}");

#if 0
        long content_len = -1;

        temp = get_token(body, "Content-Length: ", "\r\n");
        if (temp != NULL)
            content_len = atoi(temp);
        g_free(temp);
#endif
        content_type = get_token(body, "Content-Type: ", "\r\n");

        content = get_token(body, "\r\n\r\n", NULL);

        got_invite(call, branch, content_type, content);

        g_free(branch);
        g_free(content_type);
        g_free(content);
    }
    else if (strncmp(body, "MSNSLP/1.0 ", strlen("MSNSLP/1.0 ")) == 0) {
        char *content;
        char *content_type;
        /* Make sure this is "OK" */
        const char *status = body + strlen("MSNSLP/1.0 ");
        char *call_id;

        call_id = get_token(body, "Call-ID: {", "}");
        call = pn_peer_link_find_slp_call(link, call_id);
        g_free(call_id);

        g_return_if_fail(call);

        if (strncmp(status, "200 OK", 6) != 0) {
            /* It's not valid. Kill this off. */
            char temp[32];
            const char *c;

            /* Eww */
            if ((c = strchr(status, '\r')) ||
                (c = strchr(status, '\n')) ||
                (c = strchr(status, '\0')))
            {
                size_t offset =  c - status;
                if (offset >= sizeof(temp))
                    offset = sizeof(temp) - 1;

                strncpy(temp, status, offset);
                temp[offset] = '\0';
            }

            pn_warning("received non-OK result: %s", temp);

            pn_peer_call_unref(call);
            return;
        }

        content_type = get_token(body, "Content-Type: ", "\r\n");

        content = get_token(body, "\r\n\r\n", NULL);

        got_ok(call, content_type, content);

        g_free(content_type);
        g_free(content);
    }
    else if (strncmp(body, "BYE", strlen("BYE")) == 0) {
        char *call_id;

        call_id = get_token(body, "Call-ID: {", "}");
        call = pn_peer_link_find_slp_call(link, call_id);
        g_free(call_id);

        if (call)
            pn_peer_call_unref(call);
        return;
    }
}
