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

#include "pn_peer_link.h"

#include "session.h"
#include "switchboard.h"
#include "pn_peer_call.h"
#include "pn_peer_msg.h"
#include "pn_log.h"

#include "ab/pn_contact.h"

#include "session_private.h"

#include "pn_peer_call_priv.h"
#include "pn_peer_msg_priv.h"

#ifdef MSN_DIRECTCONN
#include "pn_direct_conn.h"
#endif /* MSN_DIRECTCONN */

#include "cmd/msg_private.h"

#include <glib/gstdio.h>
#include <string.h>

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <ft.h>

struct pn_peer_link {
    char *local_user;
    char *remote_user;

    int slp_seq_id;
    int slp_session_id;

    GList *slp_calls;
    GList *slp_msgs;

    GQueue *slp_msg_queue;
    struct MsnSession *session;
    struct pn_direct_conn *direct_conn;

    unsigned int ref_count;
};

static void send_msg_part(struct pn_peer_link *link, struct pn_peer_msg *peer_msg);

struct pn_peer_link *
pn_peer_link_new(MsnSession *session,
                 const char *username)
{
    struct pn_peer_link *link;

    link = g_new0(struct pn_peer_link, 1);

#ifdef PECAN_DEBUG_SLPLINK
    pn_info("link=%p", link);
#endif

    link->session = session;
    link->slp_seq_id = rand() % 0xFFFFFF00 + 4;
    link->slp_session_id = rand() % 0xFFFFFF00 + 4;

    link->local_user = g_strdup(msn_session_get_username(session));
    link->remote_user = g_strdup(username);

    link->slp_msg_queue = g_queue_new();

    link->ref_count++;

    return link;
}

void
pn_peer_link_free(struct pn_peer_link *link)
{
    MsnSession *session;

    if (!link)
        return;

#ifdef PECAN_DEBUG_SLPLINK
    pn_info("link=%p", link);
#endif

    session = link->session;

#ifdef MSN_DIRECTCONN
    if (link->direct_conn)
        pn_direct_conn_destroy(link->direct_conn);
#endif /* MSN_DIRECTCONN */

    g_free(link->local_user);
    g_free(link->remote_user);

    g_free(link);
}

struct pn_peer_link *
pn_peer_link_ref(struct pn_peer_link *link)
{
    link->ref_count++;

    return link;
}

struct pn_peer_link *
pn_peer_link_unref(struct pn_peer_link *link)
{
    link->ref_count--;

    if (link->ref_count == 0) {
        pn_peer_link_free(link);
        return NULL;
    }

    return link;
}

const char *
pn_peer_link_get_passport(const struct pn_peer_link *link)
{
    return link->remote_user;
}

MsnSession *
pn_peer_link_get_session(const struct pn_peer_link *link)
{
    return link->session;
}

struct pn_peer_link *
msn_session_find_peer_link(MsnSession *session,
                           const char *who)
{

    return g_hash_table_lookup(session->links, who);
}

struct pn_peer_link *
msn_session_get_peer_link(MsnSession *session,
                          const char *username)
{
    struct pn_peer_link *link;

    link = msn_session_find_peer_link(session, username);

    if (!link) {
        link = pn_peer_link_new(session, username);
        g_hash_table_insert(session->links, g_strdup(username), link);
    }

    return link;
}

void
pn_peer_link_add_call(struct pn_peer_link *link,
                      struct pn_peer_call *call)
{
    MsnSwitchBoard *swboard;

    swboard = msn_session_get_swboard(link->session, link->remote_user);

    if (!swboard) {
        pn_error("couldn't get swboard");
        return;
    }

    swboard->calls = g_list_prepend(swboard->calls, call);

    call->swboard = swboard;
    call->session_id = link->slp_session_id++;

    link->slp_calls = g_list_append(link->slp_calls, call);
}

void
pn_peer_link_remove_call(struct pn_peer_link *link,
                         struct pn_peer_call *call)
{
    GList *e;

    link->slp_calls = g_list_remove(link->slp_calls, call);

    for (e = link->slp_msgs; e; ) {
        struct pn_peer_msg *peer_msg = e->data;
        e = e->next;

        if (peer_msg->call == call)
            pn_peer_msg_unref(peer_msg);
    }
}

void
pn_peer_link_add_msg(struct pn_peer_link *link,
                     struct pn_peer_msg *peer_msg)
{
    link->slp_msgs = g_list_append(link->slp_msgs, peer_msg);
}

void
pn_peer_link_remove_msg(struct pn_peer_link *link,
                        struct pn_peer_msg *peer_msg)
{
    link->slp_msgs = g_list_remove(link->slp_msgs, peer_msg);
}

struct pn_peer_call *
pn_peer_link_find_slp_call(struct pn_peer_link *link,
                           const char *id)
{
    GList *l;
    struct pn_peer_call *call;

    if (!id)
        return NULL;

    for (l = link->slp_calls; l; l = l->next) {
        call = l->data;

        if (call->id && strcmp(call->id, id) == 0)
            return call;
    }

    return NULL;
}

static inline struct pn_peer_call *
find_session_call(struct pn_peer_link *link,
                  long id)
{
    GList *l;
    struct pn_peer_call *call;

    for (l = link->slp_calls; l; l = l->next) {
        call = l->data;

        if (call->session_id == id)
            return call;
    }

    return NULL;
}

static inline void
send_msg(struct pn_peer_link *link,
         struct pn_peer_msg *peer_msg)
{
    MsnSwitchBoard *swboard;
    if (peer_msg->call)
        swboard = peer_msg->call->swboard;
    else
        swboard = peer_msg->swboard;
    msn_switchboard_send_msg(swboard, peer_msg->msg, TRUE);
}

/* We have received the message ack */
static void
msg_ack(MsnMessage *msg,
        void *data)
{
    struct pn_peer_msg *peer_msg;
    guint64 real_size;

    peer_msg = data;

    real_size = (peer_msg->flags == 0x2) ? 0 : peer_msg->size;

    peer_msg->offset += msg->msnslp_header.length;

    if (peer_msg->offset < real_size)
        send_msg_part(peer_msg->link, peer_msg);
    else {
        /* The whole message has been sent */
        if (peer_msg->flags == 0x20 ||
            peer_msg->flags == 0x1000020 ||
            peer_msg->flags == 0x1000030)
        {
            if (peer_msg->call && peer_msg->call->cb)
                    peer_msg->call->cb(peer_msg->call, NULL, 0);
        }
    }

    peer_msg->msgs = g_list_remove(peer_msg->msgs, msg);
}

/* We have received the message nak. */
static void
msg_nak(MsnMessage *msg,
        void *data)
{
    struct pn_peer_msg *peer_msg;

    peer_msg = data;

    send_msg_part(peer_msg->link, peer_msg);

    peer_msg->msgs = g_list_remove(peer_msg->msgs, msg);
}

static void
send_msg_part(struct pn_peer_link *link,
              struct pn_peer_msg *peer_msg)
{
    MsnMessage *msg;
    guint64 real_size;
    size_t len = 0;

    /** @todo maybe we will want to create a new msg for this peer_msg instead of
     * reusing the same one all the time. */
    msg = peer_msg->msg;

    real_size = (peer_msg->flags == 0x2) ? 0 : peer_msg->size;

    if (peer_msg->offset < real_size) {
        if (peer_msg->fp) {
            char data[1202];
            len = fread(data, 1, sizeof(data), peer_msg->fp);
            msn_message_set_bin_data(msg, data, len);
        }
        else {
            len = peer_msg->size - peer_msg->offset;

            if (len > 1202)
                len = 1202;

            msn_message_set_bin_data(msg, peer_msg->buffer + peer_msg->offset, len);
        }

        msg->msnslp_header.offset = peer_msg->offset;
        msg->msnslp_header.length = len;
    }

#ifdef PECAN_DEBUG_SLP
    msn_message_show_readable(msg, peer_msg->info, peer_msg->text_body);
#endif

    peer_msg->msgs = g_list_append(peer_msg->msgs, msg);

#ifdef MSN_DIRECTCONN
    /* The hand-shake message has 0x100 flags. */
    if (link->direct_conn &&
        (peer_msg->flags == 0x100 || link->direct_conn->ack_recv))
        pn_direct_conn_send_msg(link->direct_conn, msg);
    else
        send_msg(link, peer_msg);
#else
    send_msg(link, peer_msg);
#endif /* MSN_DIRECTCONN */

    if (peer_msg->call) {
        if (peer_msg->flags == 0x20 ||
            peer_msg->flags == 0x1000020 ||
            peer_msg->flags == 0x1000030)
        {
            peer_msg->call->progress = TRUE;

            if (peer_msg->call->progress_cb)
                peer_msg->call->progress_cb(peer_msg->call, peer_msg->size,
                                          len, peer_msg->offset);
        }
    }

    /* peer_msg->offset += len; */
}

static void
release_peer_msg(struct pn_peer_link *link,
                 struct pn_peer_msg *peer_msg)
{
    MsnMessage *msg;

    peer_msg->msg = msg = msn_message_new_msnslp();

    switch (peer_msg->flags) {
        case 0x0:
            msg->msnslp_header.session_id = peer_msg->session_id;
            msg->msnslp_header.ack_id = rand() % 0xFFFFFF00;
            break;
        case 0x2:
            msg->msnslp_header.session_id = peer_msg->session_id;
            msg->msnslp_header.ack_id = peer_msg->ack_id;
            msg->msnslp_header.ack_size = peer_msg->ack_size;
            msg->msnslp_header.ack_sub_id = peer_msg->ack_sub_id;
            break;
        case 0x20:
        case 0x1000020:
        case 0x1000030:
            {
                struct pn_peer_call *call = peer_msg->call;

                if (call) {
                    msg->msnslp_header.session_id = call->session_id;
                    msg->msnslp_footer.value = call->app_id;
                }
                msg->msnslp_header.ack_id = rand() % 0xFFFFFF00;
                break;
            }
        case 0x100:
            msg->msnslp_header.ack_id = peer_msg->ack_id;
            msg->msnslp_header.ack_sub_id = peer_msg->ack_sub_id;
            msg->msnslp_header.ack_size = peer_msg->ack_size;
            break;
        default:
            break;
    }

    msg->msnslp_header.id = peer_msg->id;
    msg->msnslp_header.flags = peer_msg->flags;

    msg->msnslp_header.total_size = peer_msg->size;

    msn_message_set_attr(msg, "P2P-Dest", link->remote_user);

    msg->ack_cb = msg_ack;
    msg->nak_cb = msg_nak;
    msg->ack_data = peer_msg;

    send_msg_part(link, peer_msg);

    msn_message_unref(msg);
}

void
pn_peer_link_queue_msg(struct pn_peer_link *link,
                       struct pn_peer_msg *peer_msg)
{
    peer_msg->id = link->slp_seq_id++;

    g_queue_push_head(link->slp_msg_queue, peer_msg);
}

void
pn_peer_link_send_msg(struct pn_peer_link *link,
                      struct pn_peer_msg *peer_msg)
{
    peer_msg->id = link->slp_seq_id++;

    release_peer_msg(link, peer_msg);
}

void
pn_peer_link_unleash(struct pn_peer_link *link)
{
    struct pn_peer_msg *peer_msg;

    /* Send the queued msgs in the order they came. */

    pn_peer_link_ref(link);

    while ((peer_msg = g_queue_pop_tail(link->slp_msg_queue)))
        release_peer_msg(link, peer_msg);

    pn_peer_link_unref(link);
}

static inline void
send_ack(struct pn_peer_link *link,
         MsnMessage *msg)
{
    struct pn_peer_msg *peer_msg;

    peer_msg = pn_peer_msg_new(link);

    peer_msg->session_id = msg->msnslp_header.session_id;
    peer_msg->size = msg->msnslp_header.total_size;
    peer_msg->flags = 0x02;
    peer_msg->ack_id = msg->msnslp_header.id;
    peer_msg->ack_sub_id = msg->msnslp_header.ack_id;
    peer_msg->ack_size = msg->msnslp_header.total_size;

#ifdef PECAN_DEBUG_SLP
    peer_msg->info = "SLP ACK";
#endif

    pn_peer_link_send_msg(link, peer_msg);
}

static void
process_peer_msg(struct pn_peer_link *link,
                 struct pn_peer_msg *peer_msg)
{
    struct pn_peer_call *call = NULL;
    gpointer body;
    gsize body_len;

    body = peer_msg->buffer;
    body_len = peer_msg->size;

    switch (peer_msg->flags) {
        case 0x0:
        case 0x1000000:
            {
                char *body_str;

                /* Handwritten messages are just dumped down the line with no MSNObject */
                if (peer_msg->session_id == 64) {
                    const char *start;
                    char *msgid;
                    int charsize;
                    /* Just to be evil they put a 0 in the string just before the data you want,
                       and then convert to utf-16 */
                    body_str = g_utf16_to_utf8((gunichar2*) body, body_len / 2, NULL, NULL, NULL);
                    start = (char*) body + (strlen(body_str) + 1) * 2;
                    charsize = (body_len / 2) - (strlen(body_str) + 1);
                    g_free(body_str);
                    body_str = g_utf16_to_utf8((gunichar2*) start, charsize, NULL, NULL, NULL);
                    msgid = g_strdup_printf("{handwritten:%ld}", peer_msg->id);
                    msn_handwritten_msg_show(peer_msg->call->swboard, msgid, body_str + 7, link->remote_user);
                    g_free(msgid);
                }
                else {
                    body_str = g_strndup(body, body_len);
                    pn_sip_recv(link, body_str);
                }
                g_free(body_str);
                break;
            }
        case 0x20:
        case 0x1000020:
        case 0x1000030:
            call = find_session_call(link, peer_msg->session_id);

            if (!call)
                break;

            if (call->timer)
                purple_timeout_remove(call->timer);

            /* clear the error cb, otherwise it will be called when
             * the call is destroyed. */
            call->end_cb = NULL;

            call->cb(call, body, body_len);

            pn_peer_call_unref(call);
            break;
#ifdef MSN_DIRECTCONN
        case 0x100:
            call = link->direct_conn->initial_call;

            if (!call)
                break;

            pn_peer_call_session_init(call);
#endif /* MSN_DIRECTCONN */
        default:
            pn_warning("slp_process_msg: unprocessed SLP message with flags 0x%08lx",
                       peer_msg->flags);
    }
}

static inline struct pn_peer_msg *
find_message(struct pn_peer_link *link,
             long session_id,
             long id)
{
    GList *e;

    for (e = link->slp_msgs; e; e = e->next) {
        struct pn_peer_msg *peer_msg = e->data;

        if ((peer_msg->session_id == session_id) && (peer_msg->id == id))
            return peer_msg;
    }

    return NULL;
}

void
pn_peer_link_process_msg(struct pn_peer_link *link,
                         MsnMessage *msg,
                         int type,
                         void *user_data)
{
    struct pn_peer_msg *peer_msg;
    const char *data;
    guint64 offset;
    gsize len;

#ifdef PECAN_DEBUG_SLP
    pn_peer_msg_show(msg);
#endif

    if (msg->msnslp_header.total_size < msg->msnslp_header.length) {
        pn_error("This can't be good");
        g_return_if_reached();
    }

    peer_msg = NULL;
    data = msn_message_get_bin_data(msg, &len);

    /*
       OVERHEAD!
       if (msg->msnslp_header.length < msg->msnslp_header.total_size)
       */

    offset = msg->msnslp_header.offset;

    if (offset == 0) {
        peer_msg = pn_peer_msg_new(link);
        peer_msg->id = msg->msnslp_header.id;
        peer_msg->session_id = msg->msnslp_header.session_id;
        peer_msg->size = msg->msnslp_header.total_size;
        peer_msg->flags = msg->msnslp_header.flags;

        if (peer_msg->session_id) {
            if (!peer_msg->call)
                peer_msg->call = find_session_call(link, peer_msg->session_id);

            if (peer_msg->call) {
                if (peer_msg->flags == 0x20 ||
                    peer_msg->flags == 0x1000020 ||
                    peer_msg->flags == 0x1000030)
                {
                    PurpleXfer *xfer;

                    xfer = peer_msg->call->xfer;

                    if (xfer) {
                        purple_xfer_start(peer_msg->call->xfer, 0, NULL, 0);
                        peer_msg->fp = ((PurpleXfer *) peer_msg->call->xfer)->dest_fp;
                        xfer->dest_fp = NULL; /* Disable double fclose() */
                    }
                }
            }
        }

        if (!peer_msg->fp && peer_msg->size) {
            peer_msg->buffer = g_try_malloc(peer_msg->size);
            if (!peer_msg->buffer) {
                pn_error("failed to allocate buffer for peer_msg");
                return;
            }
        }
    }
    else
        peer_msg = find_message(link,
                                msg->msnslp_header.session_id,
                                msg->msnslp_header.id);

    if (!peer_msg) {
        /* Probably the transfer was canceled */
        pn_error("couldn't find peer_msg");
        return;
    }

    if (peer_msg->fp)
        len = fwrite(data, 1, len, peer_msg->fp);
    else if (peer_msg->size) {
        if (len > peer_msg->size || offset > (peer_msg->size - len)) {
            pn_error("oversized peer_msg");
            g_return_if_reached();
        }
        else
            memcpy(peer_msg->buffer + offset, data, len);
    }

    if ((peer_msg->flags == 0x20 || peer_msg->flags == 0x1000020 || peer_msg->flags == 0x1000030) &&
        peer_msg->call)
    {
        peer_msg->call->progress = TRUE;

        if (peer_msg->call->progress_cb)
            peer_msg->call->progress_cb(peer_msg->call, peer_msg->size,
                                        len, offset);
    }

#if 0
    if (peer_msg->buffer == NULL)
        return;
#endif

    if (msg->msnslp_header.offset + msg->msnslp_header.length
        >= msg->msnslp_header.total_size)
    {
        pn_peer_msg_ref(peer_msg);

        if (!peer_msg->call)
            peer_msg->swboard = user_data;

        if (peer_msg->call)
            pn_peer_call_ref(peer_msg->call);

        /* All the pieces of the peer_msg have been received */
        process_peer_msg(link, peer_msg);

        switch (peer_msg->flags) {
            case 0x0:
            case 0x20:
            case 0x1000000:
            case 0x1000020:
            case 0x1000030:
                /* Release all the messages and send the ACK */

                send_ack(link, msg);
                pn_peer_link_unleash(link);
                break;
#ifdef MSN_DIRECTCONN
            case 0x100:
                {
                    struct pn_direct_conn *direct_conn = link->direct_conn;

                    direct_conn->ack_recv = TRUE;

                    if (!direct_conn->ack_sent) {
                        pn_warning("bad ACK");
                        pn_direct_conn_send_handshake(direct_conn);
                    }
                    break;
                }
#endif /* MSN_DIRECTCONN */
            default:
                break;
        }

        if (peer_msg->call)
            pn_peer_call_unref(peer_msg->call);
        pn_peer_msg_unref(peer_msg);
    }
}

void
pn_peer_link_request_object(struct pn_peer_link *link,
                            const char *info,
                            MsnSlpCb cb,
                            MsnSlpEndCb end_cb,
                            const struct pn_msnobj *obj)
{
    struct pn_peer_call *call;
    char *msnobj_data;
    char *msnobj_base64;

    msnobj_data = pn_msnobj_to_string(obj);
    msnobj_base64 = purple_base64_encode((const guchar *)msnobj_data, strlen(msnobj_data));
    g_free(msnobj_data);

    call = pn_peer_call_new(link);

    call->data_info = g_strdup(info);
    call->cb = cb;
    call->end_cb = end_cb;

    pn_sip_send_invite(call, "A4268EEC-FEC5-49E5-95C3-F126696BDBF6", 1,
                       msnobj_base64);

    g_free(msnobj_base64);
}
