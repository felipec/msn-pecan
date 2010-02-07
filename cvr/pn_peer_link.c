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

static void
send_msg_part(struct pn_peer_link *link,
              struct pn_peer_msg *peer_msg,
              MsnMessage *msg);

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

static void
remove_lingering(struct pn_peer_link *link)
{
    GList *l;

    /* remove extra calls */
    for (l = link->slp_calls; l; ) {
        struct pn_peer_call *call = l->data;
        l = l->next;

        pn_info("remove lingering call: %p", call);
        pn_peer_call_unref(call);
    }
    g_list_free(link->slp_calls);

    /* remove extra slp_msgs */
    for (l = link->slp_msgs; l; ) {
        struct pn_peer_msg *peer_msg = l->data;
        l = l->next;

        pn_info("removing lingering slpmsg: %p", peer_msg);
        pn_peer_msg_unref(peer_msg);
    }
    g_list_free(link->slp_msgs);
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

    remove_lingering(link);

#ifdef MSN_DIRECTCONN
    if (link->direct_conn)
        pn_direct_conn_destroy(link->direct_conn);
#endif /* MSN_DIRECTCONN */

    g_queue_free(link->slp_msg_queue);

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
    if (!link->direct_conn) {
        MsnSwitchBoard *swboard;

        swboard = msn_session_get_swboard(link->session, link->remote_user);

        if (!swboard) {
            pn_error("couldn't get swboard");
            return;
        }

        swboard->calls = g_list_prepend(swboard->calls, call);

        call->swboard = swboard;
    }

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

        if (peer_msg->call == call) {
            peer_msg->link = NULL;
            link->slp_msgs = g_list_remove(link->slp_msgs, peer_msg);
            pn_peer_msg_unref(peer_msg);
        }
    }
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
         struct pn_peer_msg *peer_msg,
         MsnMessage *msg)
{
    MsnSwitchBoard *swboard;
    if (peer_msg->call)
        swboard = peer_msg->call->swboard;
    else
        swboard = peer_msg->swboard;
    msn_switchboard_send_msg(swboard, msg, TRUE);
}

/* We have received the message ack */
static void
msg_ack(MsnMessage *msg,
        void *data)
{
    struct pn_peer_msg *peer_msg;
    guint64 real_size;

    peer_msg = data;

    if (!peer_msg->link) {
        pn_warning("msg with no link?");
        goto leave;
    }

    real_size = (peer_msg->flags == 0x2) ? 0 : peer_msg->size;

    peer_msg->offset += msg->msnslp_header.length;

    if (peer_msg->offset < real_size)
        send_msg_part(peer_msg->link, peer_msg, msg);
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

leave:
    pn_peer_msg_unref(peer_msg);
}

/* We have received the message nak. */
static void
msg_nak(MsnMessage *msg,
        void *data)
{
    struct pn_peer_msg *peer_msg;

    peer_msg = data;

    pn_peer_msg_unref(peer_msg);
}

static void
send_msg_part(struct pn_peer_link *link,
              struct pn_peer_msg *peer_msg,
              MsnMessage *msg)
{
    guint64 real_size;
    size_t len = 0;

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

    pn_peer_msg_ref(peer_msg);

#ifdef MSN_DIRECTCONN
    /* The hand-shake message has 0x100 flags. */
    if (link->direct_conn &&
        (peer_msg->flags == 0x100 || link->direct_conn->ack_recv))
        pn_direct_conn_send_msg(link->direct_conn, msg);
    else
        send_msg(link, peer_msg, msg);
#else
    send_msg(link, peer_msg, msg);
#endif /* MSN_DIRECTCONN */

    if (peer_msg->call) {
        if (peer_msg->flags == 0x20 ||
            peer_msg->flags == 0x1000020 ||
            peer_msg->flags == 0x1000030)
        {
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

    peer_msg->link = link;

    msg = msn_message_new_msnslp();

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

    send_msg_part(link, peer_msg, msg);

    msn_message_unref(msg);
    pn_peer_msg_unref(peer_msg);
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
         struct pn_peer_msg *peer_msg)
{
    struct pn_peer_msg *ack_msg;

    ack_msg = pn_peer_msg_new();

    ack_msg->session_id = peer_msg->session_id;
    ack_msg->size = peer_msg->size;
    ack_msg->flags = 0x02;
    ack_msg->ack_id = peer_msg->id;
    ack_msg->ack_sub_id = peer_msg->ack_id;
    ack_msg->ack_size = peer_msg->size;

    ack_msg->call = peer_msg->call;
    ack_msg->swboard = peer_msg->swboard;

#ifdef PECAN_DEBUG_SLP
    ack_msg->info = "SLP ACK";
#endif

    pn_peer_link_send_msg(link, ack_msg);
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

                if (peer_msg->session_id == 64)
                {
                    /* This is for handwritten messages (ink) */
                    GError *error;
                    glong items_read, items_written;

                    body_str = g_utf16_to_utf8 ((gunichar2 *) body, body_len / 2, &items_read, &items_written, &error);
                    body_len -= items_read * 2 + 2;
                    body += items_read * 2 + 2;

                    if (body_str == NULL || body_len <= 0 || strstr (body_str, "image/gif") == NULL)
                    {
                        if (error != NULL)
                            pn_error ("ink receiving: unable to convert ink header from UTF-16 to UTF-8: %s", error->message);
                        else
                            pn_error ("ink receiving: unknown format\n");

                        g_free(body_str);

                        return;
                    }

                    g_free(body_str);

                    body_str = g_utf16_to_utf8 ((gunichar2 *) body, body_len / 2, &items_read, &items_written, &error);

                    if (!body_str)
                    {
                        pn_error ("ink receiving: unable to convert ink body from UTF-16 to UTF-8: %s", error->message);

                        return;
                    }

                    switchboard_show_ink (peer_msg->call->swboard, link->remote_user, body_str);
                }
                else
                {
                    body_str = g_strndup ((const char *) body, body_len);
                    if (!pn_sip_recv (link, body_str)) {
                        pn_warning("'%s' sent a bogus message: [%s]:%li",
                                   pn_peer_link_get_passport(link), body_str, peer_msg->flags);
                    }
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

            /* clear the error cb, otherwise it will be called when
             * the call is destroyed. */
            call->end_cb = NULL;

            call->cb(call, body, body_len);

            pn_peer_call_unref(call);
            break;
        default:
            pn_info("slp_process_msg: unprocessed SLP message with flags 0x%08lx",
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
        peer_msg = pn_peer_msg_new();
        peer_msg->id = msg->msnslp_header.id;
        peer_msg->session_id = msg->msnslp_header.session_id;
        peer_msg->ack_id = msg->msnslp_header.ack_id;
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
                if (peer_msg->call)
                    pn_peer_call_unref(peer_msg->call);
                pn_peer_msg_free(peer_msg);
                return;
            }
        }

        peer_msg->link = link;
        link->slp_msgs = g_list_append(link->slp_msgs, peer_msg);
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
    else if (peer_msg->size && peer_msg->buffer) {
        if (len > peer_msg->size || offset > (peer_msg->size - len)) {
            pn_warning("oversized peer_msg: %zu", len);
            link->slp_msgs = g_list_remove(link->slp_msgs, peer_msg);
            pn_peer_msg_unref(peer_msg);
            return;
        }
        else
            memcpy(peer_msg->buffer + offset, data, len);
    }

    if ((peer_msg->flags == 0x20 || peer_msg->flags == 0x1000020 || peer_msg->flags == 0x1000030) &&
        peer_msg->call)
    {
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
        struct pn_peer_call *call = peer_msg->call;

        if (!call)
            peer_msg->swboard = user_data;

        if (call)
            pn_peer_call_ref(call);

        /* All the pieces of the peer_msg have been received */
        process_peer_msg(link, peer_msg);

        switch (peer_msg->flags) {
            case 0x0:
            case 0x20:
            case 0x1000000:
            case 0x1000020:
            case 0x1000030:
                /* Release all the messages and send the ACK */

                send_ack(link, peer_msg);
                pn_peer_link_unleash(link);
                break;
            default:
                break;
        }

        link->slp_msgs = g_list_remove(link->slp_msgs, peer_msg);
        pn_peer_msg_unref(peer_msg);

        if (call)
            pn_peer_call_unref(call);
    }
    else if (peer_msg->flags == 0x2) {
        /* this is an ACK, lets just get rid of it */
        link->slp_msgs = g_list_remove(link->slp_msgs, peer_msg);
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

struct pn_direct_conn *
pn_peer_link_get_directconn(const struct pn_peer_link *link)
{
    return link->direct_conn;
}

void
pn_peer_link_set_directconn(struct pn_peer_link *link,
                            struct pn_direct_conn *direct_conn)
{
    link->direct_conn = direct_conn;
}
