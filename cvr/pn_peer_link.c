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
#include "slpcall.h"
#include "slpmsg.h"
#include "slp.h"
#include "pn_log.h"

#include "xfer.h"

#include "ab/pn_contact.h"

#include "session_private.h"

#ifdef MSN_DIRECTCONN
#include "directconn.h"
#endif /* MSN_DIRECTCONN */

#include "cmd/msg_private.h"

#include <glib/gstdio.h>
#include <string.h>

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <ft.h>

static void send_msg_part(PnPeerLink *link, MsnSlpMessage *slpmsg);

PnPeerLink *
pn_peer_link_new(MsnSession *session,
                 const char *username)
{
    PnPeerLink *link;

    link = g_new0(PnPeerLink, 1);

#ifdef PECAN_DEBUG_SLPLINK
    pn_info("link=%p", link);
#endif

    link->session = session;
    link->slp_seq_id = rand() % 0xFFFFFF00 + 4;
    link->slp_session_id = rand() % 0xFFFFFF00 + 4;

    link->local_user = g_strdup(msn_session_get_username(session));
    link->remote_user = g_strdup(username);

    link->slp_msg_queue = g_queue_new();

    session->links = g_list_append(session->links, link);

    link ->ref_count++;

    return link;
}

void
pn_peer_link_destroy(PnPeerLink *link)
{
    MsnSession *session;

    if (!link)
        return;

#ifdef PECAN_DEBUG_SLPLINK
    pn_info("link=%p", link);
#endif

    session = link->session;
    session->links = g_list_remove(session->links, link);

    if (link->swboard)
        link->swboard->links = g_list_remove(link->swboard->links, link);

    while (link->slp_calls)
        msn_slp_call_destroy(link->slp_calls->data);

#ifdef MSN_DIRECTCONN
    if (link->directconn)
        msn_directconn_destroy(link->directconn);
#endif /* MSN_DIRECTCONN */

    g_free(link->local_user);
    g_free(link->remote_user);

    g_free(link);
}

PnPeerLink *
pn_peer_link_ref(PnPeerLink *link)
{
    link->ref_count++;

    return link;
}

PnPeerLink *
pn_peer_link_unref(PnPeerLink *link)
{
    link->ref_count--;

    if (link->ref_count == 0) {
        pn_peer_link_destroy (link);
        return NULL;
    }

    return link;
}

PnPeerLink *
msn_session_find_peer_link(MsnSession *session,
                           const char *who)
{
    GList *l;

    for (l = session->links; l; l = l->next) {
        PnPeerLink *link;

        link = l->data;

        if (strcmp(link->remote_user, who) == 0)
            return link;
    }

    return NULL;
}

PnPeerLink *
msn_session_get_peer_link(MsnSession *session,
                          const char *username)
{
    PnPeerLink *link;

    link = msn_session_find_peer_link(session, username);

    if (!link)
        link = pn_peer_link_new(session, username);
    else
        pn_peer_link_ref(link);

    return link;
}

void
pn_peer_link_add_slpcall(PnPeerLink *link,
                         MsnSlpCall *slpcall)
{
    link->slp_calls = g_list_append(link->slp_calls, slpcall);
}

void
pn_peer_link_remove_slpcall(PnPeerLink *link,
                            MsnSlpCall *slpcall)
{
    link->slp_calls = g_list_remove(link->slp_calls, slpcall);
}

MsnSlpCall *
pn_peer_link_find_slp_call(PnPeerLink *link,
                           const char *id)
{
    GList *l;
    MsnSlpCall *slpcall;

    if (!id)
        return NULL;

    for (l = link->slp_calls; l; l = l->next) {
        slpcall = l->data;

        if (slpcall->id && strcmp(slpcall->id, id) == 0)
            return slpcall;
    }

    return NULL;
}

static inline MsnSlpCall *
find_session_slpcall(PnPeerLink *link,
                     long id)
{
    GList *l;
    MsnSlpCall *slpcall;

    for (l = link->slp_calls; l; l = l->next) {
        slpcall = l->data;

        if (slpcall->session_id == id)
            return slpcall;
    }

    return NULL;
}

static inline void
send_msg(PnPeerLink *link,
         MsnMessage *msg)
{
    if (!link->swboard) {
        MsnSwitchBoard *swboard;
        swboard = msn_session_get_swboard(link->session, link->remote_user);

        if (!swboard)
            return;

        pn_peer_link_ref(link);

        /* If swboard is destroyed we will be too */
        swboard->links = g_list_prepend(swboard->links, link);

        link->swboard = swboard;
    }

    msn_switchboard_send_msg(link->swboard, msg, TRUE);
}

/* We have received the message ack */
static void
msg_ack(MsnMessage *msg,
        void *data)
{
    MsnSlpMessage *slpmsg;
    guint64 real_size;

    slpmsg = data;

    real_size = (slpmsg->flags == 0x2) ? 0 : slpmsg->size;

    slpmsg->offset += msg->msnslp_header.length;

    if (slpmsg->offset < real_size)
        send_msg_part(slpmsg->link, slpmsg);
    else {
        /* The whole message has been sent */
        if (slpmsg->flags == 0x20 ||
            slpmsg->flags == 0x1000020 ||
            slpmsg->flags == 0x1000030)
        {
            if (slpmsg->slpcall && slpmsg->slpcall->cb)
                    slpmsg->slpcall->cb(slpmsg->slpcall, NULL, 0);
        }
    }

    slpmsg->msgs = g_list_remove(slpmsg->msgs, msg);
}

/* We have received the message nak. */
static void
msg_nak(MsnMessage *msg, void *data)
{
    MsnSlpMessage *slpmsg;

    slpmsg = data;

    send_msg_part(slpmsg->link, slpmsg);

    slpmsg->msgs = g_list_remove(slpmsg->msgs, msg);
}

static void
send_msg_part(PnPeerLink *link,
              MsnSlpMessage *slpmsg)
{
    MsnMessage *msg;
    guint64 real_size;
    size_t len = 0;

    /** @todo maybe we will want to create a new msg for this slpmsg instead of
     * reusing the same one all the time. */
    msg = slpmsg->msg;

    real_size = (slpmsg->flags == 0x2) ? 0 : slpmsg->size;

    if (slpmsg->offset < real_size) {
        if (slpmsg->fp) {
            char data[1202];
            len = fread(data, 1, sizeof(data), slpmsg->fp);
            msn_message_set_bin_data(msg, data, len);
        }
        else {
            len = slpmsg->size - slpmsg->offset;

            if (len > 1202)
                len = 1202;

            msn_message_set_bin_data(msg, slpmsg->buffer + slpmsg->offset, len);
        }

        msg->msnslp_header.offset = slpmsg->offset;
        msg->msnslp_header.length = len;
    }

#ifdef PECAN_DEBUG_SLP
    msn_message_show_readable(msg, slpmsg->info, slpmsg->text_body);
#endif

    slpmsg->msgs = g_list_append(slpmsg->msgs, msg);

#ifdef MSN_DIRECTCONN
    /* The hand-shake message has 0x100 flags. */
    if (link->directconn &&
        (slpmsg->flags == 0x100 || link->directconn->ack_recv))
        msn_directconn_send_msg(link->directconn, msg);
    else
        send_msg(link, msg);
#else
    send_msg(link, msg);
#endif /* MSN_DIRECTCONN */

    if (slpmsg->slpcall) {
        if (slpmsg->flags == 0x20 ||
            slpmsg->flags == 0x1000020 ||
            slpmsg->flags == 0x1000030)
        {
            slpmsg->slpcall->progress = TRUE;

            if (slpmsg->slpcall->progress_cb)
                slpmsg->slpcall->progress_cb(slpmsg->slpcall, slpmsg->size,
                                             len, slpmsg->offset);
        }
    }

    /* slpmsg->offset += len; */
}

static void
release_slpmsg(PnPeerLink *link,
               MsnSlpMessage *slpmsg)
{
    MsnMessage *msg;

    slpmsg->msg = msg = msn_message_new_msnslp();

    switch (slpmsg->flags) {
        case 0x0:
            msg->msnslp_header.session_id = slpmsg->session_id;
            msg->msnslp_header.ack_id = rand() % 0xFFFFFF00;
            break;
        case 0x2:
            msg->msnslp_header.session_id = slpmsg->session_id;
            msg->msnslp_header.ack_id = slpmsg->ack_id;
            msg->msnslp_header.ack_size = slpmsg->ack_size;
            msg->msnslp_header.ack_sub_id = slpmsg->ack_sub_id;
            break;
        case 0x20:
        case 0x1000020:
        case 0x1000030:
            {
                MsnSlpCall *slpcall = slpmsg->slpcall;

                if (slpcall) {
                    msg->msnslp_header.session_id = slpcall->session_id;
                    msg->msnslp_footer.value = slpcall->app_id;
                }
                msg->msnslp_header.ack_id = rand() % 0xFFFFFF00;
                break;
            }
        case 0x100:
            msg->msnslp_header.ack_id = slpmsg->ack_id;
            msg->msnslp_header.ack_sub_id = slpmsg->ack_sub_id;
            msg->msnslp_header.ack_size = slpmsg->ack_size;
            break;
        default:
            break;
    }

    msg->msnslp_header.id = slpmsg->id;
    msg->msnslp_header.flags = slpmsg->flags;

    msg->msnslp_header.total_size = slpmsg->size;

    msn_message_set_attr(msg, "P2P-Dest", link->remote_user);

    msg->ack_cb = msg_ack;
    msg->nak_cb = msg_nak;
    msg->ack_data = slpmsg;

    send_msg_part(link, slpmsg);

    msn_message_destroy(msg);
}

void
pn_peer_link_queue_slpmsg(PnPeerLink *link,
                          MsnSlpMessage *slpmsg)
{
    slpmsg->id = link->slp_seq_id++;

    g_queue_push_head(link->slp_msg_queue, slpmsg);
}

void
pn_peer_link_send_slpmsg(PnPeerLink *link,
                         MsnSlpMessage *slpmsg)
{
    slpmsg->id = link->slp_seq_id++;

    release_slpmsg(link, slpmsg);
}

void
pn_peer_link_unleash(PnPeerLink *link)
{
    MsnSlpMessage *slpmsg;

    /* Send the queued msgs in the order they came. */

    pn_peer_link_ref(link);

    while ((slpmsg = g_queue_pop_tail(link->slp_msg_queue)))
        release_slpmsg(link, slpmsg);

    pn_peer_link_unref(link);
}

static inline void
send_ack(PnPeerLink *link,
         MsnMessage *msg)
{
    MsnSlpMessage *slpmsg;

    slpmsg = msn_slpmsg_new(link);

    slpmsg->session_id = msg->msnslp_header.session_id;
    slpmsg->size = msg->msnslp_header.total_size;
    slpmsg->flags = 0x02;
    slpmsg->ack_id = msg->msnslp_header.id;
    slpmsg->ack_sub_id = msg->msnslp_header.ack_id;
    slpmsg->ack_size = msg->msnslp_header.total_size;

#ifdef PECAN_DEBUG_SLP
    slpmsg->info = "SLP ACK";
#endif

    pn_peer_link_send_slpmsg(link, slpmsg);
}


static MsnSlpCall *
process_slpmsg(PnPeerLink *link,
               MsnSlpMessage *slpmsg)
{
    MsnSlpCall *slpcall;
    gpointer body;
    gsize body_len;

    slpcall = NULL;
    body = slpmsg->buffer;
    body_len = slpmsg->size;

    switch (slpmsg->flags) {
        case 0x0:
        case 0x1000000:
            {
                char *body_str;

                /* Handwritten messages are just dumped down the line with no MSNObject */
                if (slpmsg->session_id == 64) {
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
                    msgid = g_strdup_printf("{handwritten:%ld}", slpmsg->id);
                    msn_handwritten_msg_show(slpmsg->link->swboard, msgid, body_str + 7, link->remote_user);
                    g_free(msgid);
                }
                else {
                    body_str = g_strndup(body, body_len);
                    slpcall = msn_slp_sip_recv(link, body_str);
                }
                g_free(body_str);
                break;
            }
        case 0x20:
        case 0x1000020:
        case 0x1000030:
            slpcall = find_session_slpcall(link,
                                           slpmsg->session_id);

            if (!slpcall)
                break;

            if (slpcall->timer)
                purple_timeout_remove(slpcall->timer);

            /* clear the error cb, otherwise it will be called when
             * the slpcall is destroyed. */
            slpcall->end_cb = NULL;

            slpcall->cb(slpcall, body, body_len);

            slpcall->wasted = TRUE;
            break;
#ifdef MSN_DIRECTCONN
        case 0x100:
            slpcall = link->directconn->initial_call;

            if (slpcall)
                msn_slp_call_session_init(slpcall);
            break;
#endif /* MSN_DIRECTCONN */
        default:
            pn_warning("slp_process_msg: unprocessed SLP message with flags 0x%08lx",
                       slpmsg->flags);
    }

    return slpcall;
}

static inline MsnSlpMessage *
find_message(PnPeerLink *link,
             long session_id,
             long id)
{
    GList *e;

    for (e = link->slp_msgs; e; e = e->next) {
        MsnSlpMessage *slpmsg = e->data;

        if ((slpmsg->session_id == session_id) && (slpmsg->id == id))
            return slpmsg;
    }

    return NULL;
}

void
pn_peer_link_process_msg(PnPeerLink *link,
                         MsnMessage *msg)
{
    MsnSlpMessage *slpmsg;
    const char *data;
    guint64 offset;
    gsize len;

#ifdef PECAN_DEBUG_SLP
    msn_slpmsg_show(msg);
#endif

    if (msg->msnslp_header.total_size < msg->msnslp_header.length) {
        pn_error("This can't be good");
        g_return_if_reached();
    }

    slpmsg = NULL;
    data = msn_message_get_bin_data(msg, &len);

    /*
       OVERHEAD!
       if (msg->msnslp_header.length < msg->msnslp_header.total_size)
       */

    offset = msg->msnslp_header.offset;

    if (offset == 0) {
        slpmsg = msn_slpmsg_new(link);
        slpmsg->id = msg->msnslp_header.id;
        slpmsg->session_id = msg->msnslp_header.session_id;
        slpmsg->size = msg->msnslp_header.total_size;
        slpmsg->flags = msg->msnslp_header.flags;

        if (slpmsg->session_id) {
            if (!slpmsg->slpcall)
                slpmsg->slpcall = find_session_slpcall(link, slpmsg->session_id);

            if (slpmsg->slpcall) {
                if (slpmsg->flags == 0x20 ||
                    slpmsg->flags == 0x1000020 ||
                    slpmsg->flags == 0x1000030)
                {
                    PurpleXfer *xfer;

                    xfer = slpmsg->slpcall->xfer;

                    if (xfer) {
                        purple_xfer_start(slpmsg->slpcall->xfer, 0, NULL, 0);
                        slpmsg->fp = ((PurpleXfer *) slpmsg->slpcall->xfer)->dest_fp;
                        xfer->dest_fp = NULL; /* Disable double fclose() */
                    }
                }
            }
        }

        if (!slpmsg->fp && slpmsg->size) {
            slpmsg->buffer = g_try_malloc(slpmsg->size);
            if (!slpmsg->buffer) {
                pn_error("failed to allocate buffer for slpmsg");
                return;
            }
        }
    }
    else
        slpmsg = find_message(link,
                              msg->msnslp_header.session_id,
                              msg->msnslp_header.id);

    if (!slpmsg) {
        /* Probably the transfer was canceled */
        pn_error("couldn't find slpmsg");
        return;
    }

    if (slpmsg->fp)
        len = fwrite(data, 1, len, slpmsg->fp);
    else if (slpmsg->size) {
        if (len > slpmsg->size || offset > (slpmsg->size - len)) {
            pn_error("oversized slpmsg");
            g_return_if_reached();
        }
        else
            memcpy(slpmsg->buffer + offset, data, len);
    }

    if ((slpmsg->flags == 0x20 || slpmsg->flags == 0x1000020 || slpmsg->flags == 0x1000030) &&
        (slpmsg->slpcall != NULL))
    {
        slpmsg->slpcall->progress = TRUE;

        if (slpmsg->slpcall->progress_cb)
            slpmsg->slpcall->progress_cb(slpmsg->slpcall, slpmsg->size,
                                         len, offset);
    }

#if 0
    if (slpmsg->buffer == NULL)
        return;
#endif

    if (msg->msnslp_header.offset + msg->msnslp_header.length
        >= msg->msnslp_header.total_size)
    {
        /* All the pieces of the slpmsg have been received */
        MsnSlpCall *slpcall = NULL;

        slpcall = process_slpmsg(link, slpmsg);

        switch (slpmsg->flags) {
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
                    MsnDirectConn *directconn = link->directconn;

                    directconn->ack_recv = TRUE;

                    if (!directconn->ack_sent) {
                        pn_warning("bad ACK");
                        msn_directconn_send_handshake(directconn);
                    }
                    break;
                }
#endif /* MSN_DIRECTCONN */
            default:
                break;
        }

        msn_slpmsg_destroy(slpmsg);

        if (slpcall && slpcall->wasted)
            msn_slp_call_destroy(slpcall);
    }
}

void
pn_peer_link_request_object(PnPeerLink *link,
                            const char *info,
                            MsnSlpCb cb,
                            MsnSlpEndCb end_cb,
                            const PnMsnObj *obj)
{
    MsnSlpCall *slpcall;
    char *msnobj_data;
    char *msnobj_base64;

    msnobj_data = pn_msnobj_to_string(obj);
    msnobj_base64 = purple_base64_encode((const guchar *)msnobj_data, strlen(msnobj_data));
    g_free(msnobj_data);

    slpcall = msn_slp_call_new(link);
    msn_slp_call_init(slpcall, MSN_SLPCALL_ANY);

    slpcall->data_info = g_strdup(info);
    slpcall->cb = cb;
    slpcall->end_cb = end_cb;

    msn_slp_call_invite(slpcall, "A4268EEC-FEC5-49E5-95C3-F126696BDBF6", 1,
                        msnobj_base64);

    g_free(msnobj_base64);
}
