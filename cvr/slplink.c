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

#include "slplink.h"

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

static void send_msg_part(MsnSlpLink *slplink, MsnSlpMessage *slpmsg);

MsnSlpLink *
msn_slplink_new(MsnSession *session,
                const char *username)
{
    MsnSlpLink *slplink;

    slplink = g_new0(MsnSlpLink, 1);

#ifdef PECAN_DEBUG_SLPLINK
    pn_info("slplink_new: slplink(%p)", slplink);
#endif

    slplink->session = session;
    slplink->slp_seq_id = rand() % 0xFFFFFF00 + 4;
    slplink->slp_session_id = rand() % 0xFFFFFF00 + 4;

    slplink->local_user = g_strdup(msn_session_get_username(session));
    slplink->remote_user = g_strdup(username);

    slplink->slp_msg_queue = g_queue_new();

    session->slplinks = g_list_append(session->slplinks, slplink);

    return slplink;
}

void
msn_slplink_destroy(MsnSlpLink *slplink)
{
    MsnSession *session;

    if (!slplink)
        return;

#ifdef PECAN_DEBUG_SLPLINK
    pn_info("slplink_destroy: slplink(%p)", slplink);
#endif

    if (slplink->swboard)
        slplink->swboard->slplinks = g_list_remove(slplink->swboard->slplinks, slplink);

    session = slplink->session;

    g_free(slplink->local_user);
    g_free(slplink->remote_user);

#ifdef MSN_DIRECTCONN
    if (slplink->directconn)
        msn_directconn_destroy(slplink->directconn);
#endif /* MSN_DIRECTCONN */

    while (slplink->slp_calls)
        msn_slp_call_destroy(slplink->slp_calls->data);

    session->slplinks = g_list_remove(session->slplinks, slplink);

    g_free(slplink);
}

MsnSlpLink *
msn_session_find_slplink(MsnSession *session,
                         const char *who)
{
    GList *l;

    for (l = session->slplinks; l; l = l->next) {
        MsnSlpLink *slplink;

        slplink = l->data;

        if (strcmp(slplink->remote_user, who) == 0)
            return slplink;
    }

    return NULL;
}

MsnSlpLink *
msn_session_get_slplink(MsnSession *session,
                        const char *username)
{
    MsnSlpLink *slplink;

    slplink = msn_session_find_slplink(session, username);

    if (!slplink)
        slplink = msn_slplink_new(session, username);

    return slplink;
}

void
msn_slplink_add_slpcall(MsnSlpLink *slplink,
                        MsnSlpCall *slpcall)
{
    if (slplink->swboard)
        slplink->swboard->flag |= MSN_SB_FLAG_FT;

    slplink->slp_calls = g_list_append(slplink->slp_calls, slpcall);
}

void
msn_slplink_remove_slpcall(MsnSlpLink *slplink,
                           MsnSlpCall *slpcall)
{
    slplink->slp_calls = g_list_remove(slplink->slp_calls, slpcall);

    /* The slplink has no slpcalls in it. If no one is using it, we might
     * destroy the switchboard, but we should be careful not to use the slplink
     * again. */
    if (slplink->slp_calls)
        return;

    if (slplink->swboard) {
        if (msn_switchboard_release(slplink->swboard, MSN_SB_FLAG_FT)) {
            msn_switchboard_unref(slplink->swboard);
            /* I'm not sure this is the best thing to do, but it's better
             * than nothing. */
            slpcall->slplink = NULL;
        }
    }
}

MsnSlpCall *
msn_slplink_find_slp_call(MsnSlpLink *slplink,
                          const char *id)
{
    GList *l;
    MsnSlpCall *slpcall;

    if (!id)
        return NULL;

    for (l = slplink->slp_calls; l; l = l->next) {
        slpcall = l->data;

        if (slpcall->id && strcmp(slpcall->id, id) == 0)
            return slpcall;
    }

    return NULL;
}

MsnSlpCall *
msn_slplink_find_slp_call_with_session_id(MsnSlpLink *slplink,
                                          long id)
{
    GList *l;
    MsnSlpCall *slpcall;

    for (l = slplink->slp_calls; l; l = l->next) {
        slpcall = l->data;

        if (slpcall->session_id == id)
            return slpcall;
    }

    return NULL;
}

void
msn_slplink_send_msg(MsnSlpLink *slplink,
                     MsnMessage *msg)
{
    if (!slplink->swboard) {
        slplink->swboard = msn_session_get_swboard(slplink->session,
                                                   slplink->remote_user, MSN_SB_FLAG_FT);

        msn_switchboard_ref(slplink->swboard);

        if (!slplink->swboard)
            return;

        /* If swboard is destroyed we will be too */
        slplink->swboard->slplinks = g_list_prepend(slplink->swboard->slplinks, slplink);
    }

    msn_switchboard_send_msg(slplink->swboard, msg, TRUE);
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
        send_msg_part(slpmsg->slplink, slpmsg);
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

    send_msg_part(slpmsg->slplink, slpmsg);

    slpmsg->msgs = g_list_remove(slpmsg->msgs, msg);
}

static void
send_msg_part(MsnSlpLink *slplink,
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
    if (slplink->directconn &&
        (slpmsg->flags == 0x100 || slplink->directconn->ack_recv))
        msn_directconn_send_msg(slplink->directconn, msg);
    else
        msn_slplink_send_msg(slplink, msg);
#else
    msn_slplink_send_msg(slplink, msg);
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

void
msn_slplink_release_slpmsg(MsnSlpLink *slplink,
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

    msn_message_set_attr(msg, "P2P-Dest", slplink->remote_user);

    msg->ack_cb = msg_ack;
    msg->nak_cb = msg_nak;
    msg->ack_data = slpmsg;

    send_msg_part(slplink, slpmsg);

    msn_message_destroy(msg);
}

void
msn_slplink_queue_slpmsg(MsnSlpLink *slplink,
                         MsnSlpMessage *slpmsg)
{
    slpmsg->id = slplink->slp_seq_id++;

    g_queue_push_head(slplink->slp_msg_queue, slpmsg);
}

void
msn_slplink_send_slpmsg(MsnSlpLink *slplink,
                        MsnSlpMessage *slpmsg)
{
    slpmsg->id = slplink->slp_seq_id++;

    msn_slplink_release_slpmsg(slplink, slpmsg);
}

void
msn_slplink_unleash(MsnSlpLink *slplink)
{
    MsnSlpMessage *slpmsg;

    /* Send the queued msgs in the order they came. */

    while ((slpmsg = g_queue_pop_tail(slplink->slp_msg_queue)))
        msn_slplink_release_slpmsg(slplink, slpmsg);
}

void
msn_slplink_send_ack(MsnSlpLink *slplink,
                     MsnMessage *msg)
{
    MsnSlpMessage *slpmsg;

    slpmsg = msn_slpmsg_new(slplink);

    slpmsg->session_id = msg->msnslp_header.session_id;
    slpmsg->size = msg->msnslp_header.total_size;
    slpmsg->flags = 0x02;
    slpmsg->ack_id = msg->msnslp_header.id;
    slpmsg->ack_sub_id = msg->msnslp_header.ack_id;
    slpmsg->ack_size = msg->msnslp_header.total_size;

#ifdef PECAN_DEBUG_SLP
    slpmsg->info = "SLP ACK";
#endif

    msn_slplink_send_slpmsg(slplink, slpmsg);
}

void
msn_slplink_process_msg(MsnSlpLink *slplink,
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
        slpmsg = msn_slpmsg_new(slplink);
        slpmsg->id = msg->msnslp_header.id;
        slpmsg->session_id = msg->msnslp_header.session_id;
        slpmsg->size = msg->msnslp_header.total_size;
        slpmsg->flags = msg->msnslp_header.flags;

        if (slpmsg->session_id) {
            if (!slpmsg->slpcall)
                slpmsg->slpcall = msn_slplink_find_slp_call_with_session_id(slplink, slpmsg->session_id);

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
        slpmsg = msn_slplink_message_find(slplink,
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

        slpcall = msn_slp_process_msg(slplink, slpmsg);

        switch (slpmsg->flags) {
            case 0x0:
            case 0x20:
            case 0x1000000:
            case 0x1000020:
            case 0x1000030:
                /* Release all the messages and send the ACK */

                msn_slplink_send_ack(slplink, msg);
                msn_slplink_unleash(slplink);
                break;
#ifdef MSN_DIRECTCONN
            case 0x100:
                {
                    MsnDirectConn *directconn = slplink->directconn;

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

MsnSlpMessage *
msn_slplink_message_find(MsnSlpLink *slplink,
                         long session_id,
                         long id)
{
    GList *e;

    for (e = slplink->slp_msgs; e; e = e->next) {
        MsnSlpMessage *slpmsg = e->data;

        if ((slpmsg->session_id == session_id) && (slpmsg->id == id))
            return slpmsg;
    }

    return NULL;
}

void
msn_slplink_request_object(MsnSlpLink *slplink,
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

    slpcall = msn_slp_call_new(slplink);
    msn_slp_call_init(slpcall, MSN_SLPCALL_ANY);

    slpcall->data_info = g_strdup(info);
    slpcall->cb = cb;
    slpcall->end_cb = end_cb;

    msn_slp_call_invite(slpcall, "A4268EEC-FEC5-49E5-95C3-F126696BDBF6", 1,
                        msnobj_base64);

    g_free(msnobj_base64);
}
