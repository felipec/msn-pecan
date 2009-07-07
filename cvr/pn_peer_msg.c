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

#include "pn_peer_msg.h"
#include "pn_peer_link.h"
#include "pn_peer_link_priv.h"

#include "pn_peer_call.h"
#include "session.h"

#include "cmd/msg_private.h"

#include <glib/gstdio.h>
#include <string.h>

/* libpurple stuff. */
#include "fix_purple.h"

PnPeerMsg *
pn_peer_msg_new(PnPeerLink *link)
{
    PnPeerMsg *peer_msg;

    peer_msg = g_new0(PnPeerMsg, 1);

#ifdef PECAN_DEBUG_SLPMSG
    pn_info("peer_msg=%p", peer_msg);
#endif

    peer_msg->link = link;

    link->slp_msgs = g_list_append(link->slp_msgs, peer_msg);

    peer_msg->ref_count++;

    return peer_msg;
}

void
pn_peer_msg_free(PnPeerMsg *peer_msg)
{
    PnPeerLink *link;
    GList *cur;

    if (!peer_msg)
        return;

#ifdef PECAN_DEBUG_SLPMSG
    pn_info("peer_msg=%p", peer_msg);
#endif

    link = peer_msg->link;

    if (peer_msg->fp)
        fclose(peer_msg->fp);

    g_free(peer_msg->buffer);

    for (cur = peer_msg->msgs; cur; cur = cur->next) {
        /* Something is pointing to this peer_msg, so we should remove that
         * pointer to prevent a crash. */
        /* Ex: a user goes offline and after that we receive an ACK */

        MsnMessage *msg = cur->data;

#ifdef PECAN_DEBUG_SLPMSG
        pn_info("Unlink peer_msg callbacks.\n");
#endif

        msg->ack_cb = NULL;
        msg->nak_cb = NULL;
        msg->ack_data = NULL;
    }

    link->slp_msgs = g_list_remove(link->slp_msgs, peer_msg);

    g_free(peer_msg);
}

PnPeerMsg *
pn_peer_msg_ref(PnPeerMsg *peer_msg)
{
    peer_msg->ref_count++;

    return peer_msg;
}

PnPeerMsg *
pn_peer_msg_unref(PnPeerMsg *peer_msg)
{
    peer_msg->ref_count--;

    if (peer_msg->ref_count == 0) {
        pn_peer_msg_free(peer_msg);
        return NULL;
    }

    return peer_msg;
}

void
pn_peer_msg_set_body(PnPeerMsg *peer_msg,
                     gconstpointer *body,
                     guint64 size)
{
    if (body)
        peer_msg->buffer = g_memdup(body, size);
    else
        peer_msg->buffer = g_malloc0(size);

    peer_msg->size = size;
}

void
pn_peer_msg_set_image(PnPeerMsg *peer_msg,
                      PnBuffer *image)
{
    peer_msg->size = image->len;
    peer_msg->buffer = g_memdup(image->data, peer_msg->size);
}

void
pn_peer_msg_open_file(PnPeerMsg *peer_msg,
                      const char *file_name)
{
    struct stat st;

    peer_msg->fp = g_fopen(file_name, "rb");

    if (g_stat(file_name, &st) == 0)
        peer_msg->size = st.st_size;
}

#ifdef PECAN_DEBUG_SLP
void
pn_peer_msg_show(MsnMessage *msg)
{
    const char *info;
    gboolean text;

    text = FALSE;

    switch (msg->msnslp_header.flags) {
        case 0x0:
            info = "SLP CONTROL";
            text = TRUE;
            break;
        case 0x2:
            info = "SLP ACK"; break;
        case 0x20:
        case 0x1000030:
            info = "SLP DATA"; break;
        case 0x100:
            info = "SLP DC"; break;
        default:
            info = "SLP UNKNOWN"; break;
    }

    msn_message_show_readable(msg, info, text);
}
#endif

PnPeerMsg *
pn_peer_msg_sip_new(PnPeerCall *call,
                    int cseq,
                    const char *header,
                    const char *branch,
                    const char *content_type,
                    const char *content)
{
    PnPeerLink *link;
    PnPeerMsg *peer_msg;
    gchar *body;
    gsize body_len;
    gsize content_len;

    link = call->link;

    /* Let's remember that "content" should end with a 0x00 */

    content_len = content ? strlen(content) + 1 : 0;

    body = g_strdup_printf("%s\r\n"
                           "To: <msnmsgr:%s>\r\n"
                           "From: <msnmsgr:%s>\r\n"
                           "Via: MSNSLP/1.0/TLP ;branch={%s}\r\n"
                           "CSeq: %d\r\n"
                           "Call-ID: {%s}\r\n"
                           "Max-Forwards: 0\r\n"
                           "Content-Type: %s\r\n"
                           "Content-Length: %" G_GSIZE_FORMAT "\r\n"
                           "\r\n",
                           header,
                           link->remote_user,
                           link->local_user,
                           branch,
                           cseq,
                           call->id,
                           content_type,
                           content_len);

    body_len = strlen(body);

    if (content_len > 0) {
        body_len += content_len;
        body = g_realloc(body, body_len);
        g_strlcat(body, content, body_len);
    }

    peer_msg = pn_peer_msg_new(link);
    pn_peer_msg_set_body(peer_msg, (gpointer) body, body_len);

    peer_msg->sip = TRUE;
    peer_msg->call = call;

    g_free(body);

    return peer_msg;
}
