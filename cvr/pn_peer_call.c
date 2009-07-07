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

#include "pn_peer_call.h"

#include "pn_sip.h"
#include "pn_peer_link.h"
#include "pn_peer_msg.h"
#include "session.h"
#include "pn_util.h"
#include "pn_log.h"

#include "pn_peer_link_priv.h"

#include <string.h>

#ifdef MSN_DIRECTCONN
#include "pn_direct_conn.h"
#endif /* MSN_DIRECTCONN */

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <ft.h>

static gboolean
timeout(gpointer data)
{
    struct pn_peer_call *call;

    call = data;

    pn_log("call=%p", call);

    if (!call->pending && !call->progress) {
        pn_peer_call_unref(call);
        return FALSE;
    }

    call->progress = FALSE;

    return TRUE;
}

struct pn_peer_call *
pn_peer_call_new(struct pn_peer_link *link)
{
    struct pn_peer_call *call;

    call = g_new0(struct pn_peer_call, 1);

    pn_log("call=%p", call);

    call->link = link;

    {
        MsnSwitchBoard *swboard;

        swboard = msn_session_get_swboard(link->session, link->remote_user);

        if (!swboard) {
            pn_error("couldn't get swboard");
            g_free(call);
            return NULL;
        }

        swboard->calls = g_list_prepend(swboard->calls, call);

        call->swboard = swboard;
    }

    pn_peer_link_ref(link);
    pn_peer_link_add_call(link, call);

    /* The official client seems to timeout calls after 5 minutes */
    call->timer = g_timeout_add_seconds (30, timeout, call);
    call->session_id = link->slp_session_id++;

    call->ref_count++;

    return call;
}

void
pn_peer_call_free(struct pn_peer_call *call)
{
    GList *e;
    MsnSession *session;

    if (!call)
	    return;

    pn_log("call=%p", call);

    if (call->timer)
        g_source_remove(call->timer);

    g_free(call->id);
    g_free(call->branch);
    g_free(call->data_info);

    for (e = call->link->slp_msgs; e; ){
        struct pn_peer_msg *peer_msg = e->data;
        e = e->next;

        pn_log("freeing peer_msg=%p", peer_msg);

        if (peer_msg->call == call)
            pn_peer_msg_unref(peer_msg);
    }

    session = call->link->session;

    if (call->end_cb)
        call->end_cb(call, session);

    pn_peer_link_remove_call(call->link, call);
    pn_peer_link_unref(call->link);

    if (call->xfer)
        purple_xfer_unref(call->xfer);

    if (call->swboard)
        call->swboard->calls = g_list_remove(call->swboard->calls, call);

    g_free(call);
}

struct pn_peer_call *
pn_peer_call_ref(struct pn_peer_call *call)
{
    call->ref_count++;

    return call;
}

struct pn_peer_call *
pn_peer_call_unref(struct pn_peer_call *call)
{
    call->ref_count--;

    if (call->ref_count == 0) {
        pn_peer_call_free(call);
        return NULL;
    }

    return call;
}

void
pn_peer_call_init(struct pn_peer_call *call)
{
    call->id = msn_rand_guid();
}

void
pn_peer_call_session_init(struct pn_peer_call *call)
{
    if (call->init_cb)
        call->init_cb(call);

    call->started = TRUE;
}

void
pn_peer_call_invite(struct pn_peer_call *call,
                    const char *euf_guid,
                    int app_id,
                    const char *context)
{
    struct pn_peer_link *link;
    struct pn_peer_msg *peer_msg;
    char *header;
    char *content;

    link = call->link;

    call->branch = msn_rand_guid();

    content = g_strdup_printf("EUF-GUID: {%s}\r\n"
                              "SessionID: %lu\r\n"
                              "AppID: %d\r\n"
                              "Context: %s\r\n\r\n",
                              euf_guid,
                              call->session_id,
                              app_id,
                              context);

    header = g_strdup_printf("INVITE MSNMSGR:%s MSNSLP/1.0",
                             link->remote_user);

    peer_msg = pn_peer_msg_sip_new(call, 0, header, call->branch,
                                   "application/x-msnmsgr-sessionreqbody", content);

#ifdef PECAN_DEBUG_SLP
    peer_msg->info = "SLP INVITE";
    peer_msg->text_body = TRUE;
#endif

    pn_peer_link_send_msg(link, peer_msg);

    g_free(header);
    g_free(content);
}

void
pn_peer_call_close(struct pn_peer_call *call)
{
    pn_sip_send_bye(call, "application/x-msnmsgr-sessionclosebody");
    pn_peer_link_unleash(call->link);
    pn_peer_call_unref(call);
}
