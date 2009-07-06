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

#include "slp.h"
#include "pn_peer_link.h"
#include "slpmsg.h"
#include "session.h"
#include "pn_util.h"
#include "pn_log.h"

#include <string.h>

#ifdef MSN_DIRECTCONN
#include "directconn.h"
#endif /* MSN_DIRECTCONN */

/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <eventloop.h>
#include <ft.h>

/* The official client seems to timeout slp calls after 5 minutes */
#define PN_PEER_CALL_TIMEOUT 300000

/* #define PECAN_DEBUG_PEER_CALL */

PnPeerCall *
pn_peer_call_new(PnPeerLink *link)
{
    PnPeerCall *call;

    call = g_new0(PnPeerCall, 1);

#ifdef PECAN_DEBUG_PEER_CALL
    pn_info("call=%p", call);
#endif

    call->link = link;

    pn_peer_link_ref(link);
    pn_peer_link_add_call(link, call);

    call->timer = purple_timeout_add(PN_PEER_CALL_TIMEOUT, pn_peer_call_timeout, call);
    call->session_id = link->slp_session_id++;

    return call;
}

void
pn_peer_call_destroy(PnPeerCall *call)
{
    GList *e;
    MsnSession *session;

    if (!call)
	    return;

#ifdef PECAN_DEBUG_PEER_CALL
    pn_info("call=%p", call);
#endif

    if (call->timer)
        purple_timeout_remove(call->timer);

    g_free(call->id);
    g_free(call->branch);
    g_free(call->data_info);

    for (e = call->link->slp_msgs; e; ){
        MsnSlpMessage *slpmsg = e->data;
        e = e->next;

#ifdef PECAN_DEBUG_PEER_CALL_VERBOSE
        pn_info("slpmsg=%p", slpmsg);
#endif

        if (slpmsg->call == call)
            msn_slpmsg_destroy(slpmsg);
    }

    session = call->link->session;

    if (call->end_cb)
        call->end_cb(call, session);

    pn_peer_link_remove_call(call->link, call);
    pn_peer_link_unref(call->link);

    if (call->xfer)
        purple_xfer_unref(call->xfer);

    g_free(call);
}

void
pn_peer_call_init(PnPeerCall *call,
                  PnPeerCallType type)
{
    call->id = msn_rand_guid();
    call->type = type;
}

void
pn_peer_call_session_init(PnPeerCall *call)
{
    if (call->init_cb)
        call->init_cb(call);

    call->started = TRUE;
}

void
pn_peer_call_invite(PnPeerCall *call,
                    const char *euf_guid,
                    int app_id,
                    const char *context)
{
    PnPeerLink *link;
    MsnSlpMessage *slpmsg;
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

    slpmsg = msn_slpmsg_sip_new(call, 0, header, call->branch,
                                "application/x-msnmsgr-sessionreqbody", content);

#ifdef PECAN_DEBUG_SLP
    slpmsg->info = "SLP INVITE";
    slpmsg->text_body = TRUE;
#endif

    pn_peer_link_send_slpmsg(link, slpmsg);

    g_free(header);
    g_free(content);
}

void
pn_peer_call_close(PnPeerCall *call)
{
    msn_slp_sip_send_bye(call, "application/x-msnmsgr-sessionclosebody");
    pn_peer_link_unleash(call->link);
    pn_peer_call_destroy(call);
}

gboolean
pn_peer_call_timeout(gpointer data)
{
    PnPeerCall *call;

    call = data;

#ifdef PECAN_DEBUG_PEER_CALL
    pn_info("call=%p", call);
#endif

    if (!call->pending && !call->progress) {
        pn_peer_call_destroy(call);
        return FALSE;
    }

    call->progress = FALSE;

    return TRUE;
}
