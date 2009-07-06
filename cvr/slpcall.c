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

#include "slpcall.h"

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
#define MSN_SLPCALL_TIMEOUT 300000

/* #define PECAN_DEBUG_SLPCALL */

MsnSlpCall *
msn_slp_call_new(PnPeerLink *link)
{
    MsnSlpCall *slpcall;

    slpcall = g_new0(MsnSlpCall, 1);

#ifdef PECAN_DEBUG_SLPCALL
    pn_info("slpcall_new: slpcall(%p)\n", slpcall);
#endif

    slpcall->link = link;

    pn_peer_link_ref(link);
    pn_peer_link_add_slpcall(link, slpcall);

    slpcall->timer = purple_timeout_add(MSN_SLPCALL_TIMEOUT, msn_slp_call_timeout, slpcall);
    slpcall->session_id = link->slp_session_id++;

    return slpcall;
}

void
msn_slp_call_destroy(MsnSlpCall *slpcall)
{
    GList *e;
    MsnSession *session;

    if (!slpcall)
	    return;

#ifdef PECAN_DEBUG_SLPCALL
    pn_info("slpcall_destroy: slpcall(%p)\n", slpcall);
#endif

    if (slpcall->timer)
        purple_timeout_remove(slpcall->timer);

    g_free(slpcall->id);
    g_free(slpcall->branch);
    g_free(slpcall->data_info);

    for (e = slpcall->link->slp_msgs; e; ){
        MsnSlpMessage *slpmsg = e->data;
        e = e->next;

#ifdef PECAN_DEBUG_SLPCALL_VERBOSE
        pn_info("slpcall_destroy: trying slpmsg(%p)\n",
                slpmsg);
#endif

        if (slpmsg->slpcall == slpcall)
            msn_slpmsg_destroy(slpmsg);
    }

    session = slpcall->link->session;

    if (slpcall->end_cb)
        slpcall->end_cb(slpcall, session);

    pn_peer_link_remove_slpcall(slpcall->link, slpcall);
    pn_peer_link_unref(slpcall->link);

    if (slpcall->xfer)
        purple_xfer_unref(slpcall->xfer);

    g_free(slpcall);
}

void
msn_slp_call_init(MsnSlpCall *slpcall,
                  MsnSlpCallType type)
{
    slpcall->id = msn_rand_guid();
    slpcall->type = type;
}

void
msn_slp_call_session_init(MsnSlpCall *slpcall)
{
    if (slpcall->init_cb)
        slpcall->init_cb(slpcall);

    slpcall->started = TRUE;
}

void
msn_slp_call_invite(MsnSlpCall *slpcall,
                    const char *euf_guid,
                    int app_id,
                    const char *context)
{
    PnPeerLink *link;
    MsnSlpMessage *slpmsg;
    char *header;
    char *content;

    link = slpcall->link;

    slpcall->branch = msn_rand_guid();

    content = g_strdup_printf("EUF-GUID: {%s}\r\n"
                              "SessionID: %lu\r\n"
                              "AppID: %d\r\n"
                              "Context: %s\r\n\r\n",
                              euf_guid,
                              slpcall->session_id,
                              app_id,
                              context);

    header = g_strdup_printf("INVITE MSNMSGR:%s MSNSLP/1.0",
                             link->remote_user);

    slpmsg = msn_slpmsg_sip_new(slpcall, 0, header, slpcall->branch,
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
msn_slp_call_close(MsnSlpCall *slpcall)
{
    msn_slp_sip_send_bye(slpcall, "application/x-msnmsgr-sessionclosebody");
    pn_peer_link_unleash(slpcall->link);
    msn_slp_call_destroy(slpcall);
}

gboolean
msn_slp_call_timeout(gpointer data)
{
    MsnSlpCall *slpcall;

    slpcall = data;

#ifdef PECAN_DEBUG_SLPCALL
    pn_info("slpcall_timeout: slpcall(%p)\n", slpcall);
#endif

    if (!slpcall->pending && !slpcall->progress) {
        msn_slp_call_destroy(slpcall);
        return FALSE;
    }

    slpcall->progress = FALSE;

    return TRUE;
}
