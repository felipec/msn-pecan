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
#include "pn_peer_call_priv.h"

#include "pn_peer_link.h"
#include "pn_peer_msg.h"
#include "session.h"
#include "pn_util.h"
#include "pn_log.h"

#include <string.h>

/* libpurple stuff. */
#include <ft.h>

static gboolean
timeout(gpointer data)
{
    struct pn_peer_call *call;

    call = data;

    pn_log("call=%p", call);

    if (!call->pending) {
        pn_peer_call_unref(call);
        return FALSE;
    }

    return TRUE;
}

struct pn_peer_call *
pn_peer_call_new(struct pn_peer_link *link)
{
    struct pn_peer_call *call;

    call = g_new0(struct pn_peer_call, 1);

    pn_log("call=%p", call);

    call->link = link;

    pn_peer_link_add_call(link, call);

    /* The official client seems to timeout calls after 5 minutes */
    call->timer = g_timeout_add_seconds (5 * 60, timeout, call);

    call->ref_count++;

    return call;
}

void
pn_peer_call_free(struct pn_peer_call *call)
{
    MsnSession *session;

    if (!call)
	    return;

    pn_log("call=%p", call);

    if (call->timer)
        g_source_remove(call->timer);

    g_free(call->id);
    g_free(call->branch);
    g_free(call->data_info);

    session = pn_peer_link_get_session(call->link);

    if (call->end_cb)
        call->end_cb(call, session);

    pn_peer_link_remove_call(call->link, call);

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
pn_peer_call_session_init(struct pn_peer_call *call)
{
    if (call->init_cb)
        call->init_cb(call);

    call->started = TRUE;
}

void
pn_peer_call_close(struct pn_peer_call *call)
{
    pn_sip_send_bye(call, "application/x-msnmsgr-sessionclosebody");
    pn_peer_link_unleash(call->link);
    pn_peer_call_unref(call);
}
