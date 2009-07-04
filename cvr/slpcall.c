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
#include "slplink.h"
#include "slpmsg.h"
#include "session.h"
#include "pecan_util.h"
#include "pecan_log.h"

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
msn_slp_call_new(MsnSlpLink *slplink)
{
    MsnSlpCall *slpcall;

    slpcall = g_new0(MsnSlpCall, 1);

#ifdef PECAN_DEBUG_SLPCALL
    pecan_info("slpcall_new: slpcall(%p)\n", slpcall);
#endif

    slpcall->slplink = slplink;

    msn_slplink_add_slpcall(slplink, slpcall);

    slpcall->timer = purple_timeout_add(MSN_SLPCALL_TIMEOUT, msn_slp_call_timeout, slpcall);
    slpcall->session_id = slplink->slp_session_id++;

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
    pecan_info("slpcall_destroy: slpcall(%p)\n", slpcall);
#endif

    if (slpcall->timer)
        purple_timeout_remove(slpcall->timer);

    g_free(slpcall->id);
    g_free(slpcall->branch);
    g_free(slpcall->data_info);

    for (e = slpcall->slplink->slp_msgs; e; ){
        MsnSlpMessage *slpmsg = e->data;
        e = e->next;

#ifdef PECAN_DEBUG_SLPCALL_VERBOSE
        pecan_info("slpcall_destroy: trying slpmsg(%p)\n",
                   slpmsg);
#endif

        if (slpmsg->slpcall == slpcall)
            msn_slpmsg_destroy(slpmsg);
    }

    session = slpcall->slplink->session;

    if (slpcall->end_cb)
        slpcall->end_cb(slpcall, session);

    msn_slplink_remove_slpcall(slpcall->slplink, slpcall);

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
    MsnSlpLink *slplink;
    MsnSlpMessage *slpmsg;
    char *header;
    char *content;

    slplink = slpcall->slplink;

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
                             slplink->remote_user);

    slpmsg = msn_slpmsg_sip_new(slpcall, 0, header, slpcall->branch,
                                "application/x-msnmsgr-sessionreqbody", content);

#ifdef PECAN_DEBUG_SLP
    slpmsg->info = "SLP INVITE";
    slpmsg->text_body = TRUE;
#endif

    msn_slplink_send_slpmsg(slplink, slpmsg);

    g_free(header);
    g_free(content);
}

void
msn_slp_call_close(MsnSlpCall *slpcall)
{
    msn_slp_sip_send_bye(slpcall, "application/x-msnmsgr-sessionclosebody");
    msn_slplink_unleash(slpcall->slplink);
    msn_slp_call_destroy(slpcall);
}

gboolean
msn_slp_call_timeout(gpointer data)
{
    MsnSlpCall *slpcall;

    slpcall = data;

#ifdef PECAN_DEBUG_SLPCALL
    pecan_info("slpcall_timeout: slpcall(%p)\n", slpcall);
#endif

    if (!slpcall->pending && !slpcall->progress) {
        msn_slp_call_destroy(slpcall);
        return FALSE;
    }

    slpcall->progress = FALSE;

    return TRUE;
}

MsnSlpCall *
msn_slp_process_msg(MsnSlpLink *slplink,
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
                    msn_handwritten_msg_show(slpmsg->slplink->swboard, msgid, body_str + 7, slplink->remote_user);
                    g_free(msgid);
                }
                else {
                    body_str = g_strndup(body, body_len);
                    slpcall = msn_slp_sip_recv(slplink, body_str);
                }
                g_free(body_str);
                break;
            }
        case 0x20:
        case 0x1000020:
        case 0x1000030:
            slpcall = msn_slplink_find_slp_call_with_session_id(slplink,
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
            slpcall = slplink->directconn->initial_call;

            if (slpcall)
                msn_slp_call_session_init(slpcall);
            break;
#endif /* MSN_DIRECTCONN */
        default:
            pecan_warning("slp_process_msg: unprocessed SLP message with flags 0x%08lx",
                          slpmsg->flags);
    }

    return slpcall;
}
