/**
 * Copyright (C) 2007-2008 Felipe Contreras
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "pecan_status.h"

#include "session.h"
#include "notification.h"

#include "ab/pecan_contact.h"

#include "session_private.h"

#include "msn.h"

#include <string.h>

#ifdef HAVE_LIBPURPLE
/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <account.h>
#endif /* HAVE_LIBPURPLE */

static inline const gchar *
util_type_to_str (PecanStatusType status)
{
    static const gchar *status_text[] =
    { "NLN", "NLN", "BSY", "IDL", "BRB", "AWY", "PHN", "LUN", "HDN", "HDN" };

    return status_text[status];
}

static inline void
pecan_set_status (MsnSession *session,
                  PecanStatusType status)
{
    MsnCmdProc *cmdproc;
    PecanContact *user;
    const gchar *state_text;
#if defined(PECAN_CVR)
    MsnObject *msnobj;
#endif /* defined(PECAN_CVR) */

    user = msn_session_get_contact (session);
    cmdproc = session->notification->cmdproc;
    state_text = util_type_to_str (status);

#if defined(PECAN_CVR)
    msnobj = pecan_contact_get_object (user);

    if (msnobj)
    {
        gchar *msnobj_str;

        msnobj_str = msn_object_to_string (msnobj);

        msn_cmdproc_send (cmdproc, "CHG", "%s %d %s", state_text,
                          MSN_CLIENT_ID, purple_url_encode (msnobj_str));

        g_free (msnobj_str);
    }
    else
    {
        msn_cmdproc_send (cmdproc, "CHG", "%s %d", state_text,
                          MSN_CLIENT_ID);
    }
#else
    msn_cmdproc_send (cmdproc, "CHG", "%s %d", state_text,
                      MSN_CLIENT_ID);
#endif /* defined(PECAN_CVR) */
}

static inline void
pecan_set_personal_message (MsnSession *session,
                            gchar *value)
{
    MsnCmdProc *cmdproc;
    gchar *payload;

    cmdproc = session->notification->cmdproc;
    payload = pecan_strdup_printf ("<Data><PSM>%s</PSM><CurrentMedia></CurrentMedia></Data>", value ? value : "");

    {
        MsnTransaction *trans;
        trans = msn_transaction_new (cmdproc, "UUX", "%d", strlen (payload));
        msn_transaction_set_payload (trans, payload, strlen (payload));
        msn_cmdproc_send_trans (cmdproc, trans);
    }
}

#ifdef HAVE_LIBPURPLE
static inline PecanStatusType
util_status_from_account (PurpleAccount *account)
{
    PecanStatusType msnstatus;
    PurplePresence *presence;
    PurpleStatus *status;
    const gchar *status_id;

    presence = purple_account_get_presence (account);
    status = purple_presence_get_active_status (presence);
    status_id = purple_status_get_id (status);

    if (strcmp (status_id, "away") == 0)
        msnstatus = PECAN_STATUS_AWAY;
    else if (strcmp (status_id, "brb") == 0)
        msnstatus = PECAN_STATUS_BRB;
    else if (strcmp (status_id, "busy") == 0)
        msnstatus = PECAN_STATUS_BUSY;
    else if (strcmp (status_id, "phone") == 0)
        msnstatus = PECAN_STATUS_PHONE;
    else if (strcmp (status_id, "lunch") == 0)
        msnstatus = PECAN_STATUS_LUNCH;
    else if (strcmp (status_id, "invisible") == 0)
        msnstatus = PECAN_STATUS_HIDDEN;
    else if (strcmp (status_id, "online") == 0)
    {
        if (purple_presence_is_idle (presence))
            msnstatus = PECAN_STATUS_IDLE;
        else
            msnstatus = PECAN_STATUS_ONLINE;
    }
    else
        msnstatus = PECAN_STATUS_NONE;

    return msnstatus;
}

void
pecan_update_status (MsnSession *session)
{
    g_return_if_fail (session);

    if (!session->logged_in)
        return;

    pecan_set_status (session, util_status_from_account (session->account));
}

void
pecan_update_personal_message (MsnSession *session)
{
    g_return_if_fail (session);

    if (!session->logged_in)
        return;

    if (purple_account_get_bool (session->account, "use_psm", TRUE))
    {
        const gchar *msg;

        msg = purple_account_get_string (session->account, "personal_message", "");
        pecan_set_personal_message (session, (gchar *) msg);
    }
    else
    {
        PurpleStatus *status;
        const gchar *formatted_msg;

        status = purple_account_get_active_status (session->account);
        formatted_msg = purple_status_get_attr_string (status, "message");

        if (formatted_msg)
        {
            gchar *msg;
            gchar *tmp;

            tmp = purple_markup_strip_html (formatted_msg);
            msg = g_markup_escape_text (tmp, -1);
            pecan_set_personal_message (session, msg);

            g_free (tmp);
            g_free (msg);
        }
        else
        {
            pecan_set_personal_message (session, NULL);
        }
    }
}
#endif /* HAVE_LIBPURPLE */
