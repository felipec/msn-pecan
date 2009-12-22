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

#include "pn_status.h"
#include "pn_log.h"
#include "pn_global.h"

#include "session.h"
#include "notification.h"

#include "ab/pn_contact.h"

#include "session_private.h"
#include "cmd/cmdproc.h"

#include <string.h>

#ifdef HAVE_LIBPURPLE
#include <account.h>
#endif /* HAVE_LIBPURPLE */

static inline const gchar *
util_type_to_str (PecanStatus status)
{
    static const gchar *status_text[] =
    { NULL, "NLN", "BSY", "IDL", "BRB", "AWY", "PHN", "LUN", "HDN", NULL };

    return status_text[status];
}

static inline void
pn_set_personal_message (MsnSession *session,
                         gchar *value,
                         gchar *current_media)
{
    MsnCmdProc *cmdproc;
    gchar *payload;

    cmdproc = session->notification->cmdproc;
    payload = g_strdup_printf ("<Data><PSM>%s</PSM><CurrentMedia>%s</CurrentMedia></Data>",
                               value ? value : "", current_media ? current_media : "");

    {
        MsnTransaction *trans;
        trans = msn_transaction_new (cmdproc, "UUX", "%d", strlen (payload));
        msn_transaction_set_payload (trans, payload, strlen (payload));
        msn_cmdproc_send_trans (cmdproc, trans);
    }
    g_free (payload);
}

#ifdef HAVE_LIBPURPLE
static inline PecanStatus
util_status_from_session (MsnSession *session)
{
    PurpleAccount *account;
    PecanStatus msnstatus;
    PurplePresence *presence;
    PurpleStatus *status;
    const gchar *status_id;

    account = msn_session_get_user_data (session);
    presence = purple_account_get_presence (account);
    status = purple_presence_get_active_status (presence);
    status_id = purple_status_get_id (status);

    if (strcmp (status_id, "available") == 0)
        msnstatus = PN_STATUS_ONLINE;
    else if (strcmp (status_id, "away") == 0)
        msnstatus = PN_STATUS_AWAY;
    else if (strcmp (status_id, "brb") == 0)
        msnstatus = PN_STATUS_BRB;
    else if (strcmp (status_id, "busy") == 0)
        msnstatus = PN_STATUS_BUSY;
    else if (strcmp (status_id, "phone") == 0)
        msnstatus = PN_STATUS_PHONE;
    else if (strcmp (status_id, "lunch") == 0)
        msnstatus = PN_STATUS_LUNCH;
    else if (strcmp (status_id, "invisible") == 0)
        msnstatus = PN_STATUS_HIDDEN;
    else if (strcmp (status_id, "online") == 0)
    {
        if (purple_presence_is_idle (presence))
            msnstatus = PN_STATUS_IDLE;
        else
            msnstatus = PN_STATUS_ONLINE;
    }
    else
    {
        pn_error ("wrong: status_id=[%s]", status_id);
        msnstatus = PN_STATUS_WRONG;
    }

    return msnstatus;
}

static gchar *
create_current_media_string (PurplePresence *presence)
{
    const gchar *title, *game, *office;

    PurpleStatus *status = purple_presence_get_status (presence, "tune");

    if (!status || !purple_status_is_active (status))
        return NULL;

    title = purple_status_get_attr_string (status, PURPLE_TUNE_TITLE);
    game = purple_status_get_attr_string (status, "game");
    office = purple_status_get_attr_string (status, "office");

    if (title) 
    {
        const gchar *artist = purple_status_get_attr_string (status, PURPLE_TUNE_ARTIST);
        const gchar *album = purple_status_get_attr_string (status, PURPLE_TUNE_ALBUM);

        return g_strdup_printf("WMP\\0Music\\01\\0{0}%s%s\\0%s\\0%s\\0%s\\0",
                               artist ? " - {1}" : "",
                               album ? " ({2})" : "",
                               title,
                               artist ? artist : "",
                               album ? album : "");
    }
    else if (game)
        return g_strdup_printf ("\\0Games\\01\\0Playing {0}\\0%s\\0", game);
    else if (office)
        return g_strdup_printf ("\\0Office\\01\\0Editing {0}\\0%s\\0", office);
    else
        return NULL;
}

void
pn_update_status (MsnSession *session)
{
    MsnCmdProc *cmdproc;
    struct pn_contact *user;
    const gchar *state_text;
    int client_id;
    int caps;

    g_return_if_fail (session);

    if (!session->logged_in)
        return;

    user = msn_session_get_contact (session);
    cmdproc = session->notification->cmdproc;
    state_text = util_type_to_str (util_status_from_session (session));

    caps = PN_CLIENT_CAP_BASE;
#if defined(PECAN_CVR)
    caps |= PN_CLIENT_CAP_INK_GIF;
#if defined(PECAN_LIBSIREN)
    caps |= PN_CLIENT_CAP_VOICE_CLIP;
#endif
#if defined(PECAN_LIBMSPACK)
    caps |= PN_CLIENT_CAP_WINKS;
#endif
#endif

    client_id = caps | (PN_CLIENT_VER_7_5 << 24);

#if defined(PECAN_CVR)
    {
        struct pn_msnobj *obj;

        obj = pn_contact_get_object (user);

        if (obj)
        {
            gchar *msnobj_str;

            msnobj_str = pn_msnobj_to_string (obj);

            msn_cmdproc_send (cmdproc, "CHG", "%s %d %s", state_text,
                              client_id, purple_url_encode (msnobj_str));

            g_free (msnobj_str);
        }
        else
        {
            msn_cmdproc_send (cmdproc, "CHG", "%s %d", state_text,
                              client_id);
        }
    }
#else
    msn_cmdproc_send (cmdproc, "CHG", "%s %d", state_text,
                      client_id);
#endif /* defined(PECAN_CVR) */
}

void
pn_update_personal_message (MsnSession *session)
{
    PurpleAccount *account;
    PurplePresence *presence;
    gchar *current_media;

    g_return_if_fail (session);

    if (!session->logged_in)
        return;

    account = msn_session_get_user_data (session);
    presence = purple_account_get_presence (account);

    current_media = create_current_media_string (presence);

#ifndef PECAN_USE_PSM
    const gchar *msg;

    msg = purple_account_get_string (account, "personal_message", "");
    pn_set_personal_message (session, (gchar *) msg, current_media);
#else
    PurpleStatus *status;
    const gchar *formatted_msg;

    status = purple_account_get_active_status (account);
    formatted_msg = purple_status_get_attr_string (status, "message");

    if (formatted_msg)
    {
        gchar *msg;
        gchar *tmp;

        tmp = purple_markup_strip_html (formatted_msg);
        msg = g_markup_escape_text (tmp, -1);
        pn_set_personal_message (session, msg, current_media);

        g_free (tmp);
        g_free (msg);
    }
    else
    {
        pn_set_personal_message (session, NULL, current_media);
    }
#endif /* PECAN_USE_PSM */

    if (current_media)
        g_free (current_media);
}
#endif /* HAVE_LIBPURPLE */

gboolean
pn_timeout_tune_status (gpointer data)
{
    MsnSession *session;
    PurpleAccount *account;
    PurplePresence *presence;
    PurpleStatus *status;

    session = data;

    if (!session)
        return FALSE;

    account = msn_session_get_user_data (session);
    presence = purple_account_get_presence (account);
    status = purple_presence_get_status (presence, "tune");

    if (status)
    {
        if (session->autoupdate_tune.enabled)
        {
            pn_update_personal_message (session);

            if (!status || !purple_status_is_active (status))
                session->autoupdate_tune.enabled = FALSE;
        }
        else
        {
            if (status && purple_status_is_active (status))
            {
                session->autoupdate_tune.enabled = TRUE;
                pn_update_personal_message (session);
            }
        }
    }

    session->autoupdate_tune.timer = g_timeout_add_seconds (10, pn_timeout_tune_status, session);

    return FALSE;
}
