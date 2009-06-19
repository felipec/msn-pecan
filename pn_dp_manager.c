/**
 * Copyright (C) 2007-2009 Felipe Contreras
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

#include "pn_dp_manager.h"
#include "pn_log.h"

#include "cvr/slpcall.h"
#include "cvr/slplink.h"

#include "session_private.h"
#include "ab/pecan_contact_priv.h"
#include "ab/pecan_contactlist_priv.h"

#ifdef HAVE_LIBPURPLE
#include "fix_purple.h"
#include <account.h>
#endif /* HAVE_LIBPURPLE */

struct PnDpManager
{
    MsnSession *session;
    GQueue *requests;
    gint window;
    guint timer;
};

static void release (PnDpManager *dpm);

PnDpManager *
pn_dp_manager_new (MsnSession *session)
{
    PnDpManager *dpm;
    dpm = g_new0 (PnDpManager, 1);
    dpm->session = session;
    dpm->requests = g_queue_new ();
    dpm->window = 8; /** @todo this window should be for sbs in general */
    return dpm;
}

void
pn_dp_manager_free (PnDpManager *dpm)
{
    g_queue_free (dpm->requests);

    if (dpm->timer)
        g_source_remove (dpm->timer);

    g_free (dpm);
}

static void
userdisplay_ok (MsnSlpCall *slpcall,
                const guchar *data,
                gsize size)
{
    const char *info;

    info = slpcall->data_info;
    pn_info ("passport=[%s]", slpcall->slplink->remote_user);

#ifdef HAVE_LIBPURPLE
    {
        PurpleAccount *account;
        account = msn_session_get_user_data (slpcall->slplink->session);

        purple_buddy_icons_set_for_user (account, slpcall->slplink->remote_user,
                                         g_memdup (data, size), size, info);
    }
#endif /* HAVE_LIBPURPLE */
}

static inline void
queue (PnDpManager *dpm,
       PecanContact *contact)
{
    pn_debug ("passport=[%s],window=%u",
              contact->passport, dpm->window);

    g_queue_push_tail (dpm->requests, contact);

    if (dpm->window > 0)
        release (dpm);
}

static void
userdisplay_fail (MsnSlpCall *slpcall,
                  MsnSession *session)
{
    const gchar *passport;
    PecanContact *contact;

    pn_error ("unknown error");

    passport = slpcall->slplink->remote_user;

    contact = pecan_contactlist_find_contact (session->contactlist, passport);

    if (contact)
        queue (session->dp_manager, contact);
}

static void
request (PecanContact *user)
{
    PurpleAccount *account;
    MsnSession *session;
    MsnSlpLink *slplink;
    MsnObject *obj;
    const char *info;

    session = user->contactlist->session;
    account = msn_session_get_user_data (session);

    slplink = msn_session_get_slplink (session, user->passport);

    obj = pecan_contact_get_object (user);

    /* Changed while in the queue. */
    if (!obj)
    {
        purple_buddy_icons_set_for_user (account, user->passport, NULL, 0, NULL);
        return;
    }

    info = msn_object_get_sha1 (obj);

    if (g_ascii_strcasecmp (user->passport,
                            msn_session_get_username (session)))
    {
        msn_slplink_request_object (slplink, info,
                                    userdisplay_ok, userdisplay_fail, obj);
    }
    else
    {
        MsnObject *my_obj = NULL;
        gconstpointer data = NULL;
        size_t len = 0;

        pn_debug ("requesting our own user display");

        my_obj = pecan_contact_get_object (msn_session_get_contact (session));

        if (my_obj)
        {
            PecanBuffer *image;
            image = msn_object_get_image (my_obj);
            data = image->data;
            len = image->len;
        }

        purple_buddy_icons_set_for_user (account, user->passport,
                                         g_memdup (data, len), len, info);
    }
}

static gboolean
timeout (gpointer data)
{
    PnDpManager *dpm = data;

    dpm->window = 8;
    pn_log ("window=%d", dpm->window);

    /* Clear the tag for our former request timer */
    dpm->timer = 0;

    release (dpm);

    return FALSE;
}

static void
release (PnDpManager *dpm)
{
    PecanContact *user;

    pn_info ("releasing ud");

    while (dpm->window > 0)
    {
        GQueue *queue;

        queue = dpm->requests;

        if (g_queue_is_empty (queue))
        {
            pn_warning ("nothing here");
            return;
        }

        user = g_queue_pop_head (queue);

        if (!pecan_contact_can_receive (user))
            continue;

        dpm->window--;
        pn_log ("window=%d", dpm->window);

        request (user);
    }

    dpm->timer = g_timeout_add_seconds (60, timeout, dpm);
}

#ifdef HAVE_LIBPURPLE
static inline gboolean
ud_cached (PurpleAccount *account,
           MsnObject *obj)
{
    PurpleBuddy *buddy;
    const char *old;
    const char *new;

    buddy = purple_find_buddy (account, msn_object_get_creator (obj));
    if (!buddy)
        return FALSE;

    old = purple_buddy_icons_get_checksum_for_user (buddy);
    new = msn_object_get_sha1 (obj);

    if (g_strcmp0 (old, new) == 0)
        return TRUE;

    return FALSE;
}
#endif /* HAVE_LIBPURPLE */

void
pn_dp_manager_contact_set_object (PecanContact *contact,
                                  MsnObject *obj)
{
    MsnSession *session;

    if (!(contact->list_op & MSN_LIST_FL_OP))
        return;

    session = contact->contactlist->session;
    if (!obj)
    {
#ifdef HAVE_LIBPURPLE
        purple_buddy_icons_set_for_user (msn_session_get_user_data (session), contact->passport, NULL, 0, NULL);
#endif /* HAVE_LIBPURPLE */
        return;
    }

    if (msn_object_get_type (obj) != MSN_OBJECT_USERTILE)
        return;

#ifdef HAVE_LIBPURPLE
    if (!ud_cached (msn_session_get_user_data (session), obj))
    {
        queue (session->dp_manager, contact);
    }
#endif /* HAVE_LIBPURPLE */
}
