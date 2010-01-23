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

#include "pn_buffer.h"

#include "cvr/pn_peer_call.h"
#include "cvr/pn_peer_link.h"

#include "cvr/pn_peer_call_priv.h"
#include "session_private.h"
#include "ab/pn_contact_priv.h"
#include "ab/pn_contactlist_priv.h"

#ifdef HAVE_LIBPURPLE
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

static inline void
queue (PnDpManager *dpm,
       struct pn_contact *contact,
       gboolean prioritize)
{
    pn_debug ("passport=[%s],window=%u",
              contact->passport, dpm->window);

    if (prioritize)
        g_queue_push_head (dpm->requests, contact);
    else
        g_queue_push_tail (dpm->requests, contact);

    if (dpm->window > 0)
        release (dpm);
}

static void
dp_ok (struct pn_peer_call *call,
       const guchar *data,
       gsize size)
{
    const char *info;
    const char *passport;

    info = call->data_info;
    passport = pn_peer_link_get_passport(call->link);
    pn_debug ("passport=[%s]", passport);

#ifdef HAVE_LIBPURPLE
    {
        PurpleAccount *account;
        account = msn_session_get_user_data (pn_peer_link_get_session (call->link));

        purple_buddy_icons_set_for_user (account, passport,
                                         g_memdup (data, size), size, info);
    }
#endif /* HAVE_LIBPURPLE */

    {
        MsnSession *session;
        struct pn_contact *contact;

        session = pn_peer_link_get_session (call->link);
        contact = pn_contactlist_find_contact (session->contactlist, passport);

        if (contact && contact->dp_failed_attempts > 0)
            contact->dp_failed_attempts = 0;
    }
}

static void
dp_fail (struct pn_peer_call *call,
         MsnSession *session)
{
    const gchar *passport;
    struct pn_contact *contact;

    passport = pn_peer_link_get_passport(call->link);

    pn_warning ("error retrieving dp of '%s'", passport);

    contact = pn_contactlist_find_contact (session->contactlist, passport);

    if (contact)
    {
        contact->dp_failed_attempts++;

        if (contact->dp_failed_attempts == 5)
            return;

        queue (session->dp_manager, contact, FALSE);
    }
}

static void
request (struct pn_contact *user)
{
    PurpleAccount *account;
    MsnSession *session;
    struct pn_msnobj *obj;
    const char *info;

    session = user->contactlist->session;
    account = msn_session_get_user_data (session);

    obj = pn_contact_get_object (user);

    /* Changed while in the queue. */
    if (!obj)
    {
        purple_buddy_icons_set_for_user (account, user->passport, NULL, 0, NULL);
        return;
    }

    info = pn_msnobj_get_sha1 (obj);

    if (g_ascii_strcasecmp (user->passport,
                            msn_session_get_username (session)))
    {
        struct pn_peer_link *link;
        link = msn_session_get_peer_link (session, user->passport);
        pn_peer_link_request_object (link, info,
                                     dp_ok, dp_fail, obj);
    }
    else
    {
        struct pn_msnobj *my_obj = NULL;
        gconstpointer data = NULL;
        size_t len = 0;

        pn_debug ("requesting our own user display");

        my_obj = pn_contact_get_object (msn_session_get_contact (session));

        if (my_obj)
        {
            struct pn_buffer *image;
            image = pn_msnobj_get_image (my_obj);
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
    struct pn_contact *user;

    pn_debug ("releasing ud");

    while (dpm->window > 0)
    {
        GQueue *queue;

        queue = dpm->requests;

        if (g_queue_is_empty (queue))
        {
            pn_debug ("queue empty");
            return;
        }

        if (!dpm->session->connected)
            return;

        user = g_queue_pop_head (queue);

        if (!pn_contact_can_receive (user))
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
           struct pn_contact *contact,
           struct pn_msnobj *obj)
{
    PurpleBuddy *buddy;
    const char *old;
    const char *new;

    buddy = purple_find_buddy (account, pn_contact_get_passport (contact));
    if (!buddy)
        return FALSE;

    old = purple_buddy_icons_get_checksum_for_user (buddy);
    new = pn_msnobj_get_sha1 (obj);

    if (g_strcmp0 (old, new) == 0)
        return TRUE;

    return FALSE;
}
#endif /* HAVE_LIBPURPLE */

void
pn_dp_manager_contact_set_object (struct pn_contact *contact,
                                  gboolean prioritize)
{
    MsnSession *session;
    struct pn_msnobj *obj = pn_contact_get_object(contact);

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

    if (pn_msnobj_get_type (obj) != PN_MSNOBJ_USERTILE)
        return;

#ifdef HAVE_LIBPURPLE
    if (!ud_cached (msn_session_get_user_data (session), contact, obj))
    {
        queue (session->dp_manager, contact, prioritize);
    }
#endif /* HAVE_LIBPURPLE */
}
