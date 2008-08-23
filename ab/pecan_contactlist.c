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

#include "session.h"
#include "pecan_contactlist.h"
#include "pecan_contactlist_priv.h"
#include "pecan_contact_priv.h"
#include "pecan_log.h"

/** @todo this is disabled for testing only */
#ifdef HAVE_LIBPURPLE
#include "session_private.h"
#endif /* HAVE_LIBPURPLE */
#include "notification.h"
#include "pecan_util.h"

#include <string.h>

#include "msn_intl.h"

#define MSN_NULL_GROUP_NAME "Non-Grouped"

#ifdef HAVE_LIBPURPLE
/* libpurple stuff. */
#include "fix_purple_win32.h"
#include <privacy.h>
#endif /* HAVE_LIBPURPLE */

const char *lists[] = { "FL", "AL", "BL", "RL", "PL" };

typedef struct
{
    MsnSession *session;
    PecanContact *contact;
} MsnPermitAdd;

#ifdef HAVE_LIBPURPLE
/**************************************************************************
 * Callbacks
 **************************************************************************/
static void
msn_accept_add_cb (gpointer data)
{
    MsnPermitAdd *pa = data;
    const gchar *passport;
    PecanContact *contact;

    contact = pa->contact;
    passport = pecan_contact_get_passport (contact);

    pecan_contactlist_add_buddy (pa->session->contactlist, passport, MSN_LIST_AL, NULL);

    g_free (pa);
}

static void
msn_cancel_add_cb (gpointer data)
{
    MsnPermitAdd *pa = data;
    PecanContact *contact;
    const gchar *passport;

    contact = pa->contact;
    passport = pecan_contact_get_passport (contact);

    pecan_contactlist_add_buddy (pa->session->contactlist, passport, MSN_LIST_BL, NULL);

    g_free (pa);
}

static void
got_new_entry (PurpleConnection *gc,
               PecanContact *contact,
               const gchar *friendly)
{
    MsnPermitAdd *pa;
    const gchar *passport;

    passport = pecan_contact_get_passport (contact);

    pa = g_new0 (MsnPermitAdd, 1);
    pa->session = gc->proto_data;
    pa->contact = contact;

    purple_account_request_authorization (purple_connection_get_account (gc), passport, NULL, NULL, NULL,
                                          purple_find_buddy (purple_connection_get_account (gc), passport) != NULL,
                                          msn_accept_add_cb, msn_cancel_add_cb, pa);
}
#endif /* HAVE_LIBPURPLE */

/**************************************************************************
 * Utility functions
 **************************************************************************/

static gboolean
contact_is_in_group (PecanContact *contact,
                     const gchar *group_guid)
{
    if (!contact)
        return FALSE;

    if (!group_guid)
    {
        /* User is in the no-group only when he isn't in any group. */
        if (g_hash_table_size (contact->groups) == 0)
            return TRUE;

        return FALSE;
    }

    if (g_hash_table_lookup (contact->groups, group_guid))
        return TRUE;

    return FALSE;
}

static gboolean
contact_is_there (PecanContact *contact,
                  gint list_id,
                  gboolean check_group,
                  const gchar *group_guid)
{
    int list_op;

    if (!contact)
        return FALSE;

    list_op = 1 << list_id;

    if (!(contact->list_op & list_op))
        return FALSE;

    if (list_id == MSN_LIST_FL && check_group)
    {
        return contact_is_in_group (contact, group_guid);
    }

    return TRUE;
}

static const gchar*
get_store_name (PecanContact *contact)
{
    const gchar *store_name;

    g_return_val_if_fail (contact, NULL);

    if (contact->contactlist->session->server_alias)
    {
        store_name = pecan_contact_get_store_name (contact);
    }
    else
    {
        store_name = pecan_contact_get_friendly_name (contact);
    }

    if (!store_name)
        store_name = pecan_contact_get_passport (contact);

    return store_name;
}

static void
request_add_group (PecanContactList *contactlist,
                   const gchar *who,
                   const gchar *old_group_guid,
                   const gchar *new_group_name)
{
#ifdef HAVE_LIBPURPLE
    MsnCmdProc *cmdproc;
    MsnTransaction *trans;
    MsnMoveBuddy *data;

    cmdproc = contactlist->session->notification->cmdproc;
    data = g_new0 (MsnMoveBuddy, 1);

    data->who = g_strdup (who);

    if (old_group_guid)
        data->old_group_guid = g_strdup (old_group_guid);

    trans = msn_transaction_new (cmdproc, "ADG", "%s %d",
                                 purple_url_encode (new_group_name),
                                 0);

    msn_transaction_set_data (trans, data);

    msn_cmdproc_send_trans (cmdproc, trans);
#endif /* HAVE_LIBPURPLE */
}

/**************************************************************************
 * Server functions
 **************************************************************************/

MsnListId
msn_get_list_id (const gchar *list)
{
    if (list[0] == 'F')
        return MSN_LIST_FL;
    else if (list[0] == 'A')
        return MSN_LIST_AL;
    else if (list[0] == 'B')
        return MSN_LIST_BL;
    else if (list[0] == 'R')
        return MSN_LIST_RL;
    else if (list[0] == 'P')
        return MSN_LIST_PL;

    return -1;
}

void
msn_got_add_contact (MsnSession *session,
                     PecanContact *contact,
                     MsnListId list_id,
                     const gchar *group_guid)
{
#ifdef HAVE_LIBPURPLE
    PurpleAccount *account;
    const gchar *passport;

    account = session->account;

    passport = pecan_contact_get_passport (contact);

    if (list_id == MSN_LIST_FL)
    {
        if (group_guid)
        {
            pecan_contact_add_group_id (contact, group_guid);
        }
    }
    else if (list_id == MSN_LIST_AL)
    {
        purple_privacy_permit_add (account, passport, TRUE);
    }
    else if (list_id == MSN_LIST_BL)
    {
        purple_privacy_deny_add (account, passport, TRUE);
    }
    else if (list_id == MSN_LIST_RL)
    {
        PurpleConnection *gc;

        gc = purple_account_get_connection (account);

        pecan_info ("reverse list add: [%s]", passport);

        /** @todo display a non-intrusive message */
#if 0
        PurpleConversation *convo;
        convo = purple_find_conversation_with_account (PURPLE_CONV_TYPE_IM, passport, account);
        if (convo)
        {
            PurpleBuddy *buddy;
            gchar *msg;

            buddy = purple_find_buddy (account, passport);
            msg = pecan_strdup_printf (_("%s has added you to his or her buddy list."),
                                       buddy ? purple_buddy_get_contact_alias(buddy) : passport);
            purple_conv_im_write (PURPLE_CONV_IM (convo), passport, msg,
                                  PURPLE_MESSAGE_SYSTEM, time (NULL));
            g_free (msg);
        }
#endif

        if (!(contact->list_op & (MSN_LIST_AL_OP | MSN_LIST_BL_OP)))
        {
            got_new_entry (gc, contact,
                           pecan_contact_get_friendly_name (contact));
        }
    }

    contact->list_op |= (1 << list_id);
    /* purple_contact_add_list_id (contact, list_id); */
#endif /* HAVE_LIBPURPLE */
}

void
msn_got_rem_contact (MsnSession *session,
                     PecanContact *contact,
                     MsnListId list_id,
                     const gchar *group_guid)
{
#ifdef HAVE_LIBPURPLE
    PurpleAccount *account;
    const gchar *passport;

    account = session->account;

    passport = pecan_contact_get_passport (contact);

    if (list_id == MSN_LIST_FL)
    {
        /** @todo when is the contact totally removed? */
        /** when the group count reaches 0, and there's no list_op */
        if (group_guid)
        {
            pecan_contact_remove_group_id (contact, group_guid);
            return;
        }

        g_hash_table_remove_all (contact->groups);
    }
    else if (list_id == MSN_LIST_AL)
    {
        purple_privacy_permit_remove (account, passport, TRUE);
    }
    else if (list_id == MSN_LIST_BL)
    {
        purple_privacy_deny_remove (account, passport, TRUE);
    }
    else if (list_id == MSN_LIST_RL)
    {
        PurpleConversation *convo;

        pecan_info ("reverse list rem: [%s]", passport);

        convo = purple_find_conversation_with_account (PURPLE_CONV_TYPE_IM, passport, account);
        if (convo)
        {
            PurpleBuddy *buddy;
            gchar *msg;

            buddy = purple_find_buddy (account, passport);
            msg = pecan_strdup_printf (_("%s has removed you from his or her buddy list."),
                                       buddy ? purple_buddy_get_contact_alias (buddy) : passport);
            purple_conv_im_write (PURPLE_CONV_IM (convo), passport, msg,
                                  PURPLE_MESSAGE_SYSTEM, time (NULL));
            g_free (msg);
        }
    }

    contact->list_op &= ~(1 << list_id);
    /* purple_contact_remove_list_id (contact, list_id); */

    if (contact->list_op == 0)
    {
        pecan_debug ("no list op: [%s]",
                   passport);
    }
#endif /* HAVE_LIBPURPLE */
}

void
msn_got_lst_contact (MsnSession *session,
                     PecanContact *contact,
                     const gchar *extra,
                     gint list_op,
                     GSList *group_ids)
{
#ifdef HAVE_LIBPURPLE
    PurpleAccount *account;
    const gchar *passport;

    account = session->account;

    passport = pecan_contact_get_passport (contact);

    pecan_debug ("passport=%s,extra=%s,list_op=%d", contact->passport, extra, list_op);

    if (list_op & MSN_LIST_FL_OP)
    {
        if (group_ids)
        {
            GSList *c;
            for (c = group_ids; c; c = g_slist_next (c))
            {
                const gchar *group_guid;
                group_guid = (const gchar *) c->data;
                pecan_contact_add_group_id (contact, group_guid);
            }
        }
        else
        {
            pecan_contact_add_group_id (contact, NULL);
        }

        if (session->server_alias)
        {
            pecan_contact_set_store_name (contact, extra);
        }
        else
        {
            pecan_contact_set_friendly_name (contact, extra);
        }
    }

    if (list_op & MSN_LIST_AL_OP)
    {
        /* These are contacts who are allowed to see our status. */
        purple_privacy_deny_remove (account, passport, TRUE);
        purple_privacy_permit_add (account, passport, TRUE);
    }

    if (list_op & MSN_LIST_BL_OP)
    {
        /* These are contacts who are not allowed to see our status. */
        purple_privacy_permit_remove (account, passport, TRUE);
        purple_privacy_deny_add (account, passport, TRUE);
    }

    /* Somebody wants to be our friend :) */
    if (list_op & (MSN_LIST_RL_OP | MSN_LIST_PL_OP))
    {
        /* Users must be either allowed or blocked, right? */
        if (!(list_op & (MSN_LIST_AL_OP | MSN_LIST_BL_OP)))
        {
            PurpleConnection *gc;

            gc = purple_account_get_connection (account);

            got_new_entry (gc, contact, extra);
        }
    }

    contact->list_op = list_op;
#endif /* HAVE_LIBPURPLE */
}

/**************************************************************************
 * UserList functions
 **************************************************************************/

PecanContactList *
pecan_contactlist_new (MsnSession *session)
{
    PecanContactList *contactlist;

    contactlist = g_new0 (PecanContactList, 1);

    contactlist->session = session;

    contactlist->contact_names = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                                                        (GDestroyNotify) pecan_contact_free);
    contactlist->contact_guids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    contactlist->group_names = g_hash_table_new_full (g_ascii_strcase_hash, g_ascii_strcase_equal, g_free,
                                                      (GDestroyNotify) pecan_group_free);
    contactlist->group_guids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    contactlist->null_group = pecan_group_new (contactlist, MSN_NULL_GROUP_NAME, NULL);

    contactlist->buddy_icon_requests = g_queue_new ();

    /* buddy_icon_window is the number of allowed simultaneous buddy icon requests.
     * XXX With smarter rate limiting code, we could allow more at once... 5 was the limit set when
     * we weren't retrieiving any more than 5 per MSN session. */
    contactlist->buddy_icon_window = 1;

    return contactlist;
}

void
pecan_contactlist_destroy (PecanContactList *contactlist)
{
    g_hash_table_destroy (contactlist->contact_guids);
    g_hash_table_destroy (contactlist->contact_names);
    g_hash_table_destroy (contactlist->group_guids);
    g_hash_table_destroy (contactlist->group_names);

    g_queue_free (contactlist->buddy_icon_requests);

#ifdef HAVE_LIBPURPLE
    if (contactlist->buddy_icon_request_timer)
        purple_timeout_remove (contactlist->buddy_icon_request_timer);
#endif /* HAVE_LIBPURPLE */

    g_free (contactlist);
}

void
pecan_contactlist_remove_contact (PecanContactList *contactlist,
                                  PecanContact *contact)
{
    {
        const gchar *guid;
        guid = pecan_contact_get_guid (contact);
        if (guid)
            g_hash_table_remove (contactlist->contact_guids, guid);
    }
    g_hash_table_remove (contactlist->contact_names,
                         pecan_contact_get_passport (contact));
}

PecanContact *
pecan_contactlist_find_contact (PecanContactList *contactlist,
                                const gchar *passport)
{
    g_return_val_if_fail (passport, NULL);

    return g_hash_table_lookup (contactlist->contact_names, passport);
}

PecanContact *
pecan_contactlist_find_contact_by_guid (PecanContactList *contactlist,
                                        const gchar *guid)
{
    g_return_val_if_fail (guid, NULL);

    return g_hash_table_lookup (contactlist->contact_guids, guid);
}

void
pecan_contactlist_add_group (PecanContactList *contactlist,
                             PecanGroup *group)
{
    g_hash_table_insert (contactlist->group_names, g_strdup (pecan_group_get_name (group)), group);
    {
        const gchar *guid;
        guid = pecan_group_get_id (group);
        if (guid)
            g_hash_table_insert (contactlist->group_guids, g_strdup (guid), group);
    }
}

void
pecan_contactlist_remove_group (PecanContactList *contactlist,
                                PecanGroup *group)
{
    {
        const gchar *guid;
        guid = pecan_group_get_id (group);
        if (guid)
            g_hash_table_remove (contactlist->group_guids, guid);
    }
    g_hash_table_remove (contactlist->group_names, pecan_group_get_name (group));
}

PecanGroup *
pecan_contactlist_find_group_with_id (PecanContactList *contactlist,
                                      const gchar *guid)
{
    g_return_val_if_fail (contactlist, NULL);

    if (!guid)
        return contactlist->null_group;

    return g_hash_table_lookup (contactlist->group_guids, guid);
}

PecanGroup *
pecan_contactlist_find_group_with_name (PecanContactList *contactlist,
                                        const gchar *name)
{
    g_return_val_if_fail (contactlist, NULL);
    g_return_val_if_fail (name, NULL);

    if (g_ascii_strcasecmp (pecan_group_get_name (contactlist->null_group), name) == 0)
        return contactlist->null_group;

    return g_hash_table_lookup (contactlist->group_names, name);
}

const gchar *
pecan_contactlist_find_group_id (PecanContactList *contactlist,
                                 const gchar *group_name)
{
    PecanGroup *group;

    group = pecan_contactlist_find_group_with_name (contactlist, group_name);

    if (group)
        return pecan_group_get_id (group);
    else
        return NULL;
}

const gchar *
pecan_contactlist_find_group_name (PecanContactList *contactlist,
                                   const gchar *group_guid)
{
    PecanGroup *group;

    group = pecan_contactlist_find_group_with_id (contactlist, group_guid);

    if (group)
        return pecan_group_get_name (group);
    else
        return NULL;
}

void
pecan_contactlist_rename_group_id (PecanContactList *contactlist,
                                   const gchar *group_guid,
                                   const gchar *new_name)
{
    PecanGroup *group;

    group = pecan_contactlist_find_group_with_id (contactlist, group_guid);

    if (group)
        pecan_group_set_name (group, new_name);
}

void
pecan_contactlist_remove_group_id (PecanContactList *contactlist,
                                   const gchar *group_guid)
{
    PecanGroup *group;

    group = pecan_contactlist_find_group_with_id (contactlist, group_guid);

    if (group)
    {
        pecan_contactlist_remove_group (contactlist, group);
    }
}

void
pecan_contactlist_rem_buddy (PecanContactList *contactlist,
                             const gchar *who,
                             gint list_id,
                             const gchar *group_name)
{
    PecanContact *contact;
    const gchar *group_guid;
    const gchar *list;

    contact = pecan_contactlist_find_contact (contactlist, who);
    group_guid = NULL;

    pecan_debug ("who=[%s],list_id=%d,group_name=[%s]", who, list_id, group_name);

    if (group_name)
    {
        PecanGroup *group;

        group = pecan_contactlist_find_group_with_name (contactlist, group_name);

        if (!group)
        {
            /* Whoa, there is no such group. */
            pecan_error ("group doesn't exist: group_name=[%s]", group_name);
            return;
        }

        group_guid = pecan_group_get_id (group);
    }

    list = lists[list_id];

    /* First we're going to check if not there. */
    if (!(contact_is_there (contact, list_id, group_name != NULL, group_guid)))
    {
        pecan_error ("contact not there: who=[%s],list=[%s],group_guid=[%s]",
                   who, list, group_guid);
        return;
    }

#ifdef HAVE_LIBPURPLE
    /* Then request the rem to the server. */
    msn_notification_rem_buddy (contactlist->session->notification, list, who, contact->guid, group_guid);
#endif /* HAVE_LIBPURPLE */
}

void
pecan_contactlist_add_buddy (PecanContactList *contactlist,
                             const gchar *who,
                             gint list_id,
                             const gchar *group_name)
{
    PecanContact *contact;
    const gchar *group_guid;
    const gchar *contact_guid;
    const gchar *list;
    const gchar *store_name;

    group_guid = NULL;

    pecan_debug ("who=[%s],list_id=%d,group_name=[%s]", who, list_id, group_name);

    contact = pecan_contactlist_find_contact (contactlist, who);

    if (group_name)
    {
        PecanGroup *group;

        group = pecan_contactlist_find_group_with_name (contactlist, group_name);

        if (!group)
        {
            /* We must add that group first. */
            request_add_group (contactlist, who, NULL, group_name);
            return;
        }

        group_guid = pecan_group_get_id (group);

        /* There's no way to add a contact to the no-group. */
        /* Removing from other groups does that. */
        if (contact && pecan_contact_get_group_count (contact) > 0 && !group_guid)
        {
            pecan_error ("trying to add contact to a virtual group: who=[%s]",
                         who);
            return;
        }
    }

    store_name = (contact) ? get_store_name (contact) : who;
    contact_guid = (contact) ? contact->guid : NULL;

    list = lists[list_id];

#ifdef HAVE_LIBPURPLE
    msn_notification_add_buddy (contactlist->session->notification, list, who, contact_guid, store_name, group_guid);
#endif /* HAVE_LIBPURPLE */
}

void
pecan_contactlist_move_buddy (PecanContactList *contactlist,
                              const gchar *who,
                              const gchar *old_group_name,
                              const gchar *new_group_name)
{
    PecanGroup *old_group;
    PecanGroup *new_group;
    const gchar *old_group_guid;

    old_group = pecan_contactlist_find_group_with_name (contactlist, old_group_name);
    new_group = pecan_contactlist_find_group_with_name (contactlist, new_group_name);

    old_group_guid = pecan_group_get_id (old_group);

    if (!new_group)
    {
        request_add_group (contactlist, who, old_group_guid, new_group_name);
        return;
    }

    pecan_contactlist_add_buddy (contactlist, who, MSN_LIST_FL, new_group_name);
    if (old_group_guid)
        pecan_contactlist_rem_buddy (contactlist, who, MSN_LIST_FL, old_group_name);
}

static void
contact_check_pending (gpointer key,
                       gpointer value,
                       gpointer user_data)
{
    const gchar *passport;
    PecanContact *contact;
    PecanContactList *contactlist;

    passport = key;
    contact = value;
    contactlist = user_data;

    if (contact->list_op & MSN_LIST_PL_OP)
    {
        /* These are contacts who are pending for... something. */

        pecan_contactlist_add_buddy (contactlist, passport, MSN_LIST_RL, NULL);
        pecan_contactlist_rem_buddy (contactlist, passport, MSN_LIST_PL, NULL);
    }
}

void
pecan_contactlist_check_pending (PecanContactList *contactlist)
{
    g_hash_table_foreach (contactlist->contact_names, contact_check_pending, contactlist);
}

#ifdef HAVE_LIBPURPLE
/**************************************************************************
 * Purple functions
 **************************************************************************/
void
pecan_contactlist_add_buddy_helper (PecanContactList *contactlist,
                                    PurpleBuddy *buddy,
                                    PurpleGroup *purple_group)
{
    const gchar *who;
    const gchar *group_name;

    who = purple_buddy_get_name (buddy);
    group_name = purple_group_get_name (purple_group);

    pecan_debug ("who=[%s],group_name=[%s]", who, group_name);

    {
        PecanContact *contact;
        int list_id;
        const gchar *group_guid = NULL;

        list_id = MSN_LIST_FL;
        contact = pecan_contactlist_find_contact (contactlist, who);

        if (group_name)
        {
            PecanGroup *group;

            group = pecan_contactlist_find_group_with_name (contactlist, group_name);

            if (!group)
            {
                /* We must add that group first. */
                request_add_group (contactlist, who, NULL, group_name);
                return;
            }

            group_guid = pecan_group_get_id (group);

#if 0
            pecan_error ("group_guid=[%s]", group_guid);
            pecan_error ("contact=[%p]", contact);
            if (contact)
                pecan_error ("group_count=[%d]", pecan_contact_get_group_count (contact));
#endif

            /* There's no way to add a contact to the no-group. */
            /* Removing from other groups does that. */
            if (contact && pecan_contact_get_group_count (contact) > 0 && !group_guid)
            {
                pecan_error ("trying to add contact to a virtual group: who=[%s]",
                             who);
                msn_session_warning (contactlist->session,
                                     _("Can't add to \"%s\"; it's a virtual group"), group_name);
                purple_blist_remove_buddy (buddy);
                return;
            }
        }

        /* First we're going to check if he's already there. */
        if (contact && contact_is_there (contact, list_id, TRUE, group_guid))
        {
            const gchar *list;

            list = lists[list_id];

            pecan_error ("already there: who=[%s],list=[%s],group_guid=[%s]",
                         who, list, group_guid);

            /* MSN doesn't support the same contact twice in the same group. */
            purple_blist_remove_buddy (buddy);

            return;
        }
    }

    pecan_contactlist_add_buddy (contactlist, who, MSN_LIST_FL, group_name);
}
#endif /* HAVE_LIBPURPLE */
