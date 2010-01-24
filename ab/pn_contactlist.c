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

#include "session.h"
#include "pn_contactlist.h"
#include "pn_group.h"
#include "pn_contactlist_priv.h"
#include "pn_contact_priv.h"
#include "pn_log.h"
#include "pn_locale.h"
#include "pn_util.h"

#include "cmd/cmdproc.h"

/** @todo this is disabled for testing only */
#ifdef HAVE_LIBPURPLE
#include "session_private.h"
#endif /* HAVE_LIBPURPLE */
#include "notification.h"

#include <string.h>

#define MSN_NULL_GROUP_NAME "Non-Grouped"

#ifdef HAVE_LIBPURPLE
#include <privacy.h>
#endif /* HAVE_LIBPURPLE */

const char *lists[] = { "FL", "AL", "BL", "RL", "PL" };

typedef struct
{
    MsnSession *session;
    struct pn_contact *contact;
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
    struct pn_contact *contact;

    contact = pa->contact;
    passport = pn_contact_get_passport (contact);

    pn_contactlist_add_buddy (pa->session->contactlist, passport, MSN_LIST_AL, NULL);

    g_free (pa);
}

static void
msn_cancel_add_cb (gpointer data)
{
    MsnPermitAdd *pa = data;
    struct pn_contact *contact;
    const gchar *passport;

    contact = pa->contact;
    passport = pn_contact_get_passport (contact);

    pn_contactlist_add_buddy (pa->session->contactlist, passport, MSN_LIST_BL, NULL);

    g_free (pa);
}

static void
got_new_entry (PurpleConnection *gc,
               struct pn_contact *contact,
               const gchar *friendly)
{
    MsnPermitAdd *pa;
    const gchar *passport;

    passport = pn_contact_get_passport (contact);

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
contact_is_in_group (struct pn_contact *contact,
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
contact_is_there (struct pn_contact *contact,
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
get_store_name (struct pn_contact *contact)
{
    const gchar *store_name;

    g_return_val_if_fail (contact, NULL);

    if (msn_session_get_bool (contact->contactlist->session, "use_server_alias"))
    {
        store_name = pn_contact_get_store_name (contact);
    }
    else
    {
        store_name = pn_contact_get_friendly_name (contact);
    }

    if (!store_name)
        store_name = pn_contact_get_passport (contact);

    return store_name;
}

static void
request_add_group (struct pn_contact_list *contactlist,
                   const gchar *who,
                   const gchar *old_group_name,
                   const gchar *new_group_name)
{
#ifdef HAVE_LIBPURPLE
    MsnCmdProc *cmdproc;
    MsnTransaction *trans;
    MsnMoveBuddy *data;

    cmdproc = contactlist->session->notification->cmdproc;
    data = g_new0 (MsnMoveBuddy, 1);

    data->who = g_strdup (who);

    if (old_group_name)
        data->old_group_name = g_strdup (old_group_name);

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
                     struct pn_contact *contact,
                     MsnListId list_id,
                     const gchar *group_guid)
{
#ifdef HAVE_LIBPURPLE
    PurpleAccount *account;
    const gchar *passport;

    account = msn_session_get_user_data (session);

    passport = pn_contact_get_passport (contact);

    if (list_id == MSN_LIST_FL)
    {
        if (group_guid)
        {
            pn_contact_add_group_id (contact, group_guid);
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

        pn_info ("reverse list add: [%s]", passport);

        if (!(contact->list_op & (MSN_LIST_AL_OP | MSN_LIST_BL_OP)))
        {
            got_new_entry (gc, contact,
                           pn_contact_get_friendly_name (contact));
        }
    }

    contact->list_op |= (1 << list_id);
    /* purple_contact_add_list_id (contact, list_id); */
#endif /* HAVE_LIBPURPLE */
}

void
msn_got_rem_contact (MsnSession *session,
                     struct pn_contact *contact,
                     MsnListId list_id,
                     const gchar *group_guid)
{
#ifdef HAVE_LIBPURPLE
    PurpleAccount *account;
    const gchar *passport;

    account = msn_session_get_user_data (session);

    passport = pn_contact_get_passport (contact);

    if (list_id == MSN_LIST_FL)
    {
        /** @todo when is the contact totally removed? */
        /** when the group count reaches 0, and there's no list_op */
        if (group_guid)
        {
            pn_contact_remove_group_id (contact, group_guid);
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

    contact->list_op &= ~(1 << list_id);
    /* purple_contact_remove_list_id (contact, list_id); */

    if (contact->list_op == 0)
    {
        pn_debug ("no list op: [%s]",
                  passport);
    }
#endif /* HAVE_LIBPURPLE */
}

void
msn_got_lst_contact (MsnSession *session,
                     struct pn_contact *contact,
                     const gchar *extra,
                     gint list_op,
                     GSList *group_ids)
{
#ifdef HAVE_LIBPURPLE
    PurpleAccount *account;
    const gchar *passport;

    account = msn_session_get_user_data (session);

    passport = pn_contact_get_passport (contact);

    pn_debug ("passport=%s,extra=%s,list_op=%d", contact->passport, extra, list_op);

    if (list_op & MSN_LIST_FL_OP)
    {
        if (group_ids)
        {
            GSList *c;
            for (c = group_ids; c; c = g_slist_next (c))
            {
                const gchar *group_guid;
                group_guid = (const gchar *) c->data;
                pn_contact_add_group_id (contact, group_guid);
            }
        }
        else
        {
            pn_contact_add_group_id (contact, NULL);
        }

        if (msn_session_get_bool (session, "use_server_alias"))
        {
            pn_contact_set_store_name (contact, extra);
        }
        else
        {
            pn_contact_set_friendly_name (contact, extra);
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

struct pn_contact_list *
pn_contactlist_new (MsnSession *session)
{
    struct pn_contact_list *contactlist;

    contactlist = g_new0 (struct pn_contact_list, 1);

    contactlist->session = session;

    contactlist->contact_names = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                                                        (GDestroyNotify) pn_contact_free);
    contactlist->contact_guids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    contactlist->group_names = g_hash_table_new_full (g_ascii_strcase_hash, g_ascii_strcase_equal, g_free,
                                                      (GDestroyNotify) pn_group_free);
    contactlist->group_guids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    contactlist->null_group = pn_group_new (contactlist, MSN_NULL_GROUP_NAME, NULL);

    return contactlist;
}

void
pn_contactlist_destroy (struct pn_contact_list *contactlist)
{
    g_hash_table_destroy (contactlist->contact_guids);
    g_hash_table_destroy (contactlist->contact_names);
    g_hash_table_destroy (contactlist->group_guids);
    g_hash_table_destroy (contactlist->group_names);

    g_free (contactlist);
}

void
pn_contactlist_remove_contact (struct pn_contact_list *contactlist,
                               struct pn_contact *contact)
{
    {
        const gchar *guid;
        guid = pn_contact_get_guid (contact);
        if (guid)
            g_hash_table_remove (contactlist->contact_guids, guid);
    }
    g_hash_table_remove (contactlist->contact_names,
                         pn_contact_get_passport (contact));
}

struct pn_contact *
pn_contactlist_find_contact (struct pn_contact_list *contactlist,
                             const gchar *passport)
{
    g_return_val_if_fail (passport, NULL);

    return g_hash_table_lookup (contactlist->contact_names, passport);
}

struct pn_contact *
pn_contactlist_find_contact_by_guid (struct pn_contact_list *contactlist,
                                     const gchar *guid)
{
    g_return_val_if_fail (guid, NULL);

    return g_hash_table_lookup (contactlist->contact_guids, guid);
}

void
pn_contactlist_add_group (struct pn_contact_list *contactlist,
                          struct pn_group *group)
{
    g_hash_table_insert (contactlist->group_names, g_strdup (pn_group_get_name (group)), group);
    {
        const gchar *guid;
        guid = pn_group_get_id (group);
        if (guid)
            g_hash_table_insert (contactlist->group_guids, g_strdup (guid), group);
    }
}

void
pn_contactlist_remove_group (struct pn_contact_list *contactlist,
                             struct pn_group *group)
{
    {
        const gchar *guid;
        guid = pn_group_get_id (group);
        if (guid)
            g_hash_table_remove (contactlist->group_guids, guid);
    }
    g_hash_table_remove (contactlist->group_names, pn_group_get_name (group));
}

struct pn_group *
pn_contactlist_find_group_with_id (struct pn_contact_list *contactlist,
                                   const gchar *guid)
{
    g_return_val_if_fail (contactlist, NULL);

    if (!guid)
        return contactlist->null_group;

    return g_hash_table_lookup (contactlist->group_guids, guid);
}

struct pn_group *
pn_contactlist_find_group_with_name (struct pn_contact_list *contactlist,
                                     const gchar *name)
{
    g_return_val_if_fail (contactlist, NULL);
    g_return_val_if_fail (name, NULL);

    if (g_ascii_strcasecmp (pn_group_get_name (contactlist->null_group), name) == 0)
        return contactlist->null_group;

    return g_hash_table_lookup (contactlist->group_names, name);
}

const gchar *
pn_contactlist_find_group_id (struct pn_contact_list *contactlist,
                              const gchar *group_name)
{
    struct pn_group *group;

    group = pn_contactlist_find_group_with_name (contactlist, group_name);

    if (group)
        return pn_group_get_id (group);
    else
        return NULL;
}

const gchar *
pn_contactlist_find_group_name (struct pn_contact_list *contactlist,
                                const gchar *group_guid)
{
    struct pn_group *group;

    group = pn_contactlist_find_group_with_id (contactlist, group_guid);

    if (group)
        return pn_group_get_name (group);
    else
        return NULL;
}

void
pn_contactlist_rename_group_id (struct pn_contact_list *contactlist,
                                const gchar *group_guid,
                                const gchar *new_name)
{
    struct pn_group *group;

    group = pn_contactlist_find_group_with_id (contactlist, group_guid);

    if (group)
        pn_group_set_name (group, new_name);
}

void
pn_contactlist_remove_group_id (struct pn_contact_list *contactlist,
                                const gchar *group_guid)
{
    struct pn_group *group;

    group = pn_contactlist_find_group_with_id (contactlist, group_guid);

    if (group)
    {
        pn_contactlist_remove_group (contactlist, group);
    }
}

void
pn_contactlist_rem_buddy (struct pn_contact_list *contactlist,
                          const gchar *who,
                          gint list_id,
                          const gchar *group_name)
{
    struct pn_contact *contact;
    const gchar *group_guid;
    const gchar *list;

    contact = pn_contactlist_find_contact (contactlist, who);
    group_guid = NULL;

    pn_debug ("who=[%s],list_id=%d,group_name=[%s]", who, list_id, group_name);

    if (group_name)
    {
        struct pn_group *group;

        group = pn_contactlist_find_group_with_name (contactlist, group_name);

        if (!group)
        {
            /* Whoa, there is no such group. */
            pn_error ("group doesn't exist: group_name=[%s]", group_name);
            return;
        }

        group_guid = pn_group_get_id (group);
    }

    list = lists[list_id];

    /* First we're going to check if not there. */
    if (!(contact_is_there (contact, list_id, group_name != NULL, group_guid)))
    {
        pn_error ("contact not there: who=[%s],list=[%s],group_guid=[%s]",
                  who, list, group_guid);
        return;
    }

#ifdef HAVE_LIBPURPLE
    /* Then request the rem to the server. */
    msn_notification_rem_buddy (contactlist->session->notification, list, who, contact->guid, group_guid);
#endif /* HAVE_LIBPURPLE */
}

void
pn_contactlist_add_buddy (struct pn_contact_list *contactlist,
                          const gchar *who,
                          gint list_id,
                          const gchar *group_name)
{
    struct pn_contact *contact;
    const gchar *group_guid;
    const gchar *contact_guid;
    const gchar *list;
    const gchar *store_name;

    group_guid = NULL;

    pn_debug ("who=[%s],list_id=%d,group_name=[%s]", who, list_id, group_name);

    contact = pn_contactlist_find_contact (contactlist, who);

    if (group_name)
    {
        struct pn_group *group;

        group = pn_contactlist_find_group_with_name (contactlist, group_name);

        if (!group)
        {
            /* We must add that group first. */
            request_add_group (contactlist, who, NULL, group_name);
            return;
        }

        group_guid = pn_group_get_id (group);

        /* There's no way to add a contact to the no-group. */
        /* Removing from other groups does that. */
        if (contact && pn_contact_get_group_count (contact) > 0 && !group_guid)
        {
            pn_error ("trying to add contact to a virtual group: who=[%s]",
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
pn_contactlist_move_buddy (struct pn_contact_list *contactlist,
                           const gchar *who,
                           const gchar *old_group_name,
                           const gchar *new_group_name)
{
    struct pn_group *old_group;
    struct pn_group *new_group;
    const gchar *old_group_guid;

    pn_debug ("who=[%s],old_group_name=[%s],new_group_name=[%s]",
              who, old_group_name, new_group_name);

    old_group = pn_contactlist_find_group_with_name (contactlist, old_group_name);
    new_group = pn_contactlist_find_group_with_name (contactlist, new_group_name);

    old_group_guid = pn_group_get_id (old_group);

    /** @todo handle the situation where more than one buddy are being moved at
     * the same time. */
    if (!new_group)
    {
        request_add_group (contactlist, who, old_group_name, new_group_name);
        return;
    }

    pn_contactlist_add_buddy (contactlist, who, MSN_LIST_FL, new_group_name);
    if (old_group_guid)
        pn_contactlist_rem_buddy (contactlist, who, MSN_LIST_FL, old_group_name);
}

static void
contact_check_pending (gpointer key,
                       gpointer value,
                       gpointer user_data)
{
    const gchar *passport;
    struct pn_contact *contact;
    struct pn_contact_list *contactlist;

    passport = key;
    contact = value;
    contactlist = user_data;

    if (contact->list_op & MSN_LIST_PL_OP)
    {
        /* These are contacts who are pending for... something. */

        pn_contactlist_add_buddy (contactlist, passport, MSN_LIST_RL, NULL);
        pn_contactlist_rem_buddy (contactlist, passport, MSN_LIST_PL, NULL);
    }
}

void
pn_contactlist_check_pending (struct pn_contact_list *contactlist)
{
    g_hash_table_foreach (contactlist->contact_names, contact_check_pending, contactlist);
}

typedef struct
{
    pn_contact_list_func_t func;
    gpointer user_data;
} EachContactData;

static void
contact_each (gpointer key,
              gpointer value,
              gpointer user_data)
{
    EachContactData *tmp;
    tmp = user_data;
    tmp->func (value, tmp->user_data);
}

void
pn_contactlist_foreach_contact (struct pn_contact_list *contactlist,
                                pn_contact_list_func_t func,
                                gpointer user_data)
{
    EachContactData *tmp = g_new0 (EachContactData, 1);
    tmp->func = func;
    tmp->user_data = user_data;
    g_hash_table_foreach (contactlist->contact_names, contact_each, tmp);
    g_free (tmp);
}

#ifdef HAVE_LIBPURPLE
/**************************************************************************
 * Purple functions
 **************************************************************************/
void
pn_contactlist_add_buddy_helper (struct pn_contact_list *contactlist,
                                 PurpleBuddy *buddy,
                                 PurpleGroup *purple_group)
{
    const gchar *who;
    const gchar *group_name;

    who = purple_buddy_get_name (buddy);
    group_name = purple_group_get_name (purple_group);

    pn_debug ("who=[%s],group_name=[%s]", who, group_name);

    {
        struct pn_contact *contact;
        int list_id;
        const gchar *group_guid = NULL;

        list_id = MSN_LIST_FL;
        contact = pn_contactlist_find_contact (contactlist, who);

        if (group_name)
        {
            struct pn_group *group;

            group = pn_contactlist_find_group_with_name (contactlist, group_name);

            if (!group)
            {
                /* We must add that group first. */
                request_add_group (contactlist, who, NULL, group_name);
                return;
            }

            group_guid = pn_group_get_id (group);

#if 0
            pn_error ("group_guid=[%s]", group_guid);
            pn_error ("contact=[%p]", contact);
            if (contact)
                pn_error ("group_count=[%d]", pn_contact_get_group_count (contact));
#endif

            /* There's no way to add a contact to the no-group. */
            /* Removing from other groups does that. */
            if (contact && pn_contact_get_group_count (contact) > 0 && !group_guid)
            {
                pn_error ("trying to add contact to a virtual group: who=[%s]",
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

            pn_error ("already there: who=[%s],list=[%s],group_guid=[%s]",
                      who, list, group_guid);

            /* MSN doesn't support the same contact twice in the same group. */
            purple_blist_remove_buddy (buddy);

            return;
        }
    }

    pn_contactlist_add_buddy (contactlist, who, MSN_LIST_FL, group_name);
}
#endif /* HAVE_LIBPURPLE */
