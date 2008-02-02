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
#include "userlist.h"
#include "userlist_priv.h"
#include "user_priv.h"
#include "msn_log.h"

#include "session_private.h"
#include "notification.h"

#include <string.h>

#include "fix-purple.h"
#include "msn_intl.h"

/* libpurple stuff. */
#include <privacy.h>

const char *lists[] = { "FL", "AL", "BL", "RL" };

typedef struct
{
    MsnSession *session;
    gchar *who;
} MsnPermitAdd;

/**************************************************************************
 * Callbacks
 **************************************************************************/
static void
msn_accept_add_cb (gpointer data)
{
    MsnPermitAdd *pa = data;

    msn_userlist_add_buddy (pa->session->userlist, pa->who, MSN_LIST_AL, NULL);

    g_free (pa->who);
    g_free (pa);
}

static void
msn_cancel_add_cb (gpointer data)
{
    MsnPermitAdd *pa = data;

    msn_userlist_add_buddy (pa->session->userlist, pa->who, MSN_LIST_BL, NULL);

    g_free (pa->who);
    g_free (pa);
}

static void
got_new_entry (PurpleConnection *gc,
               const gchar *passport,
               const gchar *friendly)
{
    MsnPermitAdd *pa;

    pa = g_new0 (MsnPermitAdd, 1);
    pa->who = g_strdup (passport);
    pa->session = gc->proto_data;

    purple_account_request_authorization (purple_connection_get_account (gc), passport, NULL, NULL, NULL,
                                          purple_find_buddy (purple_connection_get_account (gc), passport) != NULL,
                                          msn_accept_add_cb, msn_cancel_add_cb, pa);
}

/**************************************************************************
 * Utility functions
 **************************************************************************/

static gboolean
user_is_in_group (MsnUser *user,
                  const gchar *group_guid)
{
    if (!user)
        return FALSE;

    if (!group_guid)
    {
        if (g_list_length (user->group_ids) == 0)
            return TRUE;

        return FALSE;
    }

    if (g_list_find_custom (user->group_ids, group_guid, (GCompareFunc) strcmp))
        return TRUE;

    return FALSE;
}

static gboolean
user_is_there (MsnUser *user,
               gint list_id,
               const gchar *group_guid)
{
    int list_op;

    if (!user)
        return FALSE;

    list_op = 1 << list_id;

    if (!(user->list_op & list_op))
        return FALSE;

    if (list_id == MSN_LIST_FL)
    {
        return user_is_in_group (user, group_guid);
    }

    return TRUE;
}

static const gchar*
get_store_name (MsnUser *user)
{
    const gchar *store_name;

    g_return_val_if_fail (user, NULL);

    store_name = msn_user_get_store_name (user);

    if (store_name)
        store_name = purple_url_encode (store_name);
    else
        store_name = msn_user_get_passport (user);

    return store_name;
}

static void
msn_request_add_group (MsnUserList *userlist,
                       const gchar *who,
                       const gchar *old_group_name,
                       const gchar *new_group_name)
{
    MsnCmdProc *cmdproc;
    MsnTransaction *trans;
    MsnMoveBuddy *data;

    cmdproc = userlist->session->notification->cmdproc;
    data = g_new0 (MsnMoveBuddy, 1);

    data->who = g_strdup (who);

    if (old_group_name)
        data->old_group_name = g_strdup (old_group_name);

    trans = msn_transaction_new (cmdproc, "ADG", "%s %d",
                                 purple_url_encode (new_group_name),
                                 0);

    msn_transaction_set_data (trans, data);

    msn_cmdproc_send_trans (cmdproc, trans);
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

    return -1;
}

void
msn_got_add_user (MsnSession *session,
                  MsnUser *user,
                  MsnListId list_id,
                  const gchar *group_guid)
{
    PurpleAccount *account;
    const gchar *passport;

    account = session->account;

    passport = msn_user_get_passport (user);

    if (list_id == MSN_LIST_FL)
    {
        PurpleConnection *gc;

        gc = purple_account_get_connection (account);

        if (group_guid)
        {
            msn_user_add_group_id (user, group_guid);
        }
        else
        {
            /* session->sync->fl_users_count++; */
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
        PurpleConversation *convo;

        gc = purple_account_get_connection (account);

        msn_info ("rever list add: [%s]",
                  passport);

        convo = purple_find_conversation_with_account (PURPLE_CONV_TYPE_IM, passport, account);
        if (convo)
        {
            PurpleBuddy *buddy;
            gchar *msg;

            buddy = purple_find_buddy (account, passport);
            msg = g_strdup_printf (_("%s has added you to his or her buddy list."),
                                   buddy ? purple_buddy_get_contact_alias(buddy) : passport);
            purple_conv_im_write (PURPLE_CONV_IM (convo), passport, msg,
                                  PURPLE_MESSAGE_SYSTEM, time (NULL));
            g_free (msg);
        }

        if (!(user->list_op & (MSN_LIST_AL_OP | MSN_LIST_BL_OP)))
        {
            got_new_entry (gc, passport,
                           msn_user_get_friendly_name (user));
        }
    }

    user->list_op |= (1 << list_id);
    /* purple_user_add_list_id (user, list_id); */
}

void
msn_got_rem_user (MsnSession *session,
                  MsnUser *user,
                  MsnListId list_id,
                  const gchar *group_guid)
{
    PurpleAccount *account;
    const gchar *passport;

    account = session->account;

    passport = msn_user_get_passport (user);

    if (list_id == MSN_LIST_FL)
    {
        /* TODO: When is the user totally removed? */
        if (group_guid)
        {
            msn_user_remove_group_id (user, group_guid);
            return;
        }
        else
        {
            /* session->sync->fl_users_count--; */
        }
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

        msn_info ("rever list rem: [%s]",
                  passport);

        convo = purple_find_conversation_with_account (PURPLE_CONV_TYPE_IM, passport, account);
        if (convo)
        {
            PurpleBuddy *buddy;
            gchar *msg;

            buddy = purple_find_buddy (account, passport);
            msg = g_strdup_printf (_("%s has removed you from his or her buddy list."),
                                   buddy ? purple_buddy_get_contact_alias (buddy) : passport);
            purple_conv_im_write (PURPLE_CONV_IM (convo), passport, msg,
                                  PURPLE_MESSAGE_SYSTEM, time (NULL));
            g_free (msg);
        }
    }

    user->list_op &= ~(1 << list_id);
    /* purple_user_remove_list_id (user, list_id); */

    if (user->list_op == 0)
    {
        msn_debug ("no list op: [%s]",
                   passport);
    }
}

void
msn_got_lst_user (MsnSession *session,
                  MsnUser *user,
                  const gchar *extra,
                  gint list_op,
                  GSList *group_ids)
{
    PurpleConnection *gc;
    PurpleAccount *account;
    const gchar *passport;

    account = session->account;
    gc = purple_account_get_connection (account);

    passport = msn_user_get_passport (user);

    if (list_op & MSN_LIST_FL_OP)
    {
        if (group_ids)
        {
            GSList *c;
            for (c = group_ids; c; c = g_slist_next (c))
            {
                const gchar *group_guid;
                group_guid = (const gchar *) c->data;
                msn_user_add_group_id (user, group_guid);
            }
        }
        else
        {
            msn_user_add_group_id (user, NULL);
        }

        msn_user_set_store_name (user, extra);
    }

    if (list_op & MSN_LIST_AL_OP)
    {
        /* These are users who are allowed to see our status. */
        purple_privacy_deny_remove (account, passport, TRUE);
        purple_privacy_permit_add (account, passport, TRUE);
    }

    if (list_op & MSN_LIST_BL_OP)
    {
        /* These are users who are not allowed to see our status. */
        purple_privacy_permit_remove (account, passport, TRUE);
        purple_privacy_deny_add (account, passport, TRUE);
    }

    if (list_op & MSN_LIST_RL_OP)
    {
        /* These are users who have us on their buddy list. */

        if (!(list_op & (MSN_LIST_AL_OP | MSN_LIST_BL_OP)))
        {
            got_new_entry (gc, passport, extra);
            /* msn_user_set_friendly_name(user, extra); */
        }
    }

    user->list_op = list_op;
}

/**************************************************************************
 * UserList functions
 **************************************************************************/

MsnUserList *
msn_userlist_new (MsnSession *session)
{
    MsnUserList *userlist;

    userlist = g_new0 (MsnUserList, 1);

    userlist->session = session;
    userlist->buddy_icon_requests = g_queue_new ();

    userlist->null_group = msn_group_new (userlist, NULL, "NULL");

    /* buddy_icon_window is the number of allowed simultaneous buddy icon requests.
     * XXX With smarter rate limiting code, we could allow more at once... 5 was the limit set when
     * we weren't retrieiving any more than 5 per MSN session. */
    userlist->buddy_icon_window = 1;

    return userlist;
}

void
msn_userlist_destroy (MsnUserList *userlist)
{
    GList *l;

    for (l = userlist->users; l; l = l->next)
    {
        msn_user_destroy (l->data);
    }

    g_list_free (userlist->users);

    for (l = userlist->groups; l; l = l->next)
    {
        msn_group_destroy (l->data);
    }

    g_list_free (userlist->groups);

    g_queue_free (userlist->buddy_icon_requests);

    if (userlist->buddy_icon_request_timer)
        purple_timeout_remove (userlist->buddy_icon_request_timer);

    g_free (userlist);
}

void
msn_userlist_add_user (MsnUserList *userlist,
                       MsnUser *user)
{
    userlist->users = g_list_prepend (userlist->users, user);
}

void
msn_userlist_remove_user (MsnUserList *userlist,
                          MsnUser *user)
{
    userlist->users = g_list_remove (userlist->users, user);
}

MsnUser *
msn_userlist_find_user (MsnUserList *userlist,
                        const gchar *passport)
{
    GList *l;

    g_return_val_if_fail (passport, NULL);

    for (l = userlist->users; l; l = l->next)
    {
        MsnUser *user = (MsnUser *) l->data;

        g_return_val_if_fail (user->passport, NULL);

        if (!strcmp (passport, user->passport))
            return user;
    }

    return NULL;
}

MsnUser *
msn_userlist_find_user_by_guid (MsnUserList *userlist,
                                const gchar *guid)
{
    GList *l;

    g_return_val_if_fail (guid, NULL);

    for (l = userlist->users; l; l = l->next)
    {
        MsnUser *user = (MsnUser *) l->data;

        g_return_val_if_fail (user->guid, NULL);

        if (strcmp (guid, user->guid) == 0)
            return user;
    }

    return NULL;
}

void
msn_userlist_add_group (MsnUserList *userlist,
                        MsnGroup *group)
{
    userlist->groups = g_list_append (userlist->groups, group);
}

void
msn_userlist_remove_group (MsnUserList *userlist,
                           MsnGroup *group)
{
    userlist->groups = g_list_remove (userlist->groups, group);
}

MsnGroup *
msn_userlist_find_group_with_id (MsnUserList *userlist,
                                 const gchar *guid)
{
    GList *l;

    g_return_val_if_fail (userlist, NULL);

    if (!guid)
        return userlist->null_group;

    for (l = userlist->groups; l; l = l->next)
    {
        MsnGroup *group = l->data;
        const gchar *group_guid;

        group_guid = msn_group_get_id (group);

        if (group_guid && strcmp (group_guid, guid) == 0)
            return group;
    }

    return NULL;
}

MsnGroup *
msn_userlist_find_group_with_name (MsnUserList *userlist,
                                   const gchar *name)
{
    GList *l;

    g_return_val_if_fail (userlist, NULL);
    g_return_val_if_fail (name, NULL);

    for (l = userlist->groups; l; l = l->next)
    {
        MsnGroup *group = l->data;
        const gchar *group_name = msn_group_get_name (group);

        if ((group_name) && !g_ascii_strcasecmp (name, group_name))
            return group;
    }

    return NULL;
}

const gchar *
msn_userlist_find_group_id (MsnUserList *userlist,
                            const gchar *group_name)
{
    MsnGroup *group;

    group = msn_userlist_find_group_with_name (userlist, group_name);

    if (group)
        return msn_group_get_id (group);
    else
        return NULL;
}

const gchar *
msn_userlist_find_group_name (MsnUserList *userlist,
                              const gchar *group_guid)
{
    MsnGroup *group;

    group = msn_userlist_find_group_with_id (userlist, group_guid);

    if (group)
        return msn_group_get_name (group);
    else
        return NULL;
}

void
msn_userlist_rename_group_id (MsnUserList *userlist,
                              const gchar *group_guid,
                              const gchar *new_name)
{
    MsnGroup *group;

    group = msn_userlist_find_group_with_id (userlist, group_guid);

    if (group)
        msn_group_set_name (group, new_name);
}

void
msn_userlist_remove_group_id (MsnUserList *userlist,
                              const gchar *group_guid)
{
    MsnGroup *group;

    group = msn_userlist_find_group_with_id (userlist, group_guid);

    if (group)
    {
        msn_userlist_remove_group (userlist, group);
        msn_group_destroy (group);
    }
}

void
msn_userlist_rem_buddy (MsnUserList *userlist,
                        const gchar *who,
                        gint list_id,
                        const gchar *group_name)
{
    MsnUser *user;
    const gchar *group_guid;
    const gchar *list;

    user = msn_userlist_find_user (userlist, who);
    group_guid = NULL;

    if (group_name)
    {
        group_guid = msn_userlist_find_group_id (userlist, group_name);

        if (!group_guid)
        {
            /* Whoa, there is no such group. */
            msn_error ("group doesn't exist: [%s]", group_name);
            return;
        }
    }

    list = lists[list_id];

    /* First we're going to check if not there. */
    if (!(user_is_there (user, list_id, group_guid)))
    {
        msn_error ("user not there: who=[%s],list=[%s]",
                   who, list);
        return;
    }

    /* Then request the rem to the server. */
    msn_notification_rem_buddy (userlist->session->notification, list, who, user->guid, group_guid);
}

void
msn_userlist_add_buddy (MsnUserList *userlist,
                        const gchar *who,
                        gint list_id,
                        const gchar *group_name)
{
    MsnUser *user;
    const gchar *group_guid;
    const gchar *user_guid;
    const gchar *list;
    const gchar *store_name;

    group_guid = NULL;

    if (group_name)
    {
        group_guid = msn_userlist_find_group_id (userlist, group_name);

        if (!group_guid)
        {
            /* Whoa, we must add that group first. */
            msn_request_add_group (userlist, who, NULL, group_name);
            return;
        }
    }

    user = msn_userlist_find_user (userlist, who);

    store_name = (user != NULL) ? get_store_name (user) : who;
    user_guid = (user != NULL) ? user->guid : NULL;

    list = lists[list_id];

    msn_notification_add_buddy (userlist->session->notification, list, who, user_guid, store_name, group_guid);
}

void
msn_userlist_move_buddy (MsnUserList *userlist,
                         const gchar *who,
                         const gchar *old_group_name,
                         const gchar *new_group_name)
{
    const gchar *new_group_guid;

    new_group_guid = msn_userlist_find_group_id (userlist, new_group_name);

    if (!new_group_guid)
    {
        msn_request_add_group (userlist, who, old_group_name, new_group_name);
        return;
    }

    msn_userlist_add_buddy (userlist, who, MSN_LIST_FL, new_group_name);
    if (old_group_name)
        msn_userlist_rem_buddy (userlist, who, MSN_LIST_FL, old_group_name);
}

/**************************************************************************
 * Purple functions
 **************************************************************************/
void
msn_userlist_add_buddy_helper (MsnUserList *userlist,
                               PurpleBuddy *buddy,
                               PurpleGroup *group)
{
    const gchar *who;
    const gchar *group_name;

    who = purple_buddy_get_name (buddy);
    group_name = purple_group_get_name (group);

    {
        MsnUser *user;
        int list_id;
        const gchar *group_guid = NULL;

        list_id = MSN_LIST_FL;
        user = msn_userlist_find_user (userlist, who);

        if (group_name != NULL)
        {
            group_guid = msn_userlist_find_group_id (userlist, group_name);

            if (!group_guid)
            {
                /* Whoa, we must add that group first. */
                msn_request_add_group (userlist, who, NULL, group_name);
                return;
            }

            if (user && msn_user_get_group_ids (user) && !group_guid)
            {
                msn_error ("trying to add user to a virtual group: who=[%s]",
                           who);
                purple_blist_remove_buddy (buddy);
                return;
            }
        }

        /* First we're going to check if it's already there. */
        if (user_is_there (user, list_id, group_guid))
        {
            const gchar *list;

            list = lists[list_id];
            if ((list_id == MSN_LIST_FL) && (group_guid))
            {
                msn_error ("already there: who=[%s],list=[%s],group_name=[%s]",
                           who, list, group_name);
            }
            else
            {
                msn_error ("already there: who=[%s],list=[%s]",
                           who, list);
            }

            purple_blist_remove_buddy (buddy);

            return;
        }
    }

    msn_userlist_add_buddy (userlist, who, MSN_LIST_FL, group_name);
}
