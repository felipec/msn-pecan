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

#ifndef MSN_USERLIST_H
#define MSN_USERLIST_H

typedef struct MsnUserList MsnUserList;

#include "user.h"
#include "group.h"

#include "cmd/cmdproc.h"

typedef enum
{
    MSN_LIST_FL,
    MSN_LIST_AL,
    MSN_LIST_BL,
    MSN_LIST_RL,
    MSN_LIST_PL
} MsnListId;

typedef enum
{
    MSN_LIST_FL_OP = 0x01,
    MSN_LIST_AL_OP = 0x02,
    MSN_LIST_BL_OP = 0x04,
    MSN_LIST_RL_OP = 0x08,
    MSN_LIST_PL_OP = 0x10
} MsnListOp;

struct _PurpleBuddy;
struct _PurpleGroup;

MsnListId msn_get_list_id (const gchar *list);

void msn_got_add_user (MsnSession *session, MsnUser *user, MsnListId list_id, const gchar *group_guid);
void msn_got_rem_user (MsnSession *session, MsnUser *user, MsnListId list_id, const gchar *group_guid);
void msn_got_lst_user (MsnSession *session, MsnUser *user, const gchar *extra, gint list_op, GSList *group_ids);

MsnUserList *msn_userlist_new (MsnSession *session);
void msn_userlist_destroy (MsnUserList *userlist);
void msn_userlist_add_user (MsnUserList *userlist, MsnUser *user);
void msn_userlist_remove_user (MsnUserList *userlist, MsnUser *user);
MsnUser *msn_userlist_find_user (MsnUserList *userlist, const gchar *passport);
MsnUser *msn_userlist_find_user_by_guid (MsnUserList *userlist, const gchar *user_guid);
void msn_userlist_add_group (MsnUserList *userlist, MsnGroup *group);
void msn_userlist_remove_group (MsnUserList *userlist, MsnGroup *group);
MsnGroup *msn_userlist_find_group_with_id (MsnUserList *userlist, const gchar *group_guid);
MsnGroup *msn_userlist_find_group_with_name (MsnUserList *userlist, const gchar *name);
const gchar *msn_userlist_find_group_id (MsnUserList *userlist, const gchar *group_name);
const gchar *msn_userlist_find_group_name (MsnUserList *userlist, const gchar *group_guid);
void msn_userlist_rename_group_id (MsnUserList *userlist, const gchar *group_guid, const gchar *new_name);
void msn_userlist_remove_group_id (MsnUserList *userlist, const gchar *group_guid);

void msn_userlist_rem_buddy (MsnUserList *userlist, const gchar *who, gint list_id, const gchar *group_name);
void msn_userlist_add_buddy (MsnUserList *userlist, const gchar *who, gint list_id, const gchar *group_name);
void msn_userlist_move_buddy (MsnUserList *userlist, const gchar *who, const gchar *old_group_name, const gchar *new_group_name);

void msn_userlist_add_buddy_helper (MsnUserList *userlist, struct _PurpleBuddy *buddy, struct _PurpleGroup *group);

#endif /* MSN_USERLIST_H */
