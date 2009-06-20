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

#ifndef PECAN_CONTACTLIST_H
#define PECAN_CONTACTLIST_H

typedef struct PecanContactList PecanContactList;

#include "pn_contact.h"
#include "pn_group.h"

#include "cmd/cmdproc.h"

typedef enum
{
    MSN_LIST_FL,
    MSN_LIST_AL,
    MSN_LIST_BL,
    MSN_LIST_RL,
    MSN_LIST_PL,
} MsnListId;

typedef enum
{
    MSN_LIST_FL_OP = 0x01,
    MSN_LIST_AL_OP = 0x02,
    MSN_LIST_BL_OP = 0x04,
    MSN_LIST_RL_OP = 0x08,
    MSN_LIST_PL_OP = 0x10,
} MsnListOp;

typedef void (*PecanContactListFunc) (PnContact *contact, gpointer user_data);

struct _PurpleBuddy;
struct _PurpleGroup;

MsnListId msn_get_list_id (const gchar *list);

void msn_got_add_contact (MsnSession *session,
                          PnContact *contact,
                          MsnListId list_id,
                          const gchar *group_guid);
void msn_got_rem_contact (MsnSession *session,
                          PnContact *contact,
                          MsnListId list_id,
                          const gchar *group_guid);
void msn_got_lst_contact (MsnSession *session,
                          PnContact *contact,
                          const gchar *extra,
                          gint list_op,
                          GSList *group_ids);

PecanContactList *pecan_contactlist_new (MsnSession *session);
void pecan_contactlist_destroy (PecanContactList *contactlist);
void pecan_contactlist_remove_contact (PecanContactList *contactlist,
                                       PnContact *contact);
PnContact *pecan_contactlist_find_contact (PecanContactList *contactlist,
                                              const gchar *passport);
PnContact *pecan_contactlist_find_contact_by_guid (PecanContactList *contactlist,
                                                      const gchar *contact_guid);
void pecan_contactlist_add_group (PecanContactList *contactlist, PnGroup *group);
void pecan_contactlist_remove_group (PecanContactList *contactlist, PnGroup *group);
PnGroup *pecan_contactlist_find_group_with_id (PecanContactList *contactlist,
                                                  const gchar *group_guid);
PnGroup *pecan_contactlist_find_group_with_name (PecanContactList *contactlist,
                                                    const gchar *name);
const gchar *pecan_contactlist_find_group_id (PecanContactList *contactlist,
                                              const gchar *group_name);
const gchar *pecan_contactlist_find_group_name (PecanContactList *contactlist,
                                                const gchar *group_guid);
void pecan_contactlist_rename_group_id (PecanContactList *contactlist,
                                        const gchar *group_guid,
                                        const gchar *new_name);
void pecan_contactlist_remove_group_id (PecanContactList *contactlist,
                                        const gchar *group_guid);

void pecan_contactlist_rem_buddy (PecanContactList *contactlist,
                                  const gchar *who,
                                  gint list_id,
                                  const gchar *group_name);
void pecan_contactlist_add_buddy (PecanContactList *contactlist,
                                  const gchar *who,
                                  gint list_id,
                                  const gchar *group_name);
void pecan_contactlist_move_buddy (PecanContactList *contactlist,
                                   const gchar *who,
                                   const gchar *old_group_name,
                                   const gchar *new_group_name);
void pecan_contactlist_check_pending (PecanContactList *contactlist);

void pecan_contactlist_add_buddy_helper (PecanContactList *contactlist,
                                         struct _PurpleBuddy *buddy,
                                         struct _PurpleGroup *group);

void pecan_contactlist_foreach_contact (PecanContactList *contactlist,
                                        PecanContactListFunc func,
                                        gpointer user_data);

#endif /* PECAN_CONTACTLIST_H */
