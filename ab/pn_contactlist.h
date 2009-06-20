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

#ifndef PN_CONTACTLIST_H
#define PN_CONTACTLIST_H

typedef struct PnContactList PnContactList;

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

typedef void (*PnContactListFunc) (PnContact *contact, gpointer user_data);

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

PnContactList *pn_contactlist_new (MsnSession *session);
void pn_contactlist_destroy (PnContactList *contactlist);
void pn_contactlist_remove_contact (PnContactList *contactlist,
                                    PnContact *contact);
PnContact *pn_contactlist_find_contact (PnContactList *contactlist,
                                        const gchar *passport);
PnContact *pn_contactlist_find_contact_by_guid (PnContactList *contactlist,
                                                const gchar *contact_guid);
void pn_contactlist_add_group (PnContactList *contactlist, PnGroup *group);
void pn_contactlist_remove_group (PnContactList *contactlist, PnGroup *group);
PnGroup *pn_contactlist_find_group_with_id (PnContactList *contactlist,
                                            const gchar *group_guid);
PnGroup *pn_contactlist_find_group_with_name (PnContactList *contactlist,
                                              const gchar *name);
const gchar *pn_contactlist_find_group_id (PnContactList *contactlist,
                                           const gchar *group_name);
const gchar *pn_contactlist_find_group_name (PnContactList *contactlist,
                                             const gchar *group_guid);
void pn_contactlist_rename_group_id (PnContactList *contactlist,
                                     const gchar *group_guid,
                                     const gchar *new_name);
void pn_contactlist_remove_group_id (PnContactList *contactlist,
                                     const gchar *group_guid);

void pn_contactlist_rem_buddy (PnContactList *contactlist,
                               const gchar *who,
                               gint list_id,
                               const gchar *group_name);
void pn_contactlist_add_buddy (PnContactList *contactlist,
                               const gchar *who,
                               gint list_id,
                               const gchar *group_name);
void pn_contactlist_move_buddy (PnContactList *contactlist,
                                const gchar *who,
                                const gchar *old_group_name,
                                const gchar *new_group_name);
void pn_contactlist_check_pending (PnContactList *contactlist);

void pn_contactlist_add_buddy_helper (PnContactList *contactlist,
                                      struct _PurpleBuddy *buddy,
                                      struct _PurpleGroup *group);

void pn_contactlist_foreach_contact (PnContactList *contactlist,
                                     PnContactListFunc func,
                                     gpointer user_data);

#endif /* PN_CONTACTLIST_H */
