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

struct pn_contact_list;
struct pn_contact;
struct pn_group;

struct MsnSession;

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

typedef void (*pn_contact_list_func_t) (struct pn_contact *contact, gpointer user_data);

struct _PurpleBuddy;
struct _PurpleGroup;

MsnListId msn_get_list_id (const gchar *list);

void msn_got_add_contact (struct MsnSession *session,
                          struct pn_contact *contact,
                          MsnListId list_id,
                          const gchar *group_guid);
void msn_got_rem_contact (struct MsnSession *session,
                          struct pn_contact *contact,
                          MsnListId list_id,
                          const gchar *group_guid);
void msn_got_lst_contact (struct MsnSession *session,
                          struct pn_contact *contact,
                          const gchar *extra,
                          gint list_op,
                          GSList *group_ids);

struct pn_contact_list *pn_contactlist_new (struct MsnSession *session);
void pn_contactlist_destroy (struct pn_contact_list *contactlist);
void pn_contactlist_remove_contact (struct pn_contact_list *contactlist,
                                    struct pn_contact *contact);
struct pn_contact *pn_contactlist_find_contact (struct pn_contact_list *contactlist,
                                                const gchar *passport);
struct pn_contact *pn_contactlist_find_contact_by_guid (struct pn_contact_list *contactlist,
                                                        const gchar *contact_guid);
void pn_contactlist_add_group (struct pn_contact_list *contactlist, struct pn_group *group);
void pn_contactlist_remove_group (struct pn_contact_list *contactlist, struct pn_group *group);
struct pn_group *pn_contactlist_find_group_with_id (struct pn_contact_list *contactlist,
                                                    const gchar *group_guid);
struct pn_group *pn_contactlist_find_group_with_name (struct pn_contact_list *contactlist,
                                                      const gchar *name);
const gchar *pn_contactlist_find_group_id (struct pn_contact_list *contactlist,
                                           const gchar *group_name);
const gchar *pn_contactlist_find_group_name (struct pn_contact_list *contactlist,
                                             const gchar *group_guid);
void pn_contactlist_rename_group_id (struct pn_contact_list *contactlist,
                                     const gchar *group_guid,
                                     const gchar *new_name);
void pn_contactlist_remove_group_id (struct pn_contact_list *contactlist,
                                     const gchar *group_guid);

void pn_contactlist_rem_buddy (struct pn_contact_list *contactlist,
                               const gchar *who,
                               gint list_id,
                               const gchar *group_name);
void pn_contactlist_add_buddy (struct pn_contact_list *contactlist,
                               const gchar *who,
                               gint list_id,
                               const gchar *group_name);
void pn_contactlist_move_buddy (struct pn_contact_list *contactlist,
                                const gchar *who,
                                const gchar *old_group_name,
                                const gchar *new_group_name);
void pn_contactlist_check_pending (struct pn_contact_list *contactlist);

void pn_contactlist_add_buddy_helper (struct pn_contact_list *contactlist,
                                      struct _PurpleBuddy *buddy,
                                      struct _PurpleGroup *group);

void pn_contactlist_foreach_contact (struct pn_contact_list *contactlist,
                                     pn_contact_list_func_t func,
                                     gpointer user_data);

#endif /* PN_CONTACTLIST_H */
