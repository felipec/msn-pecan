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

#ifndef PN_CONTACT_H
#define PN_CONTACT_H

#include <glib.h>

struct pn_contact;
struct pn_contact_list;
struct pn_group;

struct pn_buffer;

#include "session.h"
#if defined(PECAN_CVR)
struct pn_msnobj;
#endif /* defined(PECAN_CVR) */

/**
 * Creates a new contact structure.
 *
 * @param contactlist The ContactList that will contain this contact.
 *
 * @return A new contact structure.
 */
struct pn_contact *pn_contact_new (struct pn_contact_list *contactlist);

/**
 * Destroys a contact structure.
 *
 * @param contact The contact to destroy.
 */
void pn_contact_free (struct pn_contact *contact);


/**
 * Updates the contact.
 *
 * Communicates with the core to update the ui, etc.
 *
 * @param contact The contact to update.
 */
void pn_contact_update (struct pn_contact *contact);

gboolean pn_contact_is_account (struct pn_contact *contact);

void pn_contact_set_client_id (struct pn_contact *contact,
                               gulong client_id);
gulong pn_contact_get_client_id (struct pn_contact *contact);

/**
 * Sets the new state of contact.
 *
 * @param contact The contact.
 * @param state The state string.
 */
void pn_contact_set_state (struct pn_contact *contact,
                           const gchar *state);

/**
 * Sets the passport account for a contact.
 *
 * @param contact The contact.
 * @param passport The passport account.
 */
void pn_contact_set_passport (struct pn_contact *contact,
                              const gchar *passport);

/**
 * Sets the friendly name for a contact.
 *
 * @param contact The contact.
 * @param name The friendly name.
 */
void pn_contact_set_friendly_name (struct pn_contact *contact,
                                   const gchar *name);

/**
 * Sets the personal message for a contact.
 *
 * @param contact The contact.
 * @param name The personal message.
 */
void pn_contact_set_personal_message (struct pn_contact *contact,
                                      const gchar *value);

/**
 * Sets the current media for a contact.
 *
 * @param contact The contact.
 * @param current_media The current media.
 */
void pn_contact_set_current_media (struct pn_contact *contact,
                                   const gchar *current_media);

/**
 * Sets the store name for a contact.
 *
 * @param contact The contact.
 * @param name The store name.
 */
void pn_contact_set_store_name (struct pn_contact *contact,
                                const gchar *name);

/**
 * Sets the contact guid for a contact.
 *
 * @param contact The contact.
 * @param name The contact guid.
 */
void pn_contact_set_guid (struct pn_contact *contact,
                          const gchar *guid);

/**
 * Sets the buddy icon for a local contact.
 *
 * @param contact The contact.
 * @param img The buddy icon image
 */
void pn_contact_set_buddy_icon (struct pn_contact *contact,
                                struct pn_buffer *buffer);

/**
 * Adds the group ID for a contact.
 *
 * @param contact The contact.
 * @param id   The group ID.
 */
void pn_contact_add_group_id (struct pn_contact *contact,
                              const gchar *group_guid);

/**
 * Removes the group ID from a contact.
 *
 * @param contact The contact.
 * @param id   The group ID.
 */
void pn_contact_remove_group_id (struct pn_contact *contact,
                                 const gchar *group_guid);

/**
 * Returns the number of groups this contact is in.
 *
 * @return The group count.
 */
guint pn_contact_get_group_count (struct pn_contact *contact);

gboolean pn_contact_is_in_group (struct pn_contact *contact,
                                 struct pn_group *group);

/**
 * Sets the home phone number for a contact.
 *
 * @param contact The contact.
 * @param number The home phone number.
 */
void pn_contact_set_home_phone (struct pn_contact *contact,
                                const gchar *number);

/**
 * Sets the work phone number for a contact.
 *
 * @param contact The contact.
 * @param number The work phone number.
 */
void pn_contact_set_work_phone (struct pn_contact *contact,
                                const gchar *number);

/**
 * Sets the mobile phone number for a contact.
 *
 * @param contact The contact.
 * @param number The mobile phone number.
 */
void pn_contact_set_mobile_phone (struct pn_contact *contact,
                                  const gchar *number);

#if defined(PECAN_CVR)
/**
 * Sets the MSNObject for a contact.
 *
 * @param contact The contact.
 * @param obj  The MSNObject.
 */
void pn_contact_set_object (struct pn_contact *contact,
                            struct pn_msnobj *obj);
#endif /* defined(PECAN_CVR) */

/**
 * Sets the client information for a contact.
 *
 * @param contact The contact.
 * @param info The client information.
 */
void pn_contact_set_client_caps (struct pn_contact *contact,
                                 GHashTable *info);

#if defined(PECAN_CVR)
void pn_contact_update_object (struct pn_contact *contact);
#endif /* defined(PECAN_CVR) */

/**
 * Returns the passport account for a contact.
 *
 * @param contact The contact.
 *
 * @return The passport account.
 */
const gchar *pn_contact_get_passport (const struct pn_contact *contact);

/**
 * Returns the friendly name for a contact.
 *
 * @param contact The contact.
 *
 * @return The friendly name.
 */
const gchar *pn_contact_get_friendly_name (const struct pn_contact *contact);

/**
 * Returns the personal message of a contact.
 *
 * @param contact The contact.
 *
 * @return The personal message.
 */
const gchar *pn_contact_get_personal_message (const struct pn_contact *contact);

/**
 * Returns the store name for a contact.
 *
 * @param contact The contact.
 *
 * @return The store name.
 */
const gchar *pn_contact_get_store_name (const struct pn_contact *contact);

/**
 * Returns the contact's GUID.
 *
 * @param contact The contact.
 *
 * @return The GUID.
 */
const gchar *pn_contact_get_guid (const struct pn_contact *contact);

/**
 * Returns the home phone number for a contact.
 *
 * @param contact The contact.
 *
 * @return The contact's home phone number.
 */
const gchar *pn_contact_get_home_phone (const struct pn_contact *contact);

/**
 * Returns the work phone number for a contact.
 *
 * @param contact The contact.
 *
 * @return The contact's work phone number.
 */
const gchar *pn_contact_get_work_phone (const struct pn_contact *contact);

/**
 * Returns the mobile phone number for a contact.
 *
 * @param contact The contact.
 *
 * @return The contact's mobile phone number.
 */
const gchar *pn_contact_get_mobile_phone (const struct pn_contact *contact);

#if defined(PECAN_CVR)
/**
 * Returns the MSNObject for a contact.
 *
 * @param contact The contact.
 *
 * @return The MSNObject.
 */
struct pn_msnobj *pn_contact_get_object (const struct pn_contact *contact);
#endif /* defined(PECAN_CVR) */

/**
 * Returns the client information for a contact.
 *
 * @param contact The contact.
 *
 * @return The client information.
 */
GHashTable *pn_contact_get_client_caps (const struct pn_contact *contact);

gboolean pn_contact_is_blocked (const struct pn_contact *contact);

gboolean pn_contact_can_receive (const struct pn_contact *contact);

const gchar *pn_contact_get_client_name (struct pn_contact *contact);

void pn_contact_set_client_name (struct pn_contact *contact,
                                 const gchar *client_name);

#endif /* PN_CONTACT_H */
