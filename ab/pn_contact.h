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

typedef struct PnContact PnContact;

#include "session.h"
#if defined(PECAN_CVR)
#include "cvr/pn_msnobj.h"
#endif /* defined(PECAN_CVR) */

#include "io/pn_buffer.h"

#include "pn_contactlist.h"

/**
 * Creates a new contact structure.
 *
 * @param contactlist The ContactList that will contain this contact.
 *
 * @return A new contact structure.
 */
PnContact *pn_contact_new (PnContactList *contactlist);

/**
 * Destroys a contact structure.
 *
 * @param contact The contact to destroy.
 */
void pn_contact_free (PnContact *contact);


/**
 * Updates the contact.
 *
 * Communicates with the core to update the ui, etc.
 *
 * @param contact The contact to update.
 */
void pn_contact_update (PnContact *contact);

gboolean pn_contact_is_account (PnContact *contact);

void pn_contact_set_client_id (PnContact *contact,
                               gulong client_id);
gulong pn_contact_get_client_id (PnContact *contact);

/**
 * Sets the new state of contact.
 *
 * @param contact The contact.
 * @param state The state string.
 */
void pn_contact_set_state (PnContact *contact,
                           const gchar *state);

/**
 * Sets the passport account for a contact.
 *
 * @param contact The contact.
 * @param passport The passport account.
 */
void pn_contact_set_passport (PnContact *contact,
                              const gchar *passport);

/**
 * Sets the friendly name for a contact.
 *
 * @param contact The contact.
 * @param name The friendly name.
 */
void pn_contact_set_friendly_name (PnContact *contact,
                                   const gchar *name);

/**
 * Sets the personal message for a contact.
 *
 * @param contact The contact.
 * @param name The personal message.
 */
void pn_contact_set_personal_message (PnContact *contact,
                                      const gchar *value);

/**
 * Sets the current media for a contact.
 *
 * @param contact The contact.
 * @param current_media The current media.
 */
void pn_contact_set_current_media (PnContact *contact,
                                   const gchar *current_media);

/**
 * Sets the store name for a contact.
 *
 * @param contact The contact.
 * @param name The store name.
 */
void pn_contact_set_store_name (PnContact *contact,
                                const gchar *name);

/**
 * Sets the contact guid for a contact.
 *
 * @param contact The contact.
 * @param name The contact guid.
 */
void pn_contact_set_guid (PnContact *contact,
                          const gchar *guid);

/**
 * Sets the buddy icon for a local contact.
 *
 * @param contact The contact.
 * @param img The buddy icon image
 */
void pn_contact_set_buddy_icon (PnContact *contact,
                                PnBuffer *buffer);

/**
 * Adds the group ID for a contact.
 *
 * @param contact The contact.
 * @param id   The group ID.
 */
void pn_contact_add_group_id (PnContact *contact,
                              const gchar *group_guid);

/**
 * Removes the group ID from a contact.
 *
 * @param contact The contact.
 * @param id   The group ID.
 */
void pn_contact_remove_group_id (PnContact *contact,
                                 const gchar *group_guid);

/**
 * Returns the number of groups this contact is in.
 *
 * @return The group count.
 */
guint pn_contact_get_group_count (PnContact *contact);

/**
 * Sets the home phone number for a contact.
 *
 * @param contact The contact.
 * @param number The home phone number.
 */
void pn_contact_set_home_phone (PnContact *contact,
                                const gchar *number);

/**
 * Sets the work phone number for a contact.
 *
 * @param contact The contact.
 * @param number The work phone number.
 */
void pn_contact_set_work_phone (PnContact *contact,
                                const gchar *number);

/**
 * Sets the mobile phone number for a contact.
 *
 * @param contact The contact.
 * @param number The mobile phone number.
 */
void pn_contact_set_mobile_phone (PnContact *contact,
                                  const gchar *number);

#if defined(PECAN_CVR)
/**
 * Sets the MSNObject for a contact.
 *
 * @param contact The contact.
 * @param obj  The MSNObject.
 */
void pn_contact_set_object (PnContact *contact,
                            PnMsnObj *obj);
#endif /* defined(PECAN_CVR) */

/**
 * Sets the client information for a contact.
 *
 * @param contact The contact.
 * @param info The client information.
 */
void pn_contact_set_client_caps (PnContact *contact,
                                 GHashTable *info);

/**
 * Returns the passport account for a contact.
 *
 * @param contact The contact.
 *
 * @return The passport account.
 */
const gchar *pn_contact_get_passport (const PnContact *contact);

/**
 * Returns the friendly name for a contact.
 *
 * @param contact The contact.
 *
 * @return The friendly name.
 */
const gchar *pn_contact_get_friendly_name (const PnContact *contact);

/**
 * Returns the personal message of a contact.
 *
 * @param contact The contact.
 *
 * @return The personal message.
 */
const gchar *pn_contact_get_personal_message (const PnContact *contact);

/**
 * Returns the store name for a contact.
 *
 * @param contact The contact.
 *
 * @return The store name.
 */
const gchar *pn_contact_get_store_name (const PnContact *contact);

/**
 * Returns the contact's GUID.
 *
 * @param contact The contact.
 *
 * @return The GUID.
 */
const gchar *pn_contact_get_guid (const PnContact *contact);

/**
 * Returns the home phone number for a contact.
 *
 * @param contact The contact.
 *
 * @return The contact's home phone number.
 */
const gchar *pn_contact_get_home_phone (const PnContact *contact);

/**
 * Returns the work phone number for a contact.
 *
 * @param contact The contact.
 *
 * @return The contact's work phone number.
 */
const gchar *pn_contact_get_work_phone (const PnContact *contact);

/**
 * Returns the mobile phone number for a contact.
 *
 * @param contact The contact.
 *
 * @return The contact's mobile phone number.
 */
const gchar *pn_contact_get_mobile_phone (const PnContact *contact);

#if defined(PECAN_CVR)
/**
 * Returns the MSNObject for a contact.
 *
 * @param contact The contact.
 *
 * @return The MSNObject.
 */
PnMsnObj *pn_contact_get_object (const PnContact *contact);
#endif /* defined(PECAN_CVR) */

/**
 * Returns the client information for a contact.
 *
 * @param contact The contact.
 *
 * @return The client information.
 */
GHashTable *pn_contact_get_client_caps (const PnContact *contact);

gboolean pn_contact_can_receive (const PnContact *contact);

#endif /* PN_CONTACT_H */
