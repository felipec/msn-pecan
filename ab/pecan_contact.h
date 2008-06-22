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

#ifndef PECAN_CONTACT_H
#define PECAN_CONTACT_H

typedef struct PecanContact PecanContact;

#include "session.h"
#if defined(PECAN_CVR)
#include "cvr/pecan_slp_object.h"
#endif /* defined(PECAN_CVR) */

#include "io/pecan_buffer.h"

#include "pecan_contactlist.h"

/**
 * Creates a new contact structure.
 *
 * @param contactlist The ContactList that will contain this contact.
 *
 * @return A new contact structure.
 */
PecanContact *pecan_contact_new (PecanContactList *contactlist);

/**
 * Destroys a contact structure.
 *
 * @param contact The contact to destroy.
 */
void pecan_contact_free (PecanContact *contact);


/**
 * Updates the contact.
 *
 * Communicates with the core to update the ui, etc.
 *
 * @param contact The contact to update.
 */
void pecan_contact_update (PecanContact *contact);

gboolean pecan_contact_is_account (PecanContact *contact);

void pecan_contact_set_client_id (PecanContact *contact, gulong client_id);
gulong pecan_contact_get_client_id (PecanContact *contact);

/**
 * Sets the new state of contact.
 *
 * @param contact The contact.
 * @param state The state string.
 */
void pecan_contact_set_state (PecanContact *contact, const gchar *state);

/**
 * Sets the passport account for a contact.
 *
 * @param contact The contact.
 * @param passport The passport account.
 */
void pecan_contact_set_passport (PecanContact *contact, const gchar *passport);

/**
 * Sets the friendly name for a contact.
 *
 * @param contact The contact.
 * @param name The friendly name.
 */
void pecan_contact_set_friendly_name (PecanContact *contact, const gchar *name);

/**
 * Sets the personal message for a contact.
 *
 * @param contact The contact.
 * @param name The personal message.
 */
void pecan_contact_set_personal_message (PecanContact *contact, const gchar *value);

/**
 * Sets the store name for a contact.
 *
 * @param contact The contact.
 * @param name The store name.
 */
void pecan_contact_set_store_name (PecanContact *contact, const gchar *name);

/**
 * Sets the contact guid for a contact.
 *
 * @param contact The contact.
 * @param name The contact guid.
 */
void pecan_contact_set_guid (PecanContact *contact, const gchar *guid);

/**
 * Sets the buddy icon for a local contact.
 *
 * @param contact The contact.
 * @param img The buddy icon image
 */
void pecan_contact_set_buddy_icon (PecanContact *contact, PecanBuffer *buffer);

/**
 * Adds the group ID for a contact.
 *
 * @param contact The contact.
 * @param id   The group ID.
 */
void pecan_contact_add_group_id (PecanContact *contact, const gchar *group_guid);

/**
 * Removes the group ID from a contact.
 *
 * @param contact The contact.
 * @param id   The group ID.
 */
void pecan_contact_remove_group_id (PecanContact *contact, const gchar *group_guid);

/**
 * Returns the number of groups this contact is in.
 *
 * @return The group count.
 */
guint pecan_contact_get_group_count (PecanContact *contact);

/**
 * Sets the home phone number for a contact.
 *
 * @param contact The contact.
 * @param number The home phone number.
 */
void pecan_contact_set_home_phone (PecanContact *contact, const gchar *number);

/**
 * Sets the work phone number for a contact.
 *
 * @param contact The contact.
 * @param number The work phone number.
 */
void pecan_contact_set_work_phone (PecanContact *contact, const gchar *number);

/**
 * Sets the mobile phone number for a contact.
 *
 * @param contact The contact.
 * @param number The mobile phone number.
 */
void pecan_contact_set_mobile_phone (PecanContact *contact, const gchar *number);

#if defined(PECAN_CVR)
/**
 * Sets the MSNObject for a contact.
 *
 * @param contact The contact.
 * @param obj  The MSNObject.
 */
void pecan_contact_set_object (PecanContact *contact, MsnObject *obj);
#endif /* defined(PECAN_CVR) */

/**
 * Sets the client information for a contact.
 *
 * @param contact The contact.
 * @param info The client information.
 */
void pecan_contact_set_client_caps (PecanContact *contact, GHashTable *info);

/**
 * Returns the passport account for a contact.
 *
 * @param contact The contact.
 *
 * @return The passport account.
 */
const gchar *pecan_contact_get_passport (const PecanContact *contact);

/**
 * Returns the friendly name for a contact.
 *
 * @param contact The contact.
 *
 * @return The friendly name.
 */
const gchar *pecan_contact_get_friendly_name (const PecanContact *contact);

/**
 * Returns the personal message of a contact.
 *
 * @param contact The contact.
 *
 * @return The personal message.
 */
const gchar *pecan_contact_get_personal_message (const PecanContact *contact);

/**
 * Returns the store name for a contact.
 *
 * @param contact The contact.
 *
 * @return The store name.
 */
const gchar *pecan_contact_get_store_name (const PecanContact *contact);

/**
 * Returns the contact's GUID.
 *
 * @param contact The contact.
 *
 * @return The GUID.
 */
const gchar *pecan_contact_get_guid (const PecanContact *contact);

/**
 * Returns the home phone number for a contact.
 *
 * @param contact The contact.
 *
 * @return The contact's home phone number.
 */
const gchar *pecan_contact_get_home_phone (const PecanContact *contact);

/**
 * Returns the work phone number for a contact.
 *
 * @param contact The contact.
 *
 * @return The contact's work phone number.
 */
const gchar *pecan_contact_get_work_phone (const PecanContact *contact);

/**
 * Returns the mobile phone number for a contact.
 *
 * @param contact The contact.
 *
 * @return The contact's mobile phone number.
 */
const gchar *pecan_contact_get_mobile_phone (const PecanContact *contact);

#if defined(PECAN_CVR)
/**
 * Returns the MSNObject for a contact.
 *
 * @param contact The contact.
 *
 * @return The MSNObject.
 */
MsnObject *pecan_contact_get_object (const PecanContact *contact);
#endif /* defined(PECAN_CVR) */

/**
 * Returns the client information for a contact.
 *
 * @param contact The contact.
 *
 * @return The client information.
 */
GHashTable *pecan_contact_get_client_caps (const PecanContact *contact);

#endif /* PECAN_CONTACT_H */
