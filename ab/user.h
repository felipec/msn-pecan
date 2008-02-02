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

#ifndef MSN_USER_H
#define MSN_USER_H

typedef struct MsnUser MsnUser;

#include "session.h"
#include "object.h"

#include "userlist.h"

struct _PurpleStoredImage;

/**
 * Creates a new user structure.
 *
 * @param session      The MSN session.
 * @param passport     The initial passport.
 * @param guid         The contact guid.
 *
 * @return A new user structure.
 */
MsnUser *msn_user_new (MsnUserList *userlist, const gchar *passport, const gchar *guid);

/**
 * Destroys a user structure.
 *
 * @param user The user to destroy.
 */
void msn_user_destroy (MsnUser *user);


/**
 * Updates the user.
 *
 * Communicates with the core to update the ui, etc.
 *
 * @param user The user to update.
 */
void msn_user_update (MsnUser *user);

/**
 * Sets the new state of user.
 *
 * @param user The user.
 * @param state The state string.
 */
void msn_user_set_state (MsnUser *user, const gchar *state);

/**
 * Sets the passport account for a user.
 *
 * @param user     The user.
 * @param passport The passport account.
 */
void msn_user_set_passport (MsnUser *user, const gchar *passport);

/**
 * Sets the friendly name for a user.
 *
 * @param user The user.
 * @param name The friendly name.
 */
void msn_user_set_friendly_name (MsnUser *user, const gchar *name);

/**
 * Sets the store name for a user.
 *
 * @param user The user.
 * @param name The store name.
 */
void msn_user_set_store_name (MsnUser *user, const gchar *name);

/**
 * Sets the contact guid for a user.
 *
 * @param user The user.
 * @param name The contact guid.
 */
void msn_user_set_guid (MsnUser *user, const gchar *guid);

/**
 * Sets the buddy icon for a local user.
 *
 * @param user     The user.
 * @param img      The buddy icon image
 */
void msn_user_set_buddy_icon (MsnUser *user, struct _PurpleStoredImage *img);

/**
 * Adds the group ID for a user.
 *
 * @param user The user.
 * @param id   The group ID.
 */
void msn_user_add_group_id (MsnUser *user, const gchar *group_guid);

/**
 * Removes the group ID from a user.
 *
 * @param user The user.
 * @param id   The group ID.
 */
void msn_user_remove_group_id (MsnUser *user, const gchar *group_guid);

/**
 * Sets the home phone number for a user.
 *
 * @param user   The user.
 * @param number The home phone number.
 */
void msn_user_set_home_phone (MsnUser *user, const gchar *number);

/**
 * Sets the work phone number for a user.
 *
 * @param user   The user.
 * @param number The work phone number.
 */
void msn_user_set_work_phone (MsnUser *user, const gchar *number);

/**
 * Sets the mobile phone number for a user.
 *
 * @param user   The user.
 * @param number The mobile phone number.
 */
void msn_user_set_mobile_phone (MsnUser *user, const gchar *number);

/**
 * Sets the MSNObject for a user.
 *
 * @param user The user.
 * @param obj  The MSNObject.
 */
void msn_user_set_object (MsnUser *user, MsnObject *obj);

/**
 * Sets the client information for a user.
 *
 * @param user The user.
 * @param info The client information.
 */
void msn_user_set_client_caps (MsnUser *user, GHashTable *info);

/**
 * Returns the passport account for a user.
 *
 * @param user The user.
 *
 * @return The passport account.
 */
const gchar *msn_user_get_passport (const MsnUser *user);

/**
 * Returns the friendly name for a user.
 *
 * @param user The user.
 *
 * @return The friendly name.
 */
const gchar *msn_user_get_friendly_name (const MsnUser *user);

/**
 * Returns the store name for a user.
 *
 * @param user The user.
 *
 * @return The store name.
 */
const gchar *msn_user_get_store_name (const MsnUser *user);

/**
 * Returns the home phone number for a user.
 *
 * @param user The user.
 *
 * @return The user's home phone number.
 */
const gchar *msn_user_get_home_phone (const MsnUser *user);

/**
 * Returns the work phone number for a user.
 *
 * @param user The user.
 *
 * @return The user's work phone number.
 */
const gchar *msn_user_get_work_phone (const MsnUser *user);

/**
 * Returns the mobile phone number for a user.
 *
 * @param user The user.
 *
 * @return The user's mobile phone number.
 */
const gchar *msn_user_get_mobile_phone (const MsnUser *user);

/**
 * Returns the MSNObject for a user.
 *
 * @param user The user.
 *
 * @return The MSNObject.
 */
MsnObject *msn_user_get_object (const MsnUser *user);

/**
 * Returns the client information for a user.
 *
 * @param user The user.
 *
 * @return The client information.
 */
GHashTable *msn_user_get_client_caps (const MsnUser *user);

#endif /* MSN_USER_H */
