/**
 * Copyright (C) 2008 Felipe Contreras
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

#ifndef PECAN_CONTACT_PRIV_H
#define PECAN_CONTACT_PRIV_H

#include <glib.h>

#include "pecan_contactlist.h"
#if defined(PECAN_CVR)
#include "cvr/pecan_slp_object.h"
#endif /* defined(PECAN_CVR) */

/**
 * A contact.
 */
struct PecanContact
{
    PecanContactList *contactlist;

    gchar *passport; /**< The passport account. */
    gchar *store_name; /**< The name stored in the server. */
    gchar *friendly_name; /**< The friendly name. */
    gchar *personal_message; /**< The personal message. */
    gchar *guid; /**< The GUID. Only present for contacts in our FL. */

    const gchar *status; /**< The state of the contact. */
    gboolean idle; /**< The idle state of the contact. */

    struct
    {
        gchar *home; /**< Home phone number. */
        gchar *work; /**< Work phone number. */
        gchar *mobile; /**< Mobile phone number. */

    } phone;

    gboolean authorized; /**< Authorized to add this contact. */
    gboolean mobile; /**< Signed up with MSN Mobile. */

    GHashTable *groups; /**< The groups this contact is on. */

#if defined(PECAN_CVR)
    MsnObject *msnobj; /**< The contact's MSN Object. */
#endif /* defined(PECAN_CVR) */

    GHashTable *clientcaps; /**< The client's capabilities. */
    gulong client_id;

    gint list_op;
};

#endif /* PECAN_CONTACT_PRIV_H */
