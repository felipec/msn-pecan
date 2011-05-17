/**
 * Copyright (C) 2008-2009 Felipe Contreras
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

#ifndef PN_CONTACT_PRIV_H
#define PN_CONTACT_PRIV_H

#include <glib.h>

struct pn_contact_list;

#include "pn_status.h"

#if defined(PECAN_CVR)
struct pn_msnobj;
#endif /* defined(PECAN_CVR) */

/**
 * Current media.
 */
typedef enum
{
    CURRENT_MEDIA_UNKNOWN,
    CURRENT_MEDIA_MUSIC,
    CURRENT_MEDIA_GAMES,
    CURRENT_MEDIA_OFFICE
} CurrentMediaType;

typedef struct _CurrentMedia
{
    CurrentMediaType type;     /**< Type.   */
    gchar *title;    /**< Title.  */
    gchar *artist;   /**< Artist. */
    gchar *album;    /**< Album.  */
} CurrentMedia;

/**
 * A contact.
 */
struct pn_contact {
    struct pn_contact_list *contactlist;

    gchar *passport; /**< The passport account. */
    gchar *store_name; /**< The name stored in the server. */
    gchar *friendly_name; /**< The friendly name. */
    gchar *personal_message; /**< The personal message. */
    gchar *client_name; /**< The client name/version. */
    CurrentMedia media; /**< The current media. */
    gchar *guid; /**< The GUID. Only present for contacts in our FL. */

    PecanStatus status;

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
    struct pn_msnobj *msnobj; /**< The contact's MSN Object. */
#endif /* defined(PECAN_CVR) */

    GHashTable *clientcaps; /**< The client's capabilities. */
    gulong client_id;

    gint list_op;

    gint sent_oims;

    gint dp_failed_attempts;
};

#endif /* PN_CONTACT_PRIV_H */
