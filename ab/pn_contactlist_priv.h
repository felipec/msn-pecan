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

#ifndef PN_CONTACTLIST_PRIV_H
#define PN_CONTACTLIST_PRIV_H

#include <glib.h>

struct pn_group;

struct MsnSesion;

typedef struct
{
    gchar *who;
    gchar *old_group_name;
} MsnMoveBuddy;

struct pn_contact_list {
    struct MsnSession *session;

    GHashTable *contact_names;
    GHashTable *contact_guids;
    GHashTable *group_names;
    GHashTable *group_guids;
    struct pn_group *null_group;
};

#endif /* PN_CONTACTLIST_PRIV_H */
