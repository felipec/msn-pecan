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

#include "pn_group.h"

/**
 * A group.
 */
struct PnGroup
{
    gchar *guid; /**< The GUID. */
    gchar *name; /**< The name. */
};

PnGroup *
pn_group_new (PecanContactList *contactlist,
              const gchar *name,
              const gchar *guid)
{
    PnGroup *group;

    group = g_new0 (PnGroup, 1);

    group->guid = g_strdup (guid);
    group->name = g_strdup (name);

    if (contactlist)
        pecan_contactlist_add_group (contactlist, group);

    return group;
}

void
pn_group_free (PnGroup *group)
{
    if (!group)
        return;

    g_free (group->guid);
    g_free (group->name);
    g_free (group);
}

void
pn_group_set_guid (PnGroup *group,
                   const gchar *guid)
{
    g_free (group->guid);
    group->guid = g_strdup (guid);
}

void
pn_group_set_name (PnGroup *group,
                   const gchar *name)
{
    g_free (group->name);
    group->name = g_strdup (name);
}

const gchar *
pn_group_get_id (const PnGroup *group)
{
    return group->guid;
}

const gchar *
pn_group_get_name (const PnGroup *group)
{
    return group->name;
}
