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
#include "pn_contactlist.h"

/**
 * A group.
 */
struct pn_group {
    gchar *guid; /**< The GUID. */
    gchar *name; /**< The name. */
};

struct pn_group *
pn_group_new (struct pn_contact_list *contactlist,
              const gchar *name,
              const gchar *guid)
{
    struct pn_group *group;

    group = g_new0 (struct pn_group, 1);

    group->guid = g_strdup (guid);
    group->name = g_strdup (name);

    if (contactlist)
        pn_contactlist_add_group (contactlist, group);

    return group;
}

void
pn_group_free (struct pn_group *group)
{
    if (!group)
        return;

    g_free (group->guid);
    g_free (group->name);
    g_free (group);
}

void
pn_group_set_guid (struct pn_group *group,
                   const gchar *guid)
{
    g_free (group->guid);
    group->guid = g_strdup (guid);
}

void
pn_group_set_name (struct pn_group *group,
                   const gchar *name)
{
    g_free (group->name);
    group->name = g_strdup (name);
}

const gchar *
pn_group_get_id (const struct pn_group *group)
{
    return group->guid;
}

const gchar *
pn_group_get_name (const struct pn_group *group)
{
    return group->name;
}
