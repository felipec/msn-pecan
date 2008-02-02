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

#include "pecan_group.h"
#include "pecan_group_priv.h"

PecanGroup *
pecan_group_new (PecanContactList *contactlist,
                 const gchar *name,
                 const gchar *guid)
{
    PecanGroup *group;

    group = g_new0 (PecanGroup, 1);

    group->guid = g_strdup (guid);
    group->name = g_strdup (name);

    if (contactlist)
        pecan_contactlist_add_group (contactlist, group);

    return group;
}

void
pecan_group_free (PecanGroup *group)
{
    g_return_if_fail (group);

    g_free (group->guid);
    g_free (group->name);
    g_free (group);
}

void
pecan_group_set_guid (PecanGroup *group,
                      const gchar *guid)
{
    g_return_if_fail (group);

    g_free (group->guid);
    group->guid = g_strdup (guid);
}

void
pecan_group_set_name (PecanGroup *group,
                      const gchar *name)
{
    g_return_if_fail (group);

    g_free (group->name);
    group->name = g_strdup (name);
}

const gchar *
pecan_group_get_id (const PecanGroup *group)
{
    g_return_val_if_fail (group, NULL);

    return group->guid;
}

const gchar *
pecan_group_get_name (const PecanGroup *group)
{
    g_return_val_if_fail (group, NULL);

    return group->name;
}
