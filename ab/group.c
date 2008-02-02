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

#include "group.h"
#include "group_priv.h"

MsnGroup *
msn_group_new (MsnUserList *userlist,
               const gchar *guid,
               const gchar *name)
{
    MsnGroup *group;

    g_return_val_if_fail (userlist, NULL);

    group = g_new0 (MsnGroup, 1);

    if (guid)
        group->guid = g_strdup (guid);

    group->name = g_strdup (name);

    msn_userlist_add_group (userlist, group);

    return group;
}

void
msn_group_destroy (MsnGroup *group)
{
    g_return_if_fail (group);

    g_free (group->guid);
    g_free (group->name);
    g_free (group);
}

void
msn_group_set_id (MsnGroup *group,
                  const gchar *guid)
{
    g_return_if_fail (group);

    g_free (group->guid);

    if (guid)
        group->guid = g_strdup (guid);
}

void
msn_group_set_name (MsnGroup *group,
                    const gchar *name)
{
    g_return_if_fail (group);
    g_return_if_fail (name);

    g_free (group->name);
    group->name = g_strdup (name);
}

const gchar *
msn_group_get_id (const MsnGroup *group)
{
    g_return_val_if_fail (group, NULL);

    return group->guid;
}

const gchar *
msn_group_get_name (const MsnGroup *group)
{
    g_return_val_if_fail (group, NULL);

    return group->name;
}