/**
 * Copyright (C) 2007-2009 Felipe Contreras
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

#include "fix_purple.h"

/* libpurple stuff. */
#include <connection.h>

void
purple_buddy_set_private_alias (PurpleConnection *gc,
                                const gchar *who,
                                const gchar *value)
{
    PurpleAccount *account;
    GSList *buddies;
    PurpleBuddy *b;

    account = purple_connection_get_account (gc);
    buddies = purple_find_buddies (account, who);

    while (buddies)
    {
        b = buddies->data;
        buddies = g_slist_delete_link (buddies, buddies);

        if (g_strcmp0 (b->alias, value) == 0)
            continue;

        purple_blist_alias_buddy (b, value);
    }
}

void
purple_buddy_set_public_alias (PurpleConnection *gc,
                               const gchar *who,
                               const gchar *value)
{
    PurpleAccount *account;
    GSList *buddies;
    PurpleBuddy *b;

    account = purple_connection_get_account (gc);
    buddies = purple_find_buddies (account, who);

    while (buddies)
    {
        b = buddies->data;
        buddies = g_slist_delete_link (buddies, buddies);

        if (g_strcmp0 (b->server_alias, value) == 0)
            continue;

        purple_blist_server_alias_buddy (b, value);
    }
}
