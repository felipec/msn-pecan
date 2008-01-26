/**
 * Copyright (C) 2007-2008 Felipe Contreras
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "msn.h"
#include "fix-purple.h"

#include <string.h> /* for strcmp. */

/* libpurple stuff. */
#include <connection.h>

void
fix_purple_buddy_set_alias (PurpleConnection *gc,
                            const char *who,
                            const char *alias)
{
    PurpleAccount *account = purple_connection_get_account (gc);
    GSList *buddies = purple_find_buddies (account, who);
    PurpleBuddy *b;

    while (buddies != NULL)
    {
        b = buddies->data;
        buddies = g_slist_delete_link (buddies, buddies);

        if ((b->alias == NULL && alias == NULL) ||
            (b->alias && alias && !strcmp (b->alias, alias)))
        {
            continue;
        }

        purple_blist_alias_buddy (b, alias);
    }
}

void
fix_purple_buddy_set_friendly (PurpleConnection *gc,
                               const char *who,
                               const char *friendly)
{
    PurpleAccount *account = purple_connection_get_account (gc);
    GSList *buddies = purple_find_buddies (account, who);
    PurpleBuddy *b;

    while (buddies != NULL)
    {
        b = buddies->data;
        buddies = g_slist_delete_link (buddies, buddies);

        if ((b->server_alias == NULL && friendly == NULL) ||
            (b->server_alias && friendly && !strcmp (b->server_alias, friendly)))
        {
            continue;
        }

        purple_blist_server_alias_buddy (b, friendly);
    }
}
