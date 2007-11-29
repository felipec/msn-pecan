#include "msn.h"

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
