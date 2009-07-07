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

#include <glib.h>

#include "ab/pn_group.h"

struct MsnNotification;

void
msn_notification_add_buddy (struct MsnNotification *notification,
                            const gchar *list,
                            const gchar *who,
                            const gchar *user_guid,
                            const gchar *store_name,
                            const gchar *group_guid)
{

}

void
msn_notification_rem_buddy (struct MsnNotification *notification,
                            const gchar *list,
                            const gchar *who,
                            const gchar *user_guid,
                            const gchar *group_guid)
{
}

void
basic_group_tests (void)
{
    struct pn_group *group;

    group = pn_group_new (NULL, "foo", "bar");
    pn_group_free (group);

    group = pn_group_new (NULL, "bar", NULL);
    pn_group_set_guid (group, "foo");
    pn_group_set_name (group, "other name");
    pn_group_free (group);

    group = pn_group_new (NULL, NULL, NULL);
    pn_group_set_guid (group, NULL);
    pn_group_set_name (group, NULL);
    pn_group_free (group);
}

void
basic_contact_tests (void)
{
    struct pn_contact *contact;

    contact = pn_contact_new (NULL, "foo@bar.com", "12345678");
    pn_contact_free (contact);

    contact = pn_contact_new (NULL, "bar", NULL);
    pn_contact_set_guid (contact, "foo");
    pn_contact_set_passport (contact, "other name");
    pn_contact_free (contact);

    contact = pn_contact_new (NULL, NULL, NULL);
    pn_contact_set_guid (contact, NULL);
    pn_contact_set_passport (contact, NULL);
    pn_contact_free (contact);
}

int
main (int argc,
      char *argv[])
{
    g_type_init ();

    basic_group_tests ();
    basic_contact_tests ();

    return 0;
}
