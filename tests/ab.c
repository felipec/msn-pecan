#include <glib.h>

#include "ab/pecan_group.h"

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
    PecanGroup *group;

    group = pecan_group_new (NULL, "foo", "bar");
    pecan_group_free (group);

    group = pecan_group_new (NULL, "bar", NULL);
    pecan_group_set_guid (group, "foo");
    pecan_group_set_name (group, "other name");
    pecan_group_free (group);

    group = pecan_group_new (NULL, NULL, NULL);
    pecan_group_set_guid (group, NULL);
    pecan_group_set_name (group, NULL);
    pecan_group_free (group);
}

void
basic_contact_tests (void)
{
    PecanContact *contact;

    contact = pecan_contact_new (NULL, "foo@bar.com", "12345678");
    pecan_contact_free (contact);

    contact = pecan_contact_new (NULL, "bar", NULL);
    pecan_contact_set_guid (contact, "foo");
    pecan_contact_set_passport (contact, "other name");
    pecan_contact_free (contact);

    contact = pecan_contact_new (NULL, NULL, NULL);
    pecan_contact_set_guid (contact, NULL);
    pecan_contact_set_passport (contact, NULL);
    pecan_contact_free (contact);
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
