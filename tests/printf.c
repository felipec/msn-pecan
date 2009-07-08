/**
 * Copyright (C) 2008-2009 Felipe Contreras
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

#include <check.h>
#include "pn_printf.h"

static inline void
t_printf (const char *expect,
          const char *format,
          ...)
{
    char *buffer;
    va_list args;

    va_start (args, format);
    buffer = pn_strdup_vprintf (format, args);
    va_end (args);

    ck_assert_str_eq (buffer, expect);

    g_free (buffer);
}

START_TEST (test_printf)
{
    t_printf ("hello world!", "hello world!");
    t_printf ("hello world!", "hello %s!", "world");
    t_printf ("(null)", "%s", NULL);
    t_printf ("3", "%d", 3);
    t_printf ("3", "%i", 3);
    t_printf ("-3", "%d", -3);
    t_printf ("0xd", "%p", 13);
    t_printf ("(nil)", "%p", NULL);
    t_printf ("3", "%u", 3);
    t_printf ("4294967293", "%u", -3);
    t_printf ("3", "%lu", 3);
    t_printf ("4294967293", "%lu", -3);
    t_printf ("a", "%c", 'a');
    t_printf ("D", "%X", 13);
    t_printf ("   D", "%4X", 13);
    t_printf ("000D", "%.4X", 13);
    t_printf ("000D", "%04X", 13);
    t_printf ("foo", "%.*s", 3, "foobar");

}
END_TEST

Suite *
util_suite (void)
{
    Suite *s = suite_create ("util");

    /* Core test case */
    TCase *tc_core = tcase_create ("Core");
    tcase_add_test (tc_core, test_printf);
    suite_add_tcase (s, tc_core);

    return s;
}

int
main (void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = util_suite ();
    sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);

    return (number_failed == 0) ? 0 : 1;
}
