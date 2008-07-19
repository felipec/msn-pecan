/**
 * Copyright (C) 2007-2008 Felipe Contreras
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

#include <check.h>

#include <glib.h>
#include "io/pecan_buffer.h"

#include <string.h>

static guint times = 0x10;

/** @todo tests should be split */

START_TEST (test_basic)
{
    PecanBuffer *buf;

    buf = pecan_buffer_new ();
    pecan_buffer_free (buf);

    buf = pecan_buffer_new_and_alloc (PECAN_BUF_SIZE);
    pecan_buffer_free (buf);

    buf = pecan_buffer_new ();
    pecan_buffer_resize (buf, PECAN_BUF_SIZE);
    pecan_buffer_free (buf);

    buf = pecan_buffer_new_and_alloc (PECAN_BUF_SIZE);
    pecan_buffer_resize (buf, 2 * PECAN_BUF_SIZE);
    pecan_buffer_free (buf);

    buf = pecan_buffer_new_and_alloc (PECAN_BUF_SIZE);
    pecan_buffer_prepare (buf, 2 * PECAN_BUF_SIZE);
    pecan_buffer_free (buf);
}
END_TEST

static void
prepare_helper (guint times,
                gboolean write)
{
    PecanBuffer *buf;
    guint i;

    buf = pecan_buffer_new ();
    pecan_buffer_free (buf);

    buf = pecan_buffer_new_and_alloc (PECAN_BUF_SIZE);
    for (i = 0; i < times; i++)
    {
        pecan_buffer_prepare (buf, i * PECAN_BUF_SIZE);
        if (write) memset (buf->data, 0, buf->size);
    }
    pecan_buffer_free (buf);

    buf = pecan_buffer_new ();
    pecan_buffer_resize (buf, PECAN_BUF_SIZE);
    for (i = 0; i < times; i++)
    {
        pecan_buffer_prepare (buf, i * PECAN_BUF_SIZE);
        if (write) memset (buf->data, 0, buf->size);
    }
    pecan_buffer_free (buf);

    buf = pecan_buffer_new_and_alloc (PECAN_BUF_SIZE);
    for (i = 0; i < times; i++)
    {
        pecan_buffer_prepare (buf, i * g_random_double ());
        if (write) memset (buf->data, 0, buf->size);
    }
    pecan_buffer_free (buf);

    buf = pecan_buffer_new ();
    pecan_buffer_resize (buf, PECAN_BUF_SIZE);
    for (i = 0; i < times; i++)
    {
        pecan_buffer_prepare (buf, i * g_random_double ());
        if (write) memset (buf->data, 0, buf->size);
    }
    pecan_buffer_free (buf);
}

START_TEST (test_prepare)
{
    prepare_helper (times, FALSE);
}
END_TEST

START_TEST (test_prepare_write)
{
    prepare_helper (times, TRUE);
}
END_TEST

Suite *
util_suite (void)
{
    Suite *s = suite_create ("util");

    /* Core test case */
    TCase *tc_core = tcase_create ("Core");
    tcase_add_test (tc_core, test_basic);
    tcase_add_test (tc_core, test_prepare);
    tcase_add_test (tc_core, test_prepare_write);
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
