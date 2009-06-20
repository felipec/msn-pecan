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

#include <check.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <fcntl.h>

#include "io/pn_parser.h"
#include "io/pn_node_private.h"
#include "io/pn_stream.h"

START_TEST (test_basic)
{
    PnNode *node;

    node = pn_node_new ("foo", 0);
    pn_node_free (node);
}
END_TEST

START_TEST (test_simple)
{
    PnNode *node;
    PnParser *parser;
    gchar *str;
    gsize terminator_pos;
    gint fd;

    node = pn_node_new ("foo", 0);
    parser = pn_parser_new (node);

    fd = g_open ("stream_test/000", O_RDONLY);
    node->stream = pn_stream_new (fd);
    pn_parser_read_line (parser, &str, NULL, &terminator_pos, NULL);
    if (str)
    {
        str[terminator_pos] = '\0';
        g_debug ("str={%s}", str);
    }

    pn_parser_free (parser);
    pn_node_free (node);
}
END_TEST

START_TEST (test_through)
{
    PnNode *node;
    PnParser *parser;
    gchar *str;
    gsize terminator_pos;
    gint fd;

    node = pn_node_new ("foo", 0);
    parser = pn_parser_new (node);

    fd = g_open ("stream_test/000", O_RDONLY);
    node->stream = pn_stream_new (fd);
    {
        GIOStatus status;

        do
        {
            status = pn_parser_read_line (parser, &str, NULL, &terminator_pos, NULL);
            if (str)
            {
                str[terminator_pos] = '\0';
                g_debug ("str={%s}", str);
            }
        } while (status == G_IO_STATUS_NORMAL);
    }

    pn_parser_free (parser);
    pn_node_free (node);
}
END_TEST

START_TEST (test_cut)
{
    PnNode *node;
    PnParser *parser;
    gchar *str;
    gsize terminator_pos;
    gint fd;

    node = pn_node_new ("foo", 0);
    parser = pn_parser_new (node);

    fd = g_open ("stream_test/001", O_RDONLY);
    node->stream = pn_stream_new (fd);
    {
        GIOStatus status;

        do
        {
            status = pn_parser_read_line (parser, &str, NULL, &terminator_pos, NULL);
            if (str)
            {
                str[terminator_pos] = '\0';
                g_debug ("str={%s}", str);
            }
        } while (status == G_IO_STATUS_NORMAL);
    }

    pn_parser_free (parser);
    pn_node_free (node);
}
END_TEST

START_TEST (test_span)
{
    PnNode *node;
    PnParser *parser;
    gchar *str;
    gsize terminator_pos;
    gint fd;

    node = pn_node_new ("foo", 0);
    parser = pn_parser_new (node);

    fd = g_open ("stream_test/001", O_RDONLY);
    node->stream = pn_stream_new (fd);
    {
        GIOStatus status;
        do
        {
            status = pn_parser_read_line (parser, &str, NULL, &terminator_pos, NULL);
            if (str)
            {
                str[terminator_pos] = '\0';
                g_debug ("str={%s}", str);
            }
        } while (status == G_IO_STATUS_NORMAL);
    }
    pn_stream_free (node->stream);

    fd = g_open ("stream_test/002", O_RDONLY);
    node->stream = pn_stream_new (fd);
    {
        GIOStatus status;
        do
        {
            status = pn_parser_read_line (parser, &str, NULL, &terminator_pos, NULL);
            if (str)
            {
                str[terminator_pos] = '\0';
                g_debug ("str={%s}", str);
            }
        } while (status == G_IO_STATUS_NORMAL);
    }

    pn_parser_free (parser);
    pn_node_free (node);
}
END_TEST

Suite *
util_suite (void)
{
    Suite *s = suite_create ("util");

    g_type_init ();

    /* Core test case */
    TCase *tc_core = tcase_create ("Core");
    tcase_add_test (tc_core, test_basic);
    tcase_add_test (tc_core, test_simple);
    tcase_add_test (tc_core, test_through);
    tcase_add_test (tc_core, test_cut);
    tcase_add_test (tc_core, test_span);
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
