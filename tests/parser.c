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
#include <glib/gstdio.h>

#include <fcntl.h>

#include "io/pecan_parser.h"
#include "io/pecan_node_priv.h"
#include "io/pecan_stream.h"

START_TEST (test_basic)
{
    PecanNode *node;

    node = pecan_node_new ("foo", 0);
    pecan_node_free (node);
}
END_TEST

START_TEST (test_simple)
{
    PecanNode *node;
    PecanParser *parser;
    gchar *str;
    gsize terminator_pos;
    gint fd;

    node = pecan_node_new ("foo", 0);
    parser = pecan_parser_new (node);

    fd = g_open ("stream_test/000", O_RDONLY);
    node->stream = pecan_stream_new (fd);
    pecan_parser_read_line (parser, &str, NULL, &terminator_pos, NULL);
    if (str)
    {
        str[terminator_pos] = '\0';
        g_debug ("str={%s}", str);
    }

    pecan_parser_free (parser);
    pecan_node_free (node);
}
END_TEST

START_TEST (test_through)
{
    PecanNode *node;
    PecanParser *parser;
    gchar *str;
    gsize terminator_pos;
    gint fd;

    node = pecan_node_new ("foo", 0);
    parser = pecan_parser_new (node);

    fd = g_open ("stream_test/000", O_RDONLY);
    node->stream = pecan_stream_new (fd);
    {
        GIOStatus status;

        do
        {
            status = pecan_parser_read_line (parser, &str, NULL, &terminator_pos, NULL);
            if (str)
            {
                str[terminator_pos] = '\0';
                g_debug ("str={%s}", str);
            }
        } while (status == G_IO_STATUS_NORMAL);
    }

    pecan_parser_free (parser);
    pecan_node_free (node);
}
END_TEST

START_TEST (test_cut)
{
    PecanNode *node;
    PecanParser *parser;
    gchar *str;
    gsize terminator_pos;
    gint fd;

    node = pecan_node_new ("foo", 0);
    parser = pecan_parser_new (node);

    fd = g_open ("stream_test/001", O_RDONLY);
    node->stream = pecan_stream_new (fd);
    {
        GIOStatus status;

        do
        {
            status = pecan_parser_read_line (parser, &str, NULL, &terminator_pos, NULL);
            if (str)
            {
                str[terminator_pos] = '\0';
                g_debug ("str={%s}", str);
            }
        } while (status == G_IO_STATUS_NORMAL);
    }

    pecan_parser_free (parser);
    pecan_node_free (node);
}
END_TEST

START_TEST (test_span)
{
    PecanNode *node;
    PecanParser *parser;
    gchar *str;
    gsize terminator_pos;
    gint fd;

    node = pecan_node_new ("foo", 0);
    parser = pecan_parser_new (node);

    fd = g_open ("stream_test/001", O_RDONLY);
    node->stream = pecan_stream_new (fd);
    {
        GIOStatus status;
        do
        {
            status = pecan_parser_read_line (parser, &str, NULL, &terminator_pos, NULL);
            if (str)
            {
                str[terminator_pos] = '\0';
                g_debug ("str={%s}", str);
            }
        } while (status == G_IO_STATUS_NORMAL);
    }
    pecan_stream_free (node->stream);

    fd = g_open ("stream_test/002", O_RDONLY);
    node->stream = pecan_stream_new (fd);
    {
        GIOStatus status;
        do
        {
            status = pecan_parser_read_line (parser, &str, NULL, &terminator_pos, NULL);
            if (str)
            {
                str[terminator_pos] = '\0';
                g_debug ("str={%s}", str);
            }
        } while (status == G_IO_STATUS_NORMAL);
    }

    pecan_parser_free (parser);
    pecan_node_free (node);
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
