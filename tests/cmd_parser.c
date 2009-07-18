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

#include <glib.h>
#include "io/pn_cmd_server.h"

#include <string.h>

void
run_simple_test (const gchar *str,
                 gsize buf_size)
{
    PnCmdServer *cmdserv;
    gchar *buf;

    buf = g_malloc (buf_size);

    if (str)
        strcpy (buf, str);

    cmdserv = pn_cmd_server_new (0);
    pn_node_parse (PN_NODE (cmdserv), buf, buf_size - 1);
    pn_cmd_server_free (cmdserv);

    g_free (buf);
}

int
main (int argc,
      char *argv[])
{
    g_type_init ();

    run_simple_test (NULL, 0x400);
    run_simple_test ("MSN 1 foo\r\n", 0x400);
    run_simple_test ("do", 0x400);
    run_simple_test ("1a1", 0x400);
    run_simple_test ("averylongword", 0x400);
    run_simple_test ("©€®¥$\0foo", 0x400);
    run_simple_test ("MSN 1 foo\r\nbar\nzoo\rbar\n\r", 0x400);
    run_simple_test ("123", 0x400);
    run_simple_test ("123 1", 0x400);
    run_simple_test ("ego", 0x400);

    return 0;
}
