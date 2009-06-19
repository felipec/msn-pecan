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
#include "pecan_printf.h"

void
pecan_printf (const gchar *expect,
              const gchar *format,
              ...)
{
    gchar *buffer;
    va_list args;

    va_start (args, format);
    buffer = pecan_strdup_vprintf (format, args);
    va_end (args);

    g_printf ("[%s] %s\n", buffer, (strcmp (expect, buffer) == 0) ? "OK" : "fail" );

    g_free (buffer);
}

int
main (int argc,
      char *argv[])
{
    g_type_init ();

    pecan_printf ("hello world!", "hello world!");
    pecan_printf ("hello world!", "hello %s!", "world");
    pecan_printf ("3", "%d", 3);
    pecan_printf ("3", "%i", 3);
    pecan_printf ("-3", "%d", -3);
    pecan_printf ("0xd", "%p", 13);
    pecan_printf ("(nil)", "%p", NULL);
    pecan_printf ("3", "%u", 3);
    pecan_printf ("4294967293", "%u", -3);
    pecan_printf ("3", "%lu", 3);
    pecan_printf ("4294967293", "%lu", -3);
    pecan_printf ("a", "%c", 'a');
    pecan_printf ("D", "%X", 13);
    pecan_printf ("   D", "%4X", 13);
    pecan_printf ("000D", "%.4X", 13);
    pecan_printf ("000D", "%04X", 13);

    return 0;
}
