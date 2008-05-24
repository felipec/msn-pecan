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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include "pecan_printf.h"

#ifdef PECAN_CUSTOM_PRINTF
/** @todo this needs to be heavily optimized */
gchar *
pecan_strdup_vprintf (const gchar *format,
                      va_list args)
{
    const gchar *cur;
    GString *buf;

    buf = g_string_new (NULL);

    for (cur = format; *cur; cur++)
    {
        if (*cur == '%')
        {
            gboolean fill = FALSE;
            guint field_width = 0;

            cur++;

            /** @todo hack */
            if (*cur == '0' || *cur == '.')
            {
                cur++;
                fill = TRUE;
            }

            /* field width */
            for (; *cur >= '0' && *cur <= '9'; cur++)
                field_width = field_width * 10 + (*cur - '0');

            /** @todo hack */
            if (*cur == 'l')
                cur++;

            switch (*cur)
            {
                case 's':
                    {
                        const char *value;
                        value = va_arg (args, char *);
                        g_string_append_printf (buf, "%s", value ? value : "(nil)");
                        break;
                    }
                case 'p':
                case 'd':
                case 'i':
                case 'u':
                case 'X':
                    {
                        gchar *tmp;
                        if (field_width && fill)
                            tmp = g_strdup_printf ("%%0%d%c", field_width, *cur);
                        else if (field_width)
                            tmp = g_strdup_printf ("%%%d%c", field_width, *cur);
                        else
                            tmp = g_strdup_printf ("%%%c", *cur);
                        g_string_append_printf (buf, tmp, va_arg (args, void *));
                        g_free (tmp);
                        break;
                    }
                case 'c':
                    g_string_append_c (buf, va_arg (args, int));
                    break;
                default:
                    va_arg (args, int);
                    g_string_append_printf (buf, "%c", *cur);
                    break;
            }
        }
        else
        {
            g_string_append_c (buf, *cur);
        }
    }

    return g_string_free (buf, FALSE);
}

gchar *
pecan_strdup_printf (const gchar *format,
                     ...)
{
    gchar *buffer;
    va_list args;

    va_start (args, format);
    buffer = pecan_strdup_vprintf (format, args);
    va_end (args);

    return buffer;
}

#endif /* PECAN_CUSTOM_PRINTF */
