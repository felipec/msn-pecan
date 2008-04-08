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

#ifdef PECAN_CUSTOM_PRINTF
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
            cur++;

            /* skip field width */
            for (; *cur >= '0' && *cur <= '9'; cur++);

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
                    g_string_append_printf (buf, "%p", va_arg (args, void *));
                    break;
                case 'd':
                case 'i':
                    g_string_append_printf (buf, "%d", va_arg (args, int));
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
