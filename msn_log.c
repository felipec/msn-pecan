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

#include "msn_log.h"

#ifdef MSN_DEBUG

#include <glib/gstdio.h>

static const gchar *
log_level_to_string (enum MsnLogLevel level)
{
    switch (level)
    {
        case MSN_LOG_LEVEL_NONE: return "NONE"; break;
        case MSN_LOG_LEVEL_ERROR: return "ERROR"; break;
        case MSN_LOG_LEVEL_WARNING: return "WARNING"; break;
        case MSN_LOG_LEVEL_INFO: return "INFO"; break;
        case MSN_LOG_LEVEL_DEBUG: return "DEBUG"; break;
        case MSN_LOG_LEVEL_LOG: return "LOG"; break;
        default: return "Unknown"; break;
    }
}

void
msn_base_log_helper (guint level,
                     const gchar *file,
                     const gchar *function,
                     gint line,
                     const gchar *fmt,
                     ...)
{
    gchar *tmp;
    va_list args;

    va_start (args, fmt);

    tmp = g_strdup_vprintf (fmt, args);
#ifdef MSN_DEBUG_FILE
    {
        static FILE *logfile;
        if (!logfile)
        {
            gint fd;
            fd = g_file_open_tmp ("pecan-XXXXXX.log", NULL, NULL);
            logfile = fdopen (fd, "w");
        }
        g_fprintf (logfile, "%s\t%s:%d:%s()\t%s\n",
                   log_level_to_string (level),
                   file, line, function,
                   tmp);
    }
#else
    msn_print ("%s %s:%d:%s() %s\n",
               log_level_to_string (level),
               file, line, function,
               tmp);
#endif
    g_free (tmp);

    va_end (args);
}

#endif /* MSN_DEBUG */
