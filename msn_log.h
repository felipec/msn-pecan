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

#ifndef MSN_LOG_H
#define MSN_LOG_H

#include <glib.h>
#include "msn.h"

#if defined(MSN_DEBUG)

/* #define MSN_DEBUG_FILE */

/* #define MSN_DEBUG_MSG */
/* #define MSN_DEBUG_SLPMSG */
/* #define MSN_DEBUG_HTTP */

/* #define MSN_DEBUG_SLP_VERBOSE */
/* #define MSN_DEBUG_SLP_FILES  */

/* #define MSN_DEBUG_NS */
/* #define MSN_DEBUG_SB */
/* #define MSN_DEBUG_DC */

/* #define MSN_DEBUG_DC_FILES */

enum MsnLogLevel
{
    MSN_LOG_LEVEL_NONE,
    MSN_LOG_LEVEL_ERROR,
    MSN_LOG_LEVEL_WARNING,
    MSN_LOG_LEVEL_INFO,
    MSN_LOG_LEVEL_DEBUG,
    MSN_LOG_LEVEL_LOG
};

void msn_base_log_helper (guint level, const gchar *file, const gchar *function, gint line, const char *fmt, ...);
void msn_dump_file (const gchar *buffer, gsize len);

#define msn_print(...) g_print (__VA_ARGS__);
/* #define msn_print(...) purple_debug_info ("msn", __VA_ARGS__); */

#define msn_base_log(level, ...) msn_base_log_helper (level, __FILE__, __func__, __LINE__, __VA_ARGS__);

#define msn_error(...) msn_base_log (MSN_LOG_LEVEL_ERROR, __VA_ARGS__);
#define msn_warning(...) msn_base_log (MSN_LOG_LEVEL_WARNING, __VA_ARGS__);
#define msn_info(...) msn_base_log (MSN_LOG_LEVEL_INFO, __VA_ARGS__);
#define msn_debug(...) msn_base_log (MSN_LOG_LEVEL_DEBUG, __VA_ARGS__);
#define msn_log(...) msn_base_log (MSN_LOG_LEVEL_LOG, __VA_ARGS__);

#elif !defined(MSN_DEBUG)

#define msn_print(...) {}
#define msn_error(...) {}
#define msn_warning(...) {}
#define msn_info(...) {}
#define msn_debug(...) {}
#define msn_log(...) {}

#endif /* !defined(MSN_DEBUG) */

#endif /* MSN_LOG_H */
