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

#ifndef PN_LOG_H
#define PN_LOG_H

#include <glib.h>

#define PN_DEBUG

#if defined(PN_DEBUG)

/* #define PN_DEBUG_MSG */
/* #define PN_DEBUG_SLPMSG */
/* #define PN_DEBUG_HTTP */

/* #define PN_DEBUG_SLP_VERBOSE */
/* #define PN_DEBUG_SLP_FILES  */

/* #define PN_DEBUG_NS */
/* #define PN_DEBUG_SB */
/* #define PN_DEBUG_DC */

/* #define PN_DEBUG_DC_FILES */

enum PecanLogLevel
{
    PN_LOG_LEVEL_NONE,
    PN_LOG_LEVEL_ERROR,
    PN_LOG_LEVEL_WARNING,
    PN_LOG_LEVEL_INFO,
    PN_LOG_LEVEL_DEBUG,
    PN_LOG_LEVEL_LOG,
    PN_LOG_LEVEL_TEST,
};

#ifdef PECAN_DEVEL
#define PECAN_LOG_LEVEL PN_LOG_LEVEL_LOG
#else
#define PECAN_LOG_LEVEL PN_LOG_LEVEL_INFO
#endif

typedef enum PecanLogLevel PecanLogLevel;

void pn_base_log_helper (PecanLogLevel level,
                         const gchar *file,
                         const gchar *function,
                         gint line,
                         const gchar *fmt,
                         ...) G_GNUC_PRINTF (5, 6);
#ifdef PN_DUMP_FILE
void pn_dump_file (const gchar *buffer, gsize len);
#endif /* PN_DUMP_FILE */

#define pn_base_log(level, ...) pn_base_log_helper (level, __FILE__, __func__, __LINE__, __VA_ARGS__)

#define pn_error(...) pn_base_log (PN_LOG_LEVEL_ERROR, __VA_ARGS__)
#define pn_warning(...) pn_base_log (PN_LOG_LEVEL_WARNING, __VA_ARGS__)
#define pn_info(...) pn_base_log (PN_LOG_LEVEL_INFO, __VA_ARGS__)
#define pn_debug(...) pn_base_log (PN_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define pn_log(...) pn_base_log (PN_LOG_LEVEL_LOG, __VA_ARGS__)
#define pn_test(...) pn_base_log (PN_LOG_LEVEL_TEST, __VA_ARGS__)

#elif !defined(PN_DEBUG)

#define pn_error(...) {}
#define pn_warning(...) {}
#define pn_info(...) {}
#define pn_debug(...) {}
#define pn_log(...) {}
#define pn_test(...) {}
#define pn_dump_file(...) {}

#endif /* !defined(PN_DEBUG) */

#endif /* PN_LOG_H */
