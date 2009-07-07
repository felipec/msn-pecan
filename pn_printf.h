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

#ifndef PN_PRINTF_H
#define PN_PRINTF_H

#include <glib.h>

#define PN_CUSTOM_PRINTF

#ifdef PN_CUSTOM_PRINTF
char *pn_strdup_vprintf(const char *format, va_list args);
char *pn_strdup_printf(const char *format, ...);
#else
#define pn_strdup_vprintf g_strdup_vprintf
#define pn_strdup_printf g_strdup_printf
#endif /* PN_CUSTOM_PRINTF */

#endif /* PN_PRINTF_H */
