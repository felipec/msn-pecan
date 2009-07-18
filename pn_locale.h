/**
 * Copyright (C) 2008-2009 Felipe Contreras
 * Copyright (C) 1998-2006 Pidgin (see pidgin-copyright)
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

#ifndef PN_LOCALE_H
#define PN_LOCALE_H

#ifdef ENABLE_NLS
#  include <locale.h>
#  include <libintl.h>
#  define N_(s) (s)
#  define _(s) ((const char *) dgettext("libmsn-pecan", (s)))
#else
#  define N_(s) (s)
#  define _(s) ((const char *) s)
#endif

#endif /* PN_LOCALE_H */
