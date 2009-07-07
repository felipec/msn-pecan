/*
 * Copyright (C) 2006-2009 Felipe Contreras.
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

#ifndef PN_BUFFER_H
#define PN_BUFFER_H

#include <glib.h>

struct pn_buffer {
    gchar *data;
    gchar *alloc_data;
    gsize size;
    gsize len;
};

struct pn_buffer *pn_buffer_new (void);
struct pn_buffer *pn_buffer_new_and_alloc (gsize size);
struct pn_buffer *pn_buffer_new_memdup (const gpointer data, gsize size);
void pn_buffer_free (struct pn_buffer *buffer);
void pn_buffer_resize (struct pn_buffer *buffer, gsize new_size);
gchar *pn_buffer_to_string (struct pn_buffer *buffer);
void pn_buffer_prepare (struct pn_buffer *buffer, gsize extra_size);

#endif /* PN_BUFFER_H */
