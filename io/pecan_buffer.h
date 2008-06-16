/*
 * Copyright (C) 2006-2008 Felipe Contreras.
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PECAN_BUFFER_H
#define PECAN_BUFFER_H

#include <glib.h>

typedef struct PecanBuffer PecanBuffer;

struct PecanBuffer
{
    gchar *data;
    gchar *alloc_data;
    gsize size;
    gsize len;
};

#define PECAN_BUF_SIZE 0x1000

PecanBuffer *pecan_buffer_new (void);
PecanBuffer *pecan_buffer_new_and_alloc (gsize size);
PecanBuffer *pecan_buffer_new_memdup (const gpointer data, gsize size);
void pecan_buffer_free (PecanBuffer *buffer);
void pecan_buffer_resize (PecanBuffer *buffer, gsize new_size);
gchar *pecan_buffer_to_string (PecanBuffer *buffer);
void pecan_buffer_prepare (PecanBuffer *buffer, gsize extra_size);

#endif /* PECAN_BUFFER_H */
