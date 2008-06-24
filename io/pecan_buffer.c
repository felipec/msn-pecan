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

#include "pecan_buffer.h"

PecanBuffer *
pecan_buffer_new (void)
{
    PecanBuffer *buffer;
    buffer = g_new (PecanBuffer, 1);
    buffer->data = NULL;
    buffer->alloc_data = NULL;
    buffer->size = 0;
    buffer->len = 0;
    return buffer;
}

PecanBuffer *
pecan_buffer_new_and_alloc (gsize size)
{
    PecanBuffer *buffer;

    if (size <= 0)
        size = PECAN_BUF_SIZE;

    buffer = g_new (PecanBuffer, 1);
    buffer->data = buffer->alloc_data = g_malloc (size);
    buffer->size = size;
    buffer->len = 0;
    return buffer;
}

PecanBuffer *
pecan_buffer_new_memdup (gpointer data,
                         gsize size)
{
    PecanBuffer *buffer;

    buffer = g_new (PecanBuffer, 1);
    buffer->size = buffer->len = size;
    buffer->data = buffer->alloc_data = g_memdup (data, size);

    return buffer;
}

void
pecan_buffer_free (PecanBuffer *buffer)
{
    if (!buffer)
        return;

    g_free (buffer->alloc_data);
    g_free (buffer);
}

void
pecan_buffer_resize (PecanBuffer *buffer,
                     gsize new_size)
{
    new_size = ((new_size / PECAN_BUF_SIZE) + 1) * PECAN_BUF_SIZE;
    buffer->data = buffer->alloc_data = g_realloc (buffer->data, new_size);
    buffer->size = new_size;
}

void
pecan_buffer_prepare (PecanBuffer *buffer,
                      gsize extra_size)
{
    if (buffer->size - buffer->len < extra_size)
    {
        pecan_buffer_resize (buffer, buffer->len + extra_size);
    }
}
