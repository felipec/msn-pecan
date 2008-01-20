/*
 * Copyright (C) 2006-008 Felipe Contreras.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef MSN_BUFFER_H
#define MSN_BUFFER_H

#include <glib.h>

typedef struct MsnBuffer MsnBuffer;

#define MSN_BUF_SIZE 0x1000

struct MsnBuffer
{
    gchar *data;
    gchar *alloc_data;
    guint size;
    guint filled;
};

MsnBuffer *msn_buffer_new ();
MsnBuffer *msn_buffer_new_and_alloc (guint size);
void msn_buffer_free (MsnBuffer *);
void msn_buffer_resize (MsnBuffer *buffer, guint new_size);
gchar *msn_buffer_to_string (MsnBuffer *buffer);
void msn_buffer_prepare (MsnBuffer *buffer, guint extra_size);

#endif /* MSN_BUFFER_H */
