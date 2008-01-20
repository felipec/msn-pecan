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

#ifndef MSN_IO_H
#define MSN_IO_H

#include "msn.h"

GIOStatus msn_io_read (GIOChannel *channel, gchar *buf, gsize count, gsize *bytes_read, GError **error);
GIOStatus msn_io_write (GIOChannel *channel, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
GIOStatus msn_io_read_full (GIOChannel *channel, gchar *buf, gsize count, gsize *bytes_read, GError **error);
GIOStatus msn_io_write_full (GIOChannel *channel, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
GIOStatus msn_io_flush (GIOChannel *channel, GError **error);

#endif /* MSN_IO_H */
