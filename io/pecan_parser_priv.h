/*
 * Copyright (C) 2008 Felipe Contreras.
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

#ifndef PECAN_PARSER_PRIVATE_H
#define PECAN_PARSER_PRIVATE_H

#include "io/pecan_parser.h"
#include "io/pecan_node.h"

struct PecanParser
{
    PecanNode *node;
    gchar *rx_buf;
    gsize rx_len;
    gboolean need_more;
};

#endif /* PECAN_PARSER_PRIVATE_H */
