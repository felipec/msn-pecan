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

#ifndef PECAN_PARSER_H
#define PECAN_PARSER_H

typedef struct PecanParser PecanParser;

#include "io/pecan_node.h"

PecanParser *pecan_parser_new (PecanNode *node);
void pecan_parser_free (PecanParser *parser);
GIOStatus pecan_parser_read_line (PecanParser *parser,
                                  gchar **str_return,
                                  gsize *length,
                                  gsize *terminator_pos,
                                  GError **error);

#endif /* PECAN_PARSER_H */
